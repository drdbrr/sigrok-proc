#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>
#include <glib.h>
#include "sigrok-proc.h"
#include <float.h>
#include <glib-object.h>
#include <json-glib/json-glib.h>
#include <time.h>

#define PH_LEN 4

#define BUF_SIZE 1024

#define CHUNK_SIZE (4 * 1024 * 1024)

static gint sort_pds(gconstpointer a, gconstpointer b);

GMainLoop *loop = NULL;

struct sr_session *session = NULL;
struct sr_context *sr_ctx = NULL;
struct sr_dev_inst *sdi = NULL;
struct sr_dev_driver *driver = NULL;
GSList *devices = NULL;

struct writer_data *wrd;

static uint64_t sample_rate = 0;

struct srd_session *srd_sess = NULL;
struct srd_decoder_inst *di;


struct sr_output_module {
    const char *id;
    const char *name;
    const char *desc;
    const char *const *exts;
    const uint64_t flags;
    const struct sr_option *(*options) (void);
    int (*init) (struct sr_output *o, GAsyncQueue *out_queue);
    int (*receive) (const struct sr_output *o, const struct sr_datafeed_packet *packet, GString **out);
    int (*cleanup) (struct sr_output *o);
};


gpointer session_state = 0;
GMutex session_state_mutex;
GCond session_state_cond;


void sr_sampling_thread(void){
    if (sr_session_start(session) == SR_OK){
        g_message("START sampling");
        g_mutex_lock(&session_state_mutex);
        session_state = 1;
        g_cond_signal(&session_state_cond);
        g_mutex_unlock(&session_state_mutex);
        sr_session_run(session);
    }
}

guint64 *gen_list(guint64 start, guint64 len){
    guint64 *array = g_malloc((64/8) * len * 3);
    guint64 divs[] = {2, 5, 10};
    guint64 mult = 1;
    int v = 0;
    for (int i = 0; i < len; i++){
        for (int j = 2; j >= 0; j--){
            guint64 value = start * 10 / divs[j] * mult;
            array[v] = value;
            v++;
        }
        mult *= 10;
    }
    return array;
}

//--------------------------GET OPTIONS--------------------------
static void  array_get_cb(JsonArray *array, guint i, JsonNode *element_node, gpointer builder){

    const char *req = NULL;
    JsonObject *reqObj = NULL;
    
    GType reqType = json_node_get_node_type(element_node);
    
    if (reqType == JSON_NODE_VALUE){
        req = json_node_get_string(element_node);
    }

    else if (reqType == JSON_NODE_OBJECT){
        reqObj = json_node_get_object(element_node);
    }
        
    const char *get_drivers = "drivers";
    const char *get_scan = "scan";

    const char *get_decoders_list = "decoders_list";

    GVariant *gvar, *gvar_list, *gvar_dict;
    gsize num_elements;

    const struct sr_key_info *srci;
    
    struct sr_channel_group *channel_group;
    GArray *opts;
    
    
    //REQ PD LIST
    if (!strcmp(req, get_decoders_list)){
        GSList *sl;
        const GSList *l;
        struct srd_decoder *dec;
        
        char *doc_str = "";
        
        //srd_decoder_load_all();
        sl = g_slist_copy((GSList *)srd_decoder_list());
        sl = g_slist_sort(sl, sort_pds);
        
        json_builder_set_member_name(builder, "decoders_list");
        json_builder_begin_array(builder);
        
        for (l = sl; l; l = l->next) {
            dec = l->data;
            json_builder_begin_object(builder);
            
            json_builder_set_member_name(builder, "id");
            json_builder_add_string_value(builder, dec->id);
            
            json_builder_set_member_name(builder, "name");
            json_builder_add_string_value(builder, dec->name);
            
            json_builder_set_member_name(builder, "longname");
            json_builder_add_string_value(builder, dec->longname);
            
            json_builder_set_member_name(builder, "desc");
            json_builder_add_string_value(builder, dec->desc);
            
            json_builder_set_member_name(builder, "tags");
            json_builder_begin_array(builder);
            for (GSList *l = dec->tags; l; l = l->next){
                char *tag = l->data;
                json_builder_add_string_value(builder, tag);
            }
            json_builder_end_array(builder);
            
            //ATTENTION
            json_builder_set_member_name(builder, "doc");            
            doc_str = srd_decoder_doc_get(dec);
            JsonNode *doc_nd = json_node_init_string (json_node_alloc(), doc_str);
            json_builder_add_value(builder, doc_nd);              
            g_free(doc_str);
            
            /*
            json_builder_set_member_name(builder, "license");
            json_builder_add_string_value(builder, dec->license);
            */
            
            json_builder_end_object(builder);
        }
        g_slist_free(sl);
        //srd_decoder_unload_all();
        json_builder_end_array(builder);
    }
    
    //REQUEST DRIVERS
    else if (!strcmp(req, get_drivers)){
        struct sr_dev_driver **drivers;
        json_builder_set_member_name (builder, "drivers");
        json_builder_begin_array(builder);
        drivers = sr_driver_list(sr_ctx);
        for (int i = 0; drivers[i]; i++){
            json_builder_add_string_value(builder, drivers[i]->name);
        }
        json_builder_end_array(builder);
        g_message("Get drivers");
    }

    //REQUEST SCAN FOR DEVICE
    else if (!strcmp(req, get_scan)){
        json_builder_set_member_name(builder, "scan");
        if (driver == NULL){
            json_builder_add_string_value(builder, "error: no driver");
            g_message("ERROR: Get scan, no driver");
        }
        else{
            GSList *drvopts = NULL;
            devices = sr_driver_scan(driver, drvopts);
            json_builder_begin_array(builder);
            for (int i = 0; i < g_slist_length(devices); i++) {
                struct sr_dev_inst *dev_d = g_slist_nth_data(devices, i);
                struct sr_dev_driver *drv = sr_dev_inst_driver_get(dev_d);
                
                json_builder_begin_object(builder);
                
                json_builder_set_member_name(builder, "vendor");
                const char *vendor = sr_dev_inst_vendor_get(dev_d);
                json_builder_add_string_value(builder, vendor);
                
                json_builder_set_member_name(builder, "model");
                const char *model = sr_dev_inst_model_get(dev_d);
                json_builder_add_string_value(builder, model);
                
                json_builder_set_member_name(builder, "driverName");
                json_builder_add_string_value(builder, drv->name);
                
                json_builder_set_member_name(builder, "connectionId");
                const char *connid = sr_dev_inst_connid_get(dev_d);
                json_builder_add_string_value(builder, connid);
                
                json_builder_end_object(builder);
            }
            json_builder_end_array(builder);
            g_message("Get scan: %d", g_slist_length(devices));
        }
    }
}
//---------------------------------------------------------------

gint find_channel_cb(gpointer pa, gpointer pb){
    struct sr_channel *ch = pa;
    return strcmp(ch->name, pb);
}

static void process_pd_opts_cb(struct srd_decoder_option *o, JsonBuilder *builder){
    json_builder_begin_object(builder);
            
    json_builder_set_member_name(builder, "id");
    json_builder_add_string_value(builder, o->id);
    
    json_builder_set_member_name(builder, "desc");
    json_builder_add_string_value(builder, o->desc);
    
    const gchar *type_str = NULL;
    type_str = g_variant_get_type_string(o->def);
    
    if (type_str != NULL){
        JsonNode *type_nd = json_node_init_string (json_node_alloc(), type_str);
        json_builder_set_member_name(builder, "type");
        json_builder_add_value(builder, type_nd);
        
        json_builder_set_member_name(builder, "defv");
        JsonNode *def_nd = json_gvariant_serialize(o->def);
        json_builder_add_value(builder, def_nd);
        
        if(o->values != NULL){
            json_builder_set_member_name(builder, "values");
            json_builder_begin_array(builder);
            for (GSList *ovl = o->values; ovl; ovl = ovl->next){
                JsonNode *v_nd = json_gvariant_serialize(ovl->data);
                json_builder_add_value(builder, v_nd);
            }
            json_builder_end_array(builder);
        }
    }
    json_builder_end_object(builder);
}

void pd_channels_to_json(GSList *channels, gpointer builder){
    json_builder_begin_array(builder);
    struct srd_channel *pdch;
    GSList *l;
    for (l = channels; l; l = l->next) {
        pdch = l->data;
        json_builder_begin_object(builder);
        
        
        json_builder_set_member_name(builder, "id");
        json_builder_add_string_value(builder, pdch->id);
        
        json_builder_set_member_name(builder, "name");
        json_builder_add_string_value(builder, pdch->name);
        
        json_builder_set_member_name(builder, "desc");
        json_builder_add_string_value(builder, pdch->desc);
        
        json_builder_set_member_name(builder, "order");
        json_builder_add_int_value(builder, pdch->order);
        
        json_builder_end_object(builder);
    }
    json_builder_end_array(builder);
}

//--------------------------SET OPTIONS--------------------------
static void object_set_cb(JsonObject *object, const char *member_name, JsonNode *member_node, gpointer builder) {
    const char *set_driver = "driver";
    const char *set_dev_num = "dev_num";
    const char *set_run_session = "run_session";
    
    GVariant *gvar = NULL, *gvar_dict, *gvar_list;
    gsize num_elements;
    
    const char *set_decoder = "register_pd";
    struct srd_decoder *dec;
    
    GSList *l;
    struct srd_decoder_option *opt;

    
    //ADD DECODER BY ID
    if(!strcmp(member_name, set_decoder)){
        const char *id = json_node_get_string(member_node);
        //const char *id = json_object_get_string_member(object, "id");
        
        /*
        if (srd_decoder_load("uart") == SRD_OK ){
            g_message("_____SRD_LOAD");
        }
        */
        
        if (srd_decoder_get_by_id(id)){
            g_message("ALL OK");
        }
        
        di = srd_inst_new(srd_sess, id, NULL);
        
        dec = di->decoder;
        
        json_builder_set_member_name(builder, "register_pd");
        json_builder_begin_object(builder);
        
        
        json_builder_set_member_name(builder, "id");
        json_builder_add_string_value(builder, dec->id);
        
        json_builder_set_member_name(builder, "name");
        json_builder_add_string_value(builder, dec->name);
        
        json_builder_set_member_name(builder, "longname");
        json_builder_add_string_value(builder, dec->longname);
        
        json_builder_set_member_name(builder, "desc");
        json_builder_add_string_value(builder, dec->desc);
        

        json_builder_set_member_name(builder, "options");
        json_builder_begin_array(builder);
        g_slist_foreach(dec->options, process_pd_opts_cb, builder);
        json_builder_end_array(builder);
        
        json_builder_set_member_name(builder, "annotationRows");
        json_builder_begin_array(builder);
        GSList *l;
        const struct srd_decoder_annotation_row *row;
        for (l = dec->annotation_rows; l; l = l->next){
            row = l->data;
            json_builder_begin_object(builder);
            json_builder_set_member_name(builder, "id");
            json_builder_add_string_value(builder, row->id);
            json_builder_set_member_name(builder, "desc");
            json_builder_add_string_value(builder, row->desc);
            json_builder_end_object(builder);
        }
        json_builder_end_array(builder);
        
        json_builder_set_member_name(builder, "channels");
        pd_channels_to_json(dec->channels, builder);
        json_builder_set_member_name(builder, "optChannels");
        pd_channels_to_json(dec->opt_channels, builder);
        
        
        json_builder_end_object(builder);
        
        /*
        if (!(di = srd_inst_new(srd_sess, pd_id, options))) {
            g_message("_____CANT SRD_INIT");
        }
        */
        
    }
   
    //SET DRIVER
    else if (!strcmp(member_name, set_driver)){
        const char *drv = json_node_get_string(member_node);
        driver = NULL;
        struct sr_dev_driver **drivers;
        GSList *drvopts = NULL;
        drivers = sr_driver_list(sr_ctx);
        json_builder_set_member_name(builder, "driver");
        for (int i = 0; drivers[i]; i++){
            if (strcmp(drivers[i]->name, drv))
                continue;
            driver = drivers[i];
        }
        if (sr_driver_init(sr_ctx, driver) != SR_OK){
            json_builder_add_string_value(builder, "error");
            g_message("ERROR: driver can not set");
        }
        else{
            json_builder_add_string_value(builder, "set");
            g_message("Set driver: %s", drv);
        }
    }
    
    //SET DEV_NUM
    else if (!strcmp(member_name, set_dev_num)){
        
        if (sdi != NULL){
            sr_dev_close(sdi);
            sr_session_dev_remove(session, sdi);
            sdi = NULL;
        }
        
        guint8 num = json_node_get_int(member_node);
        sdi = g_slist_nth_data(devices, num);
        
        json_builder_set_member_name(builder, "dev_num");
        
        json_builder_begin_object(builder);

        if (sr_session_dev_add(session, sdi) != SR_OK){
            json_builder_add_string_value(builder, "error");
            g_message("ERROR: add device");
        }
        else if (sr_dev_open(sdi) != SR_OK){
            json_builder_add_string_value(builder, "error");
            g_message("ERROR: open device");
        } else {
            struct sr_dev_driver *drv;
            
            static uint64_t limit_sample = 1000000;
            gvar = g_variant_new_uint64(limit_sample);
            sr_config_set(sdi, NULL, SR_CONF_LIMIT_SAMPLES, gvar);

            json_builder_set_member_name(builder, "sourcename");
            drv = sr_dev_inst_driver_get(sdi);
            if (!strcmp(drv->name, (char *)"demo")){
                json_builder_add_string_value(builder, "Demo");
            }
            else{
                const char *vendor = sr_dev_inst_vendor_get(sdi);
                json_builder_add_string_value(builder, vendor);
            }

            
            
            GArray *opts;
            const struct sr_key_info *srci;
            guint8 i;

            // DEVICE OPTIONS (ConfigKey.TRIGGER_MATCH, ConfigKey.AVG_SAMPLES, ConfigKey.AVERAGING, ConfigKey.CAPTURE_RATIO, ConfigKey.SAMPLERATE etc...)
            // HAS CAPABILITIES
            json_builder_set_member_name(builder, "devopts");
            if (sdi != NULL){
                json_builder_begin_array(builder);
                drv = sr_dev_inst_driver_get(sdi);
              
                opts = sr_dev_options(drv, sdi, NULL);
                
                for (i = 0; i < opts->len; i++) {
                    if (!(srci = sr_key_info_get(SR_KEY_CONFIG, g_array_index(opts, uint32_t, i))))
                        continue;
                    
                    json_builder_begin_object(builder);

                    json_builder_set_member_name(builder, "key");
                    json_builder_add_int_value(builder, srci->key);
                    
                    if (srci->id){
                        json_builder_set_member_name(builder, "id");
                        json_builder_add_string_value(builder, srci->id);
                    }
                    
                    if (srci->name){
                        json_builder_set_member_name(builder, "name");
                        json_builder_add_string_value(builder, srci->name);
                    }
                    
                    if (srci->description){
                        json_builder_set_member_name(builder, "desc");
                        json_builder_add_string_value(builder, srci->description);
                    }

                    JsonArray *capsList = json_array_new();
                    if (sr_dev_config_capabilities_list(sdi, NULL, srci->key) & SR_CONF_GET){
                        json_array_add_string_element(capsList, "GET");
                        
                        json_builder_set_member_name(builder, "value");

                        if (sr_config_get(driver, sdi, NULL, srci->key, &gvar) == SR_OK){
                            if (srci->key == SR_CONF_SAMPLERATE){
                                guint64 smplrate = g_variant_get_uint64(gvar);
                                char *rate = sr_samplerate_string(smplrate);
                                json_builder_add_string_value(builder, rate);
                                g_free(rate);
                            }
                            else if (srci->key == SR_CONF_LIMIT_SAMPLES){
                                guint64 sample = g_variant_get_uint64(gvar);
                                char *rate = sr_si_string_u64(sample, " samples");
                                json_builder_add_string_value(builder, rate);
                                g_free(rate);
                                
                                json_array_add_string_element(capsList, "LIST");
                                json_builder_set_member_name(builder, "values");
                                guint64 *samples = gen_list(100, 12);
                                json_builder_begin_array(builder);
                                for (int i = 0; samples[i]; i++){
                                    rate = sr_si_string_u64(samples[i], " samples");
                                    json_builder_add_string_value(builder, rate);
                                    g_free(rate);
                                }
                                json_builder_end_array(builder);
                            } 
                            else {
                                JsonNode *value = json_gvariant_serialize(gvar);
                                json_builder_add_value(builder, value);
                            }
                        }
                    }
                    
                    if (sr_dev_config_capabilities_list(sdi, NULL, srci->key) & SR_CONF_SET){
                        json_array_add_string_element(capsList, "SET");
                    }

                    if (sr_dev_config_capabilities_list(sdi, NULL, srci->key) & SR_CONF_LIST){
                        json_array_add_string_element(capsList, "LIST");

                        sr_config_list(driver, sdi, NULL, srci->key, &gvar_dict);
                        json_builder_set_member_name(builder, "values");
                        
                        if (srci->key == SR_CONF_SAMPLERATE){
                        
                            uint64_t *rates;
                            char *rate;
                            
                            json_builder_begin_array(builder);
                            if ((gvar_list = g_variant_lookup_value(gvar_dict, "samplerates", G_VARIANT_TYPE("at")))){
                                rates = g_variant_get_fixed_array(gvar_list, &num_elements, sizeof(rates));
                                for (int i = 0; i < num_elements; i++) {
                                    rate = sr_samplerate_string(rates[i]);
                                    json_builder_add_string_value(builder, rate);
                                    g_free(rate);
                                }
                                //g_variant_unref(gvar_dict);
                            }
                            else if ((gvar_list = g_variant_lookup_value(gvar_dict, "samplerate-steps", G_VARIANT_TYPE("at")))) {
                                rates = gen_list(10, 8);
                                for (int i = 0; rates[i]; i++){
                                    rate = sr_samplerate_string(rates[i]);
                                    json_builder_add_string_value(builder, rate);
                                    g_free(rate);
                                }
                                //g_variant_unref(gvar_dict);
                            }
                            
                            json_builder_end_array(builder);
                            g_variant_unref(gvar_dict);
                            g_variant_unref(gvar_list);
                        }
                        else {
                            JsonNode *value = json_gvariant_serialize(gvar_dict);
                            json_builder_add_value(builder, value);
                        }
                    }
                    
                    if (json_array_get_length(capsList)){
                        json_builder_set_member_name(builder, "caps");
                        JsonNode *capsNode = json_node_init_array(json_node_alloc(), capsList);
                        json_builder_add_value(builder, capsNode);
                    }
                    
                    json_builder_end_object(builder);
                    
                }
                json_builder_end_array(builder);
                g_array_free(opts, TRUE);
            }
            
            //DRIVER OPTIONS (ConfigKey.DEMO_DEV, ConfigKey.OSCILLOSCOPE, ConfigKey.LOGIC_ANALYZER etc...)
            //HAVE NO "identifier", NO CAPABILITIES
            json_builder_set_member_name(builder, "drvopts");
            if (sdi != NULL) {
                json_builder_begin_array(builder);
                drv = sr_dev_inst_driver_get(sdi);
                if ((opts = sr_dev_options(drv, NULL, NULL))) {
                    if (opts->len > 0) {
                        
                        for (i = 0; i < opts->len; i++) {
                            if (!(srci = sr_key_info_get(SR_KEY_CONFIG, g_array_index(opts, uint32_t, i))))
                                continue;
                            
                            json_builder_begin_object(builder);

                            json_builder_set_member_name(builder, "key");
                            json_builder_add_int_value(builder, srci->key);

                            if (srci->id){
                                json_builder_set_member_name(builder, "id");
                                json_builder_add_string_value(builder, srci->id);
                            }

                            if (srci->name){
                                json_builder_set_member_name(builder, "name");
                                json_builder_add_string_value(builder, srci->name);
                            }

                            if (srci->description){
                                json_builder_set_member_name(builder, "desc");
                                json_builder_add_string_value(builder, srci->description);
                            }
                            json_builder_end_object(builder);
                        }
                        g_array_free(opts, TRUE);
                    }
                }
                json_builder_end_array(builder);
            }
            }
        
        struct sr_channel *ch;
        GSList *l, *channels;
        channels = sr_dev_inst_channels_get(sdi);
        
        json_builder_set_member_name(builder, "channels");
        json_builder_begin_array(builder);
        for (l = channels; l; l = l->next) {
            ch = l->data;
            
            json_builder_begin_object(builder);
            
            json_builder_set_member_name(builder, "name");
            json_builder_add_string_value(builder, ch->name);

            json_builder_set_member_name(builder, "enabled");
            json_builder_add_boolean_value(builder, ch->enabled);

            json_builder_set_member_name(builder, "index");
            json_builder_add_int_value(builder, ch->index);
            
            json_builder_set_member_name(builder, "type");

            if (ch->type == SR_CHANNEL_LOGIC /*10000*/)
                json_builder_add_string_value(builder, "logic");
            else if (ch->type == 10001 /*SR_CHANNEL_ANALOG*/)
                json_builder_add_string_value(builder, "analog");
            
            json_builder_end_object(builder);
                
        }
        json_builder_end_array(builder);
        json_builder_end_object(builder);
    }
    
    //SET RUN SESSION
    else if (!strcmp(member_name, set_run_session) && sdi != NULL){
        //guint8 sr_run = json_node_get_int(member_node);
        json_builder_set_member_name(builder, "run_session");
        
        g_mutex_lock(&session_state_mutex);
        if(!session_state){
            GThread *thread = g_thread_new("sr_sampling_thread", sr_sampling_thread, NULL);
            while (!session_state)
                g_cond_wait (&session_state_cond, &session_state_mutex);
            
            json_builder_add_int_value(builder, session_state);
            g_message("Start session: %d", session_state);
        }
        else if (session_state){
            if (sr_session_stop(session) == SR_OK){
                session_state = 0;
                json_builder_add_int_value(builder, session_state);
                g_message("Stop session");
            }
        }
        g_mutex_unlock(&session_state_mutex);
    }
    else {
        g_message("Unknown set option");
    }
}
//---------------------------------------------------------------
    
static void object_member_cb(JsonObject *object, const char *member_name, JsonNode *member_node, gpointer builder){
    const char *get = "get";
    const char *set = "set";
    
    if (!strcmp(member_name, get)){
        json_builder_set_member_name(builder, "get");
        json_builder_begin_object(builder);
        JsonArray *get_opts = json_node_get_array(member_node);
        json_array_foreach_element(get_opts, array_get_cb, builder);
        json_builder_end_object(builder);
    }
    //else if (!strcmp(member_name, set)){
    if (!strcmp(member_name, set)){
        json_builder_set_member_name(builder, "set");
        json_builder_begin_object(builder);
        JsonObject *set_opts = json_node_get_object(member_node);
        json_object_foreach_member(set_opts, object_set_cb, builder);
        json_builder_end_object(builder);
    }
}

struct data_packet {
    guchar *data;
    guint32 length;
};

guint32 json_parse(char *buf, guint64 len, GAsyncQueue *out_queue){
    GError *error = NULL;
    JsonBuilder *builder = json_builder_new();
    
    buf[len] = '\0';
    //g_message("PROC-RX: %s, json_len:%d", buf, len);
    
    JsonParser *parser = json_parser_new();
    json_parser_load_from_data(parser, buf, len, &error);
    JsonNode *root = json_parser_get_root(parser);
    
    JsonObject *object = json_node_get_object(root);
    
    //ATTENTION rid - request ID
    char *rid = json_object_get_string_member(object, "rid");
    guint32 content_length = 0;
    
    if (json_object_has_member(object, "content-length"))
        content_length = json_object_get_int_member(object, "content-length");
    
    json_builder_begin_object(builder);

    json_object_foreach_member(object, object_member_cb, builder);
    json_builder_set_member_name(builder, "rid");
    json_builder_add_string_value(builder, rid);
    
    json_builder_set_member_name(builder, "content-type");
    json_builder_add_string_value(builder, "text/json");
    
    json_builder_end_object(builder);
    
    JsonGenerator *gen = json_generator_new();
    JsonNode *resp_root = json_builder_get_root(builder);
    json_generator_set_root(gen, resp_root);
    
    guint32 *tmp_len = 0;
    struct data_packet *response = g_malloc(sizeof(struct data_packet));
    char *tmp = json_generator_to_data(gen, &tmp_len);
    
    guint32 resp_len = tmp_len;
    
    response->data = g_malloc(resp_len + PH_LEN);
    memcpy(response->data, &resp_len, PH_LEN);
    memcpy(&response->data[4], tmp, resp_len);
    response->length = resp_len + PH_LEN;
    
    g_async_queue_push(out_queue, response);
    
    json_node_free(resp_root);
    g_object_unref(parser);
    g_object_unref(builder);
    g_object_unref(gen);

    return content_length;
}

void process_content(guchar *content, guint32 len){
    g_free(content);
}

struct reader_data{
    gchar *buf;
    GByteArray *array;
    guint32 json_len;
    guint32 content_len;
    uint64_t received;
    GAsyncQueue *out_queue;
    guint32 content_length;
};

gboolean read_cb(GIOChannel *source, GIOCondition cond, gpointer data){
    struct reader_data *rrd = data;
    gsize recv_count;
    GError *error = NULL;
    g_io_channel_read_chars(source, rrd->buf, BUF_SIZE, &recv_count, &error);
    
    g_message("recv_count:%d", recv_count);
    
    g_byte_array_append(rrd->array, rrd->buf, recv_count);
    rrd->received += recv_count;

    //DETECT PACKET START
    if (!rrd->json_len && recv_count >= PH_LEN && !rrd->content_length){
        rrd->received -= PH_LEN;
        rrd->json_len = *((guint32*)rrd->array->data);//GET JSON HEADER LEN
        g_byte_array_remove_range(rrd->array, 0, PH_LEN);
    }
    
    //COMPLETE RECEIVING JSON HEADER
    if (rrd->json_len && rrd->json_len <= rrd->received && !rrd->content_length){
        rrd->content_length = json_parse(rrd->array->data, rrd->json_len, rrd->out_queue);
        g_byte_array_remove_range(rrd->array, 0, rrd->json_len);
        rrd->received -= rrd->json_len;
        rrd->json_len = 0;
    }
    
    if (rrd->content_length && rrd->content_length <= rrd->received){
        process_content(rrd->array->data, rrd->content_length);
        g_byte_array_remove_range(rrd->array, 0, rrd->content_length);
        rrd->received -= rrd->content_length;
        rrd->content_length = 0;
    }
    
    return TRUE;
}

gboolean socket_broken_cb(GIOChannel *source, GIOCondition cond, gpointer data){
    GError *error = NULL;
    g_io_channel_shutdown(source, TRUE, &error);
    // g_main_loop_quit(loop);
    g_message("Socket broken");
    sr_exit(sr_ctx);
    return TRUE;
};

void writer_thread(struct writer_data *wrd){
    GError *error=NULL;
    gsize *bytes_written;
    struct data_packet *response;
    
    guint32 pos;
    guint32 tt;
    guchar *dt;
    guint8 retry;
    
    while(TRUE){
        response = g_async_queue_pop(wrd->out_queue);
        
        //GIOFlags flags = g_io_channel_get_flags(wr->channel);
        //if (flags |= G_IO_FLAG_IS_WRITABLE){
        
        //dt = response->data;
        pos = 0;
        retry = 0;
        while (response->length){
            dt = &response->data[pos];
            g_io_channel_write(wrd->channel, dt, response->length, &bytes_written);
            g_message("SOCKET WRITE:%d, response->length:%d, header len:%d, retry:%d", bytes_written, response->length, *((guint32*)response->data), retry);
            retry++;
            tt = (guint32)bytes_written;
            pos += tt;
            response->length -= tt;
        }
        
        //g_io_channel_write(wr->channel, response->data, response->length, &bytes_written);
        //g_message("SOCKET WRITE:%d, response->length:%d", bytes_written, response->length);
        
        //}
        //g_io_channel_flush(wr->channel, &error);
        g_free(response->data);
        g_free(response);
    }
}

gboolean incoming_callback(GThreadedSocketService *service, GSocketConnection *connection, GObject *source_object, gpointer data){
    g_message("Client connect");
    GError *error=NULL;
    
    //struct writer_data *
    wrd = g_malloc(sizeof(struct writer_data));
    
    //INIT INCOME STRUCT
    struct reader_data *rrd = g_malloc(sizeof(struct reader_data));
    rrd->buf = g_malloc(BUF_SIZE);
    rrd->array = g_byte_array_new();
    rrd->json_len = 0;
    rrd->received = 0;
    rrd->content_length = 0;



    //srd_log_loglevel_set(5);
    /*
    if (srd_init(NULL) == SRD_OK) {
        srd_decoder_load_all();
    }
    srd_session_new(&srd_sess);
    */
    
    g_byte_array_ref(rrd->array);
    g_object_ref(connection);
    
    GSocket *socket = g_socket_connection_get_socket(connection);
    gint fd = g_socket_get_fd(socket);
    wrd->channel = g_io_channel_unix_new(fd);
    rrd->out_queue = wrd->out_queue = g_async_queue_new();
    g_io_channel_ref(wrd->channel);
    g_io_channel_set_encoding(wrd->channel, NULL, &error);
    
    g_io_channel_set_flags(wrd->channel, G_IO_FLAG_NONBLOCK, &error);
    
    g_io_add_watch(wrd->channel, G_IO_IN, (GIOFunc) read_cb, rrd);
    g_io_add_watch(wrd->channel, G_IO_HUP, (GIOFunc) socket_broken_cb, NULL);
    
    GThread *wr_thread = g_thread_new("writer_thread", writer_thread, wrd);
    
    return FALSE;
}

gboolean opt_version = FALSE;
gchar **opt_unix_socket = NULL;
gchar *opt_channel_group = NULL;

static const GOptionEntry optargs[] = {
    {"version", 'V', 0, G_OPTION_ARG_NONE, &opt_version, "Show version", NULL},
    {"unix-socket", 'u', 0, G_OPTION_ARG_FILENAME_ARRAY, &opt_unix_socket, "Create unix socket by path", NULL},
    {NULL, 0, 0, 0, NULL, NULL, NULL}
};

static gint sort_pds(gconstpointer a, gconstpointer b){
    const struct srd_decoder *sda, *sdb;
    sda = (const struct srd_decoder *)a;
    sdb = (const struct srd_decoder *)b;
    return strcmp(sda->id, sdb->id);
}

int main(int argc, char **argv) {
    GError *error = NULL;
    GOptionContext *context = g_option_context_new(NULL);
    
    g_option_context_add_main_entries(context, optargs, NULL);
    
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_critical("%s", error->message);
        goto done;
    }
    
    if (opt_version){
        g_message("sigrok-proc 0.0.1");
    }
    
    if(opt_unix_socket){
        gchar *unix_socket = g_strdup(opt_unix_socket[0]);
        g_message("unix_socket: %s", unix_socket);
        if (sr_init(&sr_ctx) != SR_OK)
            goto done;
        
        loop = g_main_loop_new(NULL, TRUE);
        
        g_message("Start sigrok-proc");
        sr_session_new(sr_ctx, &session);
        sr_session_datafeed_callback_add(session, datafeed_in, NULL);
        sr_session_stopped_callback_set(session, (sr_session_stopped_callback)end_sampling_cb, loop);
        
        
        
        
        
        
        
        
        GThreadedSocketService *service;
        //service = g_socket_service_new();
        
        service = (GThreadedSocketService*)g_threaded_socket_service_new(1);
        
        GSocketAddress *socket_address = g_unix_socket_address_new(unix_socket);
        
        g_strfreev(opt_unix_socket);
        opt_unix_socket = NULL;
        
        g_socket_listener_add_address(G_SOCKET_LISTENER(service), socket_address, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_DEFAULT, NULL, NULL, &error);
        //g_signal_connect(service, "incoming", G_CALLBACK(incoming_callback), NULL);
        
        g_signal_connect(service, "run", G_CALLBACK(incoming_callback), NULL);
        
        g_socket_service_start(G_SOCKET_SERVICE(service));
        
        g_main_loop_run(loop);
    }
    
    done:
        if (sr_ctx)
            sr_exit(sr_ctx);
    return 0;
}

const struct sr_output *setup_output_format(const struct sr_dev_inst *sdi, GAsyncQueue *out_queue){
    const struct sr_output_module *omod;
    struct sr_output *o;
    
    omod = sr_output_find("srtest");
    
    o = g_malloc(sizeof(struct sr_output));
    o->module = omod;
    o->sdi = sdi;
    o->filename = NULL;
    
    if (o->module->init && o->module->init(o, out_queue) != SR_OK){
        g_free(o);
        o = NULL;
    }
    
    return o;
}

//int pck_cnt = 0;
//time_t now, beg; 
//clock_t begin, end;// = clock();

void datafeed_in(const struct sr_dev_inst *sdi, const struct sr_datafeed_packet *packet, void *cb_data){
    const struct sr_datafeed_analog *analog;
    const struct sr_datafeed_logic *logic;
    //const struct sr_datafeed_meta *meta;
    static uint64_t rcvd_samples_logic = 0;
    static uint64_t rcvd_samples_analog = 0;
    
    //gssize nwrote;
    //GError *err = NULL;
    
    
    GString *out;
    static const struct sr_output *o = NULL;
    //uint64_t end_sample;
    
    //pck_cnt++;
    switch (packet->type){
        case SR_DF_HEADER:
            //time(&beg);
            //begin = clock();
            g_message("Header received");
            //pck_cnt = 0;
            rcvd_samples_logic = rcvd_samples_analog = 0;
            
            if (o != NULL){
                sr_output_free(o);
                g_message("END CLEAN");
            }
            
            o = setup_output_format(sdi, wrd->out_queue);
            break;
            
        case SR_DF_LOGIC:
            logic = packet->payload;
            uint8_t *buf = logic->data;
            if (logic->length == 0)
                break;
            rcvd_samples_logic += logic->length / logic->unitsize;//end_sample;
            break;

        case SR_DF_ANALOG:
            analog = packet->payload;
            
            if (analog->num_samples == 0)
                break;
            
            rcvd_samples_analog += analog->num_samples;
            
            break;

        case SR_DF_END:
            
            //end = clock();
            //double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
            
            //if (o)
                //sr_output_free(o);
            //o = NULL;
             
            g_message("rcvd_samples_logic: %d", rcvd_samples_logic);
            g_message("rcvd_samples_analog: %d", rcvd_samples_analog);
            
            //g_message("dS: %f", time_spent * 100);
            break;

        default:
            break;
    }
    sr_output_send(o, packet, &out);
}

void session_stop_response(void){
    g_mutex_lock (&session_state_mutex);
    session_state = 0;
    //g_cond_signal(&session_state_cond);
    g_mutex_unlock(&session_state_mutex);
    
    JsonBuilder *builder = json_builder_new();
    json_builder_begin_object(builder);

    json_builder_set_member_name(builder, "run_session");
    json_builder_add_int_value(builder, session_state);
    
    json_builder_set_member_name(builder, "content-type");
    json_builder_add_string_value(builder, "application/json");
    
    json_builder_end_object(builder);
    JsonGenerator *gen = json_generator_new();
    JsonNode *resp_root = json_builder_get_root(builder);
    json_generator_set_root(gen, resp_root);
    
    //char *tmp = json_generator_to_data(gen, NULL);
    
    
    guint32 *tmp_len = 0;
    struct data_packet *response = g_malloc(sizeof(struct data_packet));
    char *tmp = json_generator_to_data(gen, &tmp_len);
    
    guint32 resp_len = tmp_len;
    
    response->data = g_malloc(resp_len + PH_LEN);
    memcpy(response->data, &resp_len, PH_LEN);
    memcpy(&response->data[4], tmp, resp_len);
    response->length = resp_len + PH_LEN;
    
    json_node_free(resp_root);
    g_object_unref(gen);
    g_object_unref(builder);
    
    g_async_queue_push(wrd->out_queue, response);
    
    g_free(tmp);
}

void end_sampling_cb(void){
    if (session_state)
        session_stop_response();
}
