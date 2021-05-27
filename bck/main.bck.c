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

GMainLoop *loop = NULL;

struct sr_session *session = NULL;
struct sr_context *sr_ctx = NULL;
struct sr_dev_inst *sdi = NULL;
struct sr_dev_driver *driver = NULL;
GSList *devices = NULL;

struct writer_data *wrd;

static uint64_t sample_rate = 0;

/*
struct sr_output {
    const struct sr_output_module *module;
    const struct sr_dev_inst *sdi;
    const char *filename;
    void *priv;
};
*/

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
    const char *req = json_node_get_string(element_node);
    
    const char *get_drivers = "drivers";
    const char *get_samplerates = "samplerates";
    const char *get_samplerate = "samplerate";
    const char *get_samples = "samples";
    const char *get_sample = "sample";
    const char *get_scan = "scan";
    const char *get_session = "session";
    const char *get_channels = "channels";
    const char *get_session_state = "session_state";
    
    GVariant *gvar, *gvar_list, *gvar_dict;
    gsize num_elements;
    
    //struct sr_channel_group *channel_group;
    //struct sr_dev_driver *driver;
    GArray *opts;
    const struct sr_key_info *srci;
    
    //REQUEST SESSION STATE
    if (!strcmp(req, get_session_state)){
        json_builder_set_member_name(builder, "session_state");
        
        //WARNING lock/unlock
        //g_mutex_lock (&session_state_mutex);
        json_builder_add_int_value(builder, session_state);//session_state);
        //g_mutex_unlock (&session_state_mutex);
        
        g_message("Get session state %d", session_state);
    }
    //REQUEST CHANNELS
    else if (!strcmp(req, get_channels)){
        json_builder_set_member_name(builder, "channels");
        
        if (sdi != NULL){
            struct sr_channel *ch;
            GSList *l, *channels;
            channels = sr_dev_inst_channels_get(sdi);
            
            json_builder_begin_object(builder);
            
            
            //**************LOGIC**************
            json_builder_set_member_name(builder, "logic");
            json_builder_begin_array(builder);
            
            for (l = channels; l; l = l->next) {
                ch = l->data;
                if (ch->type == SR_CHANNEL_LOGIC /*10000*/){
                    json_builder_begin_object(builder);
                    
                    json_builder_set_member_name(builder, "name");
                    json_builder_add_string_value(builder, ch->name);
                    
                    json_builder_set_member_name(builder, "text");
                    json_builder_add_string_value(builder, ch->name);
                    
                    json_builder_set_member_name(builder, "visible");
                    json_builder_add_boolean_value(builder, ch->enabled);
                    
                    json_builder_end_object(builder);
                }
            }
            json_builder_end_array(builder);
            //*********************************
            
            //**************ANALOG**************
            json_builder_set_member_name(builder, "analog");
            json_builder_begin_array(builder);
            //
            
            for (l = channels; l; l = l->next) {
                ch = l->data;
                if (ch->type == 10001 /*SR_CHANNEL_ANALOG*/){
                    json_builder_begin_object(builder);
                    
                    json_builder_set_member_name(builder, "name");
                    json_builder_add_string_value(builder, ch->name);
                    
                    json_builder_set_member_name(builder, "text");
                    json_builder_add_string_value(builder, ch->name);
                    
                    json_builder_set_member_name(builder, "visible");
                    json_builder_add_boolean_value(builder, ch->enabled);
                    
                    json_builder_end_object(builder);
                }
            }
            json_builder_end_array(builder);
            //**********************************
            
            json_builder_end_object(builder);
        }
        else {
            json_builder_add_string_value(builder, "");
        }
        
    }
    
    //REQUEST SESSION
    else if (!strcmp(req, get_session)){
        json_builder_set_member_name(builder, "session");
        
        json_builder_begin_object(builder);
        
        json_builder_set_member_name(builder, "type");
        if (sdi != NULL){
            json_builder_add_string_value(builder, "device");
        }
        else {
            json_builder_add_string_value(builder, "");
        }
        
        json_builder_set_member_name(builder, "sourcename");
        if (sdi != NULL){
            struct sr_dev_driver *drv = sr_dev_inst_driver_get(sdi);
            if (!strcmp(drv->name, (char *)"demo")){
                json_builder_add_string_value(builder, "Demo");
            }
            else{
                const char *vendor = sr_dev_inst_vendor_get(sdi);
                json_builder_add_string_value(builder, vendor);
            }
        }
        else{
            json_builder_add_string_value(builder, "");
        }
        
        json_builder_set_member_name(builder, "config");
        if (sdi != NULL){
            json_builder_begin_array(builder);
            
            driver = sr_dev_inst_driver_get(sdi);
            //channel_group = lookup_channel_group(sdi, NULL);
            
            opts = sr_dev_options(driver, sdi, NULL);//, channel_group);
            
            for (int o = 0; o < opts->len; o++) {
                uint32_t key = g_array_index(opts, uint32_t, o);
                if (!(srci = sr_key_info_get(SR_KEY_CONFIG, key)))
                    continue;
                json_builder_add_string_value(builder, srci->id);
            }
            //g_array_free(opts, TRUE);
            json_builder_end_array(builder);
        }
        else{
            json_builder_add_string_value(builder, "");
        }
        
        json_builder_set_member_name(builder, "channels");
        json_builder_begin_array(builder);
        
        if (sdi != NULL){
            GSList *cgl, *channel_groups;
            struct sr_channel_group *cg;
            channel_groups = sr_dev_inst_channel_groups_get(sdi);
            for (cgl = channel_groups; cgl; cgl = cgl->next){
                cg = cgl->data;
                if ( !strcmp(cg->name, (char *)"Logic" )){
                    json_builder_add_string_value(builder, "logic");
                }
                else if ( !strcmp(cg->name, (char *)"Analog" )){
                    json_builder_add_string_value(builder, "analog");
                }
            }
        }
        
        json_builder_end_array(builder);
        json_builder_end_object(builder);
        g_message("Get session");
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
    
    //REQUEST SAMPLERATES LIST
    else if (!strcmp(req, get_samplerates)){
        json_builder_set_member_name(builder, "samplerates");
        if (sdi == NULL){
            json_builder_add_string_value(builder, "error: no device");
            g_message("ERROR: Get samplerates, no device");
        }
        else{
            if (sr_config_list(driver, sdi, NULL, SR_CONF_SAMPLERATE, &gvar_dict) != SR_OK){
                json_builder_add_string_value(builder, "error");
                g_message("ERROR: Get samplerates");
            }
            else{
                const guint64 *rates;
                json_builder_begin_array(builder);
                if ((gvar_list = g_variant_lookup_value(gvar_dict, "samplerates", G_VARIANT_TYPE("at")))){
                    rates = g_variant_get_fixed_array(gvar_list, &num_elements, sizeof(rates));
                    for (i = 0; i < num_elements; i++) {
                        json_builder_add_int_value(builder, rates[i]);
                    }
                }
                else if ((gvar_list = g_variant_lookup_value(gvar_dict, "samplerate-steps", G_VARIANT_TYPE("at")))) {
                    rates = gen_list(10, 8);
                    for (i = 0; rates[i]; i++){
                        json_builder_add_int_value(builder, rates[i]);
                    }
                }
                //g_variant_unref(gvar_list);
                json_builder_end_array(builder);
                //g_variant_unref(gvar_dict);
                g_message("Get samplerates");
            }
        }
    }
    
    //REQUEST CURRENT SAMPLERATE
    else if (!strcmp(req, get_samplerate)){
        json_builder_set_member_name(builder, "samplerate");
        if (sdi == NULL){
            json_builder_add_string_value(builder, "error: no device");
            g_message("ERROR: Get samplerate, no device");
        }
        else{
            if(sr_config_get(driver, sdi, NULL, SR_CONF_SAMPLERATE, &gvar) != SR_OK){
                json_builder_add_string_value(builder, "error");
                g_message("ERROR: Get samplerate");
            }
            else{
                guint64 samplerate = g_variant_get_uint64(gvar);
                json_builder_add_int_value(builder, samplerate);
                //g_variant_unref(gvar);
                g_message("Get samplerate: %ld", samplerate);
            }
        }
    }
    
    //REQUEST SAMPLE NUM LIST
    else if (!strcmp(req, get_samples)){
        guint64 *samples = gen_list(100, 12);
        json_builder_set_member_name (builder, "samples");
        json_builder_begin_array(builder);
        for (int i = 0; samples[i]; i++){
            json_builder_add_int_value(builder, samples[i]);
        }
        json_builder_end_array(builder);
        //g_free(samples);
        g_message("Get samples");
    }
    
    //REQUEST CURRENT SAMPLE NUM
    else if (!strcmp(req, get_sample)){
        json_builder_set_member_name(builder, "sample");
        
        if (sdi == NULL){
            json_builder_add_string_value(builder, "error: no device");
            g_message("ERROR: Get samplerate, no device");
        }
        else{
            if (sr_config_get(driver, sdi, NULL, SR_CONF_LIMIT_SAMPLES, &gvar) != SR_OK){
                json_builder_add_string_value(builder, "error");
                g_message("ERROR: Get sample");
            }
            else{
                guint64 sample = g_variant_get_uint64(gvar);
                json_builder_add_int_value(builder, sample);
                //g_variant_unref(gvar);
                g_message("Get sample: %ld", sample);
            }
        }
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

//--------------------------SET OPTIONS--------------------------
static void object_set_cb(JsonObject *object, const char *member_name, JsonNode *member_node, gpointer builder){
    const char *set_driver = "driver";
    const char *set_dev_num = "dev_num";
    const char *set_samplerate = "samplerate";
    const char *set_sample = "sample";
    const char *set_run_session = "run_session";
    GVariant *gvar = NULL;
    GVariant *omg = NULL;
    
    //SET DRIVER
    if (!strcmp(member_name, set_driver)){
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
        
        if (sr_session_dev_add(session, sdi) != SR_OK){
            json_builder_add_string_value(builder, "error");
            g_message("ERROR: add device");
        }
        else if (sr_dev_open(sdi) != SR_OK){
            json_builder_add_string_value(builder, "error");
            g_message("ERROR: open device");
        }
        else{
            static uint64_t limit_samples = 1000000;
            gvar = g_variant_new_uint64(limit_samples);
            sr_config_set(sdi, NULL, SR_CONF_LIMIT_SAMPLES, gvar);
            
            sr_config_get(driver, sdi, NULL, SR_CONF_SAMPLERATE, &omg);
            sample_rate = g_variant_get_uint64(omg);
            //g_message("-------->%d", sample_rate);
            //g_variant_unref(omg);
            
            
            json_builder_add_string_value(builder, "set"); //indicates device is set
            g_slist_free(devices);
            g_message("Set dev_num %d", num);
        }
    }
    
    //SET SAMPLERATE
    else if (!strcmp(member_name, set_samplerate) && sdi != NULL){
        guint64 smprate = json_node_get_int(member_node);
        gvar = g_variant_new_uint64(smprate);
        json_builder_set_member_name(builder, "samplerate");
        if (sr_config_set(sdi, NULL, SR_CONF_SAMPLERATE, gvar) == SR_OK){            
            json_builder_add_string_value(builder, "set");
            g_message("Set samplerate %ld", smprate);
            //g_variant_unref(gvar);
        }
        else {
            json_builder_add_string_value(builder, "error");
            g_message("ERROR: Set samplerate");
        }
    }
    
    //SET SAMPLES NUM
    else if (!strcmp(member_name, set_sample) && sdi != NULL){
        gint64 smpnum = json_node_get_int(member_node);
        gvar = g_variant_new_uint64(smpnum);
        json_builder_set_member_name(builder, "sample");
        if (sr_config_set(sdi, NULL, SR_CONF_LIMIT_SAMPLES, gvar) == SR_OK){            
            json_builder_add_string_value(builder, "set");
            g_message("Set sample %ld", smpnum);
            //g_variant_unref(gvar);
        }
        else {
            json_builder_add_string_value(builder, "error");
            g_message("ERROR: Set sample");
        }
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
    const char *get = "get-config";
    const char *set = "set-config";
    
    if (!strcmp(member_name, get)){
        json_builder_set_member_name(builder, "get-config");
        json_builder_begin_object(builder);
        JsonArray *get_opts = json_node_get_array(member_node);
        json_array_foreach_element(get_opts, array_get_cb, builder);
        json_builder_end_object(builder);
    }
    //else if (!strcmp(member_name, set)){
    if (!strcmp(member_name, set)){
        json_builder_set_member_name(builder, "set-config");
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
    //g_object_unref(gen);

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
    g_message("Socket broken");
    return TRUE;
};

void writer_thread(struct writer_data *wr){
    GError *error=NULL;
    gsize *bytes_written;
    struct data_packet *response;
    
    guint32 pos;
    guint32 tt;
    guchar *dt;
    guint8 retry;
    
    while(TRUE){
        response = g_async_queue_pop(wr->out_queue);
        
        //GIOFlags flags = g_io_channel_get_flags(wr->channel);
        //if (flags |= G_IO_FLAG_IS_WRITABLE){
        
        //dt = response->data;
        pos = 0;
        retry = 0;
        while (response->length){
            dt = &response->data[pos];
            g_io_channel_write(wr->channel, dt, response->length, &bytes_written);
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

int main(int argc, char **argv){
    GMainLoop *loop;
    
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
    
    json_builder_end_object(builder);
    JsonGenerator *gen = json_generator_new();
    JsonNode *resp_root = json_builder_get_root(builder);
    json_generator_set_root(gen, resp_root);
    char *response = json_generator_to_data(gen, NULL);
    
    char *tmp = g_malloc(strlen(response) + 1);
    //tmp[0] = AUTO_JSON_PT;
    tmp[1] = '\0';
    strcat(tmp, response);
    
    //g_output_stream_write(ostream, tmp, strlen(tmp), NULL, NULL);
    //g_output_stream_write_async(ostream, tmp, strlen(tmp), G_PRIORITY_DEFAULT, NULL, NULL, NULL);
    
    g_object_unref(gen);
    g_object_unref(builder);
    g_free(response);
    g_free(tmp);
    //g_message("send status %d", session_state);
};

void end_sampling_cb(void){
    if (session_state)
        session_stop_response();
}
