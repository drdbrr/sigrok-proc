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

#define BUF_SIZE 1024

#define JSON_PT 0b00000001
#define BINARY_PT 0b00000010
#define AUTO_JSON_PT 0b00000011
#define AUTO_BINARY_PT 0b00000100

GOutputStream *ostream = NULL;
GMainLoop *loop = NULL;

struct sr_session *session = NULL;
struct sr_context *sr_ctx = NULL;
struct sr_dev_inst *sdi = NULL;
struct sr_dev_driver *driver = NULL;
GSList *devices = NULL;

int pck_cnt = 0;
int logic_cnt = 0;
int analog_cnt = 0;

gpointer session_state = 0;
GMutex session_state_mutex;
GCond session_state_cond;

void sr_sampling_thread(void){
    if (sr_session_start(session) == SR_OK){
        g_message("START sampling");
        g_mutex_lock (&session_state_mutex);
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
    
    struct sr_channel_group *channel_group;
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
            channel_group = lookup_channel_group(sdi, NULL);
            
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
                    for (int i = 0; rates[i]; i++){
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
        
        driver = NULL;
        pck_cnt = 0;
        logic_cnt = 0;
        analog_cnt = 0;
        
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
    const char *get = "get";
    const char *set = "set";
    
    if (!strcmp(member_name, get)){
        json_builder_set_member_name(builder, "get");
        json_builder_begin_object(builder);
        JsonArray *get_opts = json_node_get_array(member_node);
        json_array_foreach_element(get_opts, array_get_cb, builder);
        json_builder_end_object(builder);
    }
    else if (!strcmp(member_name, set)){
        json_builder_set_member_name(builder, "set");
        json_builder_begin_object(builder);
        JsonObject *set_opts = json_node_get_object(member_node);
        json_object_foreach_member(set_opts, object_set_cb, builder);
        json_builder_end_object(builder);
    }
}

void json_parse(char *buf, guint64 len){
    GError *error = NULL;
    
    JsonBuilder *builder = json_builder_new();
    
    JsonParser *parser = json_parser_new();
    json_parser_load_from_data(parser, buf, len, &error);
    JsonNode *root = json_parser_get_root(parser);
    
    JsonObject *object = json_node_get_object(root);
    
    //ATTENTION rid - request ID
    char *rid = json_object_get_string_member(object, "rid");
    
    json_builder_begin_object(builder);



    json_object_foreach_member(object, object_member_cb, builder);
    json_builder_set_member_name(builder, "rid");
    json_builder_add_string_value(builder, rid);
    
    
    json_builder_end_object(builder);
    
    JsonGenerator *gen = json_generator_new();
    JsonNode *resp_root = json_builder_get_root(builder);
    json_generator_set_root(gen, resp_root);
    char *response = json_generator_to_data(gen, NULL);
    
    //WARNING Magic begins
    char *tmp = g_malloc(strlen(response) + 1);
    tmp[0] = JSON_PT;
    tmp[1] = '\0';
    strcat(tmp, response);
    //Magic ends
    
    g_output_stream_write(ostream, tmp, strlen(tmp), NULL, NULL);
    
    //json_generator_to_stream(gen, ostream, NULL, NULL);
    
    //json_node_free(resp_root);
    //g_object_unref(parser);
    //g_object_unref(builder);
    //g_object_unref(gen);
    //g_free(response);
    //g_free(tmp);
}

gboolean read_cb(GIOChannel *source, GIOCondition cond, gpointer data){
    GError *error = NULL;
    gsize len;
    char *buf = g_malloc(BUF_SIZE);
    g_io_channel_read_chars(source, buf, BUF_SIZE, &len, &error);
    //g_message("buf----> %s", buf);
    json_parse(buf, len);
    //g_free(buf);
    return TRUE;
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
    tmp[0] = AUTO_JSON_PT;
    tmp[1] = '\0';
    strcat(tmp, response);
    
    g_output_stream_write(ostream, tmp, strlen(tmp), NULL, NULL);
    
    g_object_unref(gen);
    g_object_unref(builder);
    g_free(response);
    g_free(tmp);
    g_message("send status %d", session_state);
}

gboolean incoming_callback(GSocketService *service, GSocketConnection *connection, GObject *source_object, gpointer user_data){
    g_message("Client connect");
    GError *error=NULL;
    g_object_ref(connection);
    GSocket *socket = g_socket_connection_get_socket(connection);
    ostream = g_io_stream_get_output_stream(connection);
    
    gint fd = g_socket_get_fd(socket);
    GIOChannel *channel = g_io_channel_unix_new(fd);
    g_io_channel_set_encoding(channel, NULL, &error);
    g_io_add_watch(channel, G_IO_IN, (GIOFunc) read_cb, NULL);
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
        
        g_message("Start sigrok-proc");
        sr_session_new(sr_ctx, &session);
        struct df_arg_desc df_arg;
        memset(&df_arg, 0, sizeof(df_arg));
        df_arg.do_props = FALSE;
        df_arg.session = session;
        
        sr_session_datafeed_callback_add(session, datafeed_in, &df_arg);
        sr_session_stopped_callback_set(session, (sr_session_stopped_callback)end_sampling_cb, loop);
        df_arg.session = NULL;
        
        GSocketService *service = g_socket_service_new();
        GSocketAddress *socket_address = g_unix_socket_address_new(unix_socket);
        
        g_strfreev(opt_unix_socket);
        opt_unix_socket = NULL;
        
        g_socket_listener_add_address(G_SOCKET_LISTENER(service), socket_address, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_DEFAULT, NULL, NULL, &error);
        g_signal_connect(service, "incoming", G_CALLBACK(incoming_callback), NULL);
        g_socket_service_start(service);
        loop = g_main_loop_new(NULL, FALSE);
        
        g_main_loop_run(loop);
    }
    
done:
    if (sr_ctx)
        sr_exit(sr_ctx);
    
    return 0;
}

void datafeed_in(const struct sr_dev_inst *sdi, const struct sr_datafeed_packet *packet, void *cb_data){
    pck_cnt++;
    switch (packet->type) {
        case SR_DF_HEADER:
            g_message("Header received");
            break;
            
        case SR_DF_LOGIC:
            logic_cnt++;
            break;

        case SR_DF_ANALOG:
            analog_cnt++;
            break;

        case SR_DF_END:
            g_message("END SAMPLING");
            break;

        default:
            break;
    }
}

struct sr_channel_group *lookup_channel_group(struct sr_dev_inst *sdi, const char *cg_name){
    struct sr_channel_group *cg;
    GSList *l, *channel_groups;

    if (!cg_name)
        cg_name = opt_channel_group;
    if (cg_name && g_ascii_strcasecmp(cg_name, "global") == 0)
        cg_name = NULL;
    if (!cg_name || !*cg_name)
        return NULL;

    channel_groups = sr_dev_inst_channel_groups_get(sdi);
    if (!channel_groups) {
        g_critical("This device does not have any channel groups.");
        return NULL;
    }
    
    for (l = channel_groups; l; l = l->next) {
        cg = l->data;
        if (g_ascii_strcasecmp(cg_name, cg->name) != 0)
            continue;
        return cg;
    }
    g_critical("Invalid channel group '%s'", cg_name);
    return NULL;
}

void end_sampling_cb(void){
    session_stop_response();
    
    g_message("End sampling");
    g_message("logic:%d", logic_cnt);
    g_message("analog:%d", analog_cnt);
    g_message("total:%d", pck_cnt);
}
