#include <libsigrokdecode/libsigrokdecode.h>
#include <libsigrok/libsigrok.h>
#include <json-glib/json-glib.h>
#include <glib.h>

struct writer_data {
    GAsyncQueue *out_queue;
    GIOChannel *channel;
};

struct sr_output {
    const struct sr_output_module *module;
    const struct sr_dev_inst *sdi;
    const char *filename;
    void *priv;
};

extern struct sr_context *sr_ctx;

const struct sr_output *setup_output_format(const struct sr_dev_inst *sdi, GAsyncQueue *out_queue);

void datafeed_in(const struct sr_dev_inst *sdi, const struct sr_datafeed_packet *packet, void *cb_data);

void sr_sampling_thread(void);
guint64 *gen_list(guint64 start, guint64 len);
static void  array_get_cb(JsonArray *array, guint i, JsonNode *element_node, gpointer builder);
static void object_set_cb(JsonObject *object, const char *member_name, JsonNode *member_node, gpointer builder);
static void object_member_cb(JsonObject *object, const char *member_name, JsonNode *member_node, gpointer builder);
guint32 json_parse(char *buf, guint64 len, GAsyncQueue *out_queue);
gboolean read_cb(GIOChannel *source, GIOCondition cond, gpointer data);
//gboolean incoming_callback(GSocketService *service, GSocketConnection *connection, GObject *source_object, gpointer user_data);

gboolean incoming_callback(GThreadedSocketService *service, GSocketConnection *connection, GObject *source_object, gpointer user_data);

void end_sampling_cb(void);
struct sr_channel_group *lookup_channel_group(struct sr_dev_inst *sdi, const char *cg_name);

extern gboolean opt_version;
extern gchar **opt_unix_socket;
extern gchar *opt_channel_group;
