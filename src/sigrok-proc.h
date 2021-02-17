#include <libsigrokdecode/libsigrokdecode.h>
#include <libsigrok/libsigrok.h>
#include <json-glib/json-glib.h>

extern struct sr_context *sr_ctx;

struct df_arg_desc {
    struct sr_session *session;
    int do_props;
    struct input_stream_props {
        uint64_t samplerate;
        GSList *channels;
        const struct sr_channel *first_analog_channel;
        size_t unitsize;
        uint64_t sample_count_logic;
        uint64_t sample_count_analog;
        uint64_t frame_count;
        uint64_t triggered;
    } props;
};

void datafeed_in(const struct sr_dev_inst *sdi, const struct sr_datafeed_packet *packet, void *cb_data);
void sr_sampling_thread(void);
guint64 *gen_list(guint64 start, guint64 len);
static void  array_get_cb(JsonArray *array, guint i, JsonNode *element_node, gpointer builder);
static void object_set_cb(JsonObject *object, const char *member_name, JsonNode *member_node, gpointer builder);
static void object_member_cb(JsonObject *object, const char *member_name, JsonNode *member_node, gpointer builder);
void json_parse(char *buf, guint64 len);
gboolean read_cb(GIOChannel *source, GIOCondition cond, gpointer data);
gboolean incoming_callback(GSocketService *service, GSocketConnection *connection, GObject *source_object, gpointer user_data);
void end_sampling_cb(void);
struct sr_channel_group *lookup_channel_group(struct sr_dev_inst *sdi, const char *cg_name);

extern gboolean opt_version;
extern gchar **opt_unix_socket;
extern gchar *opt_channel_group;
