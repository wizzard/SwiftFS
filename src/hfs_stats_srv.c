/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "hfs_stats_srv.h"
#include "client_pool.h"

typedef struct {
    guint32 bytes;
    time_t time;
} SpeedEntry;

#define STATS_INTERVAL_SECS 5
#define STATS_LOG "stats"

struct _HfsStatsSrv {
    Application *app;
    ConfData *conf;
    struct evhttp *http;

    SpeedEntry a_down_speed[STATS_INTERVAL_SECS]; // list of SpeedEntry for downloading
    SpeedEntry a_up_speed[STATS_INTERVAL_SECS]; // list of SpeedEntry for uploading

    gint auth_server_status;
    gchar *auth_server_status_line;
    guint64 auth_server_requests;
    gint storage_server_status;
    gchar *storage_server_status_line;
    guint64 storage_server_requests;

    GQueue *q_history; // queue of HistoryItem
};

typedef struct {
    gchar *url;
    gchar *http_method;
    guint64 bytes;
    struct timeval start_tv;
    struct timeval end_tv;
} HistoryItem;

static void hfs_stats_srv_on_stats_cb (struct evhttp_request *req, void *arg);
static void history_item_destroy (HistoryItem *item);

HfsStatsSrv *hfs_stats_srv_create (Application *app)
{
    HfsStatsSrv *srv;

    srv = g_new0 (HfsStatsSrv, 1);
    srv->app = app;
    srv->conf = application_get_conf (app);

    srv->auth_server_status = 0;
    srv->storage_server_status = 0;
    srv->auth_server_status_line = NULL;
    srv->storage_server_status_line = NULL;
    srv->auth_server_requests = 0;
    srv->storage_server_requests = 0;
    srv->q_history = g_queue_new ();

    if (conf_get_boolean (srv->conf, "statistics.enabled")) {
        gint port;
        struct evhttp_bound_socket *handle;

        srv->http = evhttp_new (application_get_evbase (app));

        evhttp_set_cb (srv->http, "/stats", hfs_stats_srv_on_stats_cb, srv);

        port = conf_get_int (srv->conf, "statistics.port");
        handle = evhttp_bind_socket_with_handle (srv->http, "0.0.0.0", port);
        if (!handle) {
            LOG_err (STATS_LOG, "Failed to bind socket to port %d", port);
            return NULL;
        }

        LOG_msg (STATS_LOG, "Statistics server listening on %s:%d", "0.0.0.0", port);

    }
    return srv;
}

void hfs_stats_srv_destroy (HfsStatsSrv *srv)
{
    g_free (srv->auth_server_status_line);
    g_free (srv->storage_server_status_line);

    g_queue_free_full (srv->q_history, (GDestroyNotify ) history_item_destroy);

    g_free (srv);
}

/*{{{ speed */
static void hfs_stats_srv_add_speed_bytes (SpeedEntry *a_speed, guint32 bytes)
{
    time_t now = time (NULL);

    if (a_speed[now % STATS_INTERVAL_SECS].time == now) {
        a_speed[now % STATS_INTERVAL_SECS].bytes += bytes;
    } else {
        a_speed[now % STATS_INTERVAL_SECS].time = now;
        a_speed[now % STATS_INTERVAL_SECS].bytes = bytes;
    }
}

static guint32 hfs_stats_srv_get_speed (SpeedEntry *a_speed)
{
    guint32 i;
    time_t now = time (NULL);
    guint32 sum = 0;
    guint items = 0;

    for (i = 0; i < STATS_INTERVAL_SECS; i++) {
        if (a_speed[i].time && now - a_speed[i].time <= STATS_INTERVAL_SECS) {
            sum += a_speed[i].bytes;
            items ++;
        }
    }

    if (sum)
        return (guint32) ((gdouble)sum / (gdouble)STATS_INTERVAL_SECS);
    else
        return 0;
}

#define MB (1024 * 1024)
#define KB (1024)
static const gchar *hfs_stats_srv_get_speed_str (SpeedEntry *a_speed)
{
    guint32 bps;
    static gchar out[20];
    gdouble tmp;

    bps = hfs_stats_srv_get_speed (a_speed);

    if (bps >= MB) {
        tmp = (gdouble)bps / (gdouble)MB;
        g_snprintf (out, sizeof (out), "%.2fMb/s", tmp);
    } else {
        tmp = (gdouble)bps / (gdouble)KB;
        g_snprintf (out, sizeof (out), "%.2fKb/s", tmp);
    }

    return out;
}

void hfs_stats_srv_add_down_bytes (HfsStatsSrv *srv, guint32 bytes)
{
    hfs_stats_srv_add_speed_bytes (srv->a_down_speed, bytes);
}

guint32 hfs_stats_srv_get_down_speed (HfsStatsSrv *srv)
{
    return hfs_stats_srv_get_speed (srv->a_down_speed);
}

const gchar *hfs_stats_srv_get_down_speed_str (HfsStatsSrv *srv)
{
    return hfs_stats_srv_get_speed_str (srv->a_down_speed);
}


void hfs_stats_srv_add_up_bytes (HfsStatsSrv *srv, guint32 bytes)
{
    hfs_stats_srv_add_speed_bytes (srv->a_up_speed, bytes);
}

guint32 hfs_stats_srv_get_up_speed (HfsStatsSrv *srv)
{
    return hfs_stats_srv_get_speed (srv->a_up_speed);
}

const gchar *hfs_stats_srv_get_up_speed_str (HfsStatsSrv *srv)
{
    return hfs_stats_srv_get_speed_str (srv->a_up_speed);
}
/*}}}*/

static void hfs_stats_srv_on_stats_cb (struct evhttp_request *req, void *arg)
{
    HfsStatsSrv *srv = (HfsStatsSrv *) arg;
    struct evbuffer *evb = NULL;
    const gchar *refresh = NULL;
    gint ref = 0;
    const gchar *query;

    query = evhttp_uri_get_query (evhttp_request_get_evhttp_uri (req));
    if (query) {
        struct evkeyvalq q_params;
        TAILQ_INIT (&q_params);
        evhttp_parse_query_str (query, &q_params);
        refresh = evhttp_find_header (&q_params, "refresh");
        ref = atoi (refresh);
        evhttp_clear_headers (&q_params);
    }

    evb = evbuffer_new ();

    if (refresh) {
        evbuffer_add_printf (evb, "<meta http-equiv=\"refresh\" content=\"%d\">", ref);
    }

    {
        gchar down_speed[20];
        strcpy (down_speed, hfs_stats_srv_get_down_speed_str (srv));
        evbuffer_add_printf (evb, 
            "Auth server status: %d (%s) Requests: %"G_GUINT64_FORMAT" <BR>"
            "Storage server status: %d (%s) Requests: %"G_GUINT64_FORMAT" <BR>"
            "Down speed: %s Up speed: %s",
            srv->auth_server_status, srv->auth_server_status_line, srv->auth_server_requests,
            srv->storage_server_status, srv->storage_server_status_line, srv->storage_server_requests,
            down_speed, hfs_stats_srv_get_up_speed_str (srv)
        );
    }

    {
        GString *str;

        str = client_pool_get_task_list (application_get_write_client_pool (srv->app));
        evbuffer_add_printf (evb, "<BR>Write clients: %s<BR>",
            str->str);
        g_string_free (str, TRUE);

        str = client_pool_get_task_list (application_get_read_client_pool (srv->app));
        evbuffer_add_printf (evb, "Read clients: %s<BR>",
            str->str);
        g_string_free (str, TRUE);

        str = client_pool_get_task_list (application_get_ops_client_pool (srv->app));
        evbuffer_add_printf (evb, "Operations clients: %s<BR>",
            str->str);
        g_string_free (str, TRUE);
    }

    {
        size_t i;

        evbuffer_add_printf (evb, "<BR>History:<BR>");

        for (i = 0; i < g_queue_get_length (srv->q_history); i++) {
            gchar *tstr;
            guint64 secs = 0;

            HistoryItem *item = (HistoryItem *) g_queue_peek_nth (srv->q_history, i);

            if (item->end_tv.tv_sec > item->start_tv.tv_sec) {
                secs = item->end_tv.tv_sec - item->start_tv.tv_sec;
            }

            evbuffer_add_printf (evb, "%s %s %"G_GUINT64_FORMAT" %s", item->url, item->http_method, item->bytes, tstr);
        }
    }

    evhttp_send_reply (req, 200, "OK", evb);
    evbuffer_free (evb);
}

void hfs_stats_srv_set_auth_srv_status (HfsStatsSrv *srv, gint code, const gchar *status_line)
{
    srv->auth_server_requests ++;
    if (srv->auth_server_status != code) {
        srv->auth_server_status = code;
        g_free (srv->auth_server_status_line);
        srv->auth_server_status_line = g_strdup (status_line);
    }
}

void hfs_stats_srv_set_storage_srv_status (HfsStatsSrv *srv, gint code, const gchar *status_line)
{
    srv->storage_server_requests ++;
    if (srv->storage_server_status != code) {
        srv->storage_server_status = code;
        g_free (srv->storage_server_status_line);
        srv->storage_server_status_line = g_strdup (status_line);
    }
}

static void history_item_destroy (HistoryItem *item)
{
    g_free (item->url);
    g_free (item->http_method);
    g_free (item);
}

void hfs_stats_srv_add_history (HfsStatsSrv *srv, const gchar *url, const gchar *http_method, 
    guint64 bytes, struct timeval *start_tv, struct timeval *end_tv)
{
    HistoryItem *item;

    if (!conf_get_boolean (srv->conf, "statistics.enabled")) 
        return;
    
    item = g_new0 (HistoryItem, 1);
    item->url = g_strdup (url);
    item->http_method = g_strdup (http_method);
    item->bytes = bytes;
    item->start_tv.tv_sec = start_tv->tv_sec;
    item->start_tv.tv_usec = start_tv->tv_usec;
    item->end_tv.tv_sec = end_tv->tv_sec;
    item->end_tv.tv_usec = end_tv->tv_usec;

    while (g_queue_get_length (srv->q_history) > conf_get_uint (srv->conf, "statistics.history_max_items")) {
        HistoryItem *tmp = g_queue_pop_tail (srv->q_history);
        if (tmp) {
            history_item_destroy (tmp);
        }
    }

    g_queue_push_head (srv->q_history, item);
}
