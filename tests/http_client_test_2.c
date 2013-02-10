/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "global.h"
#include "http_client.h"
#include "http_connection.h"
#include "client_pool.h"
#include "auth_client.h"

// 1. Create 100 files, fill with random data, get MD5 sum
// 2. Start HTTP server
// 3. Send 100 requests
// 4. Get parts, save them to output file
// 4. get Md5 sum and compare with the original MD5 sum

#define HTTP_TEST "http_test2"
typedef struct {
    gchar *in_name;
    gchar *md5;
    gint id;
    
    gchar *out_name;
    FILE *fout;

    gboolean checked;
    gboolean sent;
} FileData;

typedef struct {
    GList *l_files;
} CBData;

struct _Application {
    struct event_base *evbase;
    struct evdns_base *dns_base;
    ConfData *conf;
    struct evhttp *http_srv;
    struct event *timeout;

    AuthClient *auth_client;
    HfsStatsSrv *stats;

    gint files_count;

    GList *l_files;
    HttpClient *http;
};

static Application *app;

// create max_files and fill with random data
// return list of {file name, content md5}
static GList *populate_file_list (gint max_files, GList *l_files, gchar *in_dir)
{
    gint i;
    gchar *out_dir;
    GError *error = NULL;
    FileData *fdata;
    gchar *name;
    FILE *f;

    out_dir = g_dir_make_tmp (NULL, &error);
    g_assert (out_dir);


    LOG_debug (HTTP_TEST, "In dir: %s   Out dir: %s", in_dir, out_dir);

    for (i = 0; i < max_files; i++) {
        char *bytes;
        size_t bytes_len;

        fdata = g_new0 (FileData, 1);
        fdata->checked = FALSE;
        fdata->sent = FALSE;
        fdata->id = i;
        bytes_len = g_random_int_range (100000, 1000000);
        bytes = g_malloc (bytes_len + 1);
        RAND_pseudo_bytes ((unsigned char *)bytes, bytes_len);
        *(bytes + bytes_len) = '\0';
        
        name = get_random_string (15, TRUE);
        fdata->in_name = g_strdup_printf ("%s/%s", in_dir, name);
        f = fopen (fdata->in_name, "w");
        fwrite (bytes, 1, bytes_len + 1, f);
        fclose (f);

        fdata->out_name = g_strdup_printf ("%s/%s", out_dir, name);
        fdata->md5 = get_md5_sum (bytes, bytes_len + 1);
        
        fdata->fout = fopen (fdata->out_name, "w");
        g_assert (fdata->fout);

        LOG_debug (HTTP_TEST, "%s -> %s, size: %u", fdata->in_name, fdata->md5, bytes_len);

        g_free (bytes);
        
        g_free (name);
        l_files = g_list_append (l_files, fdata);
    }

    g_free (out_dir);

    return l_files;
}

gboolean check_list (GList *l)
{
    GList *tmp;
    
    for (tmp = g_list_first (l); tmp; tmp = g_list_next (tmp)) {
        FileData *fdata = (FileData *) tmp->data;
        if (!fdata->checked)
            return FALSE;
    }
    return TRUE;
}

static void on_last_chunk_cb (HttpClient *http, struct evbuffer *input_buf, gpointer ctx)
{
    gchar *buf = NULL;
    size_t buf_len;
    FileData *fdata = (FileData *) ctx;
    gchar *md5;
    int fd;
    struct stat st;
    struct evbuffer *evb = NULL;
    struct timeval tv;

    buf_len = evbuffer_get_length (input_buf);
    buf = (gchar *) evbuffer_pullup (input_buf, buf_len);

    LOG_debug (HTTP_TEST, "%p Last chunk ID:%d len: %zu", http, fdata->id, buf_len);

    g_assert (fwrite (buf, 1, buf_len, fdata->fout) == buf_len);

    evbuffer_drain (input_buf, buf_len);
    
    // close output file
    fclose (fdata->fout);

	g_assert ((fd = open(fdata->out_name, O_RDONLY)) >= 0);
    g_assert (fstat(fd, &st) >= 0);

    evb = evbuffer_new();
    evbuffer_add_file(evb, fd, 0, st.st_size);

    md5 = get_md5_sum ((const char *)evbuffer_pullup (evb, -1), evbuffer_get_length (evb));

    LOG_debug (HTTP_TEST, "%s == %s", fdata->md5, md5);
    g_assert_cmpstr (fdata->md5, ==, md5);
    g_free (md5);

    evbuffer_free (evb);
    close (fd);

    fdata->checked = TRUE;

    http_client_release (http);

    if (check_list (app->l_files)) {
        event_base_loopbreak (app->evbase);
        LOG_debug (HTTP_TEST, "Test passed !");
    }

    evutil_timerclear(&tv);
    tv.tv_sec = g_random_int_range (0, 10);
    tv.tv_usec = 500;
    event_add (app->timeout, &tv);

}

static void on_chunk_cb (HttpClient *http, struct evbuffer *input_buf, gpointer ctx)
{
    gchar *buf = NULL;
    size_t buf_len;
    FileData *fdata = (FileData *) ctx;
    gchar *md5;

    buf_len = evbuffer_get_length (input_buf);
    buf = (gchar *) evbuffer_pullup (input_buf, buf_len);

    g_assert (fwrite (buf, 1, buf_len, fdata->fout) == buf_len);

    evbuffer_drain (input_buf, buf_len);
    
}

static void send_request (FileData *fdata)
{


    http_client_acquire (app->http);

    http_client_request_reset (app->http);

    http_client_set_cb_ctx (app->http, fdata);
    http_client_set_on_chunk_cb (app->http, on_chunk_cb);
    http_client_set_on_last_chunk_cb (app->http, on_last_chunk_cb);

    http_client_set_output_length (app->http, 0);

    http_client_start_request_to_storage_url (app->http, Method_get, fdata->in_name);
}

static void on_output_timer (evutil_socket_t fd, short event, void *ctx)
{
    GList *tmp;

    for (tmp = g_list_first (app->l_files); tmp; tmp = g_list_next (tmp)) {
        FileData *fdata = (FileData *) tmp->data;
        if (!fdata->sent) {
            fdata->sent = TRUE;
            send_request (fdata);
            return;
        }
    }

}

/*{{{ http server */
#define BUFFER_SIZE 1024 * 10

static void on_srv_storage_request (struct evhttp_request *req, void *ctx)
{
    struct evbuffer *in;
    gchar *dir = (gchar *) ctx;
    gchar *path;
    gchar *tmp, *decoded_path;
	const char *uri = evhttp_request_get_uri(req);
	struct evhttp_uri *decoded = NULL;
    struct evbuffer *evb = NULL;
    char buf[BUFFER_SIZE];
    FILE *f;
    size_t bytes_read;
    size_t total_bytes = 0;

    in = evhttp_request_get_input_buffer (req);

	decoded = evhttp_uri_parse(uri);
    g_assert (decoded);
	tmp = evhttp_uri_get_path(decoded);
    g_assert (tmp);
    decoded_path = evhttp_uridecode(tmp, 0, NULL);
    path = decoded_path + strlen ("/storage");

    evb = evbuffer_new();

    //path = g_strdup_printf ("%s/%s", dir, decoded_path);
    LOG_debug (HTTP_TEST, "SRV: received %d bytes. Req: %s, path: %s", evbuffer_get_length (in), evhttp_request_get_uri (req), path);

    f = fopen (path, "r");
    g_free (decoded_path);
    evhttp_uri_free (decoded);
    g_assert (f);
    //g_free (path);

    while ((bytes_read = fread (buf, 1, BUFFER_SIZE, f)) > 0) {
        evbuffer_add (evb, buf, bytes_read);
        total_bytes += bytes_read;
    }

    evhttp_add_header (req->output_headers, "Connection", "close");
    evhttp_send_reply(req, 200, "OK", evb);

    LOG_debug (HTTP_TEST, "Total bytes sent: %u", total_bytes);

    fclose(f);
    evbuffer_free(evb);
}

static void on_srv_auth_request (struct evhttp_request *req, void *ctx)
{
    evhttp_add_header (req->output_headers, "X-Auth-Token", "abcdef");
    evhttp_add_header (req->output_headers, "X-Storage-Url", "http://127.0.0.1:8011/storage");
    evhttp_send_reply(req, 200, "OK", NULL);
}

static void on_srv_gen_request (struct evhttp_request *req, void *ctx)
{
	const char *uri = evhttp_request_get_uri(req);
    
    if (!strstr (uri, "/storage/")) {
        LOG_debug (HTTP_TEST, "%s", uri);
        g_assert_not_reached ();
    }

    on_srv_storage_request (req, ctx);
}

static void start_srv (struct event_base *base, gchar *in_dir)
{
    app->http_srv = evhttp_new (base);
    g_assert (app->http_srv);
    evhttp_bind_socket (app->http_srv, "127.0.0.1", 8011);
    evhttp_set_cb (app->http_srv, "/storage/", on_srv_storage_request, in_dir);
    evhttp_set_cb (app->http_srv, "/get_auth", on_srv_auth_request, NULL);
    evhttp_set_gencb (app->http_srv, on_srv_gen_request, in_dir);

    LOG_debug (HTTP_TEST, "SRV: started");
}

/*}}}*/
/*{{{ utils */
struct event_base *application_get_evbase (Application *app)
{
    return app->evbase;
}

struct evdns_base *application_get_dnsbase (Application *app)
{
    return app->dns_base;
}

const gchar *application_get_container_name (Application *app)
{
    return "test";
}

ConfData *application_get_conf (Application *app)
{
    return app->conf;
}

AuthClient *application_get_auth_client (Application *app)
{
    return app->auth_client;
}

const gchar *application_get_storage_url (Application *app)
{
    return NULL;
}

HfsStatsSrv *application_get_stats_srv (Application *app)
{
    return app->stats;
}

/*}}}*/

int main (int argc, char *argv[])
{
    struct timeval tv;
    GList *l_files = NULL;
    CBData *cb;
    gchar *in_dir;
    GList *tmp;
    struct evhttp_uri *uri;

    log_level = LOG_debug;

    event_set_mem_functions (g_malloc, g_realloc, g_free);

    in_dir = g_dir_make_tmp (NULL, NULL);
    g_assert (in_dir);

    app = g_new0 (Application, 1);
    app->files_count = 10;
    app->evbase = event_base_new ();
	app->dns_base = evdns_base_new (app->evbase, 1);
    app->stats = hfs_stats_srv_create (app);

        app->conf = conf_create ();
        conf_add_boolean (app->conf, "log.use_syslog", TRUE);
        
        conf_add_uint (app->conf, "auth.ttl", 85800);
        
        conf_add_int (app->conf, "pool.writers", 2);
        conf_add_int (app->conf, "pool.readers", 2);
        conf_add_int (app->conf, "pool.operations", 4);
        conf_add_uint (app->conf, "pool.max_requests_per_pool", 100);

        conf_add_int (app->conf, "connection.timeout", 20);
        conf_add_int (app->conf, "connection.retries", -1);

        conf_add_uint (app->conf, "filesystem.dir_cache_max_time", 5);
        conf_add_boolean (app->conf, "filesystem.cache_enabled", TRUE);
        conf_add_string (app->conf, "filesystem.cache_dir", "/tmp/hydrafs");
        conf_add_string (app->conf, "filesystem.cache_dir_max_size", "1Gb");

        conf_add_boolean (app->conf, "statistics.enabled", TRUE);
        conf_add_int (app->conf, "statistics.port", 8011);

    conf_add_string (app->conf, "auth.user", "test");
    conf_add_string (app->conf, "auth.key", "test");
    uri = evhttp_uri_parse ("http://127.0.0.1:8011/get_auth");
    app->auth_client = auth_client_create (app, uri);

    l_files = populate_file_list (app->files_count, l_files, in_dir);
    g_assert (l_files);

    app->l_files = l_files;
    app->http = http_client_create (app);

    // start server
    start_srv (app->evbase, in_dir);
    
    cb = g_new (CBData, 1);
    cb->l_files = l_files;
    
    app->timeout = evtimer_new (app->evbase, on_output_timer, cb);

    evutil_timerclear(&tv);
    tv.tv_sec = 0;
    tv.tv_usec = 500;
    event_add (app->timeout, &tv);

    event_base_dispatch (app->evbase);

    for (tmp = g_list_first (l_files); tmp; tmp = g_list_next (tmp)) {
        FileData *fdata = (FileData *) tmp->data;
        
        g_free (fdata->in_name);
        g_free (fdata->md5);
        g_free (fdata->out_name);
        g_free (fdata);
    };
    g_free (in_dir);

    g_free (cb);

    evhttp_uri_free (uri);
    event_del (app->timeout);
    event_free (app->timeout);

    evhttp_free (app->http_srv);
    auth_client_destroy (app->auth_client);

    evdns_base_free (app->dns_base, 0);
    event_base_free (app->evbase);

    conf_destroy (app->conf);
    g_free (app);

    return 0;
}
