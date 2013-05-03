/*  
 * Copyright 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include "global.h"
#include "http_client.h"
#include "http_connection.h"
#include "client_pool.h"
#include "auth_client.h"
#include "log.h"

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

    SSL_CTX *ssl_ctx;
};

static Application *app;

#define HTTP_TEST "http_test3"


static void on_srv_gen_request (struct evhttp_request *req, void *ctx)
{
	const char *uri = evhttp_request_get_uri(req);
    
    if (!strstr (uri, "/storage/")) {
        LOG_debug (HTTP_TEST, "%s", uri);
        g_assert_not_reached ();
    }
}

static void start_srv (struct event_base *base, gchar *in_dir)
{
    app->http_srv = evhttp_new (base);
    g_assert (app->http_srv);
    evhttp_bind_socket (app->http_srv, "127.0.0.1", 8011);
    evhttp_set_gencb (app->http_srv, on_srv_gen_request, in_dir);

    LOG_debug (HTTP_TEST, "SRV: started");
}

#define BUFFER_SIZE 1024 * 10

static void on_output_timer (evutil_socket_t fd, short event, void *ctx)
{
    gchar *path;
    char buf[BUFFER_SIZE];
    FILE *f;
    size_t bytes_read;
    size_t total_bytes = 0;
    struct evbuffer *evb = NULL;

    LOG_debug (HTTP_TEST, "On timer");

    http_client_acquire (app->http);

    http_client_request_reset (app->http);

    path = g_strdup ("fin.txt");
    f = fopen (path, "r");
    g_free (path);
    g_assert (f);

    evb = evbuffer_new ();
    while ((bytes_read = fread (buf, 1, BUFFER_SIZE, f)) > 0) {
        evbuffer_add (evb, buf, bytes_read);
        total_bytes += bytes_read;
    }

    fclose (f);


    //http_client_set_cb_ctx (app->http, fdata);
    //http_client_set_on_chunk_cb (app->http, on_chunk_cb);
    //http_client_set_on_last_chunk_cb (app->http, on_last_chunk_cb);
    //http_client_set_output_length (app->http, 0);

    http_client_start_request_to_storage_url (app->http, Method_put, "/test1", evb, NULL);

    evbuffer_free (evb);
}

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

ClientPool *application_get_write_client_pool (Application *app)
{
    return NULL;
}

ClientPool *application_get_read_client_pool (Application *app)
{
    return NULL;
}

ClientPool *application_get_ops_client_pool (Application *app)
{
    return NULL;
}

SSL_CTX *application_get_ssl_ctx (Application *app)
{
    return app->ssl_ctx;
}

/*}}}*/

int main (int argc, char *argv[])
{
    gchar *in_dir;
    GList *tmp;
    struct evhttp_uri *uri;
    struct timeval tv;

    log_level = LOG_debug;

    event_set_mem_functions (g_malloc, g_realloc, g_free);
    // init SSL libraries
    CRYPTO_set_mem_functions (g_malloc0, g_realloc, g_free);
    ENGINE_load_builtin_engines ();
    ENGINE_register_all_complete ();
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();

    SSL_load_error_strings ();
    SSL_library_init ();
    if (!RAND_poll ()) {
        fprintf(stderr, "RAND_poll() failed.\n");
        return 1;
    }
    g_random_set_seed (time (NULL));

    in_dir = g_dir_make_tmp (NULL, NULL);
    g_assert (in_dir);

    app = g_new0 (Application, 1);
    app->files_count = 10;
    app->evbase = event_base_new ();
	app->dns_base = evdns_base_new (app->evbase, 1);

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

    conf_add_string (app->conf, "auth.user", "test:tester");
    conf_add_string (app->conf, "auth.key", "testing");
    uri = evhttp_uri_parse ("https://10.0.0.104:8080/auth/v1.0");
    
    app->ssl_ctx = SSL_CTX_new (TLSv1_client_method ());
    
    app->stats = hfs_stats_srv_create (app);
    app->auth_client = auth_client_create (app, uri);

    app->http = http_client_create (app);

    // start server
     start_srv (app->evbase, in_dir);

    app->timeout = evtimer_new (app->evbase, on_output_timer, NULL);

    evutil_timerclear(&tv);
    tv.tv_sec = 0;
    tv.tv_usec = 500;
    event_add (app->timeout, &tv);

    event_base_dispatch (app->evbase);

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
