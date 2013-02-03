/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "global.h"
#include "auth_client.h"

#define AUTH_TEST "auth_test"

struct _Application {
    struct event_base *evbase;
    struct evdns_base *dns_base;
    ConfData *conf;
    struct evhttp *http;

    AuthClient *auth_client;
    GList *l_requests;
};

typedef struct {
    gint id;
    gboolean checked;
} ARequest;

static Application *app;

/*{{{*/
struct event_base *application_get_evbase (Application *app)
{
    return app->evbase;
}

struct evdns_base *application_get_dnsbase (Application *app)
{
    return app->dns_base;
}

ConfData *application_get_conf (Application *app)
{
    return app->conf;
}
/*}}}*/

gboolean check_list (GList *l)
{
    GList *tmp;
    
    for (tmp = g_list_first (l); tmp; tmp = g_list_next (tmp)) {
        ARequest *req = (ARequest *) l->data;
        if (!req->checked)
            return FALSE;
    }
    return TRUE;
}

static void on_auth_data_cb (gpointer ctx, gboolean success, 
    const gchar *auth_token, const struct evhttp_uri *storage_uri)
{
    ARequest *req = (ARequest *) ctx;

    g_assert (success);

    req->checked = TRUE;

    if (check_list (app->l_requests)) {
        event_base_loopbreak (app->evbase);
        LOG_debug (AUTH_TEST, "Test passed !");
    }
}

static void on_timer_cb (evutil_socket_t fd, short event, void *ctx)
{
    gint i;
    GList *l;

    for (l = g_list_first (app->l_requests); l; l = g_list_next (l)) {
        ARequest *req = (ARequest *) l->data;
        auth_client_get_data (app->auth_client, FALSE, on_auth_data_cb, req);
    }
}

int main (int argc, char *argv[])
{
    struct evhttp_uri *auth_server_uri;
    gint i;
    struct timeval tv;
    struct event *timeout;

    log_level = LOG_debug;

    event_set_mem_functions (g_malloc, g_realloc, g_free);

    app = g_new0 (Application, 1);
    app->evbase = event_base_new ();
	app->dns_base = evdns_base_new (app->evbase, 1);
    app->l_requests = NULL;
    app->conf = conf_create ();
    g_assert (conf_parse_file (app->conf, "test.conf.xml") == TRUE);
    conf_add_string (app->conf, "auth.user", "test:tester");
    conf_add_string (app->conf, "auth.key", "testing");

    auth_server_uri = evhttp_uri_parse ("http://10.0.0.104:8080/auth/v1.0");
    app->auth_client = auth_client_create (app, auth_server_uri);

    for (i = 1; i <= 10; i++) {
        ARequest *req = g_new0 (ARequest, 1);
        req->id = i;
        req->checked = FALSE;
        app->l_requests = g_list_append (app->l_requests, req);
    }

    timeout = evtimer_new (app->evbase, on_timer_cb, NULL);

    evutil_timerclear(&tv);
    tv.tv_sec = 0;
    tv.tv_usec = 500;
    event_add (timeout, &tv);

    event_base_dispatch (app->evbase);

    evhttp_uri_free (auth_server_uri);
    auth_client_destroy (app->auth_client);
    event_del (timeout);
    event_free (timeout);

    evdns_base_free (app->dns_base, 0);
    event_base_free (app->evbase);

    return 0;
}
