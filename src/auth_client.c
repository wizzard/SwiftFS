/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "auth_client.h"

#define AUTH_LOG "auth"

struct _AuthClient {
    Application *app;
    const struct evhttp_uri *auth_server_uri;
    time_t auth_data_time; // time when Auth data was received
    gchar *auth_token; // cached version of auth_token
    struct evhttp_uri *storage_uri; // cached version of sorage_uri
};

static void auth_client_on_close_cb (struct evhttp_connection *evcon, void *ctx);

AuthClient *auth_client_create (Application *app, const struct evhttp_uri *auth_server_uri)
{
    AuthClient *auth;

    auth_client = g_new0 (AuthClient, 1);
    auth_client->app = app;
    auth_client->auth_server_uri = auth_server_uri;
    auth_client->auth_data_time = 0;
    auth_client->auth_token = NULL;
    auth_client->storage_uri = NULL;

    return auth_client;
}

void auth_client_destroy (AuthClient *auth_client)
{
    if (auth_client->auth_token)
        g_free (auth_client->auth_token);
    if (auth_client->storage_uri)
        evhttp_uri_free (auth_client->storage_uri);
    g_free (auth_client);
}

void auth_client_get_data (AuthClient *auth_client, gboolean force, AuthClient_on_data on_data, const gpointer ctx)
{
    int port;
    struct bufferevent *bev;
    struct evhttp_connection *evcon;
    time_t now = time (NULL);

    // check if auth data is still valid
    if (!force && now > auth_client->auth_data_time && now - auth_client->auth_data_time <= auth_client->app->conf->auth_data_max_time) {
        on_data (ctx, TRUE, app->auth_token, app->storage_uri);
        return;
    }

    // create HTTPS connection to Auth server
    if (uri_is_https (auth_client->auth_server_uri)) {
        SSL_CTX *ssl_ctx;
        SSL *ssl;

		ssl_ctx = SSL_CTX_new (SSLv23_method());
		ssl = SSL_new (ssl_ctx);

		bev = bufferevent_openssl_socket_new (
            application_get_evbase (auth_client->app), 
            -1,
            ssl,
		    BUFFEREVENT_SSL_CONNECTING,
		    BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS
        );
    // create HTTP connection to Auth server
    } else {
		bev = bufferevent_socket_new (
            application_get_evbase (auth_client->app),
            -1,
		    BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    }

    port = uri_get_port (auth_client->auth_server_uri);

    evcon = evhttp_connection_base_bufferevent_new (
        application_get_evbase (auth_client->app),
        application_get_dnsbase (auth_client->app),
        bev,
        evhttp_uri_get_host (auth_client->auth_server_uri),
        port
    );

    evhttp_connection_set_timeout (evcon, auth_client->app->conf->timeout);
    evhttp_connection_set_retries (evcon, auth_client->app->conf->retries);

    evhttp_connection_set_closecb (evcon, auth_client_on_close_cb, con);

    // send request to Auth server
}


// Connection closed by server, free connection object
static void auth_client_on_close_cb (struct evhttp_connection *evcon, void *ctx)
{
    AuthClient *auth_client = (AuthClient *) ctx;

    LOG_debug (AUTH_LOG, "Connection closed");

    evhttp_connection_free (evcon);
}
