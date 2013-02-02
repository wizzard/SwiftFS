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

    gboolean is_requesting; // TRUE if new Auth data is being requested
    GList *l_get_data; // List of requests to auth_client_get_data
};

typedef struct {
    AuthClient_on_data on_data;
    const gpointer ctx;
} AuthData;

static void auth_client_on_close_cb (struct evhttp_connection *evcon, void *ctx);

AuthClient *auth_client_create (Application *app, const struct evhttp_uri *auth_server_uri)
{
    AuthClient *auth_client;

    auth_client = g_new0 (AuthClient, 1);
    auth_client->app = app;
    auth_client->auth_server_uri = auth_server_uri;
    auth_client->auth_data_time = 0;
    auth_client->auth_token = NULL;
    auth_client->storage_uri = NULL;
    auth_client->is_requesting = FALSE;
    auth_client->l_get_data = NULL;

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
    struct evhttp_request *req;
    int res;
    AuthData *adata;

    // check if auth data is still valid
    if (!force && now > auth_client->auth_data_time && now - auth_client->auth_data_time <= auth_client->app->conf->auth_data_max_time) {
        LOG_debug (AUTH_LOG, "Returning auth data from cache");
        on_data (ctx, TRUE, auth_client->auth_token, auth_client->storage_uri);
        return;
    }
    
    // add request to the list
    adata = g_new0 (AuthData, 1);
    adata->on_data = on_data;
    adata->ctx = ctx;
    auth_client->l_get_data = g_list_append (auth_client->l_get_data, adata);

    // exit function, if Auth data is being requested
    if (auth_client->is_requesting) {
        LOG_debug (AUTH_LOG, "Auth data is being requested, add cb to the list");
        return
    }

    // mark AuthClient as being updating, all further requests should be added to l_get_data list
    auth_client->is_requesting = TRUE;

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

    if (!bev) {
        LOG_err (AUTH_LOG, "Failed to create bufferevent!");
        on_data (ctx, FALSE, NULL, NULL);
        return;
    }

    port = uri_get_port (auth_client->auth_server_uri);

    evcon = evhttp_connection_base_bufferevent_new (
        application_get_evbase (auth_client->app),
        application_get_dnsbase (auth_client->app),
        bev,
        evhttp_uri_get_host (auth_client->auth_server_uri),
        port
    );

    if (!evcon) {
        LOG_err (AUTH_LOG, "Failed to create evhttp_connection!");
        on_data (ctx, FALSE, NULL, NULL);
        return;
    }

    evhttp_connection_set_timeout (evcon, auth_client->app->conf->timeout);
    evhttp_connection_set_retries (evcon, auth_client->app->conf->retries);

    evhttp_connection_set_closecb (evcon, auth_client_on_close_cb, auth_client);

    // create request object
    req = evhttp_request_new (auth_client_on_response_cb, auth_client);
    if (!req) {
        LOG_err (AUTH_LOG, "Failed to create HTTP request object !");
        on_data (ctx, FALSE, NULL, NULL);
        return;
    }
    
    // close connection
    evhttp_add_header (req->output_headers, "Connection", "close");

    LOG_debug (AUTH_LOG, "Sending request to Auth server");
    // send request to Auth server
    res = evhttp_make_request (evcon, req, EVHTTP_REQ_GET, request_str);

    if (res < 0) {
        LOG_err (AUTH_LOG, "Failed execute HTTP request !");
        on_data (ctx, FALSE, NULL, NULL);
        return;
    }
}


// Connection closed by server, free connection object
static void auth_client_on_close_cb (struct evhttp_connection *evcon, void *ctx)
{
    AuthClient *auth_client = (AuthClient *) ctx;

    LOG_debug (AUTH_LOG, "Connection closed");

    evhttp_connection_free (evcon);
}

// got response from Auth server
static void http_connection_on_response_cb (struct evhttp_request *req, void *ctx)
{
    AuthClient *auth_client = (AuthClient *) ctx;
    struct evbuffer *inbuf;
    const char *buf;
    size_t buf_len;
    GList *l;
    gchar *storage_url;
    gchar *auth_token;
    struct evkeyvalq *headers;
    gboolean success = FALSE;

    if (!req) {
        LOG_err (AUTH_LOG, "Request failed !");
        goto done;
    }
    
    LOG_debug (AUTH_LOG, "Got HTTP response (code: %d) from Auth server !", evhttp_request_get_response_code (req));

    // XXX: handle redirect
    // only 200 HTTP code is accepted
    if (evhttp_request_get_response_code (req) != 200 ) {
        LOG_err (CON_LOG, "Server returned HTTP error: %s (%d)!", req->response_code_line, evhttp_request_get_response_code (req));
        goto done;
    }

    // get X-Storage-Url and X-Auth-Token headers
    headers = evhttp_request_get_input_headers (req);
    if (!headers) {
        LOG_err (AUTH_LOG, "Failed to get input headers !");
        goto done;
    }

    storage_url = evhttp_find_header (headers, "X-Storage-Url");
    auth_token = evhttp_find_header (headers, "X-Auth-Token");

    // make sure we got all headers' values
    if (!storage_url || !auth_token) {
        LOG_err (AUTH_LOG, "Failed to get X-Storage-Url and X-Auth-Token haeders !");
        goto done;
    }

    // set new values
    if (auth_client->auth_token) {
        g_free (auth_client->auth_token);
        auth_client->auth_token = NULL;
    }
    if (auth_client->storage_uri) {
        evhttp_uri_free (auth_client->storage_uri);
        auth_client->storage_uri = NULL;
    }

    auth_client->auth_token = g_strdup (auth_token);
    auth_client->storage_uri = evhttp_uri_parse (storage_url);

    if (!auth_client->auth_token || auth_client->storage_uri) {
        LOG_err (AUTH_LOG, "Failed to parse X-Storage-Url: %s", storage_url);
        goto done;
    }

    // set as success
    success = TRUE;

    LOG_debug (AUTH_LOG, "Successfully got new AuthToken and StorageUrl: %s", storage_url);

done:
    auth_client->is_requesting = FALSE;
    
    // inform everyone   
    for (l = g_list_first (auth_client->l_get_data); l; l = g_list_next (l)) {
        AuthData *adata = (AuthData *) l->data;
        adata->on_data (adata->ctx, success, auth_client->auth_token, auth_client->storage_uri);
        // free AuthData
        g_free (adata);
    }
    // reset list
    g_list_free (auth_client->l_get_data);
    auth_client->l_get_data = NULL;
}
