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
#include "auth_client.h"
#include "hfs_stats_srv.h"

#define AUTH_LOG "auth"

struct _AuthClient {
    Application *app;
    ConfData *conf;
    struct bufferevent *bev;
    struct evhttp_connection *evcon;

    const struct evhttp_uri *auth_server_uri;
    time_t auth_data_time; // time when Auth data was received
    gchar *auth_token; // cached version of auth_token
    gchar *storage_uri; // cached version of sorage_uri

    gboolean is_requesting; // TRUE if new Auth data is being requested
    GList *l_get_data; // List of requests to auth_client_get_data
};

typedef struct {
    AuthClient_on_data on_data;
    gpointer ctx;
} AuthData;

static void auth_client_on_close_cb (struct evhttp_connection *evcon, void *ctx);
static void auth_client_on_response_cb (struct evhttp_request *req, void *ctx);

AuthClient *auth_client_create (Application *app, const struct evhttp_uri *auth_server_uri)
{
    AuthClient *auth_client;

    auth_client = g_new0 (AuthClient, 1);
    auth_client->app = app;
    auth_client->conf = application_get_conf (app);
    auth_client->auth_server_uri = auth_server_uri;
    auth_client->auth_data_time = 0;
    auth_client->auth_token = NULL;
    auth_client->storage_uri = NULL;
    auth_client->is_requesting = FALSE;
    auth_client->l_get_data = NULL;
    auth_client->bev = NULL;
    auth_client->evcon = NULL;

    return auth_client;
}

void auth_client_destroy (AuthClient *auth_client)
{
    if (auth_client->auth_token)
        g_free (auth_client->auth_token);
    if (auth_client->storage_uri)
        g_free (auth_client->storage_uri);
  //  freed in evhttp_connection_free
  //  if (auth_client->bev)
  //      bufferevent_free (auth_client->bev);
    if (auth_client->evcon)
        evhttp_connection_free (auth_client->evcon);
    g_free (auth_client);
}

void auth_client_get_data (AuthClient *auth_client, gboolean force, AuthClient_on_data on_data, const gpointer ctx)
{
    int port;
    time_t now = time (NULL);
    struct evhttp_request *req;
    int res;
    AuthData *adata;

    // check if auth data is still valid
    if (!force && now >= auth_client->auth_data_time && now - auth_client->auth_data_time <= conf_get_uint (auth_client->conf, "auth.ttl")) {
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
        return;
    }

    // mark AuthClient as being updating, all further requests should be added to l_get_data list
    auth_client->is_requesting = TRUE;

    // create HTTPS connection to Auth server
    if (uri_is_https (auth_client->auth_server_uri)) {
        SSL_CTX *ssl_ctx;
        SSL *ssl;

		ssl_ctx = SSL_CTX_new (SSLv23_method());
        if (!ssl_ctx) {
            LOG_err (AUTH_LOG, "Failed to create SSL_CTX !");
            on_data (ctx, FALSE, NULL, NULL);
            return;
        }
		ssl = SSL_new (ssl_ctx);
        if (!ssl) {
            LOG_err (AUTH_LOG, "Failed to create ssl object !");
            on_data (ctx, FALSE, NULL, NULL);
            return;
        }

		auth_client->bev = bufferevent_openssl_socket_new (
            application_get_evbase (auth_client->app), 
            -1,
            ssl,
		    BUFFEREVENT_SSL_CONNECTING,
		    BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS
        );
    // create HTTP connection to Auth server
    } else {
		auth_client->bev = bufferevent_socket_new (
            application_get_evbase (auth_client->app),
            -1,
		    BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    }

    if (!auth_client->bev) {
        LOG_err (AUTH_LOG, "Failed to create bufferevent!");
        on_data (ctx, FALSE, NULL, NULL);
        return;
    }

    port = uri_get_port (auth_client->auth_server_uri);

    auth_client->evcon = evhttp_connection_base_bufferevent_new (
        application_get_evbase (auth_client->app),
        application_get_dnsbase (auth_client->app),
        auth_client->bev,
        evhttp_uri_get_host (auth_client->auth_server_uri),
        port
    );

    if (!auth_client->evcon) {
        LOG_err (AUTH_LOG, "Failed to create evhttp_connection!");
        on_data (ctx, FALSE, NULL, NULL);
        return;
    }

    evhttp_connection_set_timeout (auth_client->evcon, conf_get_int (auth_client->conf, "connection.timeout"));
    evhttp_connection_set_retries (auth_client->evcon, conf_get_int (auth_client->conf, "connection.retries"));

    evhttp_connection_set_closecb (auth_client->evcon, auth_client_on_close_cb, auth_client);

    // create request object
    req = evhttp_request_new (auth_client_on_response_cb, auth_client);
    if (!req) {
        LOG_err (AUTH_LOG, "Failed to create HTTP request object !");
        on_data (ctx, FALSE, NULL, NULL);
        return;
    }
    
    // close connection
    evhttp_add_header (req->output_headers, "Connection", "close");
    // auth headers
    evhttp_add_header (req->output_headers, "X-Auth-User", conf_get_string (auth_client->conf, "auth.user"));
    evhttp_add_header (req->output_headers, "X-Auth-Key", conf_get_string (auth_client->conf, "auth.key"));

    LOG_debug (AUTH_LOG, "Sending request to Auth server: %s:%i %s", 
        evhttp_uri_get_host (auth_client->auth_server_uri), port, evhttp_uri_get_path (auth_client->auth_server_uri));
    // send request to Auth server
    res = evhttp_make_request (auth_client->evcon, req, EVHTTP_REQ_GET, evhttp_uri_get_path (auth_client->auth_server_uri));

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

    LOG_debug (AUTH_LOG, "[evcon: %p auth: %p] Connection closed", evcon, auth_client);

    //evhttp_connection_free (evcon);
}

// got response from Auth server
static void auth_client_on_response_cb (struct evhttp_request *req, void *ctx)
{
    AuthClient *auth_client = (AuthClient *) ctx;
    GList *l;
    const gchar *storage_url;
    const gchar *auth_token;
    struct evkeyvalq *headers;
    gboolean success = FALSE;
    HfsStatsSrv *stats;

    if (!req) {
        LOG_err (AUTH_LOG, "Request failed !");
        goto done;
    }
    
    LOG_debug (AUTH_LOG, "Got HTTP response (code: %d) from Auth server !", evhttp_request_get_response_code (req));

    stats = application_get_stats_srv (auth_client->app);
    if (stats) {
        hfs_stats_srv_set_auth_srv_status (stats, evhttp_request_get_response_code (req), req->response_code_line);
    }

    // XXX: handle redirect
    // only 200 HTTP code is accepted
    if (evhttp_request_get_response_code (req) != 200 ) {
        LOG_err (AUTH_LOG, "Server returned HTTP error: %s (%d)!", req->response_code_line, evhttp_request_get_response_code (req));
        goto done;
    }

    // get X-Storage-Url and X-Auth-Token headers
    headers = evhttp_request_get_input_headers (req);
    if (!headers) {
        LOG_err (AUTH_LOG, "Failed to get input headers !");
        goto done;
    }

    // use user-specified StorageURL
    storage_url = application_get_storage_url (auth_client->app);
    if (!storage_url)
        storage_url = evhttp_find_header (headers, "X-Storage-Url");

    auth_token = evhttp_find_header (headers, "X-Auth-Token");

    // make sure we got all headers' values
    if (!storage_url || !auth_token) {
        LOG_err (AUTH_LOG, "Failed to get X-Storage-Url and X-Auth-Token headers !");
        goto done;
    }

    // set new values
    if (auth_client->auth_token) {
        g_free (auth_client->auth_token);
        auth_client->auth_token = NULL;
    }
    if (auth_client->storage_uri) {
        g_free (auth_client->storage_uri);
        auth_client->storage_uri = NULL;
    }

    auth_client->auth_token = g_strdup (auth_token);
    auth_client->storage_uri = g_strdup (storage_url);

    if (!auth_client->auth_token || !auth_client->storage_uri) {
        LOG_err (AUTH_LOG, "Failed to parse X-Storage-Url: %s", storage_url);
        goto done;
    }

    // set as success
    success = TRUE;
    auth_client->auth_data_time = time (NULL);

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
