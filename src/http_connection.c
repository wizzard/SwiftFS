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
#include "http_connection.h"
#include "auth_client.h"
#include "hfs_stats_srv.h"

/*{{{ struct*/

// HTTP header: key, value
typedef struct {
    gchar *key;
    gchar *value;
} HttpConnectionHeader;

#define CON_LOG "con"
#define IDLE "idle"

static void http_connection_on_close (struct evhttp_connection *evcon, void *ctx);

/*}}}*/

/*{{{ create / destroy */
// create HttpConnection object
// establish HTTP connections to 
gpointer http_connection_create (Application *app)
{
    HttpConnection *con;

    con = g_new0 (HttpConnection, 1);
    if (!con) {
        LOG_err (CON_LOG, "Failed to create HttpConnection !");
        return NULL;
    }

    con->app = app;
    con->conf = application_get_conf (app);
    con->stats_srv = application_get_stats_srv (app);
    con->auth_client = application_get_auth_client (app);
    con->evcon = NULL;
    con->auth_token = NULL;
    con->l_output_headers = NULL;
    con->s_status = g_strdup (IDLE);
    timeval_zero (&con->start_tv);

    con->is_acquired = FALSE;

    return (gpointer)con;
}

// destory HttpConnection
void http_connection_destroy (gpointer data)
{
    HttpConnection *con = (HttpConnection *) data;

    if (con->auth_token)
        g_free (con->auth_token);

    if (con->s_status)
        g_free (con->s_status);

    if (con->evcon)    
        evhttp_connection_free (con->evcon);
    g_free (con);
}
/*}}}*/

static gboolean http_connection_connect (HttpConnection *con, const gchar *storage_url)
{
    gint port;
    struct bufferevent *bev;
    struct evhttp_uri *uri;

    uri = evhttp_uri_parse (storage_url);
    if (!uri) {
        LOG_err (CON_LOG, "Failed to parse StorageUrl: %s", storage_url);
        return FALSE;
    }
    port = uri_get_port (uri);

    LOG_debug (CON_LOG, "Connecting to %s:%d", 
        evhttp_uri_get_host (uri),
        port
    );

    // create SSL buffer
    if (uri_is_https (uri)) {
        SSL *ssl;

        ssl = SSL_new (application_get_ssl_ctx (con->app));

        bev = bufferevent_openssl_socket_new (
            application_get_evbase (con->app), 
            -1,
            ssl,
            BUFFEREVENT_SSL_CONNECTING,
            BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS
        );

        // LOG_err (CON_LOG, "Using SSL !");
    } else {
		bev = bufferevent_socket_new (
            application_get_evbase (con->app),
            -1,
		    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    }

    if (!bev) {
        LOG_err (CON_LOG, "Failed to create bufferevent !");
        return FALSE;
    }

    con->evcon = evhttp_connection_base_bufferevent_new (
        application_get_evbase (con->app),
        application_get_dnsbase (con->app),
        bev,
        evhttp_uri_get_host (uri),
        port
    );

    if (!con->evcon) {
        LOG_err (CON_LOG, "Failed to create evhttp_connection !");
        return FALSE;
    }
    
    evhttp_connection_set_timeout (con->evcon, conf_get_int (con->conf, "connection.timeout"));
    evhttp_connection_set_retries (con->evcon, conf_get_int (con->conf, "connection.retries"));

    evhttp_connection_set_closecb (con->evcon, http_connection_on_close, con);

    evhttp_uri_free (uri);

    return TRUE;
}

void http_connection_set_on_released_cb (gpointer client, ClientPool_on_released_cb client_on_released_cb, gpointer ctx)
{
    HttpConnection *con = (HttpConnection *) client;

    con->client_on_released_cb = client_on_released_cb;
    con->pool_ctx = ctx;
}

gboolean http_connection_check_rediness (gpointer client)
{
    HttpConnection *con = (HttpConnection *) client;

    return !con->is_acquired;
}

ClientInfo *http_connection_get_info (gpointer client)
{
    HttpConnection *con = (HttpConnection *) client;
    ClientInfo *info = g_new0 (ClientInfo, 1);
    
    info->con = con;
    info->status = g_strdup (con->s_status);
    if (con->upload_bytes)
        info->bytes = con->upload_bytes;
    timeval_copy (&info->start_tv, &con->start_tv);
    
    return info;
}

gboolean http_connection_acquire (HttpConnection *con)
{
    con->is_acquired = TRUE;

    return TRUE;
}

gboolean http_connection_release (HttpConnection *con)
{
    con->is_acquired = FALSE;

    if (con->client_on_released_cb)
        con->client_on_released_cb (con, con->pool_ctx);
    
    return TRUE;
}

// callback connection is closed
static void http_connection_on_close (struct evhttp_connection *evcon, void *ctx)
{
    HttpConnection *con = (HttpConnection *) ctx;

    LOG_debug (CON_LOG, "[evcon: %p con: %p] Connection closed !", evcon, con);

    con->evcon = NULL;
}

/*{{{ getters */
Application *http_connection_get_app (HttpConnection *con)
{
    return con->app;
}

struct evhttp_connection *http_connection_get_evcon (HttpConnection *con)
{
    return con->evcon;
}

/*}}}*/

typedef struct {
    HttpConnection *con;
    HttpConnection_response_cb response_cb;
    gpointer ctx;
} RequestData;

static void http_connection_on_response_cb (struct evhttp_request *req, void *ctx)
{
    RequestData *data = (RequestData *) ctx;
    struct evbuffer *inbuf;
    const char *buf;
    size_t buf_len;
    HfsStatsSrv *stats;

    if (data->con->s_status)
        g_free (data->con->s_status);
    data->con->s_status = g_strdup (IDLE);
    timeval_zero (&data->con->start_tv);

    LOG_debug (CON_LOG, "[%p] Request cb !", data->con);
    
    if (!req) {
        LOG_err (CON_LOG, "[%p] Request failed !", data->con);
        if (data->response_cb)
            data->response_cb (data->con, data->ctx, NULL, 0, NULL, FALSE);
        goto done;
    }

    stats = application_get_stats_srv (data->con->app);
    if (stats) {
        hfs_stats_srv_set_storage_srv_status (stats, evhttp_request_get_response_code (req), req->response_code_line);

        hfs_stats_srv_add_up_bytes (data->con->stats_srv, data->con->upload_bytes);
    }
    data->con->upload_bytes = 0;

    // XXX: handle redirect
    // 200 (Ok), 201 (Created), 202 (Accepted), 204 (No Content) are ok
    if (evhttp_request_get_response_code (req) != 200 && evhttp_request_get_response_code (req) != 204 &&
            evhttp_request_get_response_code (req) != 202 && evhttp_request_get_response_code (req) != 201) {
        LOG_err (CON_LOG, "Server returned HTTP error: %d !", evhttp_request_get_response_code (req));
        LOG_debug (CON_LOG, "[%p] Error str: %s", data->con, req->response_code_line);
        if (data->response_cb)
            data->response_cb (data->con, data->ctx, NULL, 0, NULL, FALSE);
        goto done;
    }

    inbuf = evhttp_request_get_input_buffer (req);
    buf_len = evbuffer_get_length (inbuf);
    buf = (const char *) evbuffer_pullup (inbuf, buf_len);

    LOG_debug (CON_LOG, "[%p] Got HTTP response from server: %d %s inbuf: %zu", data->con,
        evhttp_request_get_response_code (req), req->response_code_line, buf_len);

    if (buf_len) {
        // update stats
        hfs_stats_srv_add_down_bytes (data->con->stats_srv, buf_len);
    }
    
    if (data->response_cb)
        data->response_cb (data->con, data->ctx, buf, buf_len, evhttp_request_get_input_headers (req), TRUE);
    else
        LOG_msg (CON_LOG, ">>> NO callback function !");

done:
    g_free (data);
}

// add an header to the outgoing request
void http_connection_add_output_header (HttpConnection *con, const gchar *key, const gchar *value)
{
    HttpConnectionHeader *header;

    header = g_new0 (HttpConnectionHeader, 1);
    header->key = g_strdup (key);
    header->value = g_strdup (value);

    con->l_output_headers = g_list_append (con->l_output_headers, header);
}

static void http_connection_free_headers (GList *l_headers)
{
    GList *l;
    for (l = g_list_first (l_headers); l; l = g_list_next (l)) {
        HttpConnectionHeader *header = (HttpConnectionHeader *) l->data;
        g_free (header->key);
        g_free (header->value);
    }

    g_list_free (l_headers);
}

// internal
gboolean http_connection_make_request_ (HttpConnection *con, 
    const gchar *url,
    const gchar *http_cmd,
    struct evbuffer *out_buffer,
    HttpConnection_response_cb response_cb,
    gpointer ctx)
{
    struct evhttp_request *req;
	time_t t;
    char time_str[50];
    RequestData *data;
    int res;
    enum evhttp_cmd_type cmd_type;
    struct evhttp_uri *uri;
    gchar *req_uri;
    GList *l;

    // connect
    if (!con->evcon) {
        if (!http_connection_connect (con, url)) {
            LOG_err (CON_LOG, "Failed to connect to Storage server !");
            return FALSE;
        }
    }

    uri = evhttp_uri_parse (url);
    if (!uri) {
        LOG_err (CON_LOG, "Failed to parse StorageUrl: %s", url);
        return FALSE;
    }

    // XXX: we need to update application container path
    // application_update_full_container_name (con->app, evhttp_uri_get_path (uri));
    
    data = g_new0 (RequestData, 1);
    data->response_cb = response_cb;
    data->ctx = ctx;
    data->con = con;
    
    if (!strcasecmp (http_cmd, "GET")) {
        cmd_type = EVHTTP_REQ_GET;
    } else if (!strcasecmp (http_cmd, "PUT")) {
        cmd_type = EVHTTP_REQ_PUT;
    } else if (!strcasecmp (http_cmd, "DELETE")) {
        cmd_type = EVHTTP_REQ_DELETE;
    } else if (!strcasecmp (http_cmd, "HEAD")) {
        cmd_type = EVHTTP_REQ_HEAD;
    } else {
        LOG_err (CON_LOG, "Unsupported HTTP method: %s", http_cmd);
        return FALSE;
    }
    
    t = time (NULL);
    strftime (time_str, sizeof (time_str), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));

    req = evhttp_request_new (http_connection_on_response_cb, data);
    if (!req) {
        LOG_err (CON_LOG, "Failed to create HTTP request object !");
        return FALSE;
    }

    evhttp_add_header (req->output_headers, "X-Auth-Token", con->auth_token);
    evhttp_add_header (req->output_headers, "Host", evhttp_uri_get_host (uri));
    evhttp_add_header (req->output_headers, "Accept-Encoding", "identify");
    // ask to keep connection opened
    evhttp_add_header (req->output_headers, "Connection", "keep-alive");

    // add headers
    for (l = g_list_first (con->l_output_headers); l; l = g_list_next (l)) {
        HttpConnectionHeader *header = (HttpConnectionHeader *) l->data;
        evhttp_add_header (req->output_headers, 
            header->key, header->value
        );
    }

    http_connection_free_headers (con->l_output_headers);
    con->l_output_headers = NULL;

    if (out_buffer) {
        evbuffer_add_buffer (req->output_buffer, out_buffer);

        // update stats
        con->upload_bytes = evbuffer_get_length (req->output_buffer);

    } else {
        con->upload_bytes = 0;
    }

    gettimeofday (&con->start_tv, NULL);

    LOG_msg (CON_LOG, "[%p] New request: %s %s buf: %zu", con, http_cmd, url, evbuffer_get_length (req->output_buffer));
    
    if (evhttp_uri_get_query (uri))
        req_uri = g_strdup_printf ("%s?%s", evhttp_uri_get_path (uri), evhttp_uri_get_query (uri));
    else
        req_uri = g_strdup (evhttp_uri_get_path (uri));
    res = evhttp_make_request (http_connection_get_evcon (con), req, cmd_type, req_uri);
    
    g_free (req_uri);
    evhttp_uri_free (uri);

    if (res < 0) {
        LOG_err (CON_LOG, "Failed to create request !");
        return FALSE;
    } else
        return TRUE;
}

typedef struct {
    HttpConnection *con; 
    gchar *resource_path;
    gchar *http_cmd;
    struct evbuffer *out_buffer;
    HttpConnection_response_cb response_cb;
    gpointer ctx;
} ARequest;

// on AuthServer reply
static void http_connection_on_auth_data_cb (gpointer ctx, gboolean success, 
    const gchar *auth_token, const gchar *storage_uri)
{
    ARequest *req = (ARequest *) ctx;
    gchar *url;

    if (!success) {
        LOG_err (CON_LOG, "Failed to get AuthToken !");
        // inform higher level
        req->response_cb (req->con, req->ctx, NULL, 0, NULL, FALSE);
    } else {
        url = g_strdup_printf ("%s%s", storage_uri, req->resource_path);
        if (req->con->auth_token)
            g_free (req->con->auth_token);
        req->con->auth_token = g_strdup (auth_token);

        http_connection_make_request_ (req->con, url, req->http_cmd, req->out_buffer, req->response_cb, req->ctx);

        g_free (url);
    }
    
    g_free (req->resource_path);
    g_free (req->http_cmd);
    g_free (req);
}


// get AuthData and perform HTTP request to StorageURL
gboolean http_connection_make_request_to_storage_url (HttpConnection *con, 
    const gchar *resource_path,
    const gchar *http_cmd,
    struct evbuffer *out_buffer,
    HttpConnection_response_cb response_cb,
    gpointer ctx)
{
    ARequest *req;

    req = g_new0 (ARequest, 1);
    req->con = con;
    req->resource_path = g_strdup (resource_path);
    req->http_cmd = g_strdup (http_cmd);
    req->out_buffer = out_buffer;
    req->response_cb = response_cb;
    req->ctx = ctx;

    if (con->s_status)
        g_free (con->s_status);
    con->s_status = g_strdup_printf ("%s %s", http_cmd, resource_path);

    auth_client_get_data (application_get_auth_client (con->app), FALSE, http_connection_on_auth_data_cb, req);
    return TRUE;

}
