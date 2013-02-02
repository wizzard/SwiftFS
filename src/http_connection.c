/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "http_connection.h"

/*{{{ struct*/

#define CON_LOG "con"

static void http_connection_on_close (struct evhttp_connection *evcon, void *ctx);

/*}}}*/

/*{{{ create / destroy */
// create HttpConnection object
// establish HTTP connections to 
gpointer http_connection_create (Application *app)
{
    HttpConnection *con;
    int port;
    struct bufferevent *bev;

    con = g_new0 (HttpConnection, 1);
    if (!con) {
        LOG_err (CON_LOG, "Failed to create HttpConnection !");
        return NULL;
    }

    con->app = app;
    con->storage_url = g_strdup (application_get_host (app));
    con->uri = application_get_storage_uri (app);

    con->is_acquired = FALSE;

    port = evhttp_uri_get_port (con->uri);
    // if no port is specified, libevent returns -1
    if (port == -1) {
        if (uri_is_https (con->uri))
            port = 443;
        else
            port = 80;
    }

    LOG_debug (CON_LOG, "Connecting to %s:%d", 
        evhttp_uri_get_host (con->uri),
        port
    );

    // create SSL buffer
    if (uri_is_https (con->uri)) {
        SSL_CTX *ssl_ctx;
        SSL *ssl;

		ssl_ctx = SSL_CTX_new (SSLv23_method());
		ssl = SSL_new (ssl_ctx);

		bev = bufferevent_openssl_socket_new (
            application_get_evbase (app), 
            -1,
            ssl,
		    BUFFEREVENT_SSL_CONNECTING,
		    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS
        );
    } else {
		bev = bufferevent_socket_new (
            application_get_evbase (app),
            -1,
		    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    }

    con->evcon = evhttp_connection_base_bufferevent_new (
        application_get_evbase (app),
        application_get_dnsbase (app),
        bev,
        evhttp_uri_get_host (con->uri),
        port
    );

    if (!con->evcon) {
        LOG_err (CON_LOG, "Failed to create evhttp_connection !");
        return NULL;
    }
    
    // XXX: config these
    evhttp_connection_set_timeout (con->evcon, 20);
    evhttp_connection_set_retries (con->evcon, -1);

    evhttp_connection_set_closecb (con->evcon, http_connection_on_close, con);

    return (gpointer)con;
}

// destory HttpConnection
void http_connection_destroy (gpointer data)
{
    HttpConnection *con = (HttpConnection *) data;

    g_free (con->storage_url);
    if (con->evcon)    
        evhttp_connection_free (con->evcon);
    g_free (con);
}
/*}}}*/

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

    LOG_debug (CON_LOG, "Connection closed !");
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

// create  and setup HTTP connection request
struct evhttp_request *http_connection_create_request (HttpConnection *con,
    void (*cb)(struct evhttp_request *, void *), void *arg,
    const gchar *auth_str)
{    
    struct evhttp_request *req;
    gchar auth_key[300];
    struct tm *cur_p;
	time_t t = time(NULL);
    struct tm cur;
    char date[50];
    //char hostname[1024];

	gmtime_r(&t, &cur);
	cur_p = &cur;

    req = evhttp_request_new (cb, arg);
    evhttp_add_header (req->output_headers, "X-Auth-Token", application_get_auth_token (con->app));
    evhttp_add_header (req->output_headers, "Host", application_get_host (con->app));
	evhttp_add_header (req->output_headers, "Accept", "*/*");

    LOG_debug (CON_LOG, "HOST: %s", application_get_host (con->app));
	/*	
    if (strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", cur_p) != 0) {
			evhttp_add_header (req->output_headers, "Date", date);
		}
    */
    return req;
}


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

    LOG_debug (CON_LOG, "Got HTTP response from server !");

    if (!req) {
        LOG_err (CON_LOG, "Request failed !");
        if (data->response_cb)
            data->response_cb (data->con, data->ctx, NULL, 0, NULL, FALSE);
        goto done;
    }

    // XXX: handle redirect
    // 200 (Ok), 201 (Created), 202 (Accepted), 204 (No Content) are ok
    if (evhttp_request_get_response_code (req) != 200 && evhttp_request_get_response_code (req) != 204 &&
            evhttp_request_get_response_code (req) != 202 && evhttp_request_get_response_code (req) != 201) {
        LOG_err (CON_LOG, "Server returned HTTP error: %d !", evhttp_request_get_response_code (req));
        LOG_debug (CON_LOG, "Error str: %s", req->response_code_line);
        if (data->response_cb)
            data->response_cb (data->con, data->ctx, NULL, 0, NULL, FALSE);
        goto done;
    }

    inbuf = evhttp_request_get_input_buffer (req);
    buf_len = evbuffer_get_length (inbuf);
    buf = (const char *) evbuffer_pullup (inbuf, buf_len);
    
    if (data->response_cb)
        data->response_cb (data->con, data->ctx, buf, buf_len, evhttp_request_get_input_headers (req), TRUE);
    else
        LOG_msg (CON_LOG, ">>> NO callback function !");

done:
    g_free (data);
}

gboolean http_connection_make_request (HttpConnection *con, 
    const gchar *resource_path, const gchar *request_str,
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

    evhttp_add_header (req->output_headers, "X-Auth-Token", application_get_auth_token (con->app));
    evhttp_add_header (req->output_headers, "Host", application_get_host (con->app));	
	//evhttp_add_header (req->output_headers, "Date", time_str);

    if (out_buffer) {
        evbuffer_add_buffer (req->output_buffer, out_buffer);
    }

    LOG_debug (CON_LOG, "HOST: %s", application_get_host (con->app));
    LOG_msg (CON_LOG, "[%p] New request: %s", con, request_str);

    res = evhttp_make_request (http_connection_get_evcon (con), req, cmd_type, request_str);

    if (res < 0)
        return FALSE;
    else
        return TRUE;
}
