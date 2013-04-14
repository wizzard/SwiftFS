/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _HTTP_CLIENT_H_
#define _HTTP_CLIENT_H_

#include "global.h"
#include "client_pool.h"

typedef struct _HttpClient HttpClient;

typedef enum {
    Method_get = 0,
    Method_put = 1,
} HttpClientRequestMethod;

gpointer http_client_create (Application *app);
void http_client_destroy (gpointer data);

void http_client_request_reset (HttpClient *http, gboolean free_output_headers);

void http_client_set_output_length (HttpClient *http, guint64 output_lenght);
void http_client_add_output_header (HttpClient *http, const gchar *key, const gchar *value);
void http_client_add_output_data (HttpClient *http, char *buf, size_t size);

const gchar *http_client_get_input_header (HttpClient *http, const gchar *key);
gint64 http_client_get_input_length (HttpClient *http);


gboolean http_client_check_rediness (gpointer client);
gboolean http_client_acquire (gpointer client);
gboolean http_client_release (gpointer client);
void http_client_set_on_released_cb (gpointer client, ClientPool_on_released_cb client_on_released_cb, gpointer ctx);

// return TRUE if http client is ready to execute a new request
gboolean http_client_is_ready (HttpClient *http);

// try to connect to the server
// internal
gboolean http_client_start_request_ (HttpClient *http, HttpClientRequestMethod method, const gchar *url);

// get AuthData first and call http_client_start_request ()
gboolean http_client_start_request_to_storage_url (HttpClient *http, HttpClientRequestMethod method, const gchar *path,
    struct evbuffer *out_buffer,
    gpointer ctx
        );

// set context data for all callback functions
void http_client_set_cb_ctx (HttpClient *http, gpointer ctx);


// a chunk of data is received
typedef void (*HttpClient_on_chunk_cb) (HttpClient *http, struct evbuffer *data_buf, gboolean success, gpointer ctx);
void http_client_set_on_chunk_cb (HttpClient *http, HttpClient_on_chunk_cb on_chunk_cb);
// last chunk of data is received
void http_client_set_on_last_chunk_cb (HttpClient *http, HttpClient_on_chunk_cb on_last_chunk_cb);



// connection is closed
typedef void (*HttpClient_on_close_cb) (HttpClient *http, gpointer ctx);
void http_client_set_close_cb (HttpClient *http, HttpClient_on_close_cb on_close_cb);

// connection is established
typedef void (*HttpClient_on_connection_cb) (HttpClient *http, gpointer ctx);
void http_client_set_connection_cb (HttpClient *http, HttpClient_on_connection_cb on_connection_cb);

ClientInfo *http_client_get_info (gpointer client);

#endif
