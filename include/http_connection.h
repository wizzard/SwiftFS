/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _HTTP_CONNECTION_H_
#define _HTTP_CONNECTION_H_

#include "global.h"
#include "client_pool.h"

typedef enum {
    RT_list = 0,
} RequestType;

struct _HttpConnection {
    Application *app;

    ClientPool_on_released_cb client_on_released_cb;
    gpointer pool_ctx;

    struct evhttp_connection *evcon;
    struct evhttp_uri *uri;
    gchar *storage_url;

    // is taken by high level
    gboolean is_acquired;
};


gpointer http_connection_create (Application *app);
void http_connection_destroy (gpointer data);

gchar *http_connection_get_auth_string (Application *app, 
        const gchar *method, const gchar *content_type, const gchar *resource, const gchar *time_str);

void http_connection_set_on_released_cb (gpointer client, ClientPool_on_released_cb client_on_released_cb, gpointer ctx);
gboolean http_connection_check_rediness (gpointer client);
gboolean http_connection_acquire (HttpConnection *con);
gboolean http_connection_release (HttpConnection *con);

struct evhttp_connection *http_connection_get_evcon (HttpConnection *con);
Application *http_connection_get_app (HttpConnection *con);

gboolean http_connection_connect (HttpConnection *con);

void http_connection_send (HttpConnection *con, struct evbuffer *outbuf);

struct evhttp_request *http_connection_create_request (HttpConnection *con,
    void (*cb)(struct evhttp_request *, void *), void *arg,
    const gchar *auth_str);


typedef void (*HttpConnection_directory_listing_callback) (gpointer callback_data, gboolean success);
gboolean http_connection_get_directory_listing (HttpConnection *con, const gchar *path, fuse_ino_t ino,
    HttpConnection_directory_listing_callback directory_listing_callback, gpointer callback_data);

typedef void (*HttpConnection_on_entry_sent_cb) (gpointer ctx, gboolean success);
gboolean http_connection_file_send (HttpConnection *con, int fd, const gchar *resource_path, 
    HttpConnection_on_entry_sent_cb on_entry_sent_cb, gpointer ctx);

typedef void (*HttpConnection_response_cb) (HttpConnection *con, gpointer ctx, 
        const gchar *buf, size_t buf_len, struct evkeyvalq *headers, gboolean success);

gboolean http_connection_make_request (HttpConnection *con, 
    const gchar *resource_path, const gchar *request_str,
    const gchar *http_cmd,
    struct evbuffer *out_buffer,
    HttpConnection_response_cb response_cb,
    gpointer ctx);

#endif
