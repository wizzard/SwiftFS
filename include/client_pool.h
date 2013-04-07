/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _CLIENT_POOL_H_
#define _CLIENT_POOL_H_

#include "global.h"

typedef gpointer (*ClientPool_client_create) (Application *app);
typedef void (*ClientPool_client_destroy) (gpointer client);
typedef void (*ClientPool_on_released_cb) (gpointer client, gpointer ctx);
typedef void (*ClientPool_client_set_on_released_cb) (gpointer client, ClientPool_on_released_cb client_on_released_cb, gpointer ctx);
typedef gboolean (*ClientPool_client_check_rediness) (gpointer client);

typedef struct {
    gchar *pool_name;
    gpointer con;
    gchar *status;
} ClientInfo;
typedef ClientInfo *(*ClientPool_client_get_info) (gpointer client);

ClientPool *client_pool_create (Application *app, 
    gint client_count,
    ClientPool_client_create client_create,
    ClientPool_client_destroy client_destroy,
    ClientPool_client_set_on_released_cb client_set_on_released_cb,
    ClientPool_client_check_rediness client_check_rediness,
    ClientPool_client_get_info client_get_info
);

void client_pool_destroy (ClientPool *pool);

// add client's callback to the awaiting queue
// return TRUE if added, FALSE if list is full
typedef void (*ClientPool_on_client_ready) (gpointer client, gpointer ctx);
gboolean client_pool_get_client (ClientPool *pool, ClientPool_on_client_ready on_client_ready, gpointer ctx);

typedef void (*ClientPool_on_request_done) (gpointer callback_data, gboolean success);
void client_pool_add_request (ClientPool *pool, 
    ClientPool_on_request_done on_request_done, gpointer callback_data);

GList *client_pool_get_task_list (ClientPool *pool, GList *l_tasks, const gchar *pool_name);
#endif
