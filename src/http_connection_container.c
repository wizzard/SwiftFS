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

#define CON_CONT "con_cont"

typedef struct {
    gpointer ctx;
    HttpConnection_container_meta_cb container_meta_cb;
} ContainerMeta;

// Directory read callback function
static void http_connection_on_container_meta_cb (HttpConnection *con, void *ctx, 
    G_GNUC_UNUSED const gchar *buf, G_GNUC_UNUSED size_t buf_len, 
    G_GNUC_UNUSED struct evkeyvalq *headers, gboolean success)
{   
    ContainerMeta *meta = (ContainerMeta *) ctx;

    http_connection_release (con);

    if (!success)
        LOG_err (CON_CONT, "Failed to get container info !");
    
    meta->container_meta_cb (meta->ctx, success);

    g_free (meta);
}

void http_connection_get_container_meta (HttpConnection *con,
    HttpConnection_container_meta_cb container_meta_cb, gpointer ctx)
{
    gchar *req_path;
    gboolean res;
    ContainerMeta *meta;

    LOG_debug (CON_CONT, "Getting container meta for: %s", application_get_container_name (con->app));

    // acquire HTTP client
    http_connection_acquire (con);

    meta = g_new0 (ContainerMeta, 1);
    meta->ctx = ctx;
    meta->container_meta_cb = container_meta_cb;
   
    req_path = g_strdup_printf ("/%s", application_get_container_name (con->app));

    res = http_connection_make_request_to_storage_url (con, 
        req_path, "HEAD", NULL,
        http_connection_on_container_meta_cb,
        meta
    );
    
    g_free (req_path);

    if (!res) {
        LOG_err (CON_CONT, "Failed to create HTTP request !");
        container_meta_cb (ctx, FALSE);
        http_connection_release (con);
        return;
    }
}
