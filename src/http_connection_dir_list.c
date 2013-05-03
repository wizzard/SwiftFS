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
#include "dir_tree.h"

typedef struct {
    Application *app;
    DirTree *dir_tree;
    HttpConnection *con;
    gchar *dir_path;
    fuse_ino_t ino;
    gint max_keys;
    HttpConnection_directory_listing_callback directory_listing_callback;
    gpointer callback_data;
} DirListRequest;

#define CON_DIR_LOG "con_dir"

// parses  directory XML 
// reutrns TRUE if ok
static gboolean parse_dir_xml (DirListRequest *dir_list, const char *xml, size_t xml_len)
{
    xmlNode *onode = NULL, *anode = NULL, *text_node = NULL;
    xmlParserCtxtPtr xmlctx;
    //struct tm last_modified;
    gchar *name;
    time_t last_modified = time (NULL);
    xmlNode *root_element;

    xmlctx = xmlCreatePushParserCtxt (NULL, NULL, "", 0, NULL);
    xmlParseChunk (xmlctx, (char *)xml, xml_len, 0);
    xmlParseChunk (xmlctx, "", 0, 1);

    xmlParseChunk (xmlctx, "", 0, 1);

    if (!xmlctx->wellFormed) {
        LOG_err (CON_DIR_LOG, "Failed to parse directory !");
        return FALSE;
    }

  //  LOG_debug (CON_DIR_LOG, "DIR LIST: =============\n%s\n=============", xml);

    root_element = xmlDocGetRootElement (xmlctx->myDoc);
    for (onode = root_element->children; onode; onode = onode->next) {
        gboolean is_object;
        gboolean is_subdir;

        if (onode->type != XML_ELEMENT_NODE) continue;

        is_object = !strcasecmp((const char *)onode->name, "object");
        is_subdir = !strcasecmp((const char *)onode->name, "subdir");
        
        // file
        if (is_object) {
            off_t size = 0;
            name = NULL;

            for (anode = onode->children; anode; anode = anode->next) {
                char *content = NULL;
                
                for (text_node = anode->children; text_node; text_node = text_node->next) {
                    if (text_node->type == XML_TEXT_NODE)
                      content = (char *)text_node->content;
                }

                if (!strcasecmp((const char *)anode->name, "name") && content) {
                    name = g_path_get_basename (content);
                }

                if (!strcasecmp((const char *)anode->name, "bytes") && content)
                    size = strtoll (content, NULL, 10);

                if (!strcasecmp((const char *)anode->name, "content_type") && content) {
                }

                if (!strcasecmp((const char *)anode->name, "last_modified") && content) {
                    struct tm tmp = {0};
                    strptime (content, "%FT%T", &tmp);
                    last_modified = mktime (&tmp);
                }
            }

            if (name) {
                LOG_debug (CON_DIR_LOG, ">> got file entry: %s %zu", name, size);
                dir_tree_update_entry (dir_list->dir_tree, dir_list->dir_path, DET_file, dir_list->ino, name, size, last_modified);
                g_free (name);
            }

        // directory
        } else if (is_subdir) {
            //char * slash;
            name = NULL;

            for (anode = onode->children; anode; anode = anode->next) {
                char *content = NULL;
                
                for (text_node = anode->children; text_node; text_node = text_node->next) {
                    if (text_node->type == XML_TEXT_NODE)
                      content = (char *)text_node->content;
                }

                if (!strcasecmp((const char *)anode->name, "name") && content) {
                    name = g_path_get_basename (content);
                }

            }

            if (name) {
                LOG_debug (CON_DIR_LOG, ">> got dir entry: %s", name);
                dir_tree_update_entry (dir_list->dir_tree, dir_list->dir_path, DET_dir, dir_list->ino, name, 0, last_modified);
                g_free (name);
            }
        } else {
            LOG_debug (CON_DIR_LOG, "unknown element: %s", onode->name);
        }
    }

    xmlFreeDoc (xmlctx->myDoc);
    xmlFreeParserCtxt (xmlctx);

    return TRUE;
}

static void dir_req_free (DirListRequest *dir_req)
{
    g_free (dir_req->dir_path);
    g_free (dir_req);
}

// error, return error to fuse 
static void http_connection_on_directory_listing_error (HttpConnection *con, void *ctx)
{
    DirListRequest *dir_req = (DirListRequest *) ctx;
    
    LOG_err (CON_DIR_LOG, "Failed to retrieve directory listing !");

    // we are done, stop updating
    dir_tree_stop_update (dir_req->dir_tree, dir_req->ino);
    
    if (dir_req->directory_listing_callback)
        dir_req->directory_listing_callback (dir_req->callback_data, FALSE);

    // release HTTP client
    http_connection_release (con);
    
    dir_req_free (dir_req);
}

// Directory read callback function
static void http_connection_on_directory_listing_data (HttpConnection *con, void *ctx, 
    const gchar *buf, size_t buf_len, 
    G_GNUC_UNUSED struct evkeyvalq *headers, gboolean success)
{   
    DirListRequest *dir_req = (DirListRequest *) ctx;
    const gchar *next_marker = FALSE;
    gchar *req_path;
    gboolean res;
   
    if (!buf_len || !success) {
        LOG_debug (CON_DIR_LOG, "Directory buffer is empty !");
        //http_connection_on_directory_listing_error (con, (void *) dir_req);
        if (dir_req->directory_listing_callback)
            dir_req->directory_listing_callback (dir_req->callback_data, TRUE);
        
        // we are done, stop updating
        dir_tree_stop_update (dir_req->dir_tree, dir_req->ino);
        
        // release HTTP client
        http_connection_release (con);

        dir_req_free (dir_req);
        
        return;
    }
   
    if (!parse_dir_xml (dir_req, buf, buf_len)) {

        LOG_err (CON_DIR_LOG, "Failed to parse directory data !");
        
        if (dir_req->directory_listing_callback)
            dir_req->directory_listing_callback (dir_req->callback_data, TRUE);

        // we are done, stop updating
        dir_tree_stop_update (dir_req->dir_tree, dir_req->ino);
        
        // release HTTP client
        http_connection_release (con);

        dir_req_free (dir_req);
        return;
    }

        // check if we need to get more data
    if (!next_marker) {
        LOG_debug (CON_DIR_LOG, "DONE !!");
        
        if (dir_req->directory_listing_callback)
            dir_req->directory_listing_callback (dir_req->callback_data, TRUE);
        
        // we are done, stop updating
        dir_tree_stop_update (dir_req->dir_tree, dir_req->ino);
        
        // release HTTP client
        http_connection_release (con);

        dir_req_free (dir_req);
        return;
    }

    // execute HTTP request
    req_path = g_strdup_printf ("/%s?delimiter=/&prefix=%s&max-keys=%d&marker=%s&format=xml", 
        application_get_container_name (con->app), dir_req->dir_path, dir_req->max_keys, next_marker);
    
    res = http_connection_make_request_to_storage_url (dir_req->con, 
        req_path, "GET", NULL,
        http_connection_on_directory_listing_data,
        dir_req
    );
    g_free (req_path);

    if (!res) {
        LOG_err (CON_DIR_LOG, "Failed to create HTTP request !");
        http_connection_on_directory_listing_error (con, (void *) dir_req);
        return;
    }
}

// create DirListRequest
gboolean http_connection_get_directory_listing (HttpConnection *con, const gchar *dir_path, fuse_ino_t ino,
    HttpConnection_directory_listing_callback directory_listing_callback, gpointer callback_data)
{
    DirListRequest *dir_req;
    gchar *req_path;
    gboolean res;

    LOG_debug (CON_DIR_LOG, "Getting directory listing for: %s", dir_path);

    dir_req = g_new0 (DirListRequest, 1);
    dir_req->con = con;
    dir_req->app = http_connection_get_app (con);
    dir_req->dir_tree = application_get_dir_tree (dir_req->app);
    dir_req->ino = ino;
    // XXX: settings
    dir_req->max_keys = 1000;
    dir_req->directory_listing_callback = directory_listing_callback;
    dir_req->callback_data = callback_data;

    // acquire HTTP client
    http_connection_acquire (con);
    
    // inform that we started to update the directory
    dir_tree_start_update (dir_req->dir_tree, dir_path);
    
    //XXX: fix dir_path
    if (!strcmp (dir_path, "")) {
        dir_req->dir_path = g_strdup ("");
    } else {
        dir_req->dir_path = g_strdup_printf ("%s/", dir_path);
    }
   
    req_path = g_strdup_printf ("/%s?delimiter=/&prefix=%s&max-keys=%d&format=xml", 
        application_get_container_name (con->app), dir_req->dir_path, dir_req->max_keys);

    res = http_connection_make_request_to_storage_url (con, 
        req_path, "GET", NULL,
        http_connection_on_directory_listing_data,
        dir_req
    );
    
    g_free (req_path);

    if (!res) {
        LOG_err (CON_DIR_LOG, "Failed to create HTTP request !");
        http_connection_on_directory_listing_error (con, (void *) dir_req);
        dir_req_free (dir_req);
        return FALSE;
    }

    return TRUE;
}
