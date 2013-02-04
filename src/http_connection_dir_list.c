/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "http_connection.h"
#include "dir_tree.h"

typedef struct {
    Application *app;
    DirTree *dir_tree;
    HttpConnection *con;
    gchar *resource_path;
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
    gchar *name = NULL;
    time_t last_modified = time (NULL);

    xmlctx = xmlCreatePushParserCtxt (NULL, NULL, "", 0, NULL);
    xmlParseChunk (xmlctx, (char *)xml, xml_len, 0);
    xmlParseChunk (xmlctx, "", 0, 1);

    xmlParseChunk (xmlctx, "", 0, 1);

    if (!xmlctx->wellFormed) {
        LOG_err (CON_DIR_LOG, "Failed to parse directory !");
        return FALSE;
    }

  //  LOG_debug (CON_DIR_LOG, "DIR LIST: =============\n%s\n=============", xml);

    xmlNode *root_element = xmlDocGetRootElement (xmlctx->myDoc);
    for (onode = root_element->children; onode; onode = onode->next) {
        if (onode->type != XML_ELEMENT_NODE) continue;

        char is_object = !strcasecmp((const char *)onode->name, "object");
        char is_container = !strcasecmp((const char *)onode->name, "container");
        char is_subdir = !strcasecmp((const char *)onode->name, "subdir");
        
        // file
        if (is_object) {
            name = NULL;
            off_t size = 0;

            for (anode = onode->children; anode; anode = anode->next) {
                char *content = "<?!?>";
                
                for (text_node = anode->children; text_node; text_node = text_node->next)
                    if (text_node->type == XML_TEXT_NODE)
                      content = (char *)text_node->content;

                if (!strcasecmp((const char *)anode->name, "name")) {
                    name = strdup (basename (content));
                }

                if (!strcasecmp((const char *)anode->name, "bytes"))
                    size = strtoll(content, NULL, 10);

                if (!strcasecmp((const char *)anode->name, "content_type")) {
                }

                if (!strcasecmp((const char *)anode->name, "last_modified")) {
                    struct tm tmp;
                    strptime (content, "%FT%T", &tmp);
                    last_modified = mktime(&tmp);
                }
            }
            
            //LOG_debug (CON_DIR_LOG, ">> got file entry: %s", name);
            dir_tree_update_entry (dir_list->dir_tree, dir_list->dir_path, DET_file, dir_list->ino, name, size, last_modified);

        // directory
        } else if (is_subdir) {
            char * slash;
            name = NULL;

            for (anode = onode->children; anode; anode = anode->next) {
                char *content = "<?!?>";
                
                for (text_node = anode->children; text_node; text_node = text_node->next)
                    if (text_node->type == XML_TEXT_NODE)
                      content = (char *)text_node->content;
                if (!strcasecmp((const char *)anode->name, "name")) {
                    name = g_strdup (content);
                    // Remove trailing slash
                    slash = strrchr (name, '/');
                    if (slash && (0 == *(slash + 1)))
                        *slash = 0;
                    name = name + 1;
                }
            }

            //LOG_debug (CON_DIR_LOG, ">> got dir entry: %s", name);
            dir_tree_update_entry (dir_list->dir_tree, dir_list->dir_path, DET_dir, dir_list->ino, name, 0, last_modified);
        } else {
            LOG_debug (CON_DIR_LOG, "unknown element: %s", onode->name);
        }
    }

    xmlFreeDoc (xmlctx->myDoc);
    xmlFreeParserCtxt (xmlctx);

    return TRUE;
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
    
    g_free (dir_req);
}

// Directory read callback function
static void http_connection_on_directory_listing_data (HttpConnection *con, void *ctx, 
    const gchar *buf, size_t buf_len, 
    struct evkeyvalq *headers, gboolean success)
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

        g_free (dir_req);
        
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

        g_free (dir_req);
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

        g_free (dir_req);
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
    if (!strcmp (dir_path, "/")) {
        dir_req->dir_path = g_strdup ("/");
        dir_req->resource_path = g_strdup_printf ("/");
    } else {
        dir_req->dir_path = g_strdup_printf ("/%s/", dir_path);
        dir_req->dir_path = dir_req->dir_path + 1;
        dir_req->resource_path = g_strdup_printf ("/");
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

        return FALSE;
    }

    return TRUE;
}
