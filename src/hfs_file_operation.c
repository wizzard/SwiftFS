/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "hfs_file_operation.h"
#include "http_connection.h"

/*{{{ struct */
struct _HfsFileOp {
    Application *app;
    ConfData *conf;

    gchar *fname; //original file name with path

    gboolean released; // a simple version of ref counter.
    size_t current_size; // total bytes after read / write calls
    struct evbuffer *segment_buf; // current segment buffer
    size_t segment_count; // current count of segments uploaded / downloaded

    gboolean manifest_handled; // set TRUE if manifest file is downloaded / uploaded
};
/*}}}*/

#define FOP_LOG "fop"
#define SEGMENTS_DIR "segments"

HfsFileOp *hfs_fileop_create (Application *app, const gchar *fname)
{
    HfsFileOp *fop;

    fop = g_new0 (HfsFileOp, 1);
    fop->app = app;
    fop->conf = application_get_conf (app);
    fop->released = FALSE;
    fop->current_size = 0;
    fop->segment_buf = evbuffer_new ();
    fop->segment_count = 0;
    fop->manifest_handled = FALSE;
    fop->fname = g_strdup (fname);

    return fop;
}

void hfs_fileop_destroy (HfsFileOp *fop)
{
    evbuffer_free (fop->segment_buf);
    g_free (fop->fname);
    g_free (fop);
}

/*{{{ hfs_fileop_release*/

// either manifest of segment buffer is sent
static void hfs_fileop_release_on_sent_cb (HttpConnection *con, void *ctx, 
    const gchar *buf, size_t buf_len, 
    struct evkeyvalq *headers, gboolean success)
{   
    HfsFileOp *fop = (HfsFileOp *) ctx;
    
    // release HttpConnection
    http_connection_release (con);

    // at this point segment buffer must be sent
    if (evbuffer_get_length (fop->segment_buf) > 0) {
        LOG_err (FOP_LOG, "Segment buffer is not empty !");
    }
    
    // if manifest is handled - we are done
    if (fop->manifest_handled) {
        hfs_fileop_destroy (fop);
    
    // last segment is sent, but we need to send manifest - repeat
    } else {
        hfs_fileop_release (fop);
    }
}

// got HTTPConnection object
// send either "manifest" or "segment"
static void hfs_fileop_release_on_http_client_cb (gpointer client, gpointer ctx)
{
    HttpConnection *con = (HttpConnection *) client;
    HfsFileOp *fop = (HfsFileOp *) ctx;
    gchar *req_path = NULL;
    gboolean res;

    LOG_debug (FOP_LOG, "[http_con: %p] Releasing fop, seg count: %zd", con, fop->segment_count);
    
    http_connection_acquire (con);

    // if segment buffer is empty: either send manifest (for large file) or just create an empty file
    if (evbuffer_get_length (fop->segment_buf) ==  0) {
        // mark that a manifest file is handled (for small files - mark as handled as well)
        fop->manifest_handled = TRUE;

        // send manifest for a "large" file
        if (fop->segment_count > 0) {
            gchar *tmp;

            tmp = g_strdup_printf ("/%s/%s/%s", application_get_container_name (con->app), 
                fop->fname, SEGMENTS_DIR);
            http_connection_add_output_header (con, "X-Object-Manifest", tmp);
            g_free (tmp);

            req_path = g_strdup_printf ("/%s%s", application_get_container_name (con->app), fop->fname);
        // an empty file
        } else {
            // do nothing
            req_path = g_strdup_printf ("/%s%s", application_get_container_name (con->app), fop->fname);
        }

    // segment buffer contains data. Check if a file is "small" or "large"
    } else {
        
        // send segment
        if (fop->segment_count > 0) {
            // send segment buffer, then send manifest (if file is a large)
            req_path = g_strdup_printf ("/%s/%s%s/%zu", application_get_container_name (con->app), 
                fop->fname, SEGMENTS_DIR, fop->segment_count);
        
        // send a "small" file
        } else {
            req_path = g_strdup_printf ("/%s/%s", application_get_container_name (con->app), 
                fop->fname);
            // mark that a manifest file is handled (for small files - mark as handled as well)
            fop->manifest_handled = TRUE;

        }
    }

    // XXX: encryption

    res = http_connection_make_request_to_storage_url (con, 
        req_path, "PUT", fop->segment_buf,
        hfs_fileop_release_on_sent_cb,
        fop
    );

    // drain buffer
    evbuffer_drain (fop->segment_buf, -1);
    
    g_free (req_path);

    if (!res) {
        LOG_err (FOP_LOG, "Failed to create HTTP request !");
        http_connection_release (con);
        return;
    }
}

// file is released, finish all operations
void hfs_fileop_release (HfsFileOp *fop)
{
    fop->released = TRUE;

    // get HTTP connection to upload segment (for small file) or manifest (for large file)
    if (!client_pool_get_client (application_get_write_client_pool (fop->app), hfs_fileop_release_on_http_client_cb, fop)) {
        LOG_err (FOP_LOG, "Failed to get HTTP client !");
        return;
    }
}
/*}}}*/

/*{{{ hfs_fileop_write_buffer */

// got HTTPConnection object
// send "segment"
static void hfs_fileop_release_on_http_client_cb (gpointer client, gpointer ctx)
{
    HttpConnection *con = (HttpConnection *) client;
    HfsFileOp *fop = (HfsFileOp *) ctx;
    gchar *req_path = NULL;
    gboolean res;

    http_connection_acquire (con);

    // send segment buffer
    req_path = g_strdup_printf ("/%s/%s%s/%zu", application_get_container_name (con->app), 
        fop->fname, SEGMENTS_DIR, fop->segment_count);

    fop->segment_count ++;

    // XXX: encryption

    res = http_connection_make_request_to_storage_url (con, 
        req_path, "PUT", fop->segment_buf,
        hfs_fileop_release_on_sent_cb,
        fop
    );

    // drain buffer
    evbuffer_drain (fop->segment_buf, -1);
    
    g_free (req_path);

    if (!res) {
        LOG_err (FOP_LOG, "Failed to create HTTP request !");
        http_connection_release (con);
        return;
    }
}

// Add data to segment buffer
// if segment buffer exceeds MAX size then send segment buffer to server
// execute callback function when data either is sent or added to buffer
void hfs_fileop_write_buffer (HfsFileOp *fop,
    const char *buf, size_t buf_size, off_t off,
    HfsFileOp_on_buffer_written_cb on_buffer_written_cb, gpointer ctx)
{
    // XXX: allow only sequentially write
    // current written bytes should be always match offset
    if (fop->current_size != off) {
        LOG_err (FOP_LOG, "Write call with offset %"OFF_FMT" is not allowed !", off);
        on_buffer_written_cb (fop, ctx, FALSE, 0);
        return;
    }

    // XXX: add to CacheMng

    evbuffer_add (fop->segment_buf, buf, buf_size);
    fop->current_size += buf_size;
    
    // check if we need to flush segment buffer
    if (evbuffer_get_length (fop->segment_buf) >= conf_get_uint (fop->conf, "filesystem.segment_size")) {
        
        // get HTTP connection to upload segment (for small file) or manifest (for large file)
        if (!client_pool_get_client (application_get_write_client_pool (fop->app), hfs_fileop_write_on_http_client_cb, fop)) {
            LOG_err (FOP_LOG, "Failed to get HTTP client !");
            return;
        }

    } else {
        // data is added to the current segment buffer
        on_buffer_written_cb (fop, ctx, TRUE, buf_size);
    }
}
/*}}}*/

// Send request to server to get segment buffer
void hfs_fileop_read_buffer (HfsFileOp *fop,
    size_t size, off_t off,
    HfsFileOp_on_buffer_read_cb on_buffer_read_cb, gpointer ctx)
{
    // XXX: check file in CacheMng
    // XXX: add task to ClientPool
}
