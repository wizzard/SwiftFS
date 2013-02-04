/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "hfs_file_operation.h"

/*{{{ struct */
struct _HfsFileOp {
    Application *app;
    ConfData *conf;

    gboolean released; // a simple version of ref counter.
    size_t current_size; // total bytes after read / write calls
    struct evbuffer *segment_buf; // current segment buffer
    size_t segment_count; // current count of segments uploaded / downloaded
};
/*}}}*/

#define FENTRY_LOG "fop"

HfsFileOp *hfs_fileop_create (Application *app)
{
    HfsFileOp *fop;

    fop = g_new0 (HfsFileOp, 1);
    fop->app = app;
    fop->conf = application_get_conf (app);
    fop->released = FALSE;
    fop->current_size = 0;
    fop->segment_buf = evbuffer_new ();
    fop->segment_count = 0;

    return fop;
}

void hfs_fileop_destroy (HfsFileOp *fop)
{
    evbuffer_free (fop->segment_buf);
    g_free (fop);
}

/*{{{ hfs_fileop_release*/


// got HTTPConnection object
// send either "manifest" or "segment"
static void hfs_fileop_release_on_http_client_cb (gpointer client, gpointer ctx)
{
    HttpConnection *con = (HttpConnection *) client;
    HfsFileOp *fop = (HfsFileOp *) ctx;
    gchar *req_path;
    gboolean res;

    LOG_debug (FENTRY_LOG, "[http_con: %p] Releasing fop, seg count: %zd", con, fop->segment_count);
    
    http_connection_acquire (con);

    // send .manifest file if there more than 1 segment uploaded
    if (fop->segment_count > 1) {
    
    // file size is less than filesystem.segment_size
    } else {

    }

    req_path = g_strdup_printf ("/%s", application_get_container_name (con->app));

    res = http_connection_make_request_to_storage_url (con, 
        req_path, "PUT", NULL,
        hfs_fileop_release_on_sent_cb,
        fop
    );
    
    g_free (req_path);

    if (!res) {
        LOG_err (, "Failed to create HTTP request !");
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
        LOG_err (FENTRY_LOG, "Failed to get HTTP client !");
        return;
    }
}
/*}}}*/

// Add data to file entry segment buffer
// if segment buffer exceeds MAX size then send segment buffer to server
// execute callback function when data either is sent or added to buffer
void hfs_fileop_write_buffer (HfsFileOp *fop,
    const char *buf, size_t buf_size, off_t off,
    HfsFileOp_on_buffer_written_cb on_buffer_written_cb, gpointer ctx)
{
    // XXX: allow only sequentially write
    // current written bytes should be always match offset
    if (fop->current_size != off) {
        LOG_err (FENTRY_LOG, "Write call with offset %"OFF_FMT" is not allowed !", off);
        on_buffer_written_cb (fop, ctx, FALSE, 0);
        return;
    }

    // XXX: add to CacheMng

    evbuffer_add (fop->segment_buf, buf, buf_size);
    fop->current_size += buf_size;
    
    // check if we need to flush segment buffer
    if (evbuffer_get_length (fop->segment_buf) >= conf_get_uint (fop->conf, "filesystem.segment_size")) {
        // XXX: encrypt
        // XXX: add task to ClientPool
    } else {
        // data is added to the current segment buffer
        on_buffer_written_cb (fop, ctx, TRUE, buf_size);
    }
}

// Send request to server to get segment buffer
void hfs_fileop_read_buffer (HfsFileOp *fop,
    size_t size, off_t off,
    HfsFileOp_on_buffer_read_cb on_buffer_read_cb, gpointer ctx)
{
    // XXX: check file in CacheMng
    // XXX: add task to ClientPool
}
