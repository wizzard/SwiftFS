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

    // used by reading
    size_t segment_id; // id of the segment (which is in segment_buf)
    size_t segment_pos; // position in file
};
/*}}}*/

#define FOP_LOG "fop"

/*{{{ create / destroy */

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
    fop->segment_id = 0;

    return fop;
}

void hfs_fileop_destroy (HfsFileOp *fop)
{
    evbuffer_free (fop->segment_buf);
    g_free (fop->fname);
    g_free (fop);
}
/*}}}*/

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
            gchar s[20];

            g_snprintf (s, sizeof (s), "%zu", fop->current_size);

            tmp = g_strdup_printf ("%s/%s/", application_get_container_name (con->app), 
                fop->fname);
            http_connection_add_output_header (con, "X-Object-Manifest", tmp);
            g_free (tmp);

            // add Meta header with object's size
            http_connection_add_output_header (con, "X-Object-Meta-Size", s);

            req_path = g_strdup_printf ("/%s/%s", application_get_container_name (con->app), fop->fname);
        // an empty file
        } else {
            // do nothing
            req_path = g_strdup_printf ("/%s/%s", application_get_container_name (con->app), fop->fname);
        }

    // segment buffer contains data. Check if a file is "small" or "large"
    } else {
        
        // send segment
        if (fop->segment_count > 0) {
            // send segment buffer, then send manifest (if file is a large)
            req_path = g_strdup_printf ("/%s/%s/%zu", application_get_container_name (con->app), 
                fop->fname, fop->segment_count);
        
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

typedef struct {
    HfsFileOp *fop;
    HfsFileOp_on_buffer_written_cb on_buffer_written_cb;
    size_t buf_size;
    gpointer ctx;
} FileOpWriteData;

static void hfs_fileop_write_on_http_client_cb (gpointer client, gpointer ctx);

// segment buffer is sent, check if there is more data left in segment buffer
static void hfs_fileop_write_on_sent_cb (HttpConnection *con, void *ctx, 
    const gchar *buf, size_t buf_len, 
    struct evkeyvalq *headers, gboolean success)
{
    FileOpWriteData *write_data = (FileOpWriteData *) ctx;
    HfsFileOp *fop = NULL;
    
    // release HttpConnection
    http_connection_release (con);

    if (!success) {
        LOG_err (FOP_LOG, "Failed to upload segment !");

        write_data->on_buffer_written_cb (write_data->fop, write_data->ctx, FALSE, 0);
        g_free (write_data);
        return;
    }

    fop = write_data->fop;

    // check if we need to flush segment buffer
    if (evbuffer_get_length (fop->segment_buf) >= conf_get_uint (fop->conf, "filesystem.segment_size")) {

        // get HTTP connection to upload segment (for small file) or manifest (for large file)
        if (!client_pool_get_client (application_get_write_client_pool (fop->app), hfs_fileop_write_on_http_client_cb, write_data)) {
            LOG_err (FOP_LOG, "Failed to get HTTP client !");
            return;
        }
    
    // ok, we are done
    } else {
        // data is added to the current segment buffer
        write_data->on_buffer_written_cb (write_data->fop, write_data->ctx, TRUE, write_data->buf_size);
        g_free (write_data);
    }

}

// got HTTPConnection object
// send "segment"
static void hfs_fileop_write_on_http_client_cb (gpointer client, gpointer ctx)
{
    HttpConnection *con = (HttpConnection *) client;
    FileOpWriteData *write_data = (FileOpWriteData *) ctx;
    HfsFileOp *fop = NULL;
    gchar *req_path = NULL;
    gboolean res;
    struct evbuffer *seg;
    unsigned char *buf;

    http_connection_acquire (con);

    fop = write_data->fop;

    // send segment buffer
    req_path = g_strdup_printf ("/%s/%s/%zu", application_get_container_name (con->app), 
        fop->fname, fop->segment_count);

    fop->segment_count ++;
    
    // get segment_size from the segment buffer
    buf = evbuffer_pullup (fop->segment_buf, -1);
    seg = evbuffer_new ();
    evbuffer_add_reference (seg, 
        buf, conf_get_uint (fop->conf, "filesystem.segment_size"),
        NULL, NULL
    );

    // XXX: encryption

    res = http_connection_make_request_to_storage_url (con, 
        req_path, "PUT", seg,
        hfs_fileop_write_on_sent_cb,
        write_data
    );
    evbuffer_free (seg);

    // remove segment_size bytes from segment buffer
    evbuffer_drain (fop->segment_buf, conf_get_uint (fop->conf, "filesystem.segment_size"));
    
    g_free (req_path);

    if (!res) {
        LOG_err (FOP_LOG, "Failed to create HTTP request !");
        http_connection_release (con);
        g_free (write_data);
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
        FileOpWriteData *write_data;
        
        write_data = g_new0 (FileOpWriteData, 1);
        write_data->fop = fop;
        write_data->on_buffer_written_cb = on_buffer_written_cb;
        write_data->ctx = ctx;
        write_data->buf_size = buf_size;

        // get HTTP connection to upload segment (for small file) or manifest (for large file)
        if (!client_pool_get_client (application_get_write_client_pool (fop->app), hfs_fileop_write_on_http_client_cb, write_data)) {
            LOG_err (FOP_LOG, "Failed to get HTTP client !");
            return;
        }

    } else {
        // data is added to the current segment buffer
        on_buffer_written_cb (fop, ctx, TRUE, buf_size);
    }
}
/*}}}*/

typedef struct {
    HfsFileOp *fop;
    HfsFileOp_on_buffer_read_cb on_buffer_read_cb;
    gpointer ctx;

    struct evbuffer *read_buf; // requested read buffer
    size_t size;
    off_t off;

} FileOpReadData;

// Send request to server to get segment buffer
void hfs_fileop_read_buffer (HfsFileOp *fop,
    size_t size, off_t off,
    HfsFileOp_on_buffer_read_cb on_buffer_read_cb, gpointer ctx)
{
    size_t segment_start_id;
    size_t segment_len;
    unsigned char *data_out;
    size_t data_len;

    //XXX: check cache
    
    // get the first segmentId
    segment_start_id = off / conf_get_uint (fop->conf, "filesystem.segment_size");
    segment_len = evbuffer_get_length (fop->segment_buf);

    // check that we have this segment downloaded 
    if (fop->segment_id == segment_start_id && segment_len > 0) {
        off_t start_pos;
        size_t current_len;
        
        // get the offset in the current segment
        start_pos = off - segment_start_id * conf_get_uint (fop->conf, "filesystem.segment_size");
        // get length in current segment buffer
        if (segment_len <= start_pos + size)
            current_len = segment_len - start_pos;
        else
            current_len = size;

        evbuffer_copyout_from (fop->segment_buf, &pos, data_out, data_len);
        evbuffer_add (read_buf, data_out, data_len);


    }

}
