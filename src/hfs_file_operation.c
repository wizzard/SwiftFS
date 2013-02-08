/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "hfs_file_operation.h"
#include "http_connection.h"
#include "cache_mng.h"
#include "hfs_encryption.h"

/*{{{ struct */
struct _HfsFileOp {
    Application *app;
    ConfData *conf;

    gchar *fname; //original file name with path
    size_t segment_size;
    gboolean write_called; // set TRUE if write operations were called (need to upload manifest)

    gboolean released; // a simple version of ref counter.
    size_t current_size; // total bytes after read / write calls
    struct evbuffer *segment_buf; // current segment buffer
    size_t segment_count; // current count of segments uploaded / downloaded

    gboolean manifest_handled; // set TRUE if manifest file is downloaded / uploaded

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
    fop->segment_size = conf_get_uint (fop->conf, "filesystem.segment_size");
    fop->released = FALSE;
    fop->current_size = 0;
    fop->segment_buf = evbuffer_new ();
    fop->segment_count = 0;
    fop->manifest_handled = FALSE;
    fop->fname = g_strdup (fname);
    fop->write_called = FALSE;

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

            g_snprintf (s, sizeof (s), "%zu", fop->segment_size);
            http_connection_add_output_header (con, "X-Object-Meta-Segment-Size", s);

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

    if (fop->write_called) {
        // get HTTP connection to upload segment (for small file) or manifest (for large file)
        if (!client_pool_get_client (application_get_write_client_pool (fop->app), hfs_fileop_release_on_http_client_cb, fop)) {
            LOG_err (FOP_LOG, "Failed to get HTTP client !");
            return;
        }
    } else {
        hfs_fileop_destroy (fop);
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

static void hfs_fileop_write_on_con_cb (gpointer client, gpointer ctx);

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
    if (evbuffer_get_length (fop->segment_buf) >= fop->segment_size) {

        // get HTTP connection to upload segment (for small file) or manifest (for large file)
        if (!client_pool_get_client (application_get_write_client_pool (fop->app), hfs_fileop_write_on_con_cb, write_data)) {
            LOG_err (FOP_LOG, "Failed to get HTTP client !");
            write_data->on_buffer_written_cb (write_data->fop, write_data->ctx, FALSE, 0);
            g_free (write_data);
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
static void hfs_fileop_write_on_con_cb (gpointer client, gpointer ctx)
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
    seg = evbuffer_new ();
    // copy only fop->segment_size bytes
    /*
    evbuffer_remove_buffer (fop->segment_buf, 
        seg, fop->segment_size
    );
    */
    /*
    buf = evbuffer_pullup (fop->segment_buf, -1);
    evbuffer_add_reference (seg, 
        buf, fop->segment_size,
        NULL, NULL
    );
    */
    evbuffer_remove_buffer (fop->segment_buf, 
        seg, fop->segment_size
    );

    // encryption
    /*
    if (conf_get_boolean (fop->conf, "encryption.enabled")) {
        unsigned char *in_buf;
        unsigned char *out_buf;
        int len;

        in_buf = evbuffer_pullup (seg, -1);
        len = evbuffer_get_length (seg);
        out_buf = hfs_encryption_encrypt (application_get_encryption (con->app), in_buf, &len);
        evbuffer_drain (seg, -1);
        evbuffer_add (seg, out_buf, len);
        g_free (out_buf);

        LOG_debug (FOP_LOG, "Encrypted: outlen: %zu", len);
    }
    */

    res = http_connection_make_request_to_storage_url (con, 
        req_path, "PUT", seg,
        hfs_fileop_write_on_sent_cb,
        write_data
    );
    evbuffer_free (seg);

    // remove segment_size bytes from segment buffer
    //evbuffer_drain (fop->segment_buf, fop->segment_size);
    
    g_free (req_path);

    if (!res) {
        LOG_err (FOP_LOG, "Failed to create HTTP request !");
        http_connection_release (con);
        write_data->on_buffer_written_cb (fop, write_data->ctx, FALSE, 0);
        g_free (write_data);
        return;
    }
}

// Add data to segment buffer
// if segment buffer exceeds MAX size then send segment buffer to server
// execute callback function when data either is sent or added to buffer
void hfs_fileop_write_buffer (HfsFileOp *fop,
    const char *buf, size_t buf_size, off_t off, fuse_ino_t ino,
    HfsFileOp_on_buffer_written_cb on_buffer_written_cb, gpointer ctx)
{

    // XXX: allow only sequentially write
    // current written bytes should be always match offset
    if (fop->current_size != off) {
        LOG_err (FOP_LOG, "Write call with offset %"OFF_FMT" is not allowed !", off);
        on_buffer_written_cb (fop, ctx, FALSE, 0);
        return;
    }

    // CacheMng
    cache_mng_store_file_data (application_get_cache_mng (fop->app), 
        ino, buf_size, off, (unsigned char *) buf);

    evbuffer_add (fop->segment_buf, buf, buf_size);
    fop->current_size += buf_size;
    fop->write_called = TRUE;
    
    // check if we need to flush segment buffer
    if (evbuffer_get_length (fop->segment_buf) >= fop->segment_size) {
        FileOpWriteData *write_data;
        
        write_data = g_new0 (FileOpWriteData, 1);
        write_data->fop = fop;
        write_data->on_buffer_written_cb = on_buffer_written_cb;
        write_data->ctx = ctx;
        write_data->buf_size = buf_size;

        // get HTTP connection to upload segment (for small file) or manifest (for large file)
        if (!client_pool_get_client (application_get_write_client_pool (fop->app), hfs_fileop_write_on_con_cb, write_data)) {
            LOG_err (FOP_LOG, "Failed to get HTTP client !");
            on_buffer_written_cb (fop, ctx, FALSE, 0);
            return;
        }

    } else {
        // data is added to the current segment buffer
        on_buffer_written_cb (fop, ctx, TRUE, buf_size);
    }
}
/*}}}*/

/*{{{ hfs_fileop_read_buffer*/

typedef struct {
    HfsFileOp *fop;
    HfsFileOp_on_buffer_read_cb on_buffer_read_cb;
    gpointer ctx;

    struct evbuffer *read_buf; // requested read buffer
    size_t size_left;
    off_t current_off;
    size_t req_size; // to verify
    off_t req_off;
    size_t segment_size; // updated segment size

    // used by reading
    size_t segment_id; // id of the segment (which is in segment_buf)
    size_t segment_pos; // position in file

    fuse_ino_t ino;

    struct evbuffer *segment_buf; // current segment buffer

    gboolean small_file; // send HEAD and then GET for a full file
} FileOpReadData;

static void hfs_fileop_read_get_buffer (FileOpReadData *read_data);

// segment buffer is retrieved
static void hfs_fileop_read_on_read_cb (HttpConnection *con, void *ctx, 
    const gchar *buf, size_t buf_len, 
    struct evkeyvalq *headers, gboolean success)
{
    FileOpReadData *read_data = (FileOpReadData *) ctx;
    HfsFileOp *fop = read_data->fop;
    gboolean free_buf = FALSE;
    unsigned char *out_buf;
    int out_len;
    
    LOG_debug (FOP_LOG, "Got %zu bytes for segment: %zu", buf_len, read_data->segment_id);

    // release HttpConnection
    http_connection_release (con);

    if (!success) {
        LOG_err (FOP_LOG, "Failed to retrieve segment !");
        read_data->on_buffer_read_cb (read_data->ctx, FALSE, NULL, 0);
        evbuffer_free (read_data->read_buf);
        evbuffer_free (read_data->segment_buf);
        g_free (read_data);
        return;
    }

    //XXX: MD5
    if (conf_get_boolean (fop->conf, "filesystem.md5_enabled")) {
        const char *etag_header;

        etag_header = evhttp_find_header (headers, "Etag");
        if (etag_header) {
            gchar *md5_sum;
            md5_sum = get_md5_sum (buf, buf_len);
            if (strcmp (etag_header, md5_sum) != 0) {
                LOG_err (FOP_LOG, "Segment's MD5 sum doesn't match MD5 of received content !");
                read_data->on_buffer_read_cb (read_data->ctx, FALSE, NULL, 0);
                evbuffer_free (read_data->read_buf);
                evbuffer_free (read_data->segment_buf);
                g_free (read_data);
            }  
            g_free (md5_sum);
        }
    }
    
    //decrypt
    if (conf_get_boolean (fop->conf, "encryption.enabled")) {
        out_len = buf_len;
        out_buf = hfs_encryption_decrypt (application_get_encryption (con->app), (unsigned char *)buf, &out_len);
        free_buf = TRUE;
        LOG_debug (FOP_LOG, "Decrypted, len: %zu inlen: %zd", out_len, buf_len);
    } else {
        out_buf = buf;
        out_len = buf_len;
    }

    
    cache_mng_store_file_data (application_get_cache_mng (fop->app), 
        read_data->ino, out_len, read_data->segment_size * read_data->segment_id, (unsigned char *) out_buf);

    // a full file is received
    if (read_data->small_file) {
        // done 
        read_data->on_buffer_read_cb (read_data->ctx, TRUE, (char *)out_buf, out_len);
        evbuffer_free (read_data->read_buf);
        evbuffer_free (read_data->segment_buf);
        g_free (read_data);
    } else {
        // add buf to segment
        evbuffer_add (read_data->segment_buf, out_buf, out_len);
        hfs_fileop_read_get_buffer (read_data);
    }

    if (free_buf)
        g_free (out_buf);
}

// got HTTPConnection object
// retrieve "segment"
static void hfs_fileop_read_on_con_cb (gpointer client, gpointer ctx)
{
    HttpConnection *con = (HttpConnection *) client;
    FileOpReadData *read_data = (FileOpReadData *) ctx;
    HfsFileOp *fop = NULL;
    gchar *req_path = NULL;
    gboolean res;

    http_connection_acquire (con);

    fop = read_data->fop;

    // get full file
    if (read_data->small_file) 
        req_path = g_strdup_printf ("/%s/%s", application_get_container_name (con->app), 
            fop->fname);
    // get segment
    else        
        req_path = g_strdup_printf ("/%s/%s/%zu", application_get_container_name (con->app), 
            fop->fname, read_data->segment_id);

    res = http_connection_make_request_to_storage_url (con, 
        req_path, "GET", NULL,
        hfs_fileop_read_on_read_cb,
        read_data
    );

    g_free (req_path);

    if (!res) {
        LOG_err (FOP_LOG, "Failed to create HTTP request !");
        http_connection_release (con);
        read_data->on_buffer_read_cb (read_data->ctx, FALSE, NULL, 0);
        evbuffer_free (read_data->read_buf);
        evbuffer_free (read_data->segment_buf);
        g_free (read_data);
        return;
    }
}

// check if current segment buffer contains requested buffer
static void hfs_fileop_read_get_buffer (FileOpReadData *read_data)
{
    HfsFileOp *fop = read_data->fop;
    off_t segment_start_id;
    size_t segment_len;
    unsigned char *buf;
    off_t start_pos;
    size_t len;

    // get segmentID of the beginning
    segment_start_id = read_data->current_off / read_data->segment_size;
    // current segment buf length
    segment_len = evbuffer_get_length (read_data->segment_buf);

    LOG_debug (FOP_LOG, "current segment: %zu, segment len: %zu,  requested segment: %zu, req size: %zu, got so far: %zu of %zu, current off: %zu",
        read_data->segment_id, segment_len, segment_start_id, read_data->size_left, evbuffer_get_length (read_data->read_buf), read_data->req_size,
        read_data->current_off);

    LOG_debug (FOP_LOG, "Expected seg size: %zu, actual: %zu", read_data->segment_size, evbuffer_get_length (read_data->segment_buf));

    // retrieve from cache
    buf = cache_mng_retr_file_data (application_get_cache_mng (fop->app), 
        read_data->ino, read_data->size_left, read_data->current_off);
    if (buf) {
        // empty buffer
        evbuffer_drain (read_data->segment_buf, -1);

        read_data->on_buffer_read_cb (read_data->ctx, TRUE, (char *)buf, read_data->size_left);
        g_free (buf);

        evbuffer_free (read_data->read_buf);
        evbuffer_free (read_data->segment_buf);
        g_free (read_data);

        return;
    }

    // current segment buffer has different ID or empty
    if (segment_start_id != read_data->segment_id || !segment_len) {
        // empty buffer
        evbuffer_drain (read_data->segment_buf, -1);

        // set segmentID
        read_data->segment_id = segment_start_id;

        // get HTTP connection to download segment 
        if (!client_pool_get_client (application_get_read_client_pool (fop->app), hfs_fileop_read_on_con_cb, read_data)) {
            LOG_err (FOP_LOG, "Failed to get HTTP client !");

            read_data->on_buffer_read_cb (read_data->ctx, FALSE, NULL, 0);
            // free
            evbuffer_free (read_data->read_buf);
            evbuffer_free (read_data->segment_buf);
            g_free (read_data);
            return;
        }

        return;
    }

    // we have the right segment buffer
    buf = evbuffer_pullup (read_data->segment_buf, -1);
    start_pos = read_data->current_off - (read_data->segment_size * segment_start_id);
    len = read_data->segment_size - start_pos;
    if (read_data->size_left <= len)
        len = read_data->size_left;

    LOG_debug (FOP_LOG, "segment_buf size: %zu,  start_pos: %zu   len: %zu",  evbuffer_get_length (read_data->segment_buf), start_pos, len);

    evbuffer_add (read_data->read_buf, buf + start_pos, len);

    // update
    read_data->current_off = read_data->current_off + len;
    read_data->size_left = read_data->size_left - len;

    LOG_debug (FOP_LOG, "start_pos: %zu len: %zu current_off: %zu size_left: %zu", start_pos, len, read_data->current_off, read_data->size_left);

    // check if buffer is filled
    if (!read_data->size_left) {
        // verify
        if (evbuffer_get_length (read_data->read_buf) != read_data->req_size) {
            LOG_err (FOP_LOG, "Read buffer does not match requested size: %zu != %zu",
                evbuffer_get_length (read_data->read_buf), read_data->req_size);
        }
        
        buf = evbuffer_pullup (read_data->read_buf, -1);
        read_data->on_buffer_read_cb (read_data->ctx, TRUE, (char *)buf, evbuffer_get_length (read_data->read_buf));

        // free
        evbuffer_free (read_data->segment_buf);
        evbuffer_free (read_data->read_buf);
        g_free (read_data);

    // send a new request
    } else {
        hfs_fileop_read_get_buffer (read_data);
    }
}

// manifest or a small file is retrieved
static void hfs_fileop_read_manifest_on_read_cb (HttpConnection *con, void *ctx, 
    const gchar *buf, size_t buf_len, 
    struct evkeyvalq *headers, gboolean success)
{
    FileOpReadData *read_data = (FileOpReadData *) ctx;
    HfsFileOp *fop = read_data->fop;
    gboolean free_buf = FALSE;
    unsigned char *out_buf;
    int out_len;
    const char *manifest_header;

    LOG_debug (FOP_LOG, "Got %zu bytes for manifest: %zu", buf_len, read_data->segment_id);

    // release HttpConnection
    http_connection_release (con);
    fop->manifest_handled = TRUE;

    if (!success) {
        LOG_err (FOP_LOG, "Failed to retrieve segment !");
        read_data->on_buffer_read_cb (read_data->ctx, FALSE, NULL, 0);
        evbuffer_free (read_data->read_buf);
        evbuffer_free (read_data->segment_buf);
        g_free (read_data);
        return;
    }

    manifest_header = evhttp_find_header (headers, "X-Object-Manifest");

    // 0 bytes - manifest
    if (manifest_header) {
        // get segment size header
        const char *segment_size_header = evhttp_find_header (headers, "X-Object-Meta-Segment-Size");
        const char *object_size_header = evhttp_find_header (headers, "X-Object-Meta-Size");
        guint64 object_size = 0;

        if (segment_size_header) {
            read_data->segment_size = strtoll ((char *)segment_size_header, NULL, 10);
            // update FOP segment size for further operations
            fop->segment_size = read_data->segment_size;
        }

        if (object_size_header) {
            object_size = strtoll ((char *)segment_size_header, NULL, 10);
        }
    
        LOG_debug (FOP_LOG, "Got Manifest, starting to download segments. Segment size: %zu  Object size: %zu",
            read_data->segment_size, object_size);
        // start downloading segments
        hfs_fileop_read_get_buffer (read_data);
    // a small file
    } else {

        LOG_debug (FOP_LOG, "Downloading a small file");

        read_data->small_file = TRUE;

        if (!client_pool_get_client (application_get_read_client_pool (fop->app), hfs_fileop_read_on_con_cb, read_data)) {
            LOG_err (FOP_LOG, "Failed to get HTTP client !");

            read_data->on_buffer_read_cb (read_data->ctx, FALSE, NULL, 0);
            // free
            evbuffer_free (read_data->read_buf);
            evbuffer_free (read_data->segment_buf);
            g_free (read_data);
            return;
        }
    }
}

// download manifest or a small file
static void hfs_fileop_read_manifest_on_con_cb (gpointer client, gpointer ctx)
{
    HttpConnection *con = (HttpConnection *) client;
    FileOpReadData *read_data = (FileOpReadData *) ctx;
    HfsFileOp *fop = NULL;
    gchar *req_path = NULL;
    gboolean res;

    http_connection_acquire (con);

    fop = read_data->fop;

    // XXX: check cache first

    req_path = g_strdup_printf ("/%s/%s", application_get_container_name (con->app), 
        fop->fname);

    res = http_connection_make_request_to_storage_url (con, 
        req_path, "HEAD", NULL,
        hfs_fileop_read_manifest_on_read_cb,
        read_data
    );

    g_free (req_path);

    if (!res) {
        LOG_err (FOP_LOG, "Failed to create HTTP request !");
        http_connection_release (con);
        read_data->on_buffer_read_cb (read_data->ctx, FALSE, NULL, 0);
        evbuffer_free (read_data->read_buf);
        evbuffer_free (read_data->segment_buf);
        g_free (read_data);
        return;
    }
}


// Init read_data and call loop functioin
void hfs_fileop_read_buffer (HfsFileOp *fop,
    size_t size, off_t off, fuse_ino_t ino,
    HfsFileOp_on_buffer_read_cb on_buffer_read_cb, gpointer ctx)
{
    FileOpReadData *read_data;
    
    read_data = g_new0 (FileOpReadData, 1);
    read_data->fop = fop;
    read_data->on_buffer_read_cb = on_buffer_read_cb;
    read_data->ctx = ctx;
    read_data->read_buf = evbuffer_new ();
    read_data->segment_buf = evbuffer_new ();
    read_data->size_left = size;
    read_data->current_off = off;
    read_data->req_size = size;
    read_data->req_off = off;
    read_data->segment_id = 0;
    read_data->ino = ino;
    read_data->segment_size = fop->segment_size;
    read_data->small_file = FALSE;

    if (!fop->manifest_handled) {
        // get HTTP connection to download manifest or a small file
        if (!client_pool_get_client (application_get_read_client_pool (fop->app), hfs_fileop_read_manifest_on_con_cb, read_data)) {
            LOG_err (FOP_LOG, "Failed to get HTTP client !");

            read_data->on_buffer_read_cb (read_data->ctx, FALSE, NULL, 0);
            // free
            evbuffer_free (read_data->read_buf);
            evbuffer_free (read_data->segment_buf);
            g_free (read_data);
        }
    } else {
        LOG_debug (FOP_LOG, "Continue downloading segments");
        // start downloading segments
        hfs_fileop_read_get_buffer (read_data);
    }
}
/*}}}*/
