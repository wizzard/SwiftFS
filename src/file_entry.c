/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "file_entry.h"

/*{{{ struct */
struct _FileEntry {
    Application *app;
    ConfData *conf;

    gboolean released; // a simple version of ref counter.
    size_t current_size; // total bytes after read / write calls
    struct evbuffer *segment_buf; // current segment buffer
    size_t segment_count; // current count of segments uploaded / downloaded
};
/*}}}*/

#define FENTRY_LOG "fentry"

FileEntry *file_entry_create (Application *app)
{
    FileEntry *fentry;

    fentry = g_new0 (FileEntry, 1);
    fentry->app = app;
    fentry->conf = application_get_conf (app);
    fentry->released = FALSE;
    fentry->current_size = 0;
    fentry->segment_buf = evbuffer_new ();
    fentry->segment_count = 0;

    return fentry;
}

void file_entry_destroy (FileEntry *fentry)
{
    evbuffer_free (fentry->segment_buf);
    g_free (fentry);
}

// file is released, finish all operations
void file_entry_release (FileEntry *fentry)
{
    fentry->released = TRUE;

    // send .manifest file if there more than 1 segment uploaded
    if (fentry->segment_count > 1) {
    }
}

// Add data to file entry segment buffer
// if segment buffer exceeds MAX size then send segment buffer to server
// execute callback function when data either is sent or added to buffer
void file_entry_write_buffer (FileEntry *fentry,
    const char *buf, size_t buf_size, off_t off,
    FileEntry_on_buffer_written on_buffer_written, gpointer callback_data)
{
    // XXX: allow only sequentially write
    // current written bytes should be always match offset
    if (fentry->current_size != off) {
        LOG_err (FENTRY_LOG, "Write call with offset %"OFF_FMT" is not allowed !", off);
        on_buffer_written (callback_data, FALSE);
        return;
    }

    // XXX: add to CacheMng

    evbuffer_add (fentry->segment_buf, buf, buf_size);
    fentry->current_size += buf_size;
    
    // check if we need to flush segment buffer
    if (evbuffer_get_length (fentry->segment_buf) >= conf_get_uint (fentry->conf, "filesystem.segment_size")) {
        // XXX: encrypt
        // XXX: add task to ClientPool
    } else {
        // data is added to the current segment buffer
        on_buffer_written (callback_data, TRUE);
    }
}

// Send request to server to get segment buffer
void file_entry_read_buffer (FileEntry *fentry,
    size_t size, off_t off,
    FileEntry_on_buffer_read on_buffer_read, gpointer callback_data)
{
    // XXX: check file in CacheMng
    // XXX: add task to ClientPool
}
