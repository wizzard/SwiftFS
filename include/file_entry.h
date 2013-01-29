/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _FILE_ENTRY_H_
#define _FILE_ENTRY_H_

#include "global.h"

typedef struct _FileEntry FileEntry;

FileEntry *file_entry_create ();
void file_entry_destroy (FileEntry *fentry);

void file_entry_release (FileEntry *fentry);

typedef void (*FileEntry_on_buffer_written) (gpointer callback_data, gboolean success);
void file_entry_write_buffer (FileEntry *fentry,
    const char *buf, size_t buf_size, off_t off,
    FileEntry_on_buffer_written on_buffer_written, gpointer callback_data);

typedef void (*FileEntry_on_buffer_read) (gpointer callback_data, gboolean success, char *buf, size_t size);
void file_entry_read_buffer (FileEntry *fentry,
    size_t size, off_t off,
    FileEntry_on_buffer_read on_buffer_read, gpointer callback_data);

#endif
