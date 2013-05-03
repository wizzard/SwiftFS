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
#ifndef _HFS_FILE_OPERATION_H_
#define _HFS_FILE_OPERATION_H_

#include "global.h"

typedef struct _HfsFileOp HfsFileOp;

HfsFileOp *hfs_fileop_create (Application *app, const gchar *fname);
void hfs_fileop_destroy (HfsFileOp *fop);

void hfs_fileop_release (HfsFileOp *fop);

typedef void (*HfsFileOp_on_buffer_written_cb) (HfsFileOp *fop, gpointer ctx, gboolean success, size_t count);
void hfs_fileop_write_buffer (HfsFileOp *fop,
    const char *buf, size_t buf_size, off_t off, fuse_ino_t ino,
    HfsFileOp_on_buffer_written_cb on_buffer_written_cb, gpointer ctx);

typedef void (*HfsFileOp_on_buffer_read_cb) (gpointer ctx, gboolean success, char *buf, size_t size);
void hfs_fileop_read_buffer (HfsFileOp *fop,
    size_t size, off_t off, fuse_ino_t ino,
    HfsFileOp_on_buffer_read_cb on_buffer_read_cb, gpointer ctx);

#endif
