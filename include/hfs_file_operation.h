/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _HFS_FILE_OPERATION_H_
#define _HFS_FILE_OPERATION_H_

#include "global.h"

typedef struct _HfsFileOp HfsFileOp;

HfsFileOp *hfs_fileop_create ();
void hfs_fileop_destroy (HfsFileOp *fop);

void hfs_fileop_release (HfsFileOp *fop);

typedef void (*HfsFileOp_on_buffer_written_cb) (HfsFileOp *fop, gpointer ctx, gboolean success, size_t count);
void hfs_fileop_write_buffer (HfsFileOp *fop,
    const char *buf, size_t buf_size, off_t off,
    HfsFileOp_on_buffer_written_cb on_buffer_written_cb, gpointer ctx);

typedef void (*HfsFileOp_on_buffer_read_cb) (gpointer ctx, gboolean success, char *buf, size_t size);
void hfs_fileop_read_buffer (HfsFileOp *fop,
    size_t size, off_t off,
    HfsFileOp_on_buffer_read_cb on_buffer_read_cb, gpointer ctx);

#endif
