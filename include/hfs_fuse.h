/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _FUSE_H_
#define _FUSE_H_

#include "global.h"

struct dirbuf {
	char *p;
	size_t size;
};

HfsFuse *hfs_fuse_new (Application *app, const gchar *mountpoint);
void hfs_fuse_destroy (HfsFuse *hfs_fuse);

void hfs_fuse_add_dirbuf (fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino);

#endif
