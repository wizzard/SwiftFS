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
#ifndef _FUSE_H_
#define _FUSE_H_

#include "global.h"

struct dirbuf {
	char *p;
	size_t size;
};

HfsFuse *hfs_fuse_new (Application *app, const gchar *mountpoint, const gchar *fuse_opts);
void hfs_fuse_destroy (HfsFuse *hfs_fuse);

void hfs_fuse_add_dirbuf (fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino, off_t file_size);

#endif
