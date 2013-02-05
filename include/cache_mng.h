/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _CACHE_MNG_H_
#define _CACHE_MNG_H_

#include "global.h"

CacheMng *cache_mng_create (Application *app);
void cache_mng_destroy (CacheMng *cmng);

unsigned char *cache_mng_retr_file_data (CacheMng *cmng, fuse_ino_t ino, size_t size, off_t off);
void cache_mng_store_file_data (CacheMng *cmng, fuse_ino_t ino, size_t size, off_t off, unsigned char *buf);
#endif
