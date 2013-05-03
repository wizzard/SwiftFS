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
#ifndef _CACHE_MNG_H_
#define _CACHE_MNG_H_

#include "global.h"

CacheMng *cache_mng_create (Application *app);
void cache_mng_destroy (CacheMng *cmng);

unsigned char *cache_mng_retr_file_data (CacheMng *cmng, fuse_ino_t ino, size_t size, off_t off);
void cache_mng_store_file_data (CacheMng *cmng, fuse_ino_t ino, size_t size, off_t off, unsigned char *buf);

void cache_mng_remove_file_data (CacheMng *cmng, fuse_ino_t ino);

#endif
