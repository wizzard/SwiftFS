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
#ifndef _HFS_RANGE_H_
#define _HFS_RANGE_H_

#include "global.h"

typedef struct _HfsRange HfsRange;

HfsRange *hfs_range_create ();

void hfs_range_destroy (HfsRange *range);

void hfs_range_add (HfsRange *range, guint64 start, guint64 end);

gboolean hfs_range_contain (HfsRange *range, guint64 start, guint64 end);
gint hfs_range_count (HfsRange *range);
void hfs_range_print (HfsRange *range);

#endif
