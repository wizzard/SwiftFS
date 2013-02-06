/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
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
