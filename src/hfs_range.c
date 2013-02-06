/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */

#include "hfs_range.h"

struct _HfsRange {
};

HfsRange *hfs_range_create ()
{
}

void hfs_range_destroy (HfsRange *range)
{
    g_free (range);
}

void hfs_range_add (HfsRange *range, guint64 start, guint64 end)
{
}

gboolean hfs_range_contain (HfsRange *range, guint64 start, guint64 end)
{
}
