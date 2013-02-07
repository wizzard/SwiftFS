/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _HFS_STATS_H_
#define _HFS_STATS_H_

#include "global.h"

typedef struct _HfsStats HfsStats;

HfsStats *hfs_stats_create ();
void hfd_stats_destroy (HfsStats *stats);

#endif
