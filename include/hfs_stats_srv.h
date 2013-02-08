/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _HFS_STATS_SRV_
#define _HFS_STATS_SRV_

#include "global.h"

HfsStatsSrv *hfs_stats_srv_create (Application *app);
void hfs_stats_srv_destroy (HfsStatsSrv *srv);

void hfs_stats_srv_add_down_bytes (HfsStats *stats, guint32 bytes);
void hfs_stats_srv_add_up_bytes (HfsStats *stats, guint32 bytes);

guint32 hfs_stats_srv_get_down_speed (HfsStats *stats);
guint32 hfs_stats_srv_get_up_speed (HfsStats *stats);

#endif
