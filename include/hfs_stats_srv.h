/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _HFS_STATS_SRV_
#define _HFS_STATS_SRV_

#include "global.h"

HfsStatsSrv *hfs_stats_srv_create (Application *app);
void hfs_stats_srv_destroy (HfsStatsSrv *srv);

void hfs_stats_srv_add_down_bytes (HfsStatsSrv *srv, guint32 bytes);
void hfs_stats_srv_add_up_bytes (HfsStatsSrv *srv, guint32 bytes);

guint32 hfs_stats_srv_get_down_speed (HfsStatsSrv *srv);
guint32 hfs_stats_srv_get_up_speed (HfsStatsSrv *srv);

void hfs_stats_srv_set_auth_srv_status (HfsStatsSrv *srv, gint code, const gchar *status_line);
void hfs_stats_srv_set_storage_srv_status (HfsStatsSrv *srv, gint code, const gchar *status_line);

void hfs_stats_srv_add_history (HfsStatsSrv *srv, const gchar *url, const gchar *http_method, 
    guint64 bytes, struct timeval *start_tv, struct timeval *end_tv);

#endif
