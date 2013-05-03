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
