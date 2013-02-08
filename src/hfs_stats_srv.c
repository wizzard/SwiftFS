/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "hfs_stats_srv.h"

typedef struct {
    guint32 bytes;
    time_t time;
} SpeedEntry;

#define STATS_INTERVAL_SECS 10

struct _HfsStatsSrv {
    Application *app;

    SpeedEntry a_down_speed[STATS_INTERVAL_SECS]; // list of SpeedEntry for downloading
    SpeedEntry a_up_speed[STATS_INTERVAL_SECS]; // list of SpeedEntry for uploading
};

HfsStatsSrv *hfs_stats_srv_create (Application *app)
{
    HfsStatsSrv *srv;

    srv = g_new0 (HfsStatsSrv, 1);
    srv->app = app;

    return srv;
}

void hfs_stats_srv_destroy (HfsStatsSrv *srv)
{
    g_free (srv);
}

static void hfs_stats_srv_add_speed_bytes (SpeedEntry *a_speed, guint32 bytes)
{
    time_t now = time (NULL);

    if (a_speed[now % STATS_INTERVAL_SECS].time == now) {
        a_speed[now % STATS_INTERVAL_SECS].bytes += bytes;
    } else {
        a_speed[now % STATS_INTERVAL_SECS].time = now;
        a_speed[now % STATS_INTERVAL_SECS].bytes = bytes;
    }
}

static guint32 hfs_stats_srv_get_speed (SpeedEntry *a_speed)
{
    guint32 i;
    time_t now = time (NULL);
    guint32 sum = 0;
    guint32 items = 0;

    for (i = 0; i < STATS_INTERVAL_SECS; i++) {
        if (a_speed[i].time && now - STATS_INTERVAL_SECS <= a_speed[i].time) {
            items ++;
            sum += a_speed[i].bytes;
        }
    }

    if (items)
        return (guint32) sum / items;
    else
        return 0;
}

void hfs_stats_srv_add_down_bytes (HfsStats *stats, guint32 bytes)
{
    hfs_stats_srv_add_speed_bytes (stats->a_down_speed, bytes);
}

guint32 hfs_stats_srv_get_down_speed (HfsStats *stats)
{
    return hfs_stats_srv_get_speed (stats->a_down_speed);
}

void hfs_stats_srv_add_up_bytes (HfsStats *stats, guint32 bytes)
{
    hfs_stats_srv_add_speed_bytes (stats->a_up_speed, bytes);
}

guint32 hfs_stats_srv_get_up_speed (HfsStats *stats)
{
    return hfs_stats_srv_get_speed (stats->a_up_speed);
}

