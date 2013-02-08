/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "hfs_stats.h"

typedef struct {
    guint32 bytes;
    time_t time;
} SpeedEntry;

struct _HfsStats {
    guint speed_interval; // interval in secs to store Speed entries
    SpeedEntry *a_down_speed; // list of SpeedEntry for downloading
    SpeedEntry *a_up_speed; // list of SpeedEntry for uploading
};


HfsStats *hfs_stats_create (guint speed_interval)
{
    HfsStats *stats;

    stats = g_new0 (HfsStats, 1);

    stats->speed_interval = speed_interval;
    stats->a_down_speed = g_new0 (SpeedEntry, stats->speed_interval);
    stats->a_up_speed = g_new0 (SpeedEntry, stats->speed_interval);

    return stats;
}

void hfs_stats_destroy (HfsStats *stats)
{
    g_free (stats->a_down_speed);
    g_free (stats->a_up_speed);
    g_free (stats);
}

static void hfs_stats_add_speed_bytes (SpeedEntry *a_speed, guint interval, guint32 bytes)
{
    SpeedEntry *sentry;
    time_t now = time (NULL);

   // sentry = a_speed[time % interval];
}

void hfs_stats_add_down_bytes (HfsStats *stats, guint32 bytes)
{
    hfs_stats_add_speed_bytes (stats->a_down_speed, stats->speed_interval, bytes);
}

void hfs_stats_add_up_bytes (HfsStats *stats, guint32 bytes)
{
    hfs_stats_add_speed_bytes (stats->a_up_speed, stats->speed_interval, bytes);
}
