/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "global.h"
#include "hfs_stats_srv.h"

#define STATS_TEST "stats_test"

#define TIMES 10

typedef struct {
    guint32 bytes;
    guint32 sum;
} Item;

struct _Application {
    struct event_base *evbase;
    struct evdns_base *dns_base;
    ConfData *conf;
    HfsStatsSrv *stats;
    
    struct event *timeout;

    Item a_items[TIMES];
    guint pos;
};

struct event_base *application_get_evbase (Application *app)
{
    return app->evbase;
}

struct evdns_base *application_get_dnsbase (Application *app)
{
    return app->dns_base;
}

ConfData *application_get_conf (Application *app)
{
    return app->conf;
}

HfsStatsSrv *application_get_stats_srv (Application *app)
{
    return app->stats;
}


static void on_timer_cb (evutil_socket_t fd, short event, void *ctx)
{
    Application *app = (Application *) ctx;

    if (app->pos < TIMES) {
        struct timeval tv;
        guint32 sum;
        
        hfs_stats_srv_add_down_bytes (app->stats, app->a_items[app->pos].bytes);
        sum = hfs_stats_srv_get_down_speed (app->stats);

        //g_assert_cmpint (app->a_items[app->pos].sum, ==, sum);
        if (app->a_items[app->pos].sum != sum) 
            g_printf ("Ops, expected %u, but got %u, pos: %u\n", app->a_items[app->pos].sum, sum, app->pos);
        else
            g_printf ("Ok, got %u, pos: %u\n", sum, app->pos);
        
        app->pos ++;
        evutil_timerclear (&tv);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        event_add (app->timeout, &tv);

    } else
        event_base_loopexit (app->evbase, NULL);
}

int main (int argc, char *argv[])
{
    struct timeval tv;
    Application *app;
    guint i = 0;

    log_level = LOG_debug;

    event_set_mem_functions (g_malloc, g_realloc, g_free);

    app = g_new0 (Application, 1);
    app->evbase = event_base_new ();
	app->dns_base = evdns_base_new (app->evbase, 1);
    app->conf = conf_create ();
    g_assert (conf_parse_file (app->conf, "test.conf.xml") == TRUE);
    conf_add_boolean (app->conf, "statistics.enabled", FALSE);

    app->a_items[0].bytes = 10;
    app->a_items[0].sum = 5;
    app->a_items[1].bytes = 4;
    app->a_items[1].sum = 7;
    app->a_items[2].bytes = 1;
    app->a_items[2].sum = 5;
    app->a_items[3].bytes = 9;
    app->a_items[3].sum = 6;
    app->a_items[4].bytes = 11;
    app->a_items[4].sum = 7;

    app->a_items[5].bytes = 5;
    app->a_items[5].sum = 6;
    app->a_items[6].bytes = 14;
    app->a_items[6].sum = 8;
    app->a_items[7].bytes = 21;
    app->a_items[7].sum = 12;
    app->a_items[8].bytes = 4;
    app->a_items[8].sum = 11;
    app->a_items[9].bytes = 1;
    app->a_items[9].sum = 9;

    app->pos = 0;

    app->stats = hfs_stats_srv_create (app);

    app->timeout = evtimer_new (app->evbase, on_timer_cb, app);

    evutil_timerclear (&tv);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    event_add (app->timeout, &tv);

    event_base_dispatch (app->evbase);

    return 0;
}
