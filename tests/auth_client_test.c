/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "global.h"
#include "auth_client.h"

#define AUTH_TEST "auth_test"

struct _Application {
    struct event_base *evbase;
    struct evdns_base *dns_base;
    AppConf *conf;
    struct evhttp *http;
};

static Application *app;

int main (int argc, char *argv[])
{
    log_level = LOG_debug;

    event_set_mem_functions (g_malloc, g_realloc, g_free);

    app = g_new0 (Application, 1);
    app->evbase = event_base_new ();
	app->dns_base = evdns_base_new (app->evbase, 1);

    event_base_dispatch (app->evbase);
}
