/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "global.h"
#include "http_connection.h"
#include "dir_tree.h"
#include "hfs_fuse.h"
#include "client_pool.h"
#include "http_client.h"
#include "auth_client.h"

#define APP_LOG "main"

struct _Application {
    ConfData *conf;
    struct event_base *evbase;
    struct evdns_base *dns_base;
    
    HfsFuse *hfs_fuse;
    DirTree *dir_tree;

    AuthClient *auth_client;

    ClientPool *write_client_pool;
    ClientPool *read_client_pool;
    ClientPool *ops_client_pool;

    gchar *auth_user;
    gchar *auth_pwd;

    gchar *container_name;
    struct evhttp_uri *auth_uri;

    gboolean foreground;
    gchar *mountpoint;

    struct event *sigint_ev;
    struct event *sigpipe_ev;
    struct event *sigusr1_ev;

};

// global variable, used by signals handlers
static Application *_app = NULL;


/*{{{ getters */
struct event_base *application_get_evbase (Application *app)
{
    return app->evbase;
}

struct evdns_base *application_get_dnsbase (Application *app)
{
    return app->dns_base;
}

DirTree *application_get_dir_tree (Application *app)
{
    return app->dir_tree;
}

ClientPool *application_get_write_client_pool (Application *app)
{
    return app->write_client_pool;
}

ClientPool *application_get_read_client_pool (Application *app)
{
    return app->read_client_pool;
}

ClientPool *application_get_ops_client_pool (Application *app)
{
    return app->ops_client_pool;
}

const gchar *application_get_container_name (Application *app)
{
    return app->container_name;
}

ConfData *application_get_conf (Application *app)
{
    return app->conf;
}

AuthClient *application_get_auth_client (Application *app)
{
    return app->auth_client;
}

/*}}}*/

/*{{{ signal handlers */
/* This structure mirrors the one found in /usr/include/asm/ucontext.h */
typedef struct _sig_ucontext {
    unsigned long     uc_flags;
    struct ucontext   *uc_link;
    stack_t           uc_stack;
    struct sigcontext uc_mcontext;
    sigset_t          uc_sigmask;
} sig_ucontext_t;

static void sigsegv_cb (int sig_num, siginfo_t *info, void * ucontext)
{
    void *array[50];
    void *caller_address;
    char **messages;
    int size, i;
    sig_ucontext_t *uc;
    FILE *f;
    
    g_fprintf (stderr, "Got Sigfault !\n");

	uc = (sig_ucontext_t *)ucontext;

    /* Get the address at the time the signal was raised from the EIP (x86) */
#ifdef __i386__
    caller_address = (void *) uc->uc_mcontext.eip;   
#else
    caller_address = (void *) uc->uc_mcontext.rip;   
#endif

	f = stderr;

	fprintf (f, "signal %d (%s), address is %p from %p\n", sig_num, strsignal (sig_num), info->si_addr, (void *)caller_address);

	size = backtrace (array, 50);

	/* overwrite sigaction with caller's address */
	array[1] = caller_address;

	messages = backtrace_symbols (array, size);

	/* skip first stack frame (points here) */
	for (i = 1; i < size && messages != NULL; ++i) {
		fprintf (f, "[bt]: (%d) %s\n", i, messages[i]);
	}

    fflush (f);

	free (messages);

	LOG_err (APP_LOG, "signal %d (%s), address is %p from %p\n", sig_num, strsignal (sig_num), info->si_addr, (void *)caller_address);

    // try to unmount FUSE mountpoint
    if (_app && _app->hfs_fuse)
        hfs_fuse_destroy (_app->hfs_fuse);
}

// ignore SIGPIPE
static void sigpipe_cb (G_GNUC_UNUSED evutil_socket_t sig, G_GNUC_UNUSED short events, G_GNUC_UNUSED void *user_data)
{
	LOG_msg (APP_LOG, "Got SIGPIPE");
}

// XXX: re-read config or do some useful work here
static void sigusr1_cb (G_GNUC_UNUSED evutil_socket_t sig, G_GNUC_UNUSED short events, G_GNUC_UNUSED void *user_data)
{
	LOG_err (APP_LOG, "Got SIGUSR1");

    // try to unmount FUSE mountpoint
    if (_app && _app->hfs_fuse)
        hfs_fuse_destroy (_app->hfs_fuse);
    
    exit (1);
}

// terminate application, freeing all used memory
static void sigint_cb (G_GNUC_UNUSED evutil_socket_t sig, G_GNUC_UNUSED short events, void *user_data)
{
	Application *app = (Application *) user_data;

	LOG_err (APP_LOG, "Got SIGINT");

    // terminate after running all active events 
    event_base_loopexit (app->evbase, NULL);
}
/*}}}*/

static gint application_finish_initialization_and_run (Application *app)
{
    struct sigaction sigact;

    auth_client = auth_client_create (app, app->auth_uri);
    if (!auth_client) {
        LOG_err (APP_LOG, "Failed to create AuthClient !");
        event_base_loopexit (app->evbase, NULL);
        return -1;
    }

    // create ClientPool for reading operations
    app->read_client_pool = client_pool_create (app, app->conf->readers,
        http_client_create,
        http_client_destroy,
        http_client_set_on_released_cb,
        http_client_check_rediness
        );
    if (!app->read_client_pool) {
        LOG_err (APP_LOG, "Failed to create ClientPool !");
        event_base_loopexit (app->evbase, NULL);
        return -1;
    }

    // create ClientPool for writing operations
    app->write_client_pool = client_pool_create (app, app->conf->writers,
        http_connection_create,
        http_connection_destroy,
        http_connection_set_on_released_cb,
        http_connection_check_rediness
        );
    if (!app->write_client_pool) {
        LOG_err (APP_LOG, "Failed to create ClientPool !");
        event_base_loopexit (app->evbase, NULL);
        return -1;
    }

    // create ClientPool for various operations
    app->ops_client_pool = client_pool_create (app, app->conf->ops,
        http_connection_create,
        http_connection_destroy,
        http_connection_set_on_released_cb,
        http_connection_check_rediness
        );
    if (!app->ops_client_pool) {
        LOG_err (APP_LOG, "Failed to create ClientPool !");
        event_base_loopexit (app->evbase, NULL);
        return -1;
    }

/*{{{ DirTree*/
    app->dir_tree = dir_tree_create (app);
    if (!app->dir_tree) {
        LOG_err (APP_LOG, "Failed to create DirTree !");
        event_base_loopexit (app->evbase, NULL);
        return -1;
    }
/*}}}*/

/*{{{ FUSE*/
    app->hfs_fuse = hfs_fuse_new (app, app->mountpoint);
    if (!app->hfs_fuse) {
        LOG_err (APP_LOG, "Failed to create FUSE fs !");
        event_base_loopexit (app->evbase, NULL);
        return -1;
    }
/*}}}*/

    // set global App variable
    _app = app;

/*{{{ signal handlers*/
	// SIGINT
	app->sigint_ev = evsignal_new (app->evbase, SIGINT, sigint_cb, app);
	event_add (app->sigint_ev, NULL);
	// SIGSEGV
    sigact.sa_sigaction = sigsegv_cb;
    sigact.sa_flags = (int)SA_RESETHAND | SA_SIGINFO;
	sigemptyset (&sigact.sa_mask);
    if (sigaction (SIGSEGV, &sigact, (struct sigaction *) NULL) != 0) {
        LOG_err (APP_LOG, "error setting signal handler for %d (%s)\n", SIGSEGV, strsignal(SIGSEGV));
        event_base_loopexit (app->evbase, NULL);
		return 1;
    }
	// SIGABRT
    sigact.sa_sigaction = sigsegv_cb;
    sigact.sa_flags = (int)SA_RESETHAND | SA_SIGINFO;
	sigemptyset (&sigact.sa_mask);
    if (sigaction (SIGABRT, &sigact, (struct sigaction *) NULL) != 0) {
        LOG_err (APP_LOG, "error setting signal handler for %d (%s)\n", SIGABRT, strsignal(SIGABRT));
        event_base_loopexit (app->evbase, NULL);
		return 1;
    }
	// SIGPIPE
	app->sigpipe_ev = evsignal_new (app->evbase, SIGPIPE, sigpipe_cb, app);
	event_add (app->sigpipe_ev, NULL);
    // SIGUSR1
	app->sigusr1_ev = evsignal_new (app->evbase, SIGUSR1, sigusr1_cb, app);
	event_add (app->sigusr1_ev, NULL);
/*}}}*/
    
    if (!app->foreground)
        fuse_daemonize (0);

    return 0;
}

// AuthData
static void application_on_auth_data_cb (gpointer ctx, gboolean success, 
    const gchar *auth_token, const struct evhttp_uri *storage_uri)
{
    Application *app = (Application *)ctx;

    if (!success) {
        LOG_err (APP_LOG, "Failed to get AuthToken !");
        exit (1);
    }


    
        application_finish_initialization_and_run (app);
}

static void application_destroy (Application *app)
{
    // destroy Fuse
    if (app->hfs_fuse)
        hfs_fuse_destroy (app->hfs_fuse);

    if (app->read_client_pool)
        client_pool_destroy (app->read_client_pool);
    if (app->write_client_pool)
        client_pool_destroy (app->write_client_pool);
    if (app->ops_client_pool)
        client_pool_destroy (app->ops_client_pool);

    if (app->dir_tree)
        dir_tree_destroy (app->dir_tree);

    if (app->sigint_ev)
        event_free (app->sigint_ev);
    if (app->sigpipe_ev)
        event_free (app->sigpipe_ev);
    if (app->sigusr1_ev)
        event_free (app->sigusr1_ev);
    
    if (app->auth_client)
        auth_client_destroy (app->auth_client);

    evdns_base_free (app->dns_base, 0);
    event_base_free (app->evbase);

    g_free (app->mountpoint);
    g_free (app->tmp_dir);
    g_free (app->container_name);
    evhttp_uri_free (app->uri);

    conf_destroy (app->conf);
    g_free (app);
    
    ENGINE_cleanup ();
    CRYPTO_cleanup_all_ex_data ();
	ERR_free_strings ();
	ERR_remove_thread_state (NULL);
	CRYPTO_mem_leaks_fp (stderr);
}

int main (int argc, char *argv[])
{
    Application *app;
    gboolean verbose = FALSE;
    gboolean version = FALSE;
    GError *error = NULL;
    GOptionContext *context;
    gchar **s_params = NULL;
    gchar **s_config = NULL;
    gchar *progname;
    gboolean foreground = FALSE;
    GKeyFile *key_file;
    gchar conf_str[1023];
    gchar *conf_path;
    struct stat st;

    conf_path = g_build_filename (SYSCONFDIR, "hydrafs.conf", NULL); 
    g_snprintf (conf_str, sizeof (conf_str), "Path to configuration file. Default: %s", conf_path);

    GOptionEntry entries[] = {
	    { G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY, &s_params, NULL, NULL },
	    { "config", 'c', 0, G_OPTION_ARG_FILENAME_ARRAY, &s_config, conf_str, NULL},
        { "foreground", 'f', 0, G_OPTION_ARG_NONE, &foreground, "Flag. Do not daemonize process.", NULL },
        { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Verbose output.", NULL },
        { "version", 0, 0, G_OPTION_ARG_NONE, &version, "Show application version and exit.", NULL },
        { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
    };

    // init libraries
    ENGINE_load_builtin_engines ();
    ENGINE_register_all_complete ();

    progname = argv[0];

    // init main app structure
    app = g_new0 (Application, 1);
    app->evbase = event_base_new ();
    app->auth_token = NULL;

    app->conf = conf_create ();
    // parse conf file
    if (stat (conf_path, &st) == -1) {
        // set default values
        LOG_msg (APP_LOG, "Configuration file not found, using default settings.");
        
        conf_add_boolean (app->conf, "log.use_syslog", TRUE);
        
        conf_add_uint (app->conf, "auth.ttl", 85800);
        
        conf_add_int (app->conf, "pool.writers", 2);
        conf_add_int (app->conf, "pool.readers", 2);
        conf_add_int (app->conf, "pool.operations", 4);
        conf_add_uint (app->conf, "pool.max_requests_per_pool", 100);

        conf_add_int (app->conf, "connection.timeout", 20);
        conf_add_int (app->conf, "connection.retries", -1);

        conf_add_uint (app->conf, "filesystem.dir_cache_max_time", 5);
        conf_add_boolean (app->conf, "filesystem.cache_enabled", TRUE);
        conf_add_string (app->conf, "filesystem.cache_dir", "/tmp/hydrafs");
        conf_add_string (app->conf, "filesystem.cache_dir_max_size", "1Gb");

        conf_add_boolean (app->conf, "statistics.enabled", TRUE);
        conf_add_int (app->conf, "statistics.port", 8011);
    } else {
        if (!conf_parse_file (app->conf, conf_path)) {
            LOG_err (APP_LOG, "Failed to parse configuration file: %s", conf_path);
            return -1;
        }
    }

    //XXX: fix it
    app->tmp_dir = g_strdup ("/tmp");

    if (!app->evbase) {
        LOG_err (APP_LOG, "Failed to create event base !");
        return -1;
    }

    app->dns_base = evdns_base_new (app->evbase, 1);
    if (!app->dns_base) {
        LOG_err (APP_LOG, "Failed to create DNS base !");
        return -1;
    }

/*{{{ cmd line args */

    // parse command line options
    context = g_option_context_new ("[http://auth.api.yourcloud.com/v1.0] [container] [options] [mountpoint]");
    g_option_context_add_main_entries (context, entries, NULL);
    g_option_context_set_description (context, "Please set both HydraFS_USER and HydraFS_PWD environment variables!");
    if (!g_option_context_parse (context, &argc, &argv, &error)) {
        g_fprintf (stderr, "Failed to parse command line options: %s\n", error->message);
        return FALSE;
    }

    // check if --version is specified
    if (version) {
            g_fprintf (stdout, " Fast File System v%s\n", VERSION);
            g_fprintf (stdout, "Copyright (C) 2012 Paul Ionkin <paul.ionkin@gmail.com>\n");
            g_fprintf (stdout, "Copyright (C) 2012 Skoobe GmbH. All rights reserved.\n");
            g_fprintf (stdout, "Libraries:\n");
            g_fprintf (stdout, " GLib: %d.%d.%d   libevent: %s  fuse: %d.%d  glibc: %s\n", 
                    GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION, GLIB_MICRO_VERSION, 
                    LIBEVENT_VERSION,
                    FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION,
                    gnu_get_libc_version ()
            );
        return 0;
    }
    
    // get access parameters from the environment
    app->auth_user = getenv ("HydraFS_USER");
    app->auth_pwd = getenv ("HydraFS_PWD");
    if (!app->auth_user || !app->auth_pwd) {
        LOG_err (APP_LOG, "Environment variables are not set!");
        g_fprintf (stdout, "%s\n", g_option_context_get_help (context, TRUE, NULL));
        return -1;
    }

    if (g_strv_length (s_params) != 3) {
        LOG_err (APP_LOG, "Wrong number of provided arguments!");
        g_fprintf (stdout, "%s\n", g_option_context_get_help (context, TRUE, NULL));
        return -1;
    }

    app->uri = evhttp_uri_parse (s_params[0]);
    if (!app->uri) {
        LOG_err (APP_LOG, " URL (%s) is not valid!", s_params[0]);
        g_fprintf (stdout, "%s\n", g_option_context_get_help (context, TRUE, NULL));
        return -1;
    }
    app->container_name = g_strdup (s_params[1]);
    
    app->mountpoint = g_strdup (s_params[2]);

    // check if directory exists
    if (stat (app->mountpoint, &st) == -1) {
        LOG_err (APP_LOG, "Mountpoint %s does not exist! Please check directory permissions!", app->mountpoint);
        g_fprintf (stdout, "%s\n", g_option_context_get_help (context, TRUE, NULL));
        return -1;
    }
    // check if it's a directory
    if (!S_ISDIR (st.st_mode)) {
        LOG_err (APP_LOG, "Mountpoint %s is not a directory!", app->mountpoint);
        g_fprintf (stdout, "%s\n", g_option_context_get_help (context, TRUE, NULL));
        return -1;
    }
    
    g_strfreev (s_params);

    app->foreground = foreground;

    if (verbose)
        log_level = LOG_debug;
    else
        log_level = LOG_msg;
    
    g_option_context_free (context);
/*}}}*/

/*{{{ parse config file */

    // user provided alternative config path
    if (s_config && g_strv_length (s_config) > 0) {
        g_free (conf_path);
        conf_path = g_strdup (s_config[0]);
        g_strfreev (s_config);
    }

    if (access (conf_path, R_OK) == 0) {
        LOG_msg (APP_LOG, "Using config file: %s", conf_path);
        
        key_file = g_key_file_new ();
        if (!g_key_file_load_from_file (key_file, conf_path, G_KEY_FILE_NONE, &error)) {
            LOG_err (APP_LOG, "Failed to load configuration file (%s): %s", conf_path, error->message);
            return -1;
        }
        
        // [general]
        app->conf->use_syslog = g_key_file_get_boolean (key_file, "general", "use_syslog", &error);
        if (error) {
            LOG_err (APP_LOG, "Failed to read configuration file (%s): %s", conf_path, error->message);
            return -1;
        }
        
        // [connection]
        app->conf->writers = g_key_file_get_integer (key_file, "connection", "writes", &error);
        if (error) {
            LOG_err (APP_LOG, "Failed to read configuration file (%s): %s", conf_path, error->message);
            return -1;
        }

        app->conf->readers = g_key_file_get_integer (key_file, "connection", "readers", &error);
        if (error) {
            LOG_err (APP_LOG, "Failed to read configuration file (%s): %s", conf_path, error->message);
            return -1;
        }

        app->conf->ops = g_key_file_get_integer (key_file, "connections", "operations", &error);
        if (error) {
            LOG_err (APP_LOG, "Failed to read configuration file (%s): %s", conf_path, error->message);
            return -1;
        }

        app->conf->timeout = g_key_file_get_integer (key_file, "connections", "timeout", &error);
        if (error) {
            LOG_err (APP_LOG, "Failed to read configuration file (%s): %s", conf_path, error->message);
            return -1;
        }

        app->conf->retries = g_key_file_get_integer (key_file, "connections", "retries", &error);
        if (error) {
            LOG_err (APP_LOG, "Failed to read configuration file (%s): %s", conf_path, error->message);
            return -1;
        }

        app->conf->http_port = g_key_file_get_integer (key_file, "connections", "http_port", &error);
        if (error) {
            LOG_err (APP_LOG, "Failed to read configuration file (%s): %s", conf_path, error->message);
            return -1;
        }

        app->conf->max_requests_per_pool = g_key_file_get_integer (key_file, "connections", "max_requests_per_pool", &error);
        if (error) {
            LOG_err (APP_LOG, "Failed to read configuration file (%s): %s", conf_path, error->message);
            return -1;
        }

        app->conf->dir_cache_max_time = g_key_file_get_integer (key_file, "filesystem", "dir_cache_max_time", &error);
        if (error) {
            LOG_err (APP_LOG, "Failed to read configuration file (%s): %s", conf_path, error->message);
            return -1;
        }
        
        g_free (app->tmp_dir);
        app->tmp_dir = g_key_file_get_string (key_file, "filesystem", "tmp_dir", &error);
        if (error) {
            LOG_err (APP_LOG, "Failed to read configuration file (%s): %s", conf_path, error->message);
            return -1;
        }

        g_key_file_free (key_file);
    } else {
        LOG_msg (APP_LOG, "Configuration file does not exist, using predefined values.");
    }

    g_free (conf_path);

    // update logging settings
    logger_set_syslog (app->conf->use_syslog);

/*}}}*/


        application_get_service_on_done, application_get_service_on_error, app))

    // start the loop
    event_base_dispatch (app->evbase);

    application_destroy (app);

    return 0;
}
