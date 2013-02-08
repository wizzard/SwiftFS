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
#include "hfs_encryption.h"
#include "cache_mng.h"
#include "hfs_stats_srv.h"

#define APP_LOG "main"

struct _Application {
    ConfData *conf;
    struct event_base *evbase;
    struct evdns_base *dns_base;
    
    HfsFuse *hfs_fuse;
    DirTree *dir_tree;
    CacheMng *cmng;

    AuthClient *auth_client;

    HfsEncryption *enc;

    ClientPool *write_client_pool;
    ClientPool *read_client_pool;
    ClientPool *ops_client_pool;

    gchar *auth_user;
    gchar *auth_pwd;

    gchar *container_name;
    gchar *full_container_name;
    struct evhttp_uri *auth_uri;
    gchar *storage_url; // use this URL instead of the one returned by Auth server

    gboolean foreground;
    gchar *mountpoint;

    struct event *sigint_ev;
    struct event *sigpipe_ev;
    struct event *sigusr1_ev;

    HfsStatsSrv *stats_srv;
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

// Returns:  cont1/
const gchar *application_get_container_name (Application *app)
{
    return app->container_name;
}

// Returns:  /v1/AUTH_test/cont1/
const gchar *application_get_full_container_name (Application *app)
{
    return app->full_container_name;
}

void application_update_full_container_name (Application *app, const gchar *full_container_name)
{
    if (app->full_container_name)
        return;
    app->full_container_name = g_strdup (full_container_name);

    LOG_debug (APP_LOG, "Full container name: %s", app->full_container_name);
}

ConfData *application_get_conf (Application *app)
{
    return app->conf;
}

AuthClient *application_get_auth_client (Application *app)
{
    return app->auth_client;
}

HfsEncryption *application_get_encryption (Application *app)
{
    return app->enc;
}

CacheMng *application_get_cache_mng (Application *app)
{
    return app->cmng;
}

const gchar *application_get_storage_url (Application *app)
{
    return app->storage_url;
}

HfsStatsSrv *application_get_stats_srv (Application *app)
{
    return app->stats_srv;
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

    app->cmng = cache_mng_create (app);
    if (!app->cmng) {
        LOG_err (APP_LOG, "Failed to create CacheMng !");
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

    app->stats_srv = hfs_stats_srv_create (app);
    if (!app->stats_srv) {
        LOG_err (APP_LOG, "Failed to create Stats Server !");
        event_base_loopexit (app->evbase, NULL);
        return -1;
    }

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

static void application_on_container_meta_cb (gpointer ctx, gboolean success)
{
    Application *app = (Application *) ctx;

    if (!success) {
        LOG_err (APP_LOG, "Failed to get container (%s) information !", application_get_container_name (app));
        event_base_loopexit (app->evbase, NULL);
        return;
    }

    application_finish_initialization_and_run (app);
}

static void application_on_connection_client_cb (gpointer client, gpointer ctx)
{
    HttpConnection *con = (HttpConnection *) client;
    Application *app = (Application *) ctx;

    http_connection_get_container_meta (con, application_on_container_meta_cb, app);
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

    hfs_stats_srv_destroy (app->stats_srv);

    if (app->dir_tree)
        dir_tree_destroy (app->dir_tree);

    if (app->cmng)
        cache_mng_destroy (app->cmng);

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
    g_free (app->container_name);
    g_free (app->full_container_name);
    evhttp_uri_free (app->auth_uri);

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
    gchar conf_str[1023];
    gchar *conf_path;
    struct stat st;
	int r;
    gchar **storage_url = NULL;

    conf_path = g_build_filename (SYSCONFDIR, "hydrafs.conf", NULL); 
    g_snprintf (conf_str, sizeof (conf_str), "Path to configuration file. Default: %s", conf_path);

    GOptionEntry entries[] = {
	    { G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY, &s_params, NULL, NULL },
	    { "config", 'c', 0, G_OPTION_ARG_FILENAME_ARRAY, &s_config, conf_str, NULL},
        { "foreground", 'f', 0, G_OPTION_ARG_NONE, &foreground, "Flag. Do not daemonize process.", NULL },
        { "storage_url", 's', 0, G_OPTION_ARG_STRING_ARRAY, &storage_url, "Set storage URL (Storage URL returned by Auth server will be ignored).", NULL },
        { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Verbose output.", NULL },
        { "version", 0, 0, G_OPTION_ARG_NONE, &version, "Show application version and exit.", NULL },
        { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
    };

    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    r = RAND_poll ();
    if (r == 0) {
        fprintf(stderr, "RAND_poll() failed.\n");
        return 1;
    }

    // init libraries
    ENGINE_load_builtin_engines ();
    ENGINE_register_all_complete ();

    g_random_set_seed (time (NULL));

    progname = argv[0];

    // init main app structure
    app = g_new0 (Application, 1);
    app->evbase = event_base_new ();
    app->full_container_name = NULL;

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
    context = g_option_context_new ("[http://auth.api.yourcloud.com/v1.0] [container] [mountpoint]");
    g_option_context_add_main_entries (context, entries, NULL);
    g_option_context_set_description (context, "Please set both HydraFS_USER and HydraFS_PWD environment variables!");
    if (!g_option_context_parse (context, &argc, &argv, &error)) {
        g_fprintf (stderr, "Failed to parse command line options: %s\n", error->message);
        return FALSE;
    }

    if (verbose)
        log_level = LOG_debug;
    else
        log_level = LOG_msg;

    // check if --version is specified
    if (version) {
            g_fprintf (stdout, "HydraFS File System v%s\n", VERSION);
            g_fprintf (stdout, "Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>\n");
            g_fprintf (stdout, "\nLibraries:\n");
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

    if (!s_params || g_strv_length (s_params) != 3) {
        LOG_err (APP_LOG, "Wrong number of provided arguments!");
        g_fprintf (stdout, "%s\n", g_option_context_get_help (context, TRUE, NULL));
        return -1;
    }

    app->auth_uri = evhttp_uri_parse (s_params[0]);
    if (!app->auth_uri) {
        LOG_err (APP_LOG, " URL (%s) is not valid!", s_params[0]);
        g_fprintf (stdout, "%s\n", g_option_context_get_help (context, TRUE, NULL));
        return -1;
    }

    if (storage_url && g_strv_length (storage_url) > 0) {
        app->storage_url = g_strdup (storage_url[0]);
        LOG_msg (APP_LOG, "Using StorageURL: %s", app->storage_url);
        g_strfreev (storage_url);
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

    
    g_option_context_free (context);
/*}}}*/

/*{{{ parse config file */

    // user provided alternative config path
    if (s_config && g_strv_length (s_config) > 0) {
        g_free (conf_path);
        conf_path = g_strdup (s_config[0]);
        g_strfreev (s_config);
    }

    app->conf = conf_create ();

    // parse conf file
    if (stat (conf_path, &st) == -1) {
        // set default values
        LOG_msg (APP_LOG, "Configuration file not found, using default settings.");
        
        conf_add_boolean (app->conf, "log.use_syslog", FALSE);
        
        conf_add_uint (app->conf, "auth.ttl", 85800);
        
        conf_add_int (app->conf, "pool.writers", 2);
        conf_add_int (app->conf, "pool.readers", 2);
        conf_add_int (app->conf, "pool.operations", 4);
        conf_add_uint (app->conf, "pool.max_requests_per_pool", 100);

        conf_add_int (app->conf, "connection.timeout", 20);
        conf_add_int (app->conf, "connection.retries", -1);

        conf_add_uint (app->conf, "filesystem.dir_cache_max_time", 5);
        conf_add_boolean (app->conf, "filesystem.cache_enabled", TRUE);
        conf_add_boolean (app->conf, "filesystem.md5_enabled", FALSE);
        conf_add_string (app->conf, "filesystem.cache_dir", "/tmp/hydrafs");
        conf_add_string (app->conf, "filesystem.cache_dir_max_size", "1Gb");
        conf_add_uint (app->conf, "filesystem.segment_size", 5242880); // 5mb
        conf_add_uint (app->conf, "filesystem.cache_object_ttl", 600); // 10 min

        conf_add_boolean (app->conf, "encryption.enabled", FALSE);
        conf_add_string (app->conf, "encryption.key_file", "");

        conf_add_boolean (app->conf, "statistics.enabled", TRUE);
        conf_add_int (app->conf, "statistics.port", 8011);
    } else {
        LOG_debug (APP_LOG, "Loading configuration file: %s", conf_path);
        if (!conf_parse_file (app->conf, conf_path)) {
            LOG_err (APP_LOG, "Failed to parse configuration file: %s", conf_path);
            return -1;
        }
    }
    g_free (conf_path);

    // add auth data to conf
    conf_add_string (app->conf, "auth.user", app->auth_user);
    conf_add_string (app->conf, "auth.key", app->auth_pwd);

    // update logging settings
    logger_set_syslog (conf_get_boolean (app->conf, "log.use_syslog"));

/*}}}*/
    
    // make sure tmp directory is accessible 
    if (g_access (conf_get_string (app->conf, "filesystem.cache_dir"), F_OK | W_OK) == -1) {
        // try to create it
        int mask;
        // create directory,  drwxr------
        mask = S_IRUSR | S_IWUSR | S_IXUSR;
        if (g_mkdir (conf_get_string (app->conf, "filesystem.cache_dir"), mask) == -1) {
            LOG_err (APP_LOG, "Failed to create temporary directory: %s - %s", conf_get_string (app->conf, "filesystem.cache_dir"), strerror (errno));
            return -1;
        }
    }

    // try to init Encryption
    if (conf_get_boolean (app->conf, "encryption.enabled")) {
        app->enc = hfs_encryption_create (app);
        if (!app->enc)
            return -1;
        LOG_msg (APP_LOG, "Encryption is enabled!");
    } else {
        LOG_msg (APP_LOG, "Encryption is disabled!");
        app->enc = NULL;
    }

    app->auth_client = auth_client_create (app, app->auth_uri);
    if (!app->auth_client) {
        LOG_err (APP_LOG, "Failed to create AuthClient !");
        event_base_loopexit (app->evbase, NULL);
        return -1;
    }

    // create ClientPool for reading operations
    /*
    app->read_client_pool = client_pool_create (app, conf_get_int (app->conf, "pool.readers"),
        http_client_create,
        http_client_destroy,
        http_client_set_on_released_cb,
        http_client_check_rediness
        );
    */
    app->read_client_pool = client_pool_create (app, conf_get_int (app->conf, "pool.readers"),
        http_connection_create,
        http_connection_destroy,
        http_connection_set_on_released_cb,
        http_connection_check_rediness
        );


    if (!app->read_client_pool) {
        LOG_err (APP_LOG, "Failed to create ClientPool !");
        event_base_loopexit (app->evbase, NULL);
        return -1;
    }

    // create ClientPool for writing operations
    app->write_client_pool = client_pool_create (app, conf_get_int (app->conf, "pool.writers"),
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
    app->ops_client_pool = client_pool_create (app, conf_get_int (app->conf, "pool.operations"),
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

    if (!client_pool_get_client (application_get_ops_client_pool (app), application_on_connection_client_cb, app)) {
        LOG_err (APP_LOG, "Failed to get HTTP client !");
        return 1;
    }

    // start the loop
    event_base_dispatch (app->evbase);

    application_destroy (app);

    return 0;
}
