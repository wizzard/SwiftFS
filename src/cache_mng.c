/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "cache_mng.h"

struct _CacheMng {
    Application *app;
    ConfData *conf;

    GHashTable *h_files; // ino -> CacheEntry
};

typedef struct {
} CacheEntry;

static void cache_entry_destroy (CacheEntry *en);

#define CMNG_LOG "cmng"

CacheMng *cache_mng_create (Application *app)
{
    CacheMng *cmng;

    cmng = g_new0 (CacheMng, 1);
    cmng->app = app;
    cmng->conf = application_get_conf (app);
    cmng->h_files = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)cache_entry_destroy);

    return cmng;
}

void cache_mng_destroy (CacheMng *cmng)
{
    g_hash_table_destroy (cmng->h_files);
    g_free (cmng);
}

static CacheEntry *cache_entry_create ()
{
    CacheEntry *en;

    en = g_new0 (CacheEntry, 1);

    return en;
}

static void cache_entry_destroy (CacheEntry *en)
{
    g_free (en);
}

unsigned char *cache_mng_retr_file_data (CacheMng *cmng, fuse_ino_t ino, size_t size, off_t off)
{
    CacheEntry *en;
    unsigned char *buf = NULL;


    if (!conf_get_boolean (cmng->conf, "filesystem.cache_enabled")) {
        return NULL;
    }

    en = g_hash_table_lookup (cmng->h_files, GUINT_TO_POINTER (ino));
    if (!en) {
        return NULL;
    }

    return NULL;
}


void cache_mng_store_file_data (CacheMng *cmng, fuse_ino_t ino, size_t size, off_t off, unsigned char *buf)
{
    CacheEntry *en;
    
    if (!conf_get_boolean (cmng->conf, "filesystem.cache_enabled")) {
        return;
    }

    en = g_hash_table_lookup (cmng->h_files, GUINT_TO_POINTER (ino));
    if (!en) {
        en = cache_entry_create ();
        g_hash_table_insert (cmng->h_files, GUINT_TO_POINTER (ino), en);
    }

}
