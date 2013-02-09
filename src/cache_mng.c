/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "cache_mng.h"
#include "hfs_range.h"

struct _CacheMng {
    Application *app;
    ConfData *conf;

    GHashTable *h_files; // ino -> CacheEntry

    guint64 cache_hits;
};

typedef struct {
    CacheMng *cmng;
    int fd; //rw
    gchar *fname;
    time_t create_time;
    time_t atime;

    HfsRange *range;
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
    cmng->cache_hits = 0;

    //XXX: free cache directory

    return cmng;
}

void cache_mng_destroy (CacheMng *cmng)
{
    g_hash_table_destroy (cmng->h_files);
    g_free (cmng);
}

static CacheEntry *cache_entry_create (CacheMng *cmng, fuse_ino_t ino)
{
    CacheEntry *en;

    en = g_new0 (CacheEntry, 1);
    en->cmng = cmng;
    en->fname = g_strdup_printf ("%s/%"INO_FMT, conf_get_string (cmng->conf, "filesystem.cache_dir"), ino);
    en->create_time = en->atime = time (NULL);
    en->fd = -1;
    en->range = hfs_range_create ();

    en->fd = open (en->fname, O_RDWR | O_NOATIME | O_LARGEFILE | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IXUSR);
    if (en->fd == -1) {
        LOG_err (CMNG_LOG, "Failed to create file %s for read-write: %s", en->fname, strerror (errno));
        cache_entry_destroy (en);
        return NULL;
    }

    return en;
}

static void cache_entry_destroy (CacheEntry *en)
{
    hfs_range_create (en->range);
    g_free (en->fname);
    if (en->fd != -1)
        close (en->fd);
    g_free (en);
}

unsigned char *cache_mng_retr_file_data (CacheMng *cmng, fuse_ino_t ino, size_t size, off_t off)
{
    CacheEntry *en;
    unsigned char *buf = NULL;
    ssize_t out_size;

    if (!conf_get_boolean (cmng->conf, "filesystem.cache_enabled")) {
        return NULL;
    }

    en = g_hash_table_lookup (cmng->h_files, GUINT_TO_POINTER (ino));
    if (!en) {
        return NULL;
    }
    // update access time
    en->atime = time (NULL);

    // check if we have range
    if (!hfs_range_contain (en->range, off, off + size)) {
        hfs_range_print (en->range);
        LOG_debug (CMNG_LOG, "File doesn't have requested bytes [%zu %zu]  for ino: %"INO_FMT, off, off + size, ino);
        return NULL;
    }

    buf = g_new0 (unsigned char, size);
    out_size = pread (en->fd, buf, size, off);
    if (out_size == -1) {
        LOG_debug (CMNG_LOG, "Failed to read from file %s : %s", en->fname, strerror (errno));
        g_free (buf);
        return NULL;
    }

    if (out_size != size) {
        LOG_debug (CMNG_LOG, "File doesn't have requested bytes range %s", en->fname);
        g_free (buf);
        return NULL;
    }

    LOG_debug (CMNG_LOG, "Retrieved [%zu %zu] bytes for ino: %"INO_FMT, off, off + size, ino);
    cmng->cache_hits++;
    return buf;
}


void cache_mng_store_file_data (CacheMng *cmng, fuse_ino_t ino, size_t size, off_t off, unsigned char *buf)
{
    CacheEntry *en;
    ssize_t out_size;
    
    if (!conf_get_boolean (cmng->conf, "filesystem.cache_enabled")) {
        return;
    }

    en = g_hash_table_lookup (cmng->h_files, GUINT_TO_POINTER (ino));
    if (!en) {
        en = cache_entry_create (cmng, ino);
        g_hash_table_insert (cmng->h_files, GUINT_TO_POINTER (ino), en);
    }
    // update access time
    en->atime = time (NULL);

    out_size = pwrite (en->fd, buf, size, off);
    if (out_size == -1) {
        LOG_err (CMNG_LOG, "Failed to write to file %s : %s", en->fname, strerror (errno));
        return;
    }

    // add to range
    hfs_range_add (en->range, off, off + size);

    LOG_debug (CMNG_LOG, "Stored [%zu %zu] bytes for ino: %"INO_FMT, off, off + size, ino);
}


void cache_mng_remove_file_data (CacheMng *cmng, fuse_ino_t ino)
{
    CacheEntry *en;
    
    if (!conf_get_boolean (cmng->conf, "filesystem.cache_enabled")) {
        return;
    }

    g_hash_table_remove (cmng->h_files, GUINT_TO_POINTER (ino));
}
