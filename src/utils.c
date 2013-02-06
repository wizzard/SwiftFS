/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "utils.h"

struct _HfsRange {
};

HfsRange *hfs_range_create ()
{
}

void hfs_range_destroy (HfsRange *range)
{
    g_free (range);
}

void hfs_range_add (HfsRange *range, guint64 start, guint64 end)
{
}

gboolean hfs_range_in (HfsRange *range, guint64 start, guint64 end)
{
}

gchar *get_random_string (size_t len, gboolean readable)
{
    gchar *out;

    out = g_malloc (len + 1);

    if (readable) {
        gchar readable_chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        size_t i;

        for (i = 0; i < len; i++)
            out[i] = readable_chars[rand() % strlen (readable_chars)];
    } else {
        if (!RAND_pseudo_bytes ((unsigned char *)out, len))
            return out;
    }

    *(out + len) = '\0';

    return out;
}

gchar *get_md5_sum (const char *buf, size_t len)
{
    unsigned char digest[16];
    gchar *out;
    size_t i;

    MD5 ((const unsigned char *)buf, len, digest);

    out = g_malloc (33);
    for (i = 0; i < 16; ++i)
        sprintf(&out[i*2], "%02x", (unsigned int)digest[i]);

    return out;
}


gboolean uri_is_https (const struct evhttp_uri *uri)
{
    const char *scheme;

    if (!uri)
        return FALSE;

    scheme = evhttp_uri_get_scheme (uri);
    if (!scheme)
        return FALSE;

    if (!strncasecmp ("https", scheme, 5))
        return TRUE;
    
    return FALSE;
}

gint uri_get_port (const struct evhttp_uri *uri)
{
    gint port;

    port = evhttp_uri_get_port (uri);

    // if no port is specified, libevent returns -1
    if (port == -1) {
        if (uri_is_https (uri))
            port = 443;
        else
            port = 80;
    }

    return port;
}


