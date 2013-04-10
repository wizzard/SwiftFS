/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#include "utils.h"
#include <ftw.h>

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

static int on_unlink_cb (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    int rv = remove (fpath);

    if (rv)
        perror (fpath);

    return rv;
}

// remove directory tree
int utils_del_tree (const gchar *path)
{
    return nftw (path, on_unlink_cb, 100, FTW_DEPTH | FTW_PHYS);
}

#define HOSTNAME_MAX_SIZE 255
static HostnameValidationResult matches_common_name (const char *hostname, const X509 *server_cert) {
	int common_name_loc = -1;
	X509_NAME_ENTRY *common_name_entry = NULL;
	ASN1_STRING *common_name_asn1 = NULL;
	char *common_name_str = NULL;

	// Find the position of the CN field in the Subject field of the certificate
	common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name((X509 *) server_cert), NID_commonName, -1);
	if (common_name_loc < 0) {
		return Error;
	}

	// Extract the CN field
	common_name_entry = X509_NAME_get_entry(X509_get_subject_name((X509 *) server_cert), common_name_loc);
	if (common_name_entry == NULL) {
		return Error;
	}

	// Convert the CN field to a C string
	common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
	if (common_name_asn1 == NULL) {
		return Error;
	}			
	common_name_str = (char *) ASN1_STRING_data(common_name_asn1);

	// Make sure there isn't an embedded NUL character in the CN
	if (ASN1_STRING_length(common_name_asn1) != strlen(common_name_str)) {
		return MalformedCertificate;
	}

	// Compare expected hostname with the CN
	if (strcasecmp(hostname, common_name_str) == 0) {
		return MatchFound;
	}
	else {
		return MatchNotFound;
	}
}

static HostnameValidationResult matches_subject_alternative_name (const char *hostname, const X509 *server_cert) {
	HostnameValidationResult result = MatchNotFound;
	int i;
	int san_names_nb = -1;
	STACK_OF(GENERAL_NAME) *san_names = NULL;

	// Try to extract the names within the SAN extension from the certificate
	san_names = X509_get_ext_d2i((X509 *) server_cert, NID_subject_alt_name, NULL, NULL);
	if (san_names == NULL) {
		return NoSANPresent;
	}
	san_names_nb = sk_GENERAL_NAME_num(san_names);

	// Check each name within the extension
	for (i=0; i<san_names_nb; i++) {
		const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);

		if (current_name->type == GEN_DNS) {
			// Current name is a DNS name, let's check it
			char *dns_name = (char *) ASN1_STRING_data(current_name->d.dNSName);

			// Make sure there isn't an embedded NUL character in the DNS name
			if (ASN1_STRING_length(current_name->d.dNSName) != strlen(dns_name)) {
				result = MalformedCertificate;
				break;
			}
			else { // Compare expected hostname with the DNS name
				if (strcasecmp(hostname, dns_name) == 0) {
					result = MatchFound;
					break;
				}
			}
		}
	}
	sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

	return result;
}

HostnameValidationResult validate_hostname (const char *hostname, const X509 *server_cert) {
	HostnameValidationResult result;

	if((hostname == NULL) || (server_cert == NULL))
		return Error;

	// First try the Subject Alternative Names extension
	result = matches_subject_alternative_name(hostname, server_cert);
	if (result == NoSANPresent) {
		// Extension was not found: try the Common Name
		result = matches_common_name(hostname, server_cert);
	}

	return result;
}

const gchar *timeval_to_str (struct timeval *tv)
{
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64], buf[64];

    nowtime = tv->tv_sec;
    nowtm = localtime (&nowtime);
    strftime (tmbuf, sizeof tmbuf, "%H:%M:%S", nowtm);
    snprintf (buf, sizeof buf, "%s.%06d", tmbuf, tv->tv_usec);

    return buf;
}

guint64 timeval_diff (struct timeval *starttime, struct timeval *finishtime)
{
    guint64 msec = 0;
    
    // special case, when finishtime is not set
    if (!finishtime->tv_sec && !finishtime->tv_usec)
        return 0;

    if (finishtime->tv_sec > starttime->tv_sec) {
        msec = (guint64)((finishtime->tv_sec - starttime->tv_sec) * 1000);
        msec += (guint64)((finishtime->tv_usec - starttime->tv_usec) / 1000);
    } else if (finishtime->tv_usec > starttime->tv_usec) {
        msec = (guint64)((finishtime->tv_usec - starttime->tv_usec) / 1000);
    }
    
    return msec;
}

void timeval_copy (struct timeval *dst, struct timeval *src)
{
    dst->tv_sec = src->tv_sec;
    dst->tv_usec = src->tv_usec;
}

void timeval_zero (struct timeval *tv)
{
    tv->tv_sec = 0;
    tv->tv_usec = 0;
}

#define GB (1024 * 1024 * 1024)
#define MB (1024 * 1024)
#define KB (1024)
const gchar *speed_bytes_get_string (guint64 bps)
{
    static gchar out[30];
    gdouble tmp;
    
    if (bps >= MB) {
        tmp = (gdouble)bps / (gdouble)MB;
        g_snprintf (out, sizeof (out), "%.2fMb/s", tmp);
    } else if (bps >= KB) {
        tmp = (gdouble)bps / (gdouble)KB;
        g_snprintf (out, sizeof (out), "%.2fKb/s", tmp);
    } else {
        tmp = (gdouble)bps;
        g_snprintf (out, sizeof (out), "%.2fb/s", tmp);
    }

    return out;
}

const gchar *bytes_get_string (guint64 bytes)
{
    static gchar out[30];
    gdouble tmp;
    
    if (bytes >= GB) {
        tmp = (gdouble)bytes / (gdouble)GB;
        g_snprintf (out, sizeof (out), "%.2fGb", tmp);
    } else if (bytes >= MB) {
        tmp = (gdouble)bytes / (gdouble)MB;
        g_snprintf (out, sizeof (out), "%.2fMb", tmp);
    } else if (bytes >= KB) {
        tmp = (gdouble)bytes / (gdouble)KB;
        g_snprintf (out, sizeof (out), "%.2fKb", tmp);
    } else {
        tmp = (gdouble)bytes;
        g_snprintf (out, sizeof (out), "%.2fb", tmp);
    }

    return out;
}

