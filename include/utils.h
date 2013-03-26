/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _UTILS_H_
#define _UTILS_H_

#include "global.h"

gchar *get_random_string (size_t len, gboolean readable);
gchar *get_md5_sum (const char *buf, size_t len);

// return TRUE if URI scheme is HTTPS
gboolean uri_is_https (const struct evhttp_uri *uri);

//return URI port, or default one (80 for HTTP, 443 for HTTPS)
gint uri_get_port (const struct evhttp_uri *uri);

int utils_del_tree (const gchar *path);

typedef enum {
	MatchFound,
	MatchNotFound,
	NoSANPresent,
	MalformedCertificate,
	Error
} HostnameValidationResult;
HostnameValidationResult validate_hostname (const char *hostname, const X509 *server_cert);

#endif
