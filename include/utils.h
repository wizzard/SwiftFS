/*  
 * Copyright 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

const gchar *timeval_to_str (struct timeval *tv);
const gchar *secs_to_str (guint64 secs);
guint64 timeval_diff (struct timeval *starttime, struct timeval *finishtime);
void timeval_copy (struct timeval *dst, struct timeval *src);
void timeval_zero (struct timeval *tv);

const gchar *speed_bytes_get_string (guint64 bps);
const gchar *bytes_get_string (guint64 bytes);
#endif
