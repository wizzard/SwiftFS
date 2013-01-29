/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _UTILS_H_
#define _UTILS_H_

#include "global.h"

gchar *get_random_string (size_t len, gboolean readable);
gchar *get_md5_sum (char *buf, size_t len);

#endif
