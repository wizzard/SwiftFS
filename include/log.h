/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _H_LOG_H_
#define _H_LOG_H_

#include "global.h"

enum _LogLevel {
    LOG_err = 0,
    LOG_msg = 1,
    LOG_debug = 2,
};

void logger_log_msg (const gchar *file, gint line, const gchar *func,
        LogLevel level, const gchar *subsystem,
        const gchar *format, ...);

void logger_set_syslog (gboolean use);

#define LOG_debug(subsystem, x...) \
G_STMT_START { \
    logger_log_msg (__FILE__, __LINE__, __func__, LOG_debug, subsystem, x); \
} G_STMT_END

#define LOG_msg(subsystem, x...) \
G_STMT_START { \
    logger_log_msg (__FILE__, __LINE__, __func__, LOG_msg, subsystem, x); \
} G_STMT_END

#define LOG_err(subsystem, x...) \
G_STMT_START { \
    logger_log_msg (__FILE__, __LINE__, __func__, LOG_err, subsystem, x); \
} G_STMT_END

#endif
