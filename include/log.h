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
