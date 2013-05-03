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
#include <syslog.h>
#include "log.h"

static gboolean use_syslog = FALSE;

// prints a message string to stdout
// XXX: extend it (syslog, etc)
void logger_log_msg (G_GNUC_UNUSED const gchar *file, G_GNUC_UNUSED gint line, G_GNUC_UNUSED const gchar *func, 
        LogLevel level, const gchar *subsystem,
        const gchar *format, ...)
{
    va_list args;
    char out_str[1024];
    struct tm cur;
    char ts[50];
    time_t t;
    struct tm *cur_p;

    if (log_level < level)
        return;

    t = time (NULL);
    gmtime_r (&t, &cur);
    cur_p = &cur;
    if (!strftime (ts, sizeof (ts), "%H:%M:%S", cur_p)) {
        ts[0] = '\0';
    }

    va_start (args, format);
        g_vsnprintf (out_str, sizeof (out_str), format, args);
    va_end (args);

    if (log_level == LOG_debug) {
        if (level == LOG_err)
            g_fprintf (stdout, "%s \033[1;31m[%s]\033[0m  (%s %s:%d) %s\n", ts, subsystem, func, file, line, out_str);
        else
            g_fprintf (stdout, "%s [%s] (%s %s:%d) %s\n", ts, subsystem, func, file, line, out_str);
    }
    else {
        if (use_syslog)
            syslog (log_level == LOG_msg ? LOG_INFO : LOG_ERR, "%s", out_str);
        else {
            if (level == LOG_err)
                g_fprintf (stdout, "\033[1;31mERROR!\033[0m %s\n", out_str);
            else
                g_fprintf (stdout, "%s\n", out_str);
        }
    }

}

void logger_set_syslog (gboolean use)
{
    use_syslog = use;
}
