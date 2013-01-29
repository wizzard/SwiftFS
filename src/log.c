/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
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

    if (log_level == LOG_debug)
        g_fprintf (stdout, "%s [%s] (%s %s:%d) %s\n", ts, subsystem, func, file, line, out_str);
    else {
        if (use_syslog)
            syslog (log_level == LOG_msg ? LOG_INFO : LOG_ERR, out_str);
        else
            g_fprintf (stdout, "%s\n", out_str);
    }

}

void logger_set_syslog (gboolean use)
{
    use_syslog = use;
}
