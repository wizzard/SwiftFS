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
#ifndef _CONF_PARSER_H_
#define _CONF_PARSER_H_

#include "global.h"

ConfData *conf_create ();
void conf_destroy ();

gboolean conf_parse_file (ConfData *conf, const gchar *filename);

const gchar *conf_get_string (ConfData *conf, const gchar *path);
void conf_add_string (ConfData *conf, const gchar *full_path, const gchar *val);

gint32 conf_get_int (ConfData *conf, const gchar *path);
void conf_add_int (ConfData *conf, const gchar *full_path, gint32 val);

guint32 conf_get_uint (ConfData *conf, const gchar *path);
void conf_add_uint (ConfData *conf, const gchar *full_path, guint32 val);

gboolean conf_get_boolean (ConfData *conf, const gchar *path);
void conf_add_boolean (ConfData *conf, const gchar *full_path, gboolean val);

GList *conf_get_list (ConfData *conf, const gchar *path);
void conf_list_add_string (ConfData *conf, const gchar *full_path, const gchar *val);

void conf_print (ConfData *conf);

typedef void (*ConfNodeChangeCB) (const gchar *path, gpointer user_data);
gboolean conf_set_node_change_cb (ConfData *conf, const gchar *path, ConfNodeChangeCB change_cb, gpointer user_data);

#endif
