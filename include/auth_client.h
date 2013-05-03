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
#ifndef _AUTH_CLIENT_H_
#define _AUTH_CLIENT_H_

#include "global.h"

AuthClient *auth_client_create (Application *app, const struct evhttp_uri *auth_server_uri);
void auth_client_destroy (AuthClient *auth_client);

// return auth_token and storage_uri, owned by AuthClient
// success TRUE if Ok
typedef void (*AuthClient_on_data) (gpointer ctx, gboolean success, 
    const gchar *auth_token, const gchar *storage_uri);

// returns requested data at once if cache is not expired
// or performs HTTP request to the server
// set force = TRUE to ignore cached values
void auth_client_get_data (AuthClient *auth_client, gboolean force, AuthClient_on_data on_data, const gpointer ctx);

#endif
