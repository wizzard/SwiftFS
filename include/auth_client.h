/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _AUTH_CLIENT_H_
#define _AUTH_CLIENT_H_

#include "global.h"

AuthClient *auth_client_create (Application *app, const struct evhttp_uri *auth_server_uri);
void auth_client_destroy (AuthClient *auth_client);

// return auth_token and storage_uri, owned by AuthClient
// success TRUE if Ok
typedef void (*AuthClient_on_data) (gpointer ctx, gboolean success, 
    const gchar *auth_token, const struct evhttp_uri *storage_uri);

// returns requested data at once if cache is not expired
// or performs HTTP request to the server
// set force = TRUE to ignore cached values
void auth_client_get_data (AuthClient *auth_client, gboolean force, AuthClient_on_data on_data, const gpointer ctx);

#endif
