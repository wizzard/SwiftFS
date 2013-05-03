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
#include "global.h"
#include "hfs_encryption.h"

#define ENC_TEST "enc_test"

struct _Application {
    ConfData *conf;
};

static Application *_app;

#define BUFFER_SIZE 1024

ConfData *application_get_conf (Application *app)
{
    return app->conf;
}

int main(int argc, char **argv)
{
    FILE *fin, *fout;
    HfsEncryption *enc;
    int bytes_read, written, in_bytes, out_bytes;
    int len;
    unsigned char buf[BUFFER_SIZE];

    log_level = LOG_debug;

    // init libraries
    ENGINE_load_builtin_engines ();
    ENGINE_register_all_complete ();
    
    if (argc < 2) {
        LOG_err (ENC_TEST, "%s path_to_file\n", argv[0]);
        exit (1);
    }
    
    _app = g_new0 (Application, 1);
    _app->conf = conf_create ();
    
    conf_add_boolean (_app->conf, "encryption.enabled", TRUE);
    conf_add_string (_app->conf, "encryption.key_file", "file.in");

    fin = fopen (argv[1], "r");
    g_assert (fin);
    fout = fopen ("file.out", "w");
    g_assert (fout);

    enc = hfs_encryption_create (_app);
    g_assert (enc);

    while ((bytes_read = fread (buf, 1, BUFFER_SIZE, fin)) > 0) {
        unsigned char *in;
        unsigned char *out;
        
        in_bytes = bytes_read;
        in =  hfs_encryption_encrypt (enc, buf, &in_bytes);
        out_bytes = in_bytes;
        out = hfs_encryption_decrypt (enc, in, &out_bytes);

        LOG_debug (ENC_TEST, "In bytes: %d Out bytes: %d  Orig: %d", in_bytes, out_bytes, bytes_read);

        written = fwrite (out, 1, out_bytes, fout);
        free (in);
        free (out);
    }
    hfs_encryption_destroy (enc);

    fclose (fin);
    fclose (fout);

    conf_destroy (_app->conf);
    g_free (_app);

    return 0;
}
