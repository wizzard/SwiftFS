/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
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
    int bytes_read, written;
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
    conf_add_uint (_app->conf, "encryption.salt1", 1234);
    conf_add_uint (_app->conf, "encryption.salt2", 5678);

    fin = fopen (argv[1], "r");
    g_assert (fin);
    fout = fopen ("file.out", "w");
    g_assert (fout);

    enc = hfs_encryption_create (_app);
    g_assert (enc);

    while ((bytes_read = fread (buf, 1, BUFFER_SIZE, fin)) > 0) {
        unsigned char *in;
        unsigned char *out;
        
        in =  hfs_encryption_encrypt (enc, buf, &bytes_read);
        out = hfs_encryption_decrypt (enc, in, &bytes_read);

        written = fwrite (out, 1, bytes_read, fout);
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
