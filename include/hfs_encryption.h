/* Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.txt', which is part of this source code package.
 */
#ifndef _HFS_ENCRYPTION_H_
#define _HFS_ENCRYPTION_H_

#include "global.h"

HfsEncryption *hfs_encryption_create (Application *app);
void hfs_encryption_destroy (HfsEncryption *enc);

unsigned char *hfs_encryption_encrypt (HfsEncryption *enc, unsigned char *buf, int *len);
unsigned char *hfs_encryption_decrypt (HfsEncryption *enc, unsigned char *buf, int *len);

#endif
