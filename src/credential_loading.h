/*-
 * @file   credential_loading.h
 * @brief  generic CMP client CLI helper functions like in OpenSSL apps
 *
 * @author David von Oheimb, Siemens AG, David.von.Oheimb@siemens.com
 *
 *  Copyright 2007-2025 The OpenSSL Project Authors. All Rights Reserved.
 *  Copyright (c) 2025 Siemens AG
 *
 *  Licensed under the Apache License 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You can obtain a copy in the file LICENSE in the source distribution
 *  or at https://www.openssl.org/source/license.html
 *  SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "creds.h"

int app_set_propq(const char *arg);
const char *app_get0_propq(void);
OSSL_LIB_CTX *app_get0_libctx(void);
OSSL_LIB_CTX *app_create_libctx(void);

int opt_provider_path(const char *path);
int app_provider_load(OPTIONAL OSSL_LIB_CTX *libctx, const char *provider_name);
void app_providers_cleanup(void);

#define load_key_pwd(uri, format, pass, e, desc) \
    CREDS_load_key_ex(app_get0_libctx(), app_get0_propq(), uri, format, false, pass, desc)

#define load_pubkey_pwd(uri, format, pass, e, desc) \
    CREDS_load_pubkey_ex(app_get0_libctx(), app_get0_propq(), uri, format, false, pass, desc)

#define load_cert_pwd(uri, source, desc, type_CA, vpm) \
    CREDS_load_cert_ex(app_get0_libctx(), app_get0_propq(), uri, \
                       FILES_get_format(uri), false, 0, source, desc, type_CA, vpm)
#define load_crl(uri, format, stdin, timeout, desc, vpm) \
    CREDS_load_crl_ex(app_get0_libctx(), app_get0_propq(), uri, format, stdin, timeout, desc, vpm)
#define load_crls(files, format, timeout, desc, vpm) \
    CREDS_load_crls_ex(app_get0_libctx(), app_get0_propq(), files, format, timeout, desc, 0, vpm)

#define load_certstore(files, source, desc, vpm) \
    STORE_load_check_ex(app_get0_libctx(), app_get0_propq(), \
                        files, FORMAT_PEM, source, desc, 1, vpm, NULL)

STACK_OF(X509) *load_certs_multifile(const char *files, OPTIONAL const char *source,
                                     const char *desc, int type_CA,
                                     OPTIONAL X509_VERIFY_PARAM *vpm);
