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

#ifndef GENCMP_NO_SECUTILS
#include <secutils/storage/files.h> /* for file_format_t */
#include <secutils/storage/uta_api.h> /* for utx_ctx */
#else
#include "genericCMPClient_util.h"
#endif

int app_set_propq(OPTIONAL const char *arg);
const char *app_get0_propq(void);
OSSL_LIB_CTX *app_get0_libctx(void);
OSSL_LIB_CTX *app_create_libctx(void);

int app_set_provider_path(OPTIONAL const char *path);
int app_provider_load(OPTIONAL OSSL_LIB_CTX *libctx, const char *provider_name);
void app_providers_cleanup(void);

int set_base_ui_method(const UI_METHOD *ui_meth);
int setup_ui_method(void);
void destroy_ui_method(void);

EVP_PKEY *CREDS_load_key(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                         OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                         OPTIONAL const char *source, OPTIONAL const char *desc);
#define app_load_key(uri, pass, desc) \
    CREDS_load_key(app_get0_libctx(), app_get0_propq(), uri, FORMAT_UNDEF, false, pass, desc)

EVP_PKEY *CREDS_load_pubkey(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                            OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                            OPTIONAL const char *source, OPTIONAL const char *desc);
#define app_load_pubkey_pwd(uri, format, pass, e, desc) \
    CREDS_load_pubkey(app_get0_libctx(), app_get0_propq(), uri, format, false, pass, desc)

X509 *CREDS_load_cert(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                      OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                      OPTIONAL X509_STORE *tls_ts, int timeout,
                      OPTIONAL const char *source, OPTIONAL const char *desc,
                      int type_CA, OPTIONAL const X509_VERIFY_PARAM *vpm);
#define app_load_cert(uri, source, desc, type_CA, vpm) \
    CREDS_load_cert(app_get0_libctx(), app_get0_propq(), uri, FORMAT_UNDEF, \
                    false, NULL, -1, source, desc, type_CA, vpm)

STACK_OF(X509) *CREDS_load_certs(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                                 const char *srcs, file_format_t format, bool maybe_stdin,
                                 OPTIONAL X509_STORE *tls_ts, int timeout,
                                 OPTIONAL const char *source, OPTIONAL const char *desc,
                                 int min_num, int type_CA, OPTIONAL X509_VERIFY_PARAM *vpm);
#define app_load_certs(srcs, tls_ts, timeout, source, desc, type_CA, vpm) \
    CREDS_load_certs(app_get0_libctx(), app_get0_propq(), srcs, FORMAT_UNDEF, \
                     false, tls_ts, timeout, source, desc, 1, type_CA, vpm)

X509_CRL *CREDS_load_crl(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                         OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                         OPTIONAL X509_STORE *tls_ts, int timeout, OPTIONAL const char *desc,
                         OPTIONAL const X509_VERIFY_PARAM *vpm);
#define app_load_crl(uri, timeout, desc, vpm) \
    CREDS_load_crl(app_get0_libctx(), app_get0_propq(), uri, \
                   FORMAT_UNDEF, false, NULL, timeout, desc, vpm)
STACK_OF(X509_CRL) *CREDS_load_crls(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                                    const char *srcs, file_format_t format, bool maybe_stdin,
                                    OPTIONAL X509_STORE *tls_ts, int timeout,
                                    OPTIONAL const char *desc, int min_num,
                                    OPTIONAL const X509_VERIFY_PARAM *vpm);
#define app_load_crls(files, timeout, desc, vpm) \
    CREDS_load_crls(app_get0_libctx(), app_get0_propq(), files, FORMAT_UNDEF, \
                    false, NULL, timeout, desc, 0, vpm)

bool CREDS_load_credentials(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                            OPTIONAL const char *certs, OPTIONAL const char *key,
                            file_format_t format, bool maybe_stdin,
                            OPTIONAL const char *source, OPTIONAL const char *desc,
                            int type_CA, OPTIONAL X509_VERIFY_PARAM *vpm,
                            OPTIONAL EVP_PKEY **pkey, OPTIONAL X509 **cert,
                            OPTIONAL STACK_OF(X509) **chain);
CREDENTIALS *CREDS_load(OPTIONAL OSSL_LIB_CTX *libctx, const char *propq,
                        OPTIONAL const char *certs, OPTIONAL const char *key,
                        OPTIONAL const char *source,
                        OPTIONAL const char *desc,
                        OPTIONAL X509_VERIFY_PARAM *vpm);
#define app_load_creds(certs, key, source, desc, vpm) \
    CREDS_load(app_get0_libctx(), app_get0_propq(), certs, key, source, desc, vpm)

bool STORE_load_more_check_ex(OSSL_LIB_CTX *libctx, const char *propq,
                              X509_STORE **pstore, const char *uri,
                              file_format_t format,
                              OPTIONAL X509_STORE *tls_ts, int timeout,
                              OPTIONAL const char *source,
                              OPTIONAL const char *desc, int min_certs,
                              OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx *ctx);
X509_STORE *STORE_load_check_ex(OSSL_LIB_CTX *libctx, const char *propq,
                                const char *srcs, file_format_t format,
                                OPTIONAL X509_STORE *tls_ts, int timeout,
                                OPTIONAL const char *source, OPTIONAL const char *desc,
                                int min_certs_per_file,
                                OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx *ctx);
#define app_load_certstore(srcs, source, desc, vpm) \
    STORE_load_check_ex(app_get0_libctx(), app_get0_propq(), srcs, FORMAT_UNDEF, \
                        NULL, -1, source, desc, 1, vpm, NULL)

#ifdef GENCMP_NO_SECUTILS
bool FILES_store_key(const EVP_PKEY *pkey, const char *file, bool must_exist,
                     file_format_t format,
                     OPTIONAL const char *source, OPTIONAL const char *desc);
int FILES_store_certs(OPTIONAL const STACK_OF(X509) *certs, const char *file,
                      bool must_exist, file_format_t format,
                      OPTIONAL const char *desc);
int FILES_store_crls(const STACK_OF(X509_CRL) *crls, const char *file,
                     bool must_exist, file_format_t format,
                     OPTIONAL const char *desc);
#endif
