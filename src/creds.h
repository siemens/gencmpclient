/*-
 * @file   creds.h
 * @brief  helper functions for loading credentials via OSSL_STORE and HTTP
 *
 * @author David von Oheimb, Siemens AG, David.von.Oheimb@siemens.com
 *
 *  Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *  Copyright (c) 2025 Siemens AG
 *
 *  Licensed under the Apache License 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You can obtain a copy in the file LICENSE in the source distribution
 *  or at https://www.openssl.org/source/license.html
 *  SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/ui.h>
#include <openssl/http.h>
#include <openssl/pem.h>

#include <secutils/credentials/store.h>
#include <secutils/storage/files.h> /* for file_format_t */

/* from OpenSSL/apps/lib/apps.c: */

/* TODO add documenting comments and move to new file libsecutils/src/libsecutils/include/secutils/credentials/creds.h: */
int set_base_ui_method(const UI_METHOD *ui_meth);
int setup_ui_method(void);
void destroy_ui_method(void);

EVP_PKEY *CREDS_load_key_ex(OPTIONAL OSSL_LIB_CTX *libctx, const char *propq,
                            OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                            OPTIONAL const char *source, OPTIONAL const char *desc);
EVP_PKEY *CREDS_load_pubkey_ex(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                               OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                               OPTIONAL const char *source, OPTIONAL const char *desc);
X509 *CREDS_load_cert_ex(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                         OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                         int timeout, OPTIONAL const char *source, OPTIONAL const char *desc,
                         int type_CA, OPTIONAL const X509_VERIFY_PARAM *vpm);
bool CREDS_load_certs_ex(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                         const char *srcs, file_format_t format, int timeout,
                         OPTIONAL const char *source, OPTIONAL const char *desc, int min_num,
                         int type_CA, OPTIONAL X509_VERIFY_PARAM *vpm,
                         OPTIONAL X509 **cert, OPTIONAL STACK_OF(X509) **certs);
X509_CRL *CREDS_load_crl_ex(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                            OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                            int timeout, OPTIONAL const char *desc,
                            OPTIONAL const X509_VERIFY_PARAM *vpm);
STACK_OF(X509_CRL) *CREDS_load_crls_ex(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                                       const char *srcs, file_format_t format, int timeout,
                                       OPTIONAL const char *desc, int min_num,
                                       OPTIONAL const X509_VERIFY_PARAM *vpm);
bool CREDS_load_credentials_ex(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                               OPTIONAL const char *certs, OPTIONAL const char *key,
                               file_format_t format, bool maybe_stdin,
                               OPTIONAL const char *source, OPTIONAL const char *desc,
                               OPTIONAL X509_VERIFY_PARAM *vpm, int type_CA,
                               OPTIONAL EVP_PKEY **pkey, OPTIONAL X509 **cert,
                               OPTIONAL STACK_OF(X509) **chain);
CREDENTIALS *CREDENTIALS_load_ex(OPTIONAL OSSL_LIB_CTX *libctx, const char *propq,
                                 OPTIONAL const char *certs, OPTIONAL const char *key,
                                 OPTIONAL const char *source,
                                 OPTIONAL const char *desc,
                                 OPTIONAL X509_VERIFY_PARAM *vpm);

/* TODO add documenting comments and move to libsecutils/src/libsecutils/include/secutils/credentials/store.h: */
bool STORE_load_more_check_ex(OSSL_LIB_CTX *libctx, const char *propq,
                              X509_STORE **pstore, const char *file,
                              file_format_t format, OPTIONAL const char *source,
                              OPTIONAL const char *desc, int min_certs,
                              OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx *ctx);
X509_STORE *STORE_load_check_ex(OSSL_LIB_CTX *libctx, const char *propq,
                                const char *files, file_format_t format,
                                OPTIONAL const char *source, OPTIONAL const char *desc,
                                int min_certs_per_file,
                                OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx *ctx);

