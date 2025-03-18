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

OSSL_LIB_CTX *app_get0_libctx(void);
const char *app_get0_propq(void);

int opt_provider_path(const char *path);
int app_provider_load(const char *provider_name);
void app_providers_cleanup(void);

int set_base_ui_method(const UI_METHOD *ui_meth);
int setup_ui_method(void);
void destroy_ui_method(void);

EVP_PKEY *FILES_load_key_ex(OSSL_LIB_CTX *libctx, const char *propq,
                            const char *uri, int format, bool maybe_stdin,
                            const char *source, const char *desc);
#define load_key_pwd(uri, format, pass, e, desc) \
    FILES_load_key_ex(app_get0_libctx(), app_get0_propq(), uri, format, false, pass, desc)

EVP_PKEY *FILES_load_pubkey_ex(OSSL_LIB_CTX *libctx, const char *propq,
                               const char *uri, int format, bool maybe_stdin,
                               const char *source, const char *desc);
#define load_pubkey_pwd(uri, format, pass, e, desc) \
    FILES_load_pubkey_ex(app_get0_libctx(), app_get0_propq(), uri, format, false, pass, desc)

X509 *FILES_load_cert_ex(OSSL_LIB_CTX *libctx, const char *propq,
                         const char *uri, int format, bool maybe_stdin,
                         OPTIONAL const char *source, OPTIONAL const char *desc,
                         int type_CA, OPTIONAL const X509_VERIFY_PARAM *vpm);
#define load_cert_pwd(uri, source, desc, type_CA, vpm) \
    FILES_load_cert_ex(app_get0_libctx(), app_get0_propq(), uri, \
                       FILES_get_format(uri), false, source, desc, type_CA, vpm)

bool FILES_load_certs_ex(OSSL_LIB_CTX *libctx, const char *propq,
                         const char *srcs, int format, int timeout, bool maybe_stdin,
                         const char *source, const char *desc, int min_num,
                         int type_CA, OPTIONAL X509_VERIFY_PARAM *vpm,
                         OPTIONAL X509 **cert, OPTIONAL STACK_OF(X509) **certs);
STACK_OF(X509) *load_certs_multifile(const char *files, const char *source,
                                     const char *desc, int type_CA,
                                     OPTIONAL X509_VERIFY_PARAM *vpm);

X509_CRL *FILES_load_crl_ex(OSSL_LIB_CTX *libctx, const char *propq, const char *src,
                            int format, int maybe_stdin, int timeout, OPTIONAL const char *desc,
                            OPTIONAL const X509_VERIFY_PARAM *vpm);
#define load_crl(src, format, stdin, timeout, desc, vpm) \
    FILES_load_crl_ex(app_get0_libctx(), app_get0_propq(), src, format, stdin, timeout, desc, vpm)
STACK_OF(X509_CRL) *FILES_load_crls_ex(OSSL_LIB_CTX *libctx, const char *propq,
                                       const char *files, int format, int timeout,
                                       OPTIONAL const char *desc, int min_num,
                                       OPTIONAL const X509_VERIFY_PARAM *vpm);
#define load_crls(files, format, timeout, desc, vpm)                   \
    FILES_load_crls_ex(app_get0_libctx(), app_get0_propq(), files, format, timeout, desc, 0, vpm)

bool FILES_load_credentials_ex(OPTIONAL OSSL_LIB_CTX *libctx, const char *propq,
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

bool STORE_load_more_check_ex(OSSL_LIB_CTX *libctx, const char *propq,
                              X509_STORE **pstore, const char *file,
                              file_format_t format, const char *source,
                              OPTIONAL const char *desc, int min_certs,
                              OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx *ctx);
X509_STORE *STORE_load_check_ex(OSSL_LIB_CTX *libctx, const char *propq,
                                const char *files, file_format_t format,
                                const char *source, OPTIONAL const char *desc,
                                int min_certs_per_file,
                                OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx *ctx);
#define load_certstore(files, source, desc, vpm) \
    STORE_load_check_ex(app_get0_libctx(), app_get0_propq(), \
                        files, FORMAT_PEM, source, desc, 1, vpm, NULL)
