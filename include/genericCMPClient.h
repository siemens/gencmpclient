/*-
 * @file   genericCMPClient.h
 * @brief  generic CMP client library API
 *
 * @author David von Oheimb, Siemens AG, David.von.Oheimb@siemens.com
 *
 *  Copyright (c) 2017-2025 Siemens AG
 *  Licensed under the Apache License 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You can obtain a copy in the file LICENSE in the source distribution
 *  or at https://www.openssl.org/source/license.html
 *  SPDX-License-Identifier: Apache-2.0
 */

#ifndef GENERIC_CMP_CLIENT_H
# define GENERIC_CMP_CLIENT_H

# include "genericCMPClient_config.h"

# ifdef __cplusplus
extern "C" {
# endif

# include <openssl/opensslv.h>

# define OPENSSL_3_2_FEATURES (OPENSSL_VERSION_NUMBER >= 0x30200000L || defined(USE_LIBCMP))
# define OPENSSL_3_3_FEATURES (OPENSSL_VERSION_NUMBER >= 0x30300000L || defined(USE_LIBCMP))
# define OPENSSL_3_4_FEATURES (OPENSSL_VERSION_NUMBER >= 0x30400000L || defined(USE_LIBCMP))
# define OPENSSL_4_0_FEATURES (OPENSSL_VERSION_NUMBER >= 0x40000000L || defined(USE_LIBCMP))

# if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(USE_LIBCMP)
#  include <openssl/openssl_backport.h> /* if not found, maybe genericCMPClient_config.h is not up to date w.r.t. USE_LIBCMP, or OpenSSL version < 3.0 not correctly detected in CMakeLists.txt or Makefile_v1 */
# endif
/* for low-level CMP API, in particular, type OSSL_CMP_CTX */
# include <openssl/cmp.h>
/* for abbreviation and backward compatibility: */
typedef OSSL_CMP_CTX CMP_CTX;

# if OPENSSL_VERSION_NUMBER < 0x30000080L
#  define OSSL_CMP_PKISTATUS_request                -3
#  define OSSL_CMP_PKISTATUS_trans                  -2
#  define OSSL_CMP_PKISTATUS_unspecified            -1
# endif

# if OPENSSL_VERSION_NUMBER < 0x30200000L && !defined(USE_LIBCMP) /* == !(OPENSSL_3_2_FEATURES) */
static ossl_inline
OSSL_LIB_CTX *OSSL_CMP_CTX_get0_libctx(ossl_unused const OSSL_CMP_CTX *ctx)
{
    return NULL; /* sorry, dummy */
}
static ossl_inline
const char *OSSL_CMP_CTX_get0_propq(ossl_unused const OSSL_CMP_CTX *ctx)
{
    return NULL; /* sorry, dummy */
}
#  define SN_id_mod_cmp2000_02            "id-mod-cmp2000-02"
#  define NID_id_mod_cmp2000_02           1251
#  define OBJ_id_mod_cmp2000_02           OBJ_id_pkix_mod, 50L
#  define SN_id_mod_cmp2021_88            "id-mod-cmp2021-88"
#  define NID_id_mod_cmp2021_88           1252
#  define OBJ_id_mod_cmp2021_88           OBJ_id_pkix_mod, 99L
#  define SN_id_mod_cmp2021_02            "id-mod-cmp2021-02"
#  define NID_id_mod_cmp2021_02           1253
#  define OBJ_id_mod_cmp2021_02           OBJ_id_pkix_mod, 100L
#  define SN_id_it_rootCaCert             "id-it-rootCaCert"
#  define NID_id_it_rootCaCert            1254
#  define OBJ_id_it_rootCaCert            OBJ_id_it, 20L
#  define SN_id_it_certProfile            "id-it-certProfile"
#  define NID_id_it_certProfile           1255
#  define OBJ_id_it_certProfile           OBJ_id_it, 21L
#  define SN_id_it_crlStatusList          "id-it-crlStatusList"
#  define NID_id_it_crlStatusList         1256
#  define OBJ_id_it_crlStatusList         OBJ_id_it, 22L
#  define SN_id_it_crls                   "id-it-crls"
#  define NID_id_it_crls                  1257
#  define OBJ_id_it_crls                  OBJ_id_it, 23L
#  define SN_id_regCtrl_altCertTemplate   "id-regCtrl-altCertTemplate"
#  define NID_id_regCtrl_altCertTemplate  1258
#  define OBJ_id_regCtrl_altCertTemplate  OBJ_id_regCtrl, 7L
#  define SN_id_regCtrl_algId             "id-regCtrl-algId"
#  define NID_id_regCtrl_algId            1259
#  define OBJ_id_regCtrl_algId            OBJ_id_regCtrl, 11L
#  define SN_id_regCtrl_rsaKeyLen         "id-regCtrl-rsaKeyLen"
#  define NID_id_regCtrl_rsaKeyLen        1260
#  define OBJ_id_regCtrl_rsaKeyLen        OBJ_id_regCtrl, 12L
# endif

# define CMPCLIENT_MODULE_NAME "genCMPClient"

typedef int CMP_err;
# define CMP_OK                   0
# define CMP_R_OTHER_LIB_ERR      99
# define CMP_R_LOAD_CERTS         255
# define CMP_R_LOAD_CREDS         254
# define CMP_R_GENERATE_KEY       253
# define CMP_R_STORE_CREDS        252
# define CMP_R_RECIPIENT          251
# define CMP_R_INVALID_CONTEXT    250
# if OPENSSL_VERSION_NUMBER < 0x30400000L || defined(USE_LIBCMP)
/* workaround for non-matching definitions */
#  define CMP_R_GET_ITAV           249
#  define CMP_R_GENERATE_CRLSTATUS 246
# endif
# define CMP_R_INVALID_CACERTS    248
# define CMP_R_INVALID_ROOTCAUPD  247
# define CMP_R_INVALID_CRL_LIST   245
# define CMP_R_INVALID_PARAMETERS CMP_R_INVALID_ARGS

/* further error codes are defined in cmperr.h */

# define CMP_IR    0 /* OSSL_CMP_PKIBODY_IR */
# define CMP_CR    2 /* OSSL_CMP_PKIBODY_CR */
# define CMP_P10CR 4 /* OSSL_CMP_PKIBODY_P10CR */
# define CMP_KUR   7 /* OSSL_CMP_PKIBODY_KUR */

# ifndef GENCMP_NO_SECUTILS
/* # define LOCAL_DEFS */
#  ifdef LOCAL_DEFS
#   include "genericCMPClient_imports.h"
#  else
#   include <secutils/util/log.h> /* for severity and LOG_cb_t */
#  endif
# else
#  define GENCMP_NO_HELPERS
#  include "genericCMPClient_util.h"
# endif /* ndef GENCMP_NO_SECUTILS */

/* CMP client core functions */
/* should be called once, as soon as the application starts */
CMP_err CMPclient_init(OPTIONAL const char *name, OPTIONAL LOG_cb_t log_fn);

/* must be called first */
CMP_err CMPclient_prepare(CMP_CTX **pctx,
                          OPTIONAL OSSL_LIB_CTX *libctx,
                          OPTIONAL const char *propq,
                          OPTIONAL LOG_cb_t log_fn,
                          OPTIONAL X509_STORE *cmp_truststore,
                          OPTIONAL const char *recipient,
                          OPTIONAL const STACK_OF(X509) *untrusted,
                          OPTIONAL const CREDENTIALS *creds,
                          OPTIONAL X509_STORE *creds_truststore,
                          OPTIONAL const char *digest,
                          OPTIONAL const char *mac,
                          OPTIONAL OSSL_CMP_transfer_cb_t transfer_fn,
                          int total_timeout,
                          OPTIONAL X509_STORE *new_cert_truststore,
                          bool implicit_confirm);

/* call next if the transfer_fn is NULL and no existing connection is used */
/* Will return error when used with OpenSSL compiled with OPENSSL_NO_SOCK. */
CMP_err CMPclient_setup_HTTP(CMP_CTX *ctx, const char *server, const char *path,
                             int keep_alive, int timeout, OPTIONAL SSL_CTX *tls,
                             OPTIONAL const char *proxy,
                             OPTIONAL const char *no_proxy);
/* call alternatively if transfer_fn is NULL and existing connection is used */
CMP_err CMPclient_setup_BIO(CMP_CTX *ctx, BIO *rw, OPTIONAL const char *path,
                            int keep_alive, int timeout);

# if OPENSSL_3_3_FEATURES
/* call optionally before requests; name may be UTF8-encoded string */
/* This calls OSSL_CMP_CTX_reset_geninfo_ITAVs() if name == NULL */
CMP_err CMPclient_add_certProfile(CMP_CTX *ctx, OPTIONAL const char *name);
# endif

/*-
 * @brief fill the cert template used for certificate requests (ir/cr/p10cr/kur)
 *
 * @param |ctx| CMP context to be used for implicit parameters, may get updated
 * @param |new_key| key pair to be certified;
 *        defaults to key in |csr| or |creds->key|
 * @param |old_cert| reference cert to be updated (kur),
 *        defaults to data in |csr| or |creds->cert|
 * @param |subject| to use; defaults to subject of |csr| or
 *        of reference cert for KUR, while this default is is not used for IR
 *        and CR if the |exts| or |csr| contain SANs.
 * @param |exts| X.509v3 extensions to use.  Extensions provided via
 *        the |csr| parameter are augmented or overridden individually.
 *        SANs default to SANs contained in the reference cert |old_cert|.
 * @param |csr| PKCS#10 structure directly used for P10CR command,
 *        else its contents are transformed.
 * @note All 'const' parameters are copied (and need to be freed by the caller).
 * @return CMP_OK on success, else CMP error code
 */
CMP_err CMPclient_setup_certreq(CMP_CTX *ctx,
                                OPTIONAL const EVP_PKEY *new_key,
                                OPTIONAL const X509 *old_cert,
                                OPTIONAL const X509_NAME *subject,
                                OPTIONAL const X509_EXTENSIONS *exts,
                                OPTIONAL const X509_REQ *csr);

/*-
 * Either the internal CMPclient_enroll() or the specific CMPclient_imprint(),
 * CMPclient_bootstrap(), CMPclient_pkcs10(), or CMPclient_update[_anycert]())
 * or CMPclient_revoke() can be called next.
 */
/* the structure returned in *new_creds must be freed by the caller */
/*
 * @brief perform the given type of certificate request (ir/cr/p10cr/kur)
 *
 * @param |ctx| CMP context to be used for implicit parameters, may get updated
 * @param |new_creds| pointer to variable where to store new credentials
 *        including enrolled certificate
 * @param |cmd| the type of request to be performed:
 *        CMP_IR, CMP_CR, CMP_P10CR, or CMP_KUR
 * @return CMP_OK on success, else CMP error code
 */
CMP_err CMPclient_enroll(CMP_CTX *ctx, CREDENTIALS **new_creds, int cmd);
CMP_err CMPclient_imprint(CMP_CTX *ctx, CREDENTIALS **new_creds,
                          const EVP_PKEY *new_key, const char *subject,
                          OPTIONAL const X509_EXTENSIONS *exts);
CMP_err CMPclient_bootstrap(CMP_CTX *ctx, CREDENTIALS **new_creds,
                            const EVP_PKEY *new_key, const char *subject,
                            OPTIONAL const X509_EXTENSIONS *exts);
CMP_err CMPclient_pkcs10(CMP_CTX *ctx, CREDENTIALS **new_creds,
                         const X509_REQ *csr);
CMP_err CMPclient_update(CMP_CTX *ctx, CREDENTIALS **new_creds,
                         OPTIONAL const EVP_PKEY *new_key);
CMP_err CMPclient_update_anycert(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                                 OPTIONAL const X509 *old_cert,
                                 OPTIONAL const EVP_PKEY *new_key);
CMP_err CMPclient_update_with_exts(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                                   OPTIONAL const X509 *old_cert,
                                   OPTIONAL const EVP_PKEY *new_key,
                                   OPTIONAL const X509_EXTENSIONS *exts);

/* reason codes are defined in openssl/x509v3.h */
CMP_err CMPclient_revoke(CMP_CTX *ctx, const X509 *cert, /* TODO: X509_REQ *csr, */ int reason);

# if OPENSSL_3_2_FEATURES
/* get CA certs, discard duplicates, and verify they are non-expired CA certs */
CMP_err CMPclient_caCerts(CMP_CTX *ctx, STACK_OF(X509) **out);
# endif
/* get certificate request template and related key specifications */
# if OPENSSL_3_4_FEATURES
CMP_err CMPclient_certReqTemplate(CMP_CTX *ctx,
                                  OSSL_CRMF_CERTTEMPLATE **certTemplate,
                                  OPTIONAL OSSL_CMP_ATAVS **keySpec);
# endif

# if OPENSSL_3_2_FEATURES
/* get any root CA key update and verify it as far as possible */
CMP_err CMPclient_rootCaCert(CMP_CTX *ctx,
                             const X509 *oldWithOld, X509 **newWithNew,
                             OPTIONAL X509 **newWithOld,
                             OPTIONAL X509 **oldWithNew);
# endif
# if OPENSSL_3_4_FEATURES
/* get latest CRL according to cert DPN/issuer or get any update on given CRL */
CMP_err CMPclient_crlUpdate(CMP_CTX *ctx, OPTIONAL const X509 *cert,
                            OPTIONAL const X509_CRL *last_crl, X509_CRL **crl);
# endif

/* get error information sent by the server */
char *CMPclient_snprint_PKIStatus(const OSSL_CMP_CTX *ctx,
                                  char *buf, size_t bufsize);

/* must be called between any of the above certificate management activities */
CMP_err CMPclient_reinit(CMP_CTX *ctx);

/* should be called on application termination */
void CMPclient_finish(OPTIONAL CMP_CTX *ctx);

# ifndef GENCMP_NO_HELPERS

/* CREDENTIALS helpers */
#  ifdef LOCAL_DEFS
#   include "genericCMPClient_imports.h"
#  else
#   include <secutils/credentials/key.h>
#  endif

/* X509_STORE helpers */
EVP_PKEY *KEY_load(OPTIONAL const char *file, OPTIONAL const char *pass,
                   OPTIONAL const char *engine, OPTIONAL const char *desc);
X509_REQ *CSR_load(const char *file, OPTIONAL const char *desc);

X509_CRL *CRL_load(const char *url, int timeout, OPTIONAL const char *desc);
STACK_OF(X509_CRL) *CRLs_load(const char *files, int timeout,
                              OPTIONAL const char *desc);
void CRLs_free(OPTIONAL STACK_OF(X509_CRL) *crls);
X509_STORE *STORE_load(const char *trusted_certs, OPTIONAL const char *desc,
                       OPTIONAL X509_VERIFY_PARAM *vpm);
#  ifdef LOCAL_DEFS
#   include "genericCMPClient_imports.h"
#  else
#   include <secutils/credentials/store.h>
#  endif

/* SSL_CTX helpers for HTTPS */
#  ifdef SECUTILS_NO_TLS
#   undef GENCMP_NO_TLS
#   define GENCMP_NO_TLS
#  endif

#  ifndef GENCMP_NO_TLS
#   ifdef LOCAL_DEFS
#    include "genericCMPClient_imports.h"
#   else
#    include <secutils/connections/tls.h>
#   endif
SSL_CTX *TLS_new(OPTIONAL const X509_STORE *truststore,
                 OPTIONAL const STACK_OF(X509) *untrusted,
                 OPTIONAL const CREDENTIALS *creds,
                 OPTIONAL const char *ciphers, int security_level);
void TLS_free(OPTIONAL SSL_CTX *tls);
#  endif

/* X509_EXTENSIONS helpers */
#  ifdef LOCAL_DEFS
#   include "genericCMPClient_imports.h"
#  else
#   include <secutils/util/extensions.h>
#  endif

# endif /* ndef GENCMP_NO_HELPERS */

# ifdef __cplusplus
}
# endif

#endif /* GENERIC_CMP_CLIENT_H */
