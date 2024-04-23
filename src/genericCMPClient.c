/*-
 * @file   genericCMPClient.c
 * @brief  generic CMP client library implementation
 *
 * @author David von Oheimb, Siemens AG, David.von.Oheimb@siemens.com
 *
 *  Copyright (c) 2017-2023 Siemens AG
 *
 *  Licensed under the Apache License 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You can obtain a copy in the file LICENSE in the source distribution
 *  or at https://www.openssl.org/source/license.html
 *  SPDX-License-Identifier: Apache-2.0
 */

#include "genericCMPClient.h"

#include <openssl/cmperr.h>
#include <openssl/ssl.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER < 0x10100006L
typedef
STACK_OF(X509_EXTENSION)
*(*sk_X509_EXTENSION_copyfunc)(const STACK_OF(X509_EXTENSION) *a);
#endif

#ifdef LOCAL_DEFS /* internal helper functions not documented in API spec */
# include "genericCMPClient_use.h"
#else
# include <secutils/storage/files.h>
# include <secutils/credentials/cert.h>
# include <secutils/credentials/store.h>
# include <secutils/credentials/verify.h>
# include <secutils/connections/conn.h>
# ifndef SECUTILS_NO_TLS
#  include <secutils/connections/tls.h>
# endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100006L
# define SSL_CTX_up_ref(x)((x)->references++)
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100003L
# define ERR_R_INIT_FAIL (6 | ERR_R_FATAL)
#endif

static int CMPOSSL_error(void)
{
    unsigned long err = ERR_peek_last_error();

    if (err == 0) /* check for wrong old CMPforOpenSSL behavior */
        return 100;
    if (ERR_GET_LIB(err) != ERR_LIB_CMP)
        return CMP_R_OTHER_LIB_ERR;
    return ERR_GET_REASON(err);
}

/*
 * Core functionality
 */

CMP_err CMPclient_init(OPTIONAL const char *name, OPTIONAL LOG_cb_t log_fn)
{
    if (name == NULL)
        name = CMPCLIENT_MODULE_NAME;
    LOG_set_name(name);
    LOG_init((LOG_cb_t)log_fn); /* assumes that severity in SecUtils is same as in CMPforOpenSSL */
    LOG_set_verbosity(LOG_INFO);

    UTIL_setup_openssl(OPENSSL_VERSION_NUMBER, name);
#if OPENSSL_VERSION_NUMBER < OPENSSL_V_3_0_0
# define MAJOR_MINOR_MASK 0xfffff000L
#else
# define MAJOR_MINOR_MASK 0xfff00000L
#endif
    if ((MAJOR_MINOR_MASK & OpenSSL_version_num()) !=
        (MAJOR_MINOR_MASK & OPENSSL_VERSION_NUMBER)) {
        LOG(FL_FATAL, "OpenSSL runtime version 0x%lx does not match version 0x%lx used for compiling %s",
            OpenSSL_version_num(), OPENSSL_VERSION_NUMBER, name);
        exit(EXIT_FAILURE);
    }

    if (!STORE_EX_check_index()) {
        LOG(FL_ERR, "failed to initialize STORE_EX index\n");
        return ERR_R_INIT_FAIL;
    }

    if (!OSSL_CMP_log_open()) {
        LOG(FL_ERR, "failed to initialize logging of genCMPClient\n");
        return ERR_R_INIT_FAIL;
    }
#ifndef SECUTILS_NO_TLS
    if (!TLS_init()) {
        LOG(FL_ERR, "failed to initialize TLS library of genCMPClient\n");
        return ERR_R_INIT_FAIL;
    }
#endif
    return CMP_OK;
}

static X509_NAME *parse_DN(const char *str, const char *desc)
{
    X509_NAME *name = UTIL_parse_name(str, MBSTRING_ASC, false);

    if (name == NULL)
        LOG(FL_ERR, "Unable to parse %s DN '%s'", desc, str);
    return name;
}

CMP_err CMPclient_prepare(OSSL_CMP_CTX **pctx,
                          OSSL_LIB_CTX *libctx, const char *propq,
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
                          bool implicit_confirm)
{
    OSSL_CMP_CTX *ctx = NULL;

    if (pctx == NULL) {
        return CMP_R_NULL_ARGUMENT;
    }
    if ((ctx = OSSL_CMP_CTX_new(libctx, propq)) == NULL ||
        !OSSL_CMP_CTX_set_log_cb(ctx, log_fn != NULL ?
                                 (OSSL_CMP_log_cb_t)log_fn :
                                 /* difference is in 'int' vs. 'bool' and additional TRACE value */
                                 (OSSL_CMP_log_cb_t)LOG_console)) {
        goto err; /* TODO make sure that proper error code it set by OSSL_CMP_CTX_set_log_cb() */
    }
    if (cmp_truststore != NULL
        && (!X509_STORE_up_ref(cmp_truststore) ||
            !OSSL_CMP_CTX_set0_trustedStore(ctx, cmp_truststore)))
        goto err;
    if (untrusted != NULL
        && !OSSL_CMP_CTX_set1_untrusted(ctx, (STACK_OF(X509) *)untrusted))
        goto err;

    X509 *cert = NULL;
    if (creds != NULL) {
        EVP_PKEY *pkey = CREDENTIALS_get_pkey(creds);
        STACK_OF(X509) *chain = CREDENTIALS_get_chain(creds);
        const char *pwd = CREDENTIALS_get_pwd(creds);
        const char *pwdref = CREDENTIALS_get_pwdref(creds);

        cert = CREDENTIALS_get_cert(creds);
        if ((pwd != NULL
             && !OSSL_CMP_CTX_set1_secretValue(ctx, (unsigned char *)pwd,
                                               (int)strlen(pwd))) ||
            (pwdref != NULL
             && !OSSL_CMP_CTX_set1_referenceValue(ctx, (unsigned char *)pwdref,
                                                  (int)strlen(pwdref))) ||
            (pkey != NULL && !OSSL_CMP_CTX_set1_pkey(ctx, pkey)) ||
            (cert != NULL && !OSSL_CMP_CTX_set1_cert(ctx, cert))) {
            goto err;
        }

        if (cert != NULL &&
            !OSSL_CMP_CTX_build_cert_chain(ctx, creds_truststore, chain))
            goto err;
    } else {
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_SEND, 1)) {
            goto err;
        }
    }

    /* need recipient for unprotected and PBM-protected messages */
    X509_NAME *rcp = NULL;
    if (recipient != NULL) {
        rcp = parse_DN(recipient, "recipient");
        if (rcp == NULL) {
            OSSL_CMP_CTX_free(ctx);
            return CMP_R_INVALID_PARAMETERS;
        }
    } else if (cert == NULL) {
        if (sk_X509_num(untrusted) > 0) {
            X509 *first = sk_X509_value(untrusted, 0);

            rcp = X509_NAME_dup((X509_get_subject_name(first)));
        } else {
            LOG(FL_WARN, "No explicit recipient, no cert, and no untrusted certs given; resorting to NULL DN");
            rcp = X509_NAME_new();
        }
        if (rcp == NULL) {
            LOG(FL_ERR,
                "Internal error like out of memory obtaining recipient DN",
                recipient);
            OSSL_CMP_CTX_free(ctx);
            return CMP_R_RECIPIENT;
        }
    }
    if (rcp != NULL) { /* else CMPforOpenSSL uses cert issuer */
        bool rv = OSSL_CMP_CTX_set1_recipient(ctx, rcp) != 0;

        X509_NAME_free(rcp);
        if (!rv)
            goto err;
    }

    if (digest != NULL) {
        int nid = OBJ_ln2nid(digest);

        if (nid == NID_undef) {
            LOG(FL_ERR, "Bad digest algorithm name: '%s'", digest);
            OSSL_CMP_CTX_free(ctx);
            return CMP_R_UNKNOWN_ALGORITHM_ID;
        }
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_DIGEST_ALGNID, nid)
            || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_OWF_ALGNID, nid)) {
            goto err;
        }
    }

    if (mac != NULL) {
        int mac_algnid = OBJ_ln2nid(mac);

        if (mac_algnid == NID_undef) {
            LOG(FL_ERR, "MAC algorithm name not recognized: '%s'", mac);
            OSSL_CMP_CTX_free(ctx);
            return CMP_R_UNKNOWN_ALGORITHM_ID;
        }
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_MAC_ALGNID, mac_algnid))
            goto err;
    }

    if ((transfer_fn != NULL
         && !OSSL_CMP_CTX_set_transfer_cb(ctx, transfer_fn)) ||
        (total_timeout >= 0
         && !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_TOTAL_TIMEOUT,
                                     total_timeout))) {
        goto err;
    }
    if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM,
                                 implicit_confirm ? 1 : 0)) {
        goto err;
    }
    if (new_cert_truststore != NULL) {
        /* ignore any -attime option here, since new certs are current anyway */
        X509_VERIFY_PARAM *out_vpm = X509_STORE_get0_param(new_cert_truststore);

        X509_VERIFY_PARAM_clear_flags(out_vpm, X509_V_FLAG_USE_CHECK_TIME);

        if (!OSSL_CMP_CTX_set_certConf_cb(ctx, OSSL_CMP_certConf_cb) ||
            !OSSL_CMP_CTX_set_certConf_cb_arg(ctx, new_cert_truststore) ||
            !X509_STORE_up_ref(new_cert_truststore))
            goto err;
    }

    *pctx = ctx;
    return CMP_OK;

 err:
    OSSL_CMP_CTX_free(ctx);
    return CMPOSSL_error();
}

CMP_err CMPclient_setup_BIO(CMP_CTX *ctx, BIO *rw, const char *path,
                            int keep_alive, int timeout)
{
    if (ctx == NULL) {
        return CMP_R_INVALID_CONTEXT;
    }
    if (!OSSL_CMP_CTX_set1_serverPath(ctx, path) ||
        (timeout >= 0 && !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_MSG_TIMEOUT,
                                                  timeout)) ||
        (keep_alive >= 0 && !OSSL_CMP_CTX_set_option(ctx,
                                                     OSSL_CMP_OPT_KEEP_ALIVE,
                                                     keep_alive)) ||
        !OSSL_CMP_CTX_set_transfer_cb_arg(ctx, rw)) {
        return CMPOSSL_error();
    }

    if (rw != NULL) {
        if (path == NULL)
            path = "";
        LOG(FL_INFO, "will contact CMP server via existing connection at HTTP path \"%s%s\"",
            path[0] == '/' ? "" : "/", path);
    }
    return CMP_OK;
}

#ifndef SECUTILS_NO_TLS
/* yields the name of the SW component, not the name of an executable */
static char *opt_getprog(void)
{
    return "CMP client";
}

typedef struct app_http_tls_info_st {
    const char *server;
    const char *port;
    int use_proxy;
    int timeout; /* for OSSL_HTTP_proxy_connect() */
    SSL_CTX *ssl_ctx;
    SSL *ssl;
} APP_HTTP_TLS_INFO;

static const char *tls_error_hint(void)
{
    unsigned long err = ERR_peek_error();

    if (ERR_GET_LIB(err) != ERR_LIB_SSL)
        err = ERR_peek_last_error();
    if (ERR_GET_LIB(err) != ERR_LIB_SSL)
        return NULL;

    switch (ERR_GET_REASON(err)) {
    case SSL_R_WRONG_VERSION_NUMBER:
        return "The server does not support (a suitable version of) TLS";
    case SSL_R_UNKNOWN_PROTOCOL:
        return "The server does not support HTTPS";
    case SSL_R_CERTIFICATE_VERIFY_FAILED:
        return "Cannot authenticate server via its TLS certificate, likely due to mismatch with our trusted TLS certs or missing revocation status";
    case SSL_AD_REASON_OFFSET + TLS1_AD_UNKNOWN_CA:
        return "Server did not accept our TLS certificate, likely due to mismatch with server's trust anchor or missing revocation status";
    case SSL_AD_REASON_OFFSET + SSL3_AD_HANDSHAKE_FAILURE:
        return "TLS handshake failure. Possibly the server requires our TLS certificate but did not receive it";
    default: /* no error or no hint available for error */
        return NULL;
    }
}

/* HTTP callback function that supports TLS connection also via HTTPS proxy */
/* adapted from OpenSSL:apps/lib/apps.c */
static BIO *app_http_tls_cb(BIO *bio, void *arg, int connect, int detail)
{
    APP_HTTP_TLS_INFO *info = (APP_HTTP_TLS_INFO *)arg;
    SSL_CTX *ssl_ctx = info->ssl_ctx;
    X509_STORE *ts;

    if (ssl_ctx == NULL)
        return bio; /* not using TLS */
    if (connect) {
        SSL *ssl;
        BIO *sbio = NULL;

        if ((info->use_proxy
             && !OSSL_HTTP_proxy_connect(bio, info->server, info->port,
                                         NULL, NULL, /* no proxy credentials */
                                         info->timeout, bio_err, opt_getprog()))
                || (sbio = BIO_new(BIO_f_ssl())) == NULL) {
            return NULL;
        }
        if ((ssl = SSL_new(ssl_ctx)) == NULL) {
            BIO_free(sbio);
            return NULL;
        }

        SSL_set_tlsext_host_name(ssl, info->server); /* not critical to do */
        SSL_set_connect_state(ssl);
        BIO_set_ssl(sbio, ssl, BIO_CLOSE);

        bio = BIO_push(sbio, bio);
    } else { /* disconnect */
        const char *hint;

        if (!detail) { /* an error has occurred */
            if ((hint = tls_error_hint()) != NULL)
                ERR_add_error_data(2, " : ", hint);
        }
# if OPENSSL_VERSION_NUMBER < OPENSSL_V_3_0_0
        BIO *cbio;
        (void)ERR_set_mark();
        BIO_ssl_shutdown(bio);
        cbio = BIO_pop(bio); /* connect+HTTP BIO */
        BIO_free(bio); /* SSL BIO */
        (void)ERR_pop_to_mark(); /* hide SSL_R_READ_BIO_NOT_SET etc. */
        bio = cbio;
# endif
    }
    if ((ts = SSL_CTX_get_cert_store(ssl_ctx)) != NULL) {
        /* indicate if OSSL_CMP_MSG_http_perform() with TLS is active */
        (void)STORE_set0_tls_bio(ts, bio);
    }
    return bio;
}

static void APP_HTTP_TLS_INFO_free(APP_HTTP_TLS_INFO *info)
{
    if (info != NULL) {
        SSL_CTX_free(info->ssl_ctx);
        OPENSSL_free((char *)info->server);
        OPENSSL_free((char *)info->port);
        OPENSSL_free(info);
    }
}
#endif /* ndef SECUTILS_NO_TLS */

#ifndef SECUTILS_NO_TLS
static int is_localhost(const char *host)
{
    return strcmp(host, "localhost") == 0
        || strcmp(host, "127.0.0.1") == 0
        || strcmp(host, "::1") == 0;
}
#endif

/* Will return error when used with OpenSSL compiled with OPENSSL_NO_SOCK. */
CMP_err CMPclient_setup_HTTP(OSSL_CMP_CTX *ctx,
                             const char *server, const char *path,
                             int keep_alive, int timeout, OPTIONAL SSL_CTX *tls,
                             OPTIONAL const char *proxy,
                             OPTIONAL const char *no_proxy)
{
    CMP_err err = CMP_R_INVALID_PARAMETERS;

    if (ctx == NULL) {
        LOG(FL_ERR, "No ctx parameter given");
        return CMP_R_INVALID_CONTEXT;
    }
#ifdef SECUTILS_NO_TLS
    if (tls != NULL) {
        LOG(FL_ERR, "TLS is not supported by this build");
        return err;
    }
#endif
    char *host = NULL, *server_port = NULL, *parsed_path = NULL;
    const char *proxy_host = NULL;
    if (server == NULL)
        goto set_path;

    int use_ssl, port;
    if (!OSSL_HTTP_parse_url(server, &use_ssl, NULL /* puser */, &host,
                             &server_port, &port, &parsed_path, NULL, NULL))
        return err;
    if (use_ssl && tls == NULL) {
        LOG(FL_ERR, "missing TLS context since server URL indicates HTTPS");
        goto err;
    }
    if (!OSSL_CMP_CTX_set1_server(ctx, host) ||
        (!OSSL_CMP_CTX_set_serverPort(ctx, port))) {
        err = CMPOSSL_error();
        goto err;
    }
    if (path == NULL)
        path = parsed_path;

    if (!OSSL_CMP_CTX_set1_proxy(ctx, proxy) ||
        !OSSL_CMP_CTX_set1_no_proxy(ctx, no_proxy)) {
        err = CMPOSSL_error();
        goto err;
    }
    proxy_host =
        OSSL_HTTP_adapt_proxy(proxy, no_proxy, host, tls != NULL);
#ifndef SECUTILS_NO_TLS
    if (tls != NULL) {
        const char *host_or_proxy = proxy_host == NULL ? host : proxy_host;
        X509_STORE *ts = SSL_CTX_get_cert_store(tls);

        if (is_localhost(host_or_proxy)) {
            LOG(FL_WARN, "skipping host name verification on localhost");
            /* enables self-bootstrapping of local RA using its device cert */
        } else {
            /* set expected host if not already done by caller */
            if (STORE_get0_host(ts) == NULL &&
                !STORE_set1_host_ip(ts, host_or_proxy, host_or_proxy)) {
                err = CMPOSSL_error();
                goto err;
            }
        }

        if (!OSSL_CMP_CTX_set_http_cb(ctx, app_http_tls_cb)) {
            err = CMPOSSL_error();
            goto err;
        }
        APP_HTTP_TLS_INFO *info = OPENSSL_zalloc(sizeof(*info));
        if (info == NULL) {
            err = CMPOSSL_error();
            goto err;
        }
        APP_HTTP_TLS_INFO_free(OSSL_CMP_CTX_get_http_cb_arg(ctx));
        (void)OSSL_CMP_CTX_set_http_cb_arg(ctx, info);
        /* info will be freed along with ctx */
        OSSL_CMP_CTX_set_transfer_cb_arg(ctx, NULL); /* indicate SSL not used */

        info->server = OPENSSL_strdup(host);
        info->port = OPENSSL_strdup(server_port);
        info->use_proxy = proxy_host != NULL;
        info->timeout = OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_MSG_TIMEOUT);
        if (!SSL_CTX_up_ref(tls)) {
            err = CMPOSSL_error();
            goto err;
        }
        info->ssl_ctx = tls;
    }
#endif

 set_path:
    err = CMPclient_setup_BIO(ctx, NULL, path, keep_alive, timeout);
    if (err != CMP_OK)
        goto err;

    if (path == NULL)
        path = "";
    if (server == NULL)
        LOG_info("will not contact any server"); /* since -rspin is given */
    else
        LOG(FL_INFO, "will contact http%s://%s:%d%s%s%s%s",
            tls != NULL ? "s" : "",
            host, port, path[0] == '/' ? "" : "/", path,
            proxy_host != NULL ? " via proxy " : "",
            proxy_host != NULL ? proxy_host : "");
    err = CMP_OK;

 err:
    OPENSSL_free(host);
    OPENSSL_free(server_port);
    OPENSSL_free(parsed_path);
    return err;
}

#if OPENSSL_VERSION_NUMBER >= 0x30300000L || defined USE_LIBCMP
static int ossl_cmp_sk_ASN1_UTF8STRING_push_str(STACK_OF(ASN1_UTF8STRING) *sk,
                                                const char *text, int len)
{
    ASN1_UTF8STRING *utf8string;

    if (sk == NULL || text == NULL) {
        ERR_raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if ((utf8string = ASN1_UTF8STRING_new()) == NULL)
        return 0;
    if (!ASN1_STRING_set(utf8string, text, len))
        goto err;
    if (!sk_ASN1_UTF8STRING_push(sk, utf8string))
        goto err;
    return 1;

 err:
    ASN1_UTF8STRING_free(utf8string);
    return 0;
}

CMP_err CMPclient_add_certProfile(CMP_CTX *ctx, OPTIONAL const char *name)
{
    if (ctx == NULL) {
        LOG(FL_ERR, "No ctx parameter given");
        return CMP_R_INVALID_CONTEXT;
    }

    if (name == NULL) {
        if (!OSSL_CMP_CTX_reset_geninfo_ITAVs(ctx))
            goto err;
    } else {
        OSSL_CMP_ITAV *itav = NULL;
        STACK_OF(ASN1_UTF8STRING) *sk = sk_ASN1_UTF8STRING_new_reserve(NULL, 1);

        if (sk == NULL)
            goto err;
        if (!ossl_cmp_sk_ASN1_UTF8STRING_push_str(sk, name, (int)strlen(name))
                || (itav = OSSL_CMP_ITAV_new0_certProfile(sk)) == NULL) {
            sk_ASN1_UTF8STRING_pop_free(sk, ASN1_UTF8STRING_free);
            goto err;
        }
        if (!OSSL_CMP_CTX_push0_geninfo_ITAV(ctx, itav)) {
            OSSL_CMP_ITAV_free(itav);
            goto err;
        }
    }

    return CMP_OK;

 err:
    return CMPOSSL_error();
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30300000L || defined USE_LIBCMP */

CMP_err CMPclient_setup_certreq(OSSL_CMP_CTX *ctx,
                                OPTIONAL const EVP_PKEY *new_key,
                                OPTIONAL const X509 *old_cert,
                                OPTIONAL const X509_NAME *subject,
                                OPTIONAL const X509_EXTENSIONS *exts,
                                OPTIONAL const X509_REQ *csr)
{
    if (ctx == NULL) {
        LOG(FL_ERR, "No ctx parameter given");
        return CMP_R_INVALID_CONTEXT;
    }

    if (old_cert != NULL && !OSSL_CMP_CTX_set1_oldCert(ctx, (X509 *)old_cert))
        goto err;
    if (new_key != NULL) {
        if (!EVP_PKEY_up_ref((EVP_PKEY *)new_key))
            goto err;
        if (!OSSL_CMP_CTX_set0_newPkey(ctx, 1 /* priv */,
                                       (EVP_PKEY *)new_key)) {
            EVP_PKEY_free((EVP_PKEY *)new_key);
            goto err;
        }
    }

    if (subject != NULL && !OSSL_CMP_CTX_set1_subjectName(ctx, subject))
        goto err;

    if (exts != NULL) {
        X509_EXTENSIONS *exts_copy =
            sk_X509_EXTENSION_deep_copy(exts,
                                        (sk_X509_EXTENSION_copyfunc)
                                        X509_EXTENSION_dup,
                                        X509_EXTENSION_free);

        if (exts_copy == NULL
            || !OSSL_CMP_CTX_set0_reqExtensions(ctx, exts_copy)) {
            goto err;
        }
    }

    if (csr != NULL && !OSSL_CMP_CTX_set1_p10CSR(ctx, csr)) {
        goto err;
    }

    return CMP_OK;

 err:
    return CMPOSSL_error();
}

#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP /* TODO remove decls when exported by OpenSSL */
static int ossl_x509_add_cert_new_(STACK_OF(X509) **p_sk, X509 *cert, int flags)
{
    if (*p_sk == NULL && (*p_sk = sk_X509_new_null()) == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return X509_add_cert(*p_sk, cert, flags);
}

#if 0 // TODO remove?
static int ossl_x509_add_certs_new(STACK_OF(X509) **p_sk, STACK_OF(X509) *certs,
                                   int flags)
/* compiler would allow 'const' for the certs, yet they may get up-ref'ed */
{
    int n = sk_X509_num(certs /* may be NULL */);
    int i;

    for (i = 0; i < n; i++) {
        int j = (flags & X509_ADD_FLAG_PREPEND) == 0 ? i : n - 1 - i;
        /* if prepend, add certs in reverse order to keep original order */

        if (!ossl_x509_add_cert_new_(p_sk, sk_X509_value(certs, j), flags))
            return 0;
    }
    return 1;
}

static
int ossl_cmp_X509_STORE_add1_certs(X509_STORE *store, STACK_OF(X509) *certs,
                                   int only_self_signed)
{
    int i;

    if (store == NULL) {
        ERR_raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (certs == NULL)
        return 1;
    for (i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);

        if (!only_self_signed || X509_self_signed(cert, 0) == 1)
            if (!X509_STORE_add_cert(store, cert)) /* ups cert ref counter */
                return 0;
    }
    return 1;
}
#endif

#if 0 // TODO remove?
/*-
 * Builds a certificate chain starting from <cert>
 * using the optional list of intermediate CA certificates <certs>.
 * If <store> is NULL builds the chain as far down as possible, ignoring errors.
 * Else the chain must reach a trust anchor contained in <store>.
 *
 * Returns NULL on error, else a pointer to a stack of (up_ref'ed) certificates
 * starting with given EE certificate and followed by all available intermediate
 * certificates down towards any trust anchor but without including the latter.
 *
 * NOTE: If a non-NULL stack is returned the caller is responsible for freeing.
 * NOTE: In case there is more than one possibility for the chain,
 * OpenSSL seems to take the first one; check X509_verify_cert() for details.
 */
/* TODO use instead X509_build_chain() when OpenSSL 3.0 is being used */
static
STACK_OF(X509) *ossl_cmp_build_cert_chain(OSSL_LIB_CTX *libctx,
                                          const char *propq,
                                          X509_STORE *store,
                                          STACK_OF(X509) *certs, X509 *cert)
{
    STACK_OF(X509) *chain = NULL, *res = NULL;
    X509_STORE *ts = store == NULL ? X509_STORE_new() : store;
    X509_STORE_CTX *csc = NULL;

    if (ts == NULL || cert == NULL) {
        ERR_raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    if ((csc = X509_STORE_CTX_new_ex(libctx, propq)) == NULL)
        goto err;
    if (store == NULL && certs != NULL
            && !ossl_cmp_X509_STORE_add1_certs(ts, certs, 0))
        goto err;
    if (!X509_STORE_CTX_init(csc, ts, cert,
                             store == NULL ? NULL : certs))
        goto err;
    /* disable any cert status/revocation checking etc. */
    X509_VERIFY_PARAM_clear_flags(X509_STORE_CTX_get0_param(csc),
                                  ~((unsigned long)X509_V_FLAG_USE_CHECK_TIME |
                                    (unsigned long)X509_V_FLAG_NO_CHECK_TIME));

    if (X509_verify_cert(csc) <= 0 && store != NULL)
        goto err;
    chain = X509_STORE_CTX_get0_chain(csc);

    /* result list to store the up_ref'ed not self-signed certificates */
    if (!ossl_x509_add_certs_new(&res, chain,
                                 X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP
                                 | X509_ADD_FLAG_NO_SS)) {
        sk_X509_free(res);
        res = NULL;
    }

 err:
    if (store == NULL)
        X509_STORE_free(ts);
    X509_STORE_CTX_free(csc);
    return res;
}
#endif
#endif /* end TODO remove decls when exported by OpenSSL */

CMP_err CMPclient_enroll(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds, int cmd)
{
    X509 *newcert = NULL;

    if (ctx == NULL) {
        LOG(FL_ERR, "No ctx parameter given");
        return CMP_R_INVALID_CONTEXT;
    }
    if (OSSL_CMP_CTX_get_status(ctx) != OSSL_CMP_PKISTATUS_unspecified) {
        LOG(FL_ERR, "The ctx parameter is not clean - call CMPclient_reinit()");
        return CMP_R_INVALID_CONTEXT;
    }
    if (new_creds == NULL) {
        LOG(FL_ERR, "No new_creds parameter given");
        return CMP_R_NULL_ARGUMENT;
    }

    switch (cmd) {
    case CMP_IR:
        newcert = OSSL_CMP_exec_IR_ses(ctx);
        break;
    case CMP_CR:
        newcert = OSSL_CMP_exec_CR_ses(ctx);
        break;
    case CMP_P10CR:
        newcert = OSSL_CMP_exec_P10CR_ses(ctx);
        break;
    case CMP_KUR:
        newcert = OSSL_CMP_exec_KUR_ses(ctx);
        break;
    default:
        LOG(FL_ERR, "Argument must be CMP_IR, CMP_CR, CMP_P10CR, or CMP_KUR");
        return CMP_R_INVALID_PARAMETERS;
        break;
    }
    if (newcert == NULL) {
        goto err;
    }

    EVP_PKEY *new_key =
        OSSL_CMP_CTX_get0_newPkey(ctx, 1 /* priv */); /* NULL in case P10CR */
    X509_STORE *new_cert_truststore = OSSL_CMP_CTX_get_certConf_cb_arg(ctx);
    STACK_OF(X509) *untrusted =
        OSSL_CMP_CTX_get0_untrusted(ctx); /* includes extraCerts */
    LOG_debug("Trying to build chain for newly enrolled cert");
    STACK_OF(X509) *chain = X509_build_chain(newcert, untrusted,
                                             new_cert_truststore /* may NULL */,
                                             0, OSSL_CMP_CTX_get0_libctx(ctx),
                                             OSSL_CMP_CTX_get0_propq(ctx));
    if (sk_X509_num(chain) > 0)
        X509_free(sk_X509_shift(chain)); /* remove leaf (EE) cert */
    if (new_cert_truststore != NULL) {
        if (chain == NULL) {
            LOG_err("Failed building chain for newly enrolled cert");
            goto err;
        }
        LOG_debug("Succeeded building proper chain for newly enrolled cert");
    } else if (chain == NULL) {
        LOG_warn("Could not build approximate chain for newly enrolled cert, resorting to received extraCerts");
        chain = OSSL_CMP_CTX_get1_extraCertsIn(ctx);
    } else {
        LOG_debug("Succeeded building approximate chain for newly enrolled cert");
    }

    CREDENTIALS *creds = CREDENTIALS_new(new_key, newcert, chain, NULL, NULL);
    CERTS_free(chain);
    if (creds == NULL) {
        return ERR_R_MALLOC_FAILURE;
    }
    *new_creds = creds;
    ERR_clear_error(); /* empty the OpenSSL error queue */
    return CMP_OK;

 err:
    return CMPOSSL_error();
}

CMP_err CMPclient_imprint(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                          const EVP_PKEY *new_key,
                          const char *subject,
                          OPTIONAL const X509_EXTENSIONS *exts)
{
    X509_NAME *subj = NULL;

#if 0 /* as far as needed, checks are anyway done by the low-level library */
    if (new_key == NULL) {
        LOG(FL_ERR, "No new_key parameter given");
        return CMP_R_NULL_ARGUMENT;
    }
    if (subject == NULL) {
        LOG(FL_ERR, "No subject parameter given");
        return CMP_R_NULL_ARGUMENT;
    }
#endif
    if (subject != NULL && (subj = parse_DN(subject, "subject")) == NULL)
        return CMP_R_INVALID_PARAMETERS;
    CMP_err err = CMPclient_setup_certreq(ctx, new_key, NULL /* old_cert */,
                                          subj, exts, NULL /* csr */);
    if (err == CMP_OK) {
        err = CMPclient_enroll(ctx, new_creds, CMP_IR);
    }
    X509_NAME_free(subj);
    return err;
}

CMP_err CMPclient_bootstrap(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                            const EVP_PKEY *new_key,
                            const char *subject,
                            OPTIONAL const X509_EXTENSIONS *exts)
{
    X509_NAME *subj = NULL;

#if 0 /* as far as needed, checks are anyway done by the low-level library */
    if (new_key == NULL) {
        LOG(FL_ERR, "No new_key parameter given");
        return CMP_R_NULL_ARGUMENT;
    }
    if (subject == NULL) {
        LOG(FL_ERR, "No subject parameter given");
        return CMP_R_NULL_ARGUMENT;
    }
#endif
    if (subject != NULL && (subj = parse_DN(subject, "subject")) == NULL)
        return CMP_R_INVALID_PARAMETERS;
    CMP_err err = CMPclient_setup_certreq(ctx, new_key, NULL /* old_cert */,
                                          subj, exts, NULL /* csr */);
    if (err == CMP_OK) {
        err = CMPclient_enroll(ctx, new_creds, CMP_CR);
    }
    X509_NAME_free(subj);
    return err;
}

CMP_err CMPclient_pkcs10(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                         const X509_REQ *csr)
{
    if (csr == NULL) {
        LOG(FL_ERR, "No csr parameter given");
        return CMP_R_NULL_ARGUMENT;
    }

    CMP_err err =
        CMPclient_setup_certreq(ctx, NULL /* new_key */, NULL /* old_cert */,
                                NULL /* subject */, NULL /* exts */, csr);
    if (err == CMP_OK) {
        err = CMPclient_enroll(ctx, new_creds, CMP_P10CR);
    }
    return err;
}

CMP_err CMPclient_update_anycert(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                                 OPTIONAL const X509 *old_cert,
                                 const EVP_PKEY *new_key)
{
    CMP_err err = CMPclient_setup_certreq(ctx, new_key, old_cert,
                                          NULL /* subject */, NULL /* exts */,
                                          NULL /* csr */);

    if (err == CMP_OK) {
        err = CMPclient_enroll(ctx, new_creds, CMP_KUR);
    }
    return err;
}

CMP_err CMPclient_update(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                         const EVP_PKEY *new_key)
{
    return CMPclient_update_anycert(ctx, new_creds, NULL, new_key);
}

CMP_err CMPclient_revoke(OSSL_CMP_CTX *ctx, const X509 *cert, /* TODO: X509_REQ *csr, */ int reason)
{
    if (ctx == NULL) {
        LOG(FL_ERR, "No ctx parameter given");
        return CMP_R_INVALID_CONTEXT;
    }
    if (OSSL_CMP_CTX_get_status(ctx) != OSSL_CMP_PKISTATUS_unspecified) {
        LOG(FL_ERR, "The ctx parameter is not clean - call CMPclient_reinit()");
        return CMP_R_INVALID_CONTEXT;
    }

#if 0 /* as far as needed, checks are anyway done by the low-level library */
    if (cert == NULL) {
        LOG(FL_ERR, "No cert parameter given");
        return CMP_R_NULL_ARGUMENT;
    }
#endif
    if (cert != NULL) {
        if (!OSSL_CMP_CTX_set1_oldCert(ctx, (X509 *)cert))
            goto err;
    } else {
#if 0 /* TODO enable, and check why cert == NULL is accepted by Mock server */
        if (!OSSL_CMP_CTX_set1_p10CSR(ctx, csr))
            goto err;
#endif
    }

    if ((reason >= CRL_REASON_UNSPECIFIED &&
         !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_REVOCATION_REASON, reason))
        || !OSSL_CMP_exec_RR_ses(ctx)) {
        goto err;
    }
    ERR_clear_error(); /* empty the OpenSSL error queue */
    return CMP_OK;

 err:
    return CMPOSSL_error();
}

#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
static OSSL_CMP_ITAV *get_genm_itav(CMP_CTX *ctx,
                                    OSSL_CMP_ITAV *req, /* gets consumed */
                                    int expected, const char *desc)
{
    STACK_OF(OSSL_CMP_ITAV) *itavs = NULL;
    int i, n;

    if (ctx == NULL) {
        LOG(FL_ERR, "No ctx parameter given");
        goto err;
    }
    if (OSSL_CMP_CTX_get_status(ctx) != OSSL_CMP_PKISTATUS_unspecified) {
        LOG(FL_ERR, "The ctx parameter is not clean - should call CMPclient_reinit() before");
        goto err;
    }

    if (!OSSL_CMP_CTX_push0_genm_ITAV(ctx, req))
        goto err;
    req = NULL;
    itavs = OSSL_CMP_exec_GENM_ses(ctx);
    if (itavs == NULL) {
        if (OSSL_CMP_CTX_get_status(ctx) != OSSL_CMP_PKISTATUS_request
            && OSSL_CMP_CTX_get_status(ctx) != OSSL_CMP_PKISTATUS_rejection)
            LOG(FL_ERR, "Could not obtain valid response message on genm requesting %s",
                desc);
        return NULL;
    }

    if ((n = sk_OSSL_CMP_ITAV_num(itavs)) <= 0) {
        LOG(FL_ERR, "Response on genm requesting %s does not include suitable value", desc);
        sk_OSSL_CMP_ITAV_free(itavs);
        return NULL;
    }
    if (n > 1)
        LOG(FL_WARN, "Response on genm contains %d ITAVs; will use the first ITAV with infoType id-it-%s",
            n, desc);
    for (i = 0; i < n; i++) {
        OSSL_CMP_ITAV *itav = sk_OSSL_CMP_ITAV_shift(itavs);
        ASN1_OBJECT *obj = OSSL_CMP_ITAV_get0_type(itav);
        char name[128];
        int r;

        if (OBJ_obj2nid(obj) == expected) {
            for (i++; i < n; i++)
                OSSL_CMP_ITAV_free(sk_OSSL_CMP_ITAV_shift(itavs));
            sk_OSSL_CMP_ITAV_free(itavs);
            return itav;
        }

        r = OBJ_obj2txt(name, sizeof(name), obj, 0);
        if (r < 0)
            LOG(FL_WARN, "cannot get InfoType details while expecting %s from genp",
                desc);
        else if (r == 0)
            LOG(FL_WARN, "genp contains empty InfoType name while expecting %s from genp",
                desc);
        else
            LOG(FL_WARN, "genp contains unexpected InfoType %s while expecting %s from genp",
                name, desc);
        OSSL_CMP_ITAV_free(itav);
    }
    LOG(FL_ERR, "could not find any ITAV for %s in genp", desc);

 err:
    sk_OSSL_CMP_ITAV_free(itavs);
    OSSL_CMP_ITAV_free(req);
    return NULL;
}

static const X509_VERIFY_PARAM *get0_trustedStore_vpm(const CMP_CTX *ctx)
{
    /* const */ X509_STORE *ts = OSSL_CMP_CTX_get0_trustedStore(ctx);

    return ts == NULL ? NULL : X509_STORE_get0_param(ts);
}
#endif

#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
CMP_err CMPclient_caCerts(CMP_CTX *ctx, STACK_OF(X509) **out)
{
    OSSL_CMP_ITAV *req, *itav;
    STACK_OF(X509) *certs = NULL;
    CMP_err err = CMP_OK;

    if (out == NULL) {
        LOG(FL_ERR, "No out parameter given");
        return CMP_R_NULL_ARGUMENT;
    }
    *out = NULL;

    if ((req = OSSL_CMP_ITAV_new_caCerts(NULL)) == NULL) {
        LOG(FL_ERR, "Failed to create ITAV for genm requesting caCerts");
        return CMPOSSL_error();
    }
    itav = get_genm_itav(ctx, req, NID_id_it_caCerts, "caCerts");
    if (itav == NULL)
        return CMP_R_GET_ITAV;

    if (!OSSL_CMP_ITAV_get0_caCerts(itav, &certs)) {
        err = CMPOSSL_error();
        goto end;
    }
    if (certs == NULL) /* no CA certificate available */
        goto end;
    if (!CERT_check_all("genp", certs /* may be NULL */, 1 /* CA */,
                        get0_trustedStore_vpm(ctx))) {
        err = CMP_R_INVALID_CACERTS;
        goto end;
    }
    *out = sk_X509_new_reserve(NULL, sk_X509_num(certs));
    if (!X509_add_certs(*out, certs,
                        X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP)) {
        LOG_err("Failure storing caCerts received in genp");
        sk_X509_pop_free(*out, X509_free);
        *out = NULL;
        err = CMPOSSL_error();
    }

 end:
    OSSL_CMP_ITAV_free(itav);
    return err;
}
#endif

#if OPENSSL_VERSION_NUMBER > 0x30400000L || defined USE_LIBCMP
CMP_err CMPclient_certReqTemplate(CMP_CTX *ctx,
                                  OSSL_CRMF_CERTTEMPLATE **certTemplate,
                                  OPTIONAL OSSL_CMP_ATAVS **keySpec)
{
    OSSL_CMP_ITAV *req, *itav;
    CMP_err err = CMP_OK;

    if (keySpec != NULL)
        *keySpec = NULL;
    if (certTemplate == NULL) {
        LOG(FL_ERR, "No certTemplate parameter given");
        return CMP_R_NULL_ARGUMENT;
    }
    *certTemplate = NULL;

    if ((req = OSSL_CMP_ITAV_new0_certReqTemplate(NULL, NULL)) == NULL) {
        LOG(FL_ERR, "Failed to create ITAV for genm requesting certReqTemplate");
        return CMPOSSL_error();
    }
    itav = get_genm_itav(ctx, req, NID_id_it_certReqTemplate, "certReqTemplate");
    if (itav == NULL)
        return CMP_R_GET_ITAV;

    if (!OSSL_CMP_ITAV_get1_certReqTemplate(itav, certTemplate, keySpec))
        err = CMPOSSL_error();

    OSSL_CMP_ITAV_free(itav);
    return err;
}
#endif

#if OPENSSL_VERSION_NUMBER > 0x30200000L || defined USE_LIBCMP
static int selfsigned_verify_cb(int ok, X509_STORE_CTX *store_ctx)
{
    if (ok == 0 && store_ctx != NULL
        && X509_STORE_CTX_get_error_depth(store_ctx) == 0
        && X509_STORE_CTX_get_error(store_ctx)
        == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
        int i;
        STACK_OF(X509) *trust;
        STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(store_ctx);
        STACK_OF(X509) *untrusted = X509_STORE_CTX_get0_untrusted(store_ctx);
        X509_STORE_CTX_check_issued_fn check_issued =
            X509_STORE_CTX_get_check_issued(store_ctx);
        X509 *cert = sk_X509_value(chain, 0); /* target cert */
        X509 *issuer;

        for (i = 0; i < sk_X509_num(untrusted); i++) {
            cert = sk_X509_value(untrusted, i);
            if (!X509_up_ref(cert) || !sk_X509_push(chain, cert))
                return 0;
        }

        trust = X509_STORE_get1_all_certs(X509_STORE_CTX_get0_store(store_ctx));
        for (i = 0; i < sk_X509_num(trust); i++) {
            issuer = sk_X509_value(trust, i);
            if ((*check_issued)(store_ctx, cert, issuer)) {
                if (X509_up_ref(cert) && sk_X509_push(chain, cert))
                    ok = 1;
                break;
            }
        }
        sk_X509_pop_free(trust, X509_free);
        return ok;
    } else {
        X509_STORE *ts = X509_STORE_CTX_get0_store(store_ctx);
        X509_STORE_CTX_verify_cb verify_cb;

        if (ts == NULL
            || (verify_cb = X509_STORE_get_verify_cb(ts)) == NULL)
            return ok;
        return (*verify_cb)(ok, store_ctx);
    }
}

static int validate_ss_cert(OSSL_LIB_CTX *libctx, const char *propq,
                            X509_STORE *ts, STACK_OF(X509) *untrusted,
                            X509 *target)
{
    X509_STORE_CTX *csc = NULL;
    int ok = 0;

    if (ts == NULL || target == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((csc = X509_STORE_CTX_new_ex(libctx, propq)) == NULL
            || !X509_STORE_CTX_init(csc, ts, target, untrusted))
        goto err;
    X509_STORE_CTX_set_verify_cb(csc, selfsigned_verify_cb);
    ok = X509_verify_cert(csc) > 0;

 err:
    X509_STORE_CTX_free(csc);
    return ok;
}

static int verify_cert1(CMP_CTX *ctx, X509 *trusted, X509 *trans,
                        X509 *target, const char *desc)
{
    X509_STORE *ts = OSSL_CMP_CTX_get0_trusted(ctx);
    STACK_OF(X509) *untrusted = NULL;
    int res = 0;

    if (trusted != NULL && (ts = STORE_create(NULL, trusted, NULL)) == NULL)
        goto err;

    if (trans != NULL
            && !ossl_x509_add_cert_new_(&untrusted, trans, X509_ADD_FLAG_UP_REF))
        goto err;

    res = validate_ss_cert(OSSL_CMP_CTX_get0_libctx(ctx),
                           OSSL_CMP_CTX_get0_propq(ctx),
                           ts, untrusted, target);
    if (res <= 0)
        LOG(FL_ERR, "Verifying %s certificate received in genp failed", desc);

 err:
    sk_X509_pop_free(untrusted, X509_free);
    if (trusted != NULL)
        STORE_free(ts);
    return res;
}

CMP_err CMPclient_rootCaCert(CMP_CTX *ctx,
                             const X509 *oldWithOld, X509 **newWithNew,
                             OPTIONAL X509 **newWithOld,
                             OPTIONAL X509 **oldWithNew)
{
    OSSL_CMP_ITAV *req, *itav;
    CMP_err err = CMP_OK;

    if (newWithNew == NULL) {
        LOG(FL_ERR, "No newWithNew output parameter given");
        return CMP_R_NULL_ARGUMENT;
    }
    *newWithNew = NULL;

    if ((req = OSSL_CMP_ITAV_new_rootCaCert(oldWithOld)) == NULL) {
        LOG(FL_ERR, "Failed to create ITAV for genm requesting rootCaKeyUpdate");
        return CMPOSSL_error();
    }
    itav = get_genm_itav(ctx, req, NID_id_it_rootCaKeyUpdate, "rootCaCert");
    if (itav == NULL)
        return CMP_R_GET_ITAV;

    if (!OSSL_CMP_ITAV_get0_rootCaKeyUpdate(itav, newWithNew,
                                            newWithOld, oldWithNew)) {
        err = CMPOSSL_error();
        goto end;
    }

    if (*newWithNew == NULL) /* no root CA cert update available */
        goto end;
    if (!verify_cert1(ctx, (X509 *)oldWithOld, *newWithOld,
                      *newWithNew, "newWithNew")) {
        err = CMP_R_INVALID_ROOTCAUPD;
        goto end;
    }
    if (*oldWithNew != NULL) {
        if (oldWithOld == NULL) {
            LOG(FL_WARN, "oldWithNew certificate received in genp for verifying oldWithOld, but oldWithOld was not provided");
        } else if (!verify_cert1(ctx, (X509 *)*newWithNew, *oldWithNew,
                                 (X509 *)oldWithOld, "oldWithOld")) {
            err = CMP_R_INVALID_ROOTCAUPD;
            goto end;
        }
    }

    X509_up_ref(*newWithNew);
    if (newWithOld != NULL && *newWithOld != NULL)
        X509_up_ref(*newWithOld);
    if (oldWithNew != NULL && *oldWithNew != NULL)
        X509_up_ref(*oldWithNew);

 end:
    OSSL_CMP_ITAV_free(itav);
    return err;
}
#endif

#if OPENSSL_VERSION_NUMBER > 0x30400000L || defined USE_LIBCMP
CMP_err CMPclient_crlUpdate(CMP_CTX *ctx, OPTIONAL const X509 *cert,
                            OPTIONAL const X509_CRL *last_crl, X509_CRL **crl)
{
    OSSL_CMP_CRLSTATUS *status = NULL;
    STACK_OF(OSSL_CMP_CRLSTATUS) *list = NULL;
    OSSL_CMP_ITAV *req = NULL, *itav = NULL;
    STACK_OF(X509_CRL) *crls;
    CMP_err err = CMP_OK;

    if (crl == NULL) {
        LOG(FL_ERR, "No crl output parameter given");
        return CMP_R_NULL_ARGUMENT;
    }
    *crl = NULL;

    if ((status = OSSL_CMP_CRLSTATUS_create(last_crl, cert, 1)) == NULL) {
        LOG(FL_ERR, "Cannot set up CRLStatus structure");
        err = CMP_R_GENERATE_CRLSTATUS;
        goto end;
    }
    if ((list = sk_OSSL_CMP_CRLSTATUS_new_reserve(NULL, 1)) == NULL) {
        LOG(FL_ERR, "Cannot set up CRLStatus list");
        err = CMP_R_GENERATE_CRLSTATUS;
        goto end;
    }
    (void)sk_OSSL_CMP_CRLSTATUS_push(list, status); /* cannot fail */

    if ((req = OSSL_CMP_ITAV_new0_crlStatusList(list)) == NULL) {
        LOG(FL_ERR, "Failed to create ITAV for genm requesting crlUpdate");
        err = CMPOSSL_error();
        goto end;
    }
    status = NULL;
    list = NULL;

    itav = get_genm_itav(ctx, req, NID_id_it_crls, "crl");
    if (itav == NULL) {
        err = CMP_R_GET_ITAV;
        goto end;
    }

    if (!OSSL_CMP_ITAV_get0_crls(itav, &crls)) {
        err = CMP_R_INVALID_CRL_LIST;
        goto end;
    }
    if (crls == NULL) /* no CRL update available */
        goto end;
    if (sk_X509_CRL_num(crls) != 1) {
        LOG(FL_ERR, "Unexpected number of CRLs in genp: %d",
            sk_X509_CRL_num(crls));
        err = CMP_R_INVALID_CRL_LIST;
        goto end;
    }

    if ((*crl = sk_X509_CRL_value(crls, 0)) == NULL || !X509_CRL_up_ref(*crl)) {
        *crl = NULL;
        err = CMPOSSL_error();
    }

 end:
    OSSL_CMP_CRLSTATUS_free(status);
    sk_OSSL_CMP_CRLSTATUS_free(list);
    OSSL_CMP_ITAV_free(itav);
    return err;
}
#endif

char *CMPclient_snprint_PKIStatus(const OSSL_CMP_CTX *ctx, char *buf,
                                  size_t bufsize)
{
    return OSSL_CMP_CTX_snprint_PKIStatus(ctx, buf, bufsize);
}

CMP_err CMPclient_reinit(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_CTX_print_errors(ctx /* may be NULL */);
    if (ctx == NULL) {
        LOG(FL_ERR, "No ctx parameter given");
        return CMP_R_INVALID_CONTEXT;
    }
    return OSSL_CMP_CTX_reinit(ctx) ? CMP_OK : CMPOSSL_error();
}

void CMPclient_finish(OPTIONAL OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_CTX_print_errors(ctx /* may be NULL */);
    if (ctx != NULL) {
#ifndef SECUTILS_NO_TLS
        BIO *rw = OSSL_CMP_CTX_get_transfer_cb_arg(ctx);
        APP_HTTP_TLS_INFO *info = OSSL_CMP_CTX_get_http_cb_arg(ctx);

#endif
        X509_STORE_free(OSSL_CMP_CTX_get_certConf_cb_arg(ctx));
        OSSL_CMP_CTX_free(ctx);
#ifndef SECUTILS_NO_TLS
        if (rw == NULL)
            APP_HTTP_TLS_INFO_free(info);
#endif
    }
}

/*
 * Support functionality
 */

/* credentials helpers */

inline
EVP_PKEY *KEY_load(OPTIONAL const char *file, OPTIONAL const char *pass,
                   OPTIONAL const char *engine, OPTIONAL const char *desc)
{
    return FILES_load_key_autofmt(file, FILES_get_format(file), false,
                                  pass, engine, desc);
}

inline
X509_REQ *CSR_load(const char *file, OPTIONAL const char *desc)
{
    return FILES_load_csr_autofmt(file, FILES_get_format(file), desc);
}

/* X509_STORE helpers */

inline
X509_STORE *STORE_load(const char *trusted_certs, OPTIONAL const char *desc,
                       OPTIONAL X509_VERIFY_PARAM *vpm)
{
    return STORE_load_check(trusted_certs, desc, vpm, NULL);
}

inline
X509_CRL *CRL_load(const char *url, int timeout, OPTIONAL const char *desc)
{
    return FILES_load_crl_autofmt(url, FORMAT_ASN1, timeout, desc);
}

inline
STACK_OF(X509_CRL) *CRLs_load(const char *files, int timeout,
                              OPTIONAL const char *desc)
{
    return FILES_load_crls_multi(files, FORMAT_ASN1, timeout, desc);
}

/* do not use: inline */
void CRLs_free(OPTIONAL STACK_OF(X509_CRL) *crls)
{
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
}

#ifndef SECUTILS_NO_TLS
/* SSL_CTX helpers for HTTPS */

inline
SSL_CTX *TLS_new(OPTIONAL const X509_STORE *truststore,
                 OPTIONAL const STACK_OF(X509) *untrusted,
                 OPTIONAL const CREDENTIALS *creds,
                 OPTIONAL const char *ciphers, int security_level)
{
    const int client = 1;

    return TLS_CTX_new(NULL, client, (X509_STORE *)truststore, untrusted,
                       creds, ciphers, security_level, NULL);
}

inline
void TLS_free(OPTIONAL SSL_CTX *tls)
{
    TLS_CTX_free(tls);
}
#endif
