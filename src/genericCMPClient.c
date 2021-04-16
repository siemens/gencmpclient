/*-
 * @file   genericCMPClient.c
 * @brief  generic CMP client library implementation
 *
 * @author David von Oheimb, CT RDA CST SEA, David.von.Oheimb@siemens.com
 *
 *  Copyright (c) 2018-2020 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 *  SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/cmperr.h>
#include <openssl/ssl.h>
#include <string.h>

#include "genericCMPClient.h"
#if OPENSSL_VERSION_NUMBER < 0x30000000L
# include "../cmpossl/crypto/cmp/cmp_local.h" /* needed to access ctx->server and ctx->proxy; TODO remove when OSSL_CMP_proxy_connect and ossl_cmp_build_cert_chain are available and used */
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100006L
typedef
STACK_OF(X509_EXTENSION) *(*sk_X509_EXTENSION_copyfunc)(const STACK_OF(X509_EXTENSION) *a);
#endif

#ifdef LOCAL_DEFS /* internal helper functions not documented in API spec */
# include "genericCMPClient_use.h"
#else
# include <secutils/storage/files.h>
# include <secutils/credentials/verify.h>
# include <secutils/credentials/store.h>
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

static int CMPOSSL_error()
{
    int err = ERR_GET_REASON(ERR_peek_last_error());
    if (err == 0) { /* check for wrong old CMPforOpenSSL behavior */
        err = -100;
    }
    return err;
}

/*
 * Core functionality
 */

CMP_err CMPclient_init(OPTIONAL LOG_cb_t log_fn)
{
    LOG_init((LOG_cb_t)log_fn); /* assumes that severity in SecUtils is same as in CMPforOpenSSL */
    UTIL_setup_openssl(OPENSSL_VERSION_NUMBER, "genericCMPClient");
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

X509_NAME *parse_DN(const char *str, const char *desc)
{
    X509_NAME *name = UTIL_parse_name(str, MBSTRING_ASC, false);
    if (name == NULL)
        LOG(FL_ERR, "Unable to parse %s DN '%s'", desc, str);
    return name;
}

CMP_err CMPclient_prepare(OSSL_CMP_CTX **pctx, OPTIONAL LOG_cb_t log_fn,
                          OPTIONAL X509_STORE *cmp_truststore,
                          OPTIONAL const char *recipient,
                          OPTIONAL const STACK_OF(X509) *untrusted,
                          OPTIONAL const CREDENTIALS *creds,
                          OPTIONAL X509_STORE *creds_truststore,
                          OPTIONAL const char *digest,
                          OPTIONAL const char *mac,
                          OPTIONAL OSSL_CMP_transfer_cb_t transfer_fn, int total_timeout,
                          OPTIONAL X509_STORE *new_cert_truststore, bool implicit_confirm)
{
    OSSL_CMP_CTX *ctx = NULL;

    if (pctx == NULL) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }
    if ((ctx = OSSL_CMP_CTX_new(/* TODO libctx */NULL, NULL)) == NULL ||
        !OSSL_CMP_CTX_set_log_cb(ctx, log_fn != NULL ? (OSSL_CMP_log_cb_t)log_fn :
                                 /* difference is in 'int' vs. 'bool' and additional TRACE value */
                                 (OSSL_CMP_log_cb_t)LOG_default)) {
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
        cert = CREDENTIALS_get_cert(creds);
        STACK_OF(X509) *chain = CREDENTIALS_get_chain(creds);
        const char *pwd = CREDENTIALS_get_pwd(creds);
        const char *pwdref = CREDENTIALS_get_pwdref(creds);
        if ((pwd != NULL
             && !OSSL_CMP_CTX_set1_secretValue(ctx, (unsigned char *)pwd, (int)strlen(pwd))) ||
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
            LOG(FL_ERR, "Internal error like out of memory obtaining recipient DN", recipient);
            OSSL_CMP_CTX_free(ctx);
            return CMP_R_RECIPIENT;
        }
    }
    if (rcp != NULL) { /* else CMPforOpenSSL uses cert issuer */
        bool rv = OSSL_CMP_CTX_set1_recipient(ctx, rcp);
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

    if ((transfer_fn != NULL && !OSSL_CMP_CTX_set_transfer_cb(ctx, transfer_fn)) ||
        (total_timeout >= 0
         && !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_TOTAL_TIMEOUT, total_timeout))) {
        goto err;
    }
    if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM, implicit_confirm)) {
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

#ifndef SECUTILS_NO_TLS
static const char *tls_error_hint(unsigned long err)
{
    switch (ERR_GET_REASON(err)) {
    /* case 0x1408F10B: */ /* xSL_F_SSL3_GET_RECORD */
    case SSL_R_WRONG_VERSION_NUMBER:
    /* case 0x140770FC: */ /* xSL_F_SSL23_GET_SERVER_HELLO */
    case SSL_R_UNKNOWN_PROTOCOL:
        return "The server does not support (a recent version of) TLS";
    /* case 0x1407E086: */ /* xSL_F_SSL3_GET_SERVER_HELLO */
    /* case 0x1409F086: */ /* xSL_F_SSL3_WRITE_PENDING */
    /* case 0x14090086: */ /* xSL_F_SSL3_GET_SERVER_CERTIFICATE */
    /* case 0x1416F086: */ /* xSL_F_TLS_PROCESS_SERVER_CERTIFICATE */
    case SSL_R_CERTIFICATE_VERIFY_FAILED:
        return "Cannot authenticate server via its TLS certificate, likely due to mismatch with our trusted TLS certs or missing revocation status";
    /* case 0x14094418: */ /* xSL_F_SSL3_READ_BYTES */
    case SSL_AD_REASON_OFFSET + TLS1_AD_UNKNOWN_CA:
        return "Server did not accept our TLS certificate, likely due to mismatch with server's trust anchor or missing revocation status";
    case SSL_AD_REASON_OFFSET + SSL3_AD_HANDSHAKE_FAILURE:
        return "Server requires our TLS certificate but did not receive one";
    default: /* no error or no hint available for error */
        return NULL;
    }
}

static BIO *tls_http_cb(OSSL_CMP_CTX *ctx, BIO *hbio, unsigned long detail)
{
    SSL_CTX *ssl_ctx = OSSL_CMP_CTX_get_http_cb_arg(ctx);
    BIO *sbio = NULL;

    if (detail == 1) { /* connecting */
        SSL *ssl;

        LOG_debug("connecting to TLS server");
        if ((ctx->proxy != NULL
             && !OSSL_CMP_proxy_connect(hbio, ctx, bio_err, "CMP client"))
            || (sbio = BIO_new(BIO_f_ssl())) == NULL) {
            hbio = NULL;
            goto end;
        }
        if ((ssl = SSL_new(ssl_ctx)) == NULL) {
            BIO_free(sbio);
            hbio = sbio = NULL;
            goto end;
        }

        /* set the server name indication ClientHello extension */
        char *host = ctx->server;
        if (host != NULL && *host < '0' && *host > '9' /* not IPv4 address */
            && SSL_set_tlsext_host_name(ssl, host)) {
            hbio = NULL;
            goto end;
        }

        SSL_set_connect_state(ssl);
        BIO_set_ssl(sbio, ssl, BIO_CLOSE);

        hbio = BIO_push(sbio, hbio);
    } else { /* disconnecting */
        const char *hint = tls_error_hint(detail);

        LOG_debug("disconnecting from TLS server");
        if (hint != NULL)
            ERR_add_error_data(1, hint);
        /*
         * as a workaround for OpenSSL double free, do not pop the sbio, but
         * rely on BIO_free_all() done by OSSL_CMP_PKIMESSAGE_http_perform()
         */
    }
 end:
    if (ssl_ctx != NULL) {
        X509_STORE *ts = SSL_CTX_get_cert_store(ssl_ctx);
        if (ts != NULL) {
            /* indicate if OSSL_CMP_MSG_http_perform() with TLS is active */
            (void)STORE_set0_tls_bio(ts, sbio);
        }
    }
    return hbio;
}
#endif

static bool use_proxy(const char *no_proxy, const char *server)
{
    size_t sl = strlen(server);
    const char *found = NULL;

    if (no_proxy == NULL)
        no_proxy = getenv("no_proxy");
    if (no_proxy == NULL)
        no_proxy = getenv("NO_PROXY");
    if (no_proxy != NULL)
        found = strstr(no_proxy, server);
    while (found != NULL
           && ((found != no_proxy && found[-1] != ' ' && found[-1] != ',')
               || (found[sl] != '\0' && found[sl] != ' ' && found[sl] != ',')))
        found = strstr(found + 1, server);
    return found == NULL;
}

#ifndef SECUTILS_NO_TLS
static int is_localhost(const char *host)
{
    return strcmp(host, "localhost") == 0
        || strcmp(host, "127.0.0.1") == 0
        || strcmp(host, "::1") == 0;
}
#endif

CMP_err CMPclient_setup_HTTP(OSSL_CMP_CTX *ctx,
                             const char *server, const char *path,
                             int timeout, OPTIONAL SSL_CTX *tls,
                             OPTIONAL const char *proxy,
                             OPTIONAL const char *no_proxy)
{
    char uri[255 + 1], *host = uri;
    const char *parsed_path;

    if (ctx == NULL || server == NULL) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }
#ifdef SECUTILS_NO_TLS
    if (tls != NULL) {
        LOG(FL_ERR, "TLS is not supported in this build");
        return CMP_R_INVALID_PARAMETERS;
    }
#endif

    snprintf(uri, sizeof(uri), "%s", server);
    int port = CONN_parse_uri(&host, 0, &parsed_path, "server");
    if (port <= 0) {
        return CMP_R_INVALID_PARAMETERS;
    }
    if (!OSSL_CMP_CTX_set1_server(ctx, host) ||
        (!OSSL_CMP_CTX_set_serverPort(ctx, port))) {
        goto err;
    }
    if (path == NULL)
        path = parsed_path;
    if (!OSSL_CMP_CTX_set1_serverPath(ctx, path) ||
        (timeout >= 0 && !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_MSG_TIMEOUT, timeout))) {
        goto err;
    }

    if (proxy == NULL)
        proxy = getenv("http_proxy");
    if (proxy == NULL)
        proxy = getenv("HTTP_PROXY");
    if (proxy != NULL && proxy[0] == '\0')
        proxy = NULL;
    if (proxy != NULL && !use_proxy(no_proxy, /* server */ host))
        proxy = NULL;
    /* TODO use !OSSL_CMP_CTX_set1_no_proxy() when available */
    char *proxy_host = host;
    if (proxy != NULL) {
#ifdef OLD_HTTP_API
        int proxy_port;
        char proxy_uri[255 + 1];
        if (strncmp(proxy, URL_HTTP_PREFIX, strlen(URL_HTTP_PREFIX)) == 0)
            proxy += strlen(URL_HTTP_PREFIX);
        else if (strncmp(proxy, URL_HTTPS_PREFIX, strlen(URL_HTTPS_PREFIX)) == 0)
            proxy += strlen(URL_HTTPS_PREFIX);
        snprintf(proxy_uri, sizeof(proxy_uri), "%s", proxy);
        proxy_port = UTIL_parse_server_and_port(proxy_host = proxy_uri);
        if (proxy_port < 0) {
            return CMP_R_INVALID_PARAMETERS;
        }
        if (!OSSL_CMP_CTX_set1_proxy(ctx, proxy_host) ||
            (proxy_port > 0 && !OSSL_CMP_CTX_set_proxyPort(ctx, proxy_port))) {
            goto err;
        }
#else
        if (!OSSL_CMP_CTX_set1_proxy(ctx, proxy))
            goto err;
#endif
    }

#ifndef SECUTILS_NO_TLS
    if (tls != NULL) {
        X509_STORE *ts = SSL_CTX_get_cert_store(tls);

        /*
         * If server is localhost, we will will proceed without "host verification".
         * This will enable Bootstrapping of LRA (by itself)
         * using only SMC which doesn't contain host.
         */
        if (is_localhost(proxy_host /* == host if no proxy */)) {
            LOG(FL_WARN, "skiping host verification on localhost");
        } else {
            /* set expected host if not already done by caller */
            if (STORE_get0_host(ts) == NULL &&
                !STORE_set1_host_ip(ts, proxy_host, proxy_host)) {
                goto err;
            }
        }
        if (!OSSL_CMP_CTX_set_http_cb(ctx, tls_http_cb) ||
            !SSL_CTX_up_ref(tls))
            goto err;
        SSL_CTX_free(OSSL_CMP_CTX_get_http_cb_arg(ctx));
        (void)OSSL_CMP_CTX_set_http_cb_arg(ctx, NULL);
        if (!OSSL_CMP_CTX_set_http_cb_arg(ctx, (void *)tls)) {
            SSL_CTX_free(tls);
            goto err;
        }
    }
#else
    (void)proxy_host;
#endif

    if (path == NULL)
        path = "";
    LOG(FL_INFO, "will contact http%s://%s:%d%s%s%s%s", tls != NULL ? "s" : "",
        host, port, path[0] == '/' ? "" : "/", path,
        proxy != NULL ? " via proxy " : "", proxy != NULL ? proxy : "");
    return CMP_OK;

 err:
    return CMPOSSL_error();
}

CMP_err CMPclient_setup_certreq(OSSL_CMP_CTX *ctx,
                                OPTIONAL const EVP_PKEY *new_key,
                                OPTIONAL const X509 *old_cert,
                                OPTIONAL const X509_NAME *subject,
                                OPTIONAL const X509_EXTENSIONS *exts,
                                OPTIONAL const X509_REQ *csr)
{
    if (ctx == NULL) {
        LOG(FL_ERR, "No ctx parameter given");
        return ERR_R_PASSED_NULL_PARAMETER;
    }

    if (old_cert != NULL && !OSSL_CMP_CTX_set1_oldCert(ctx, (X509 *)old_cert))
        goto err;
    if (new_key != NULL) {
        if (!EVP_PKEY_up_ref((EVP_PKEY *)new_key))
            goto err;
        if (!OSSL_CMP_CTX_set0_newPkey(ctx, 1 /* priv */, (EVP_PKEY *)new_key)) {
            EVP_PKEY_free((EVP_PKEY *)new_key);
            goto err;
        }
    }

    if (subject != NULL && !OSSL_CMP_CTX_set1_subjectName(ctx, subject))
        goto err;

    if (exts != NULL) {
        X509_EXTENSIONS *exts_copy =
            sk_X509_EXTENSION_deep_copy(exts,
                                        (sk_X509_EXTENSION_copyfunc)X509_EXTENSION_dup,
                                        X509_EXTENSION_free);
        if (exts_copy == NULL || !OSSL_CMP_CTX_set0_reqExtensions(ctx, exts_copy)) {
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L /* TODO remove decls when exported by OpenSSL */
int ossl_x509_add_cert_new(STACK_OF(X509) **p_sk, X509 *cert, int flags)
{
    if (*p_sk == NULL && (*p_sk = sk_X509_new_null()) == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return X509_add_cert(*p_sk, cert, flags);
}
int ossl_x509_add_certs_new(STACK_OF(X509) **p_sk, STACK_OF(X509) *certs,
                            int flags)
/* compiler would allow 'const' for the certs, yet they may get up-ref'ed */
{
    int n = sk_X509_num(certs /* may be NULL */);
    int i;

    for (i = 0; i < n; i++) {
        int j = (flags & X509_ADD_FLAG_PREPEND) == 0 ? i : n - 1 - i;
        /* if prepend, add certs in reverse order to keep original order */

        if (!ossl_x509_add_cert_new(p_sk, sk_X509_value(certs, j), flags))
            return 0;
    }
    return 1;
}

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
/* TODO this should be of more general interest and thus be exported. */
STACK_OF(X509)
    *ossl_cmp_build_cert_chain(OSSL_LIB_CTX *libctx, const char *propq,
                               X509_STORE *store,
                               STACK_OF(X509) *certs, X509 *cert)
{
    STACK_OF(X509) *chain = NULL, *result = NULL;
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
                                  ~((unsigned long)X509_V_FLAG_USE_CHECK_TIME
                                    | (unsigned long)X509_V_FLAG_NO_CHECK_TIME));

    if (X509_verify_cert(csc) <= 0 && store != NULL)
        goto err;
    chain = X509_STORE_CTX_get0_chain(csc);

    /* result list to store the up_ref'ed not self-signed certificates */
    if (!ossl_x509_add_certs_new(&result, chain,
                                 X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP
                                 | X509_ADD_FLAG_NO_SS)) {
        sk_X509_free(result);
        result = NULL;
    }

 err:
    if (store == NULL)
        X509_STORE_free(ts);
    X509_STORE_CTX_free(csc);
    return result;
}
#endif /* end TODO remove decls when exported by OpenSSL */

CMP_err CMPclient_enroll(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds, int cmd)
{
    X509 *newcert = NULL;

    if (ctx == NULL) {
        LOG(FL_ERR, "No ctx parameter given");
        return ERR_R_PASSED_NULL_PARAMETER;
    }
    if (new_creds == NULL) {
        LOG(FL_ERR, "No new_creds parameter given");
        return ERR_R_PASSED_NULL_PARAMETER;
    }

    /* check if any enrollment function has already been called before on ctx */
    if (OSSL_CMP_CTX_get_status(ctx) != -1) {
        return CMP_R_INVALID_CONTEXT;
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

    LOG_debug("Trying to build chain for newly enrolled cert");
    EVP_PKEY *new_key = OSSL_CMP_CTX_get0_newPkey(ctx, 1 /* priv */); /* NULL in case P10CR */
    X509_STORE *new_cert_truststore = OSSL_CMP_CTX_get_certConf_cb_arg(ctx);
    STACK_OF(X509) *untrusted = OSSL_CMP_CTX_get0_untrusted(ctx); /* includes extraCerts */
    STACK_OF(X509) *chain = ossl_cmp_build_cert_chain(/* TODO libctx */NULL, NULL,
                                                      new_cert_truststore /* may be NULL */,
                                                      untrusted, newcert);
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
#if 0
    if (new_key == NULL) {
        LOG(FL_ERR, "No new_key parameter given");
        return ERR_R_PASSED_NULL_PARAMETER;
    }
    if (subject == NULL) {
        LOG(FL_ERR, "No subject parameter given");
        return ERR_R_PASSED_NULL_PARAMETER;
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
#if 0
    if (new_key == NULL) {
        LOG(FL_ERR, "No new_key parameter given");
        return ERR_R_PASSED_NULL_PARAMETER;
    }
    if (subject == NULL) {
        LOG(FL_ERR, "No subject parameter given");
        return ERR_R_PASSED_NULL_PARAMETER;
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
        return ERR_R_PASSED_NULL_PARAMETER;
    }

    CMP_err err = CMPclient_setup_certreq(ctx, NULL /* new_key */,
                                          NULL /* old_cert */, NULL /* subject */,
                                          NULL /* exts */, csr);
    if (err == CMP_OK) {
        err = CMPclient_enroll(ctx, new_creds, CMP_P10CR);
    }
    return err;
}

CMP_err CMPclient_update_anycert(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                                 OPTIONAL const X509 *old_cert, const EVP_PKEY *new_key)
{
#if 0
    if (new_key == NULL) {
        LOG(FL_ERR, "No new_key parameter given");
        return ERR_R_PASSED_NULL_PARAMETER;
    }
#endif
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
        return ERR_R_PASSED_NULL_PARAMETER;
    }
#if 0
    if (cert == NULL) {
        LOG(FL_ERR, "No cert parameter given");
        return ERR_R_PASSED_NULL_PARAMETER;
    }
#endif
    if (cert != NULL) {
        if (!OSSL_CMP_CTX_set1_oldCert(ctx, (X509 *)cert))
            goto err;
    } else {
#if 0 /* TODO */
        if (!OSSL_CMP_CTX_set1_p10CSR(ctx, csr))
            goto err;
#endif
    }

    if ((reason >= CRL_REASON_UNSPECIFIED &&
         !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_REVOCATION_REASON, reason)) ||
        !OSSL_CMP_exec_RR_ses(ctx)) {
        goto err;
    }
    ERR_clear_error(); /* empty the OpenSSL error queue */
    return CMP_OK;

 err:
    return CMPOSSL_error();
}

char *CMPclient_snprint_PKIStatus(const OSSL_CMP_CTX *ctx, char *buf, size_t bufsize)
{
    return OSSL_CMP_CTX_snprint_PKIStatus(ctx, buf, bufsize);
}

void CMPclient_finish(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_CTX_print_errors(ctx);
    if (ctx != NULL) {
#ifndef SECUTILS_NO_TLS
        SSL_CTX_free(OSSL_CMP_CTX_get_http_cb_arg(ctx));
#endif
        X509_STORE_free(OSSL_CMP_CTX_get_certConf_cb_arg(ctx));
        OSSL_CMP_CTX_free(ctx);
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
X509 *CERT_load(const char *file, OPTIONAL const char *source, OPTIONAL const char *desc)
{
    return FILES_load_cert(file, FILES_get_format(file), source, desc);
}

inline
bool CERT_save(const X509 *cert, const char *file, OPTIONAL const char *desc)
{
    sec_file_format format = FILES_get_format(file);
    if (format == FORMAT_UNDEF) {
        LOG(FL_ERR, "Failed to determine format from file name ending of '%s'", file);
        return false;
    }
    return FILES_store_cert(cert, file, format, desc);
}

inline
X509_REQ *CSR_load(const char *file, OPTIONAL const char *desc)
{
    return FILES_load_csr_autofmt(file, FILES_get_format(file), desc);
}

/* X509_STORE helpers */

inline
STACK_OF(X509) *CERTS_load(const char *files, OPTIONAL const char *desc)
{
    return FILES_load_certs_multi(files, FORMAT_PEM, NULL /* password source */, desc);
}

inline
int CERTS_save(const STACK_OF(X509) *certs, const char *file, OPTIONAL const char *desc)
{
    sec_file_format format = FILES_get_format(file);
    if (format == FORMAT_UNDEF) {
        LOG(FL_ERR, "Failed to determine format from file name ending of '%s'", file);
        return -1;
    }
    return FILES_store_certs(certs, file, format, desc);
}

inline
void CERTS_free(OPTIONAL STACK_OF(X509) *certs)
{
    sk_X509_pop_free(certs, X509_free);
}

inline
X509_STORE *STORE_load(const char *trusted_certs, OPTIONAL const char *desc)
{
    return STORE_load_trusted(trusted_certs, desc, NULL);
}

inline
STACK_OF(X509_CRL) *CRLs_load(const char *files, int timeout, OPTIONAL const char *desc)
{
    return FILES_load_crls_multi(files, FORMAT_ASN1, timeout, desc);
}

inline
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
