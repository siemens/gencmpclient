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

#include "genericCMPClient.h"
#include "../cmpossl/crypto/cmp/cmp_local.h" /* TODO remove when OSSL_CMP_proxy_connect is available and used */

#include <openssl/cmperr.h>
#include <openssl/ssl.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER < 0x10100006L
typedef
STACK_OF(X509_EXTENSION) *(*sk_X509_EXTENSION_copyfunc)(const STACK_OF(X509_EXTENSION) *a);
#endif

#ifdef LOCAL_DEFS

EVP_PKEY *CREDENTIALS_get_pkey(const CREDENTIALS *creds);
X509 *CREDENTIALS_get_cert(const CREDENTIALS *creds);
STACK_OF(X509) *CREDENTIALS_get_chain(const CREDENTIALS *creds);
char *CREDENTIALS_get_pwd(const CREDENTIALS *creds);
char *CREDENTIALS_get_pwdref(const CREDENTIALS *creds);

void LOG_init(OPTIONAL LOG_cb_t log_fn);
bool LOG_default(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level, const char* msg);

bool LOG(OPTIONAL const char *func, OPTIONAL const char *file,
         int lineno, OPTIONAL severity level, const char *fmt, ...);

# if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901)
#  define LOG_FUNC __func__ /* function name is only available starting from C99. */
/* Trying platform-specific and compiler-specific alternatives as fallback if possible. */
# elif defined(__STDC__) && defined(PEDANTIC)
#  define LOG_FUNC "(PEDANTIC disallows function name)"
# elif defined(WIN32) || defined(__GNUC__) || defined(__GNUG__)
#  define LOG_FUNC __FUNCTION__
# elif defined(__FUNCSIG__)
#  define LOG_FUNC __FUNCSIG__
# else
#  define LOG_FUNC "(unknown function)"
# endif
# define LOG_FUNC_FILE_LINE LOG_FUNC, OPENSSL_FILE, OPENSSL_LINE
# define FL_ERR   LOG_FUNC_FILE_LINE, LOG_ERR
# define FL_WARN  LOG_FUNC_FILE_LINE, LOG_WARNING
# define FL_INFO  LOG_FUNC_FILE_LINE, LOG_INFO
# define FL_DEBUG LOG_FUNC_FILE_LINE, LOG_DEBUG
#define LOG_err(msg) LOG(FL_ERR, msg)     /*!< simple error message */

void UTIL_setup_openssl(long version, const char *build_name);
int UTIL_parse_server_and_port(char *s);
X509_NAME *UTIL_parse_name(const char *dn, long chtype, bool multirdn);

enum {
    B_FORMAT_TEXT = 0x8000
};
typedef enum {
    FORMAT_UNDEF  = 0, /* undefined file format */
    FORMAT_ASN1   = 4, /* ASN.1/DER */
    FORMAT_PEM    = 5 | B_FORMAT_TEXT, /* PEM */
    FORMAT_PKCS12 = 6, /* PKCS#12 */
    FORMAT_ENGINE = 8, /* crypto engine, which is not really a file format */
    FORMAT_HTTP   = 13 /* download using HTTP */
} sec_file_format;     /* type of format for security-related files or other input */
STACK_OF(X509) *FILES_load_certs_multi(const char *files, sec_file_format format,
                                       OPTIONAL const char *pass,
                                       OPTIONAL const char *desc);
STACK_OF(X509_CRL) *FILES_load_crls_multi(const char *files, sec_file_format format,
                                          int timeout, const char *desc);

X509_STORE *STORE_load_trusted(const char *files, OPTIONAL const char *desc,
                               OPTIONAL void /* uta_ctx */ *ctx);
bool STORE_set1_host_ip(X509_STORE *truststore, const char *host, const char *ip);
const char* STORE_get0_host(X509_STORE* store);
bool STORE_set0_tls_bio(X509_STORE *store, BIO *bio);
bool STORE_EX_init_index(void);
void STORE_EX_free_index(void);

# ifndef SEC_NO_TLS
bool TLS_init(void);
SSL_CTX *TLS_CTX_new(OPTIONAL SSL_CTX* ssl_ctx,
                     int client, OPTIONAL X509_STORE *truststore,
                     OPTIONAL const STACK_OF(X509) *untrusted,
                     OPTIONAL const CREDENTIALS *creds,
                     OPTIONAL const char *ciphers, int security_level,
                     OPTIONAL X509_STORE_CTX_verify_cb verify_cb);
void TLS_CTX_free(OPTIONAL SSL_CTX *ctx);
# endif

#else /* LOCAL_DEFS */

# include <SecUtils/storage/files.h>
# include <SecUtils/credentials/verify.h>
# include <SecUtils/credentials/store.h>
# ifndef SEC_NO_TLS
#  include <SecUtils/connections/tls.h>
# endif

#endif /* LOCAL_DEFS */

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
    if (!STORE_EX_init_index()) {
        LOG(FL_ERR, "failed to initialize STORE_EX index\n");
        return ERR_R_INIT_FAIL;
    }

    if (!OSSL_CMP_log_init()
#ifndef SEC_NO_TLS
        || !TLS_init()
#endif
        ) {
        LOG(FL_ERR, "failed to initialize genCMPClient\n");
        return ERR_R_INIT_FAIL;
    }
    return CMP_OK;
}

CMP_err CMPclient_prepare(OSSL_CMP_CTX **pctx, OPTIONAL LOG_cb_t log_fn,
                          OPTIONAL X509_STORE *cmp_truststore,
                          OPTIONAL const char *recipient,
                          OPTIONAL const STACK_OF(X509) *untrusted,
                          OPTIONAL const CREDENTIALS *creds,
                          OPTIONAL const char *digest,
                          OPTIONAL const char *mac,
                          OPTIONAL OSSL_CMP_transfer_cb_t transfer_fn, int total_timeout,
                          OPTIONAL X509_STORE *new_cert_truststore, bool implicit_confirm)
{
    OSSL_CMP_CTX *ctx = NULL;

    if (pctx == NULL) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }
    if ((ctx = OSSL_CMP_CTX_new()) == NULL ||
        !OSSL_CMP_CTX_set_log_cb(ctx, log_fn != NULL ? (OSSL_CMP_log_cb_t)log_fn :
                                 /* difference is in 'int' vs. 'bool' and additinal TRACE value */
                                 (OSSL_CMP_log_cb_t)LOG_default)) {
        goto err; /* TODO make sure that proper error code it set by OSSL_CMP_CTX_set_log_cb() */
    }
    if ((cmp_truststore != NULL
         && (!X509_STORE_up_ref(cmp_truststore) ||
             !OSSL_CMP_CTX_set0_trustedStore(ctx, cmp_truststore)))
        ||
        (untrusted != NULL
         && !OSSL_CMP_CTX_set1_untrusted_certs(ctx, (STACK_OF(X509) *)untrusted))) {
        goto err;
    }

    X509 *cert = NULL;
    if (creds != NULL) {
        EVP_PKEY *pkey = CREDENTIALS_get_pkey(creds);
        cert = CREDENTIALS_get_cert(creds);
        STACK_OF(X509) *chain = CREDENTIALS_get_chain(creds);
        const char *pwd = CREDENTIALS_get_pwd(creds);
        const char *pwdref = CREDENTIALS_get_pwdref(creds);
        if ((pkey != NULL && !OSSL_CMP_CTX_set1_pkey(ctx, pkey)) ||
            (cert != NULL && !OSSL_CMP_CTX_set1_clCert(ctx, cert)) ||
            (!OSSL_CMP_CTX_set1_untrusted_certs(ctx, chain)) ||
            (pwd != NULL
             && !OSSL_CMP_CTX_set1_secretValue(ctx, (unsigned char *) pwd, (int)strlen(pwd))) ||
            (pwdref != NULL
             && !OSSL_CMP_CTX_set1_referenceValue(ctx, (unsigned char *)pwdref,
                                                  (int)strlen(pwdref)))) {
            goto err;
        }
    } else {
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_SEND, 1)) {
            goto err;
        }
    }

    /* need recipient for unprotected and PBM-protected messages */
    X509_NAME *rcp = NULL;
    if (recipient != NULL) {
        rcp = UTIL_parse_name(recipient, MBSTRING_ASC, false);
        if (rcp == NULL) {
            LOG(FL_ERR, "Unable to parse recipient DN '%s'", recipient);
            OSSL_CMP_CTX_free(ctx);
            return CMP_R_INVALID_PARAMETERS;
        }
    } else if (cert == NULL) {
        if (sk_X509_num(untrusted) > 0) {
            rcp = X509_NAME_dup((X509_get_subject_name(sk_X509_value(untrusted, 0))));
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

#ifndef SEC_NO_TLS
static const char *tls_error_hint(unsigned long err)
{
    switch (ERR_GET_REASON(err)) {
/*  case 0x1408F10B: */ /* xSL_F_SSL3_GET_RECORD */
    case SSL_R_WRONG_VERSION_NUMBER:
/*  case 0x140770FC: */ /* xSL_F_SSL23_GET_SERVER_HELLO */
    case SSL_R_UNKNOWN_PROTOCOL:
        return "The server does not support (a recent version of) TLS";
/*  case 0x1407E086: */ /* xSL_F_SSL3_GET_SERVER_HELLO */
/*  case 0x1409F086: */ /* xSL_F_SSL3_WRITE_PENDING */
/*  case 0x14090086: */ /* xSL_F_SSL3_GET_SERVER_CERTIFICATE */
/*  case 0x1416F086: */ /* xSL_F_TLS_PROCESS_SERVER_CERTIFICATE */
    case SSL_R_CERTIFICATE_VERIFY_FAILED:
        return "Cannot authenticate server via its TLS certificate, likely due to mismatch with our trusted TLS certs or missing revocation status";
/*  case 0x14094418: */ /* xSL_F_SSL3_READ_BYTES */
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

        if ((ctx->proxyName != NULL && ctx->proxyPort != 0
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
        char *host = ctx->serverName;
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

CMP_err CMPclient_setup_HTTP(OSSL_CMP_CTX *ctx,
                             const char *server, const char *path,
                             int timeout, OPTIONAL SSL_CTX *tls,
                             OPTIONAL const char *proxy,
                             OPTIONAL const char *no_proxy)
{
    char addr[80 + 1];
    int port;

    if (ctx == NULL || server == NULL || path == NULL) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }
#ifdef SEC_NO_TLS
    if (tls != NULL) {
        LOG(FL_ERR, "TLS is not supported in this build");
        return CMP_R_INVALID_PARAMETERS;
    }
#endif

    snprintf(addr, sizeof(addr), "%s", server);
    port = UTIL_parse_server_and_port(addr);
    if (port < 0) {
        return CMP_R_INVALID_PARAMETERS;
    }
    if (!OSSL_CMP_CTX_set1_server(ctx, addr) ||
        (port > 0 && !OSSL_CMP_CTX_set_serverPort(ctx, port))) {
        goto err;
    }
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
    if (proxy != NULL && !use_proxy(no_proxy, /* server */ addr))
        proxy = NULL;
    if (proxy != NULL) {
        if (strncmp(proxy, URL_HTTP_PREFIX, strlen(URL_HTTP_PREFIX)) == 0)
            proxy += strlen(URL_HTTP_PREFIX);
        else if (strncmp(proxy, URL_HTTPS_PREFIX, strlen(URL_HTTPS_PREFIX)) == 0)
            proxy += strlen(URL_HTTPS_PREFIX);
        snprintf(addr, sizeof(addr), "%s", proxy);
        port = UTIL_parse_server_and_port(addr);
        if (port < 0) {
            return CMP_R_INVALID_PARAMETERS;
        }
        if (!OSSL_CMP_CTX_set1_proxy(ctx, addr) ||
            (port > 0 && !OSSL_CMP_CTX_set_proxyPort(ctx, port))) {
            goto err;
        }
    }

#ifndef SEC_NO_TLS
    if (tls != NULL) {
        X509_STORE *ts = SSL_CTX_get_cert_store(tls);
        /* set expected host if not already done by caller */
        if (STORE_get0_host(ts) == NULL &&
            !STORE_set1_host_ip(ts, server, server)) {
            goto err;
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
#endif

    LOG(FL_INFO, "will contact http%s://%s%s%s%s%s", tls != NULL ? "s" : "",
        server, path[0] == '/' ? "" : "/", path,
        proxy != NULL ? " via proxy " : "", proxy != NULL ? proxy : "");
    return CMP_OK;

 err:
    return CMPOSSL_error();
}

CMP_err CMPclient_setup_certreq(OSSL_CMP_CTX *ctx,
                                OPTIONAL const EVP_PKEY *new_key,
                                OPTIONAL const X509 *old_cert,
                                OPTIONAL const char *subject,
                                OPTIONAL const X509_EXTENSIONS *exts,
                                OPTIONAL const X509_REQ *p10csr)
{
    if (ctx == NULL) {
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

    if (subject != NULL) {
        X509_NAME *n = UTIL_parse_name(subject, MBSTRING_ASC, false);
        if (n == NULL) {
            LOG(FL_ERR, "Unable to parse subject DN '%s'", subject);
            return CMP_R_INVALID_PARAMETERS;
        }
        if (!OSSL_CMP_CTX_set1_subjectName(ctx, n)) {
            X509_NAME_free(n);
            goto err;
        }
        X509_NAME_free(n);
    }

    if (exts != NULL) {
        X509_EXTENSIONS *exts_copy =
            sk_X509_EXTENSION_deep_copy(exts,
                                        (sk_X509_EXTENSION_copyfunc)X509_EXTENSION_dup,
                                        X509_EXTENSION_free);
        if (exts_copy == NULL || !OSSL_CMP_CTX_set0_reqExtensions(ctx, exts_copy)) {
            goto err;
        }
    }

    if (p10csr != NULL && !OSSL_CMP_CTX_set1_p10CSR(ctx, p10csr)) {
        goto err;
    }

    return CMP_OK;

 err:
    return CMPOSSL_error();
}

CMP_err CMPclient_enroll(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds, int type)
{
    X509 *newcert = NULL;

    if (ctx == NULL || new_creds == NULL) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }

    /* check if any enrollment function has already been called before on ctx */
    if (OSSL_CMP_CTX_get0_transactionID(ctx) != NULL) {
        return CMP_R_INVALID_CONTEXT;
    }

    switch (type) {
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

    EVP_PKEY *new_key = OSSL_CMP_CTX_get0_newPkey(ctx, 1 /* priv */); /* NULL in case P10CR */
    STACK_OF(X509) *untrusted = OSSL_CMP_CTX_get0_untrusted_certs(ctx); /* includes extraCerts */
    STACK_OF(X509) *chain = OSSL_CMP_build_cert_chain(untrusted, newcert);
    if (chain != NULL) {
        X509 *new_cert = sk_X509_shift(chain);
        X509_free(new_cert);
    } else {
        LOG(FL_WARN, "Could not build proper chain for newly enrolled cert, resorting to all untrusted certs");
        chain = X509_chain_up_ref(untrusted);
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
    if (new_key == NULL || subject == NULL) {
        LOG(FL_ERR, "No parameter for either -newkey or -subject option");
        return ERR_R_PASSED_NULL_PARAMETER;
    }
    CMP_err err = CMPclient_setup_certreq(ctx, new_key, NULL /* old_cert */,
                                          subject, exts, NULL /* csr */);
    if (err == CMP_OK) {
        err = CMPclient_enroll(ctx, new_creds, CMP_IR);
    }
    return err;
}

CMP_err CMPclient_bootstrap(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                            const EVP_PKEY *new_key,
                            const char *subject,
                            OPTIONAL const X509_EXTENSIONS *exts)
{
    if (new_key == NULL || subject == NULL) {
        LOG(FL_ERR, "No parameter for either -newkey or -subject option");
        return ERR_R_PASSED_NULL_PARAMETER;
    }
    CMP_err err = CMPclient_setup_certreq(ctx, new_key, NULL /* old_cert */,
                                          subject, exts, NULL /* csr */);
    if (err == CMP_OK) {
        err = CMPclient_enroll(ctx, new_creds, CMP_CR);
    }
    return err;
}

CMP_err CMPclient_pkcs10(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                         const X509_REQ *csr)
{
    if (csr == NULL) {
        LOG(FL_ERR, "No parameter for -csr option");
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
                                 const X509 *old_cert, const EVP_PKEY *new_key)
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

CMP_err CMPclient_revoke(OSSL_CMP_CTX *ctx, const X509 *cert, int reason)
{
    if (ctx == NULL || cert == NULL) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }

    if ((reason >= CRL_REASON_UNSPECIFIED &&
         !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_REVOCATION_REASON, reason)) ||
        !OSSL_CMP_CTX_set1_oldCert(ctx, (X509 *)cert) ||
        !OSSL_CMP_exec_RR_ses(ctx)) {
        goto err;
    }
    ERR_clear_error(); /* empty the OpenSSL error queue */
    return CMP_OK;

 err:
    return CMPOSSL_error();
}

void CMPclient_finish(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_CTX_print_errors(ctx);
#ifndef SEC_NO_TLS
    SSL_CTX_free(OSSL_CMP_CTX_get_http_cb_arg(ctx));
#endif
    X509_STORE_free(OSSL_CMP_CTX_get_certConf_cb_arg(ctx));
    OSSL_CMP_CTX_free(ctx);
/*-
 * better not do here:
 *   STORE_EX_free_index();
 *   LOG_close();
 */
}


/*
 * Support functionality
 */

/* X509_STORE helpers */

inline
STACK_OF(X509) *CERTS_load(const char *files, OPTIONAL const char *desc)
{
    return FILES_load_certs_multi(files, FORMAT_PEM, NULL /* pass */, desc);
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

#ifndef SEC_NO_TLS
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
