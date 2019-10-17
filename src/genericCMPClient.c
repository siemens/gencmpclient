/*!*****************************************************************************
 * @file   genericCMPClient.c
 * @brief  generic CMP client library implementation
 *
 * @author David von Oheimb, CT RDA CST SEA, David.von.Oheimb@siemens.com
 *
 *  Copyright (c) 2018-2019 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 *  SPDX-License-Identifier: Apache-2.0
 ******************************************************************************/

#include "genericCMPClient.h"
#include "../cmpossl/crypto/cmp/cmp_int.h" /* TODO remove when OSSL_CMP_proxy_connect is available and used */

#include <openssl/cmperr.h>
#include <openssl/ssl.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER < 0x10100006L
typedef STACK_OF(X509_EXTENSION) * (*sk_X509_EXTENSION_copyfunc)(const STACK_OF(X509_EXTENSION) *a);
#endif

#ifdef LOCAL_DEFS

EVP_PKEY *CREDENTIALS_get_pkey(const CREDENTIALS *creds);
X509 *CREDENTIALS_get_cert(const CREDENTIALS *creds);
STACK_OF(X509) *CREDENTIALS_get_chain(const CREDENTIALS *creds);
char *CREDENTIALS_get_pwd(const CREDENTIALS *creds);
char *CREDENTIALS_get_pwdref(const CREDENTIALS *creds);

void LOG_init(OPTIONAL LOG_cb_t log_fn);
bool LOG(OPTIONAL const char* func, OPTIONAL const char* file,
         int lineno, OPTIONAL severity level, const char* fmt, ...);

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901)
# define LOG_FUNC __func__ /* function name is only available starting from C99.*/
/* Trying platform-specific and compiler-specific alternatives as fallback if possible. */
#elif defined(__STDC__) && defined(PEDANTIC)
# define LOG_FUNC "(PEDANTIC disallows function name)"
#elif defined(WIN32) || defined(__GNUC__) || defined(__GNUG__)
# define LOG_FUNC __FUNCTION__
#elif defined(__FUNCSIG__)
# define LOG_FUNC __FUNCSIG__
#else
# define LOG_FUNC "(unknown function)"
#endif
#define LOG_FUNC_FILE_LINE LOG_FUNC, OPENSSL_FILE, OPENSSL_LINE
#define FL_ERR   LOG_FUNC_FILE_LINE, LOG_ERR
#define FL_WARN  LOG_FUNC_FILE_LINE, LOG_WARNING
#define FL_INFO  LOG_FUNC_FILE_LINE, LOG_INFO
#define FL_DEBUG LOG_FUNC_FILE_LINE, LOG_DEBUG

void UTIL_setup_openssl(long version, const char *build_name);
int UTIL_parse_server_and_port(char *s);
X509_NAME *UTIL_parse_name(const char *dn, long chtype, bool multirdn);

enum
{
    B_FORMAT_TEXT = 0x8000
};
typedef enum
{
    FORMAT_UNDEF  = 0, /*! undefined file format */
    FORMAT_ASN1   = 4, /*! ASN.1/DER */
    FORMAT_PEM    = 5 | B_FORMAT_TEXT, /*! PEM */
    FORMAT_PKCS12 = 6, /*! PKCS#12 */
    FORMAT_ENGINE = 8, /*! crypto engine, which is not really a file format */
    FORMAT_HTTP  = 13  /*! download using HTTP */
} sec_file_format;     /*! type of format for security-related files or other input */
STACK_OF(X509)  *FILES_load_certs_multi(const char *files, sec_file_format format,
                                          OPTIONAL const char *pass, OPTIONAL const char *desc);
STACK_OF(X509_CRL)  *FILES_load_crls_multi(const char *files, sec_file_format format, const char *desc);

X509_STORE *STORE_load_trusted(const char *files, OPTIONAL const char *desc,
                               OPTIONAL void/* uta_ctx*/ *ctx);
bool STORE_set1_host_ip(X509_STORE *truststore, const char *host, const char *ip);
bool STORE_set0_tls_bio(X509_STORE* store, BIO* bio);
bool STORE_EX_init_index(void);
void STORE_EX_free_index(void);

#ifndef SEC_NO_TLS
bool TLS_init(void);
SSL_CTX *TLS_CTX_new(int client, OPTIONAL X509_STORE *truststore,
                     OPTIONAL const STACK_OF(X509) *untrusted,
                     OPTIONAL const CREDENTIALS *creds,
                     OPTIONAL const char *ciphers, int security_level,
                     OPTIONAL X509_STORE_CTX_verify_cb verify_cb);
void TLS_CTX_free(OPTIONAL SSL_CTX *ctx);
#endif

#else /* LOCAL_DEFS */

#include <SecUtils/storage/files.h>
#include <SecUtils/credentials/verify.h>
#include <SecUtils/credentials/store.h>
#ifndef SEC_NO_TLS
#include <SecUtils/connections/tls.h>
#endif

#endif /* LOCAL_DEFS */

#if OPENSSL_VERSION_NUMBER < 0x10100006L
# define SSL_CTX_up_ref(x)((x)->references++)
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100003L
#define ERR_R_INIT_FAIL (6|ERR_R_FATAL)
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

CMP_err CMPclient_init(OPTIONAL OSSL_cmp_log_cb_t log_fn)
{
    LOG_init((LOG_cb_t)log_fn); /* assumes that severity in SecUtils is same as in CMPforOpenSSL */
    UTIL_setup_openssl(OPENSSL_VERSION_NUMBER, "genericCMPClient");
    if (!STORE_EX_init_index()) {
        LOG(FL_ERR, "failed to initialize STORE_EX index\n");
        return ERR_R_INIT_FAIL;;
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

CMP_err CMPclient_prepare(OSSL_CMP_CTX **pctx, OPTIONAL OSSL_cmp_log_cb_t log_fn,
                          OPTIONAL X509_STORE *cmp_truststore,
                          OPTIONAL const char *recipient,
                          OPTIONAL const STACK_OF(X509) *untrusted,
                          OPTIONAL const CREDENTIALS *creds,
                          OPTIONAL const char *digest,
                          OPTIONAL OSSL_cmp_transfer_cb_t transfer_fn, int total_timeout,
                          OPTIONAL X509_STORE *new_cert_truststore, bool implicit_confirm)
{
    OSSL_CMP_CTX *ctx = NULL;

    if (NULL == pctx) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }

    if (pctx == NULL ||
        NULL == (ctx = OSSL_CMP_CTX_create()) ||
        !OSSL_CMP_CTX_set_log_cb(ctx, log_fn)) {
        goto err; /* TODO make sure that proper error code it set by OSSL_CMP_CTX_set_log_cb() */
    }
    if ((cmp_truststore != NULL && (!X509_STORE_up_ref(cmp_truststore) ||
                                    !OSSL_CMP_CTX_set0_trustedStore(ctx, cmp_truststore)))
        ||
        (untrusted      != NULL && !OSSL_CMP_CTX_set1_untrusted_certs(ctx, untrusted))) {
        goto err;
    }

    X509 *cert = NULL;
    if (creds != NULL) {
        const EVP_PKEY *pkey = CREDENTIALS_get_pkey(creds);
        cert = CREDENTIALS_get_cert(creds);
        STACK_OF(X509) *chain = CREDENTIALS_get_chain(creds);
        const char *pwd = CREDENTIALS_get_pwd(creds);
        const char *pwdref = CREDENTIALS_get_pwdref(creds);
        if ((pkey != NULL && !OSSL_CMP_CTX_set1_pkey(ctx, pkey)) ||
            (cert != NULL && !OSSL_CMP_CTX_set1_clCert(ctx, cert)) ||
            (sk_X509_num(chain) > 0 && !OSSL_CMP_CTX_set1_extraCertsOut(ctx, chain)) ||
            (pwd != NULL && !OSSL_CMP_CTX_set1_secretValue(ctx, (unsigned char*) pwd, strlen(pwd))) ||
            (pwdref != NULL && !OSSL_CMP_CTX_set1_referenceValue(ctx, (unsigned char *)pwdref, strlen(pwdref)))) {
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
        if (NULL == rcp) {
            LOG(FL_ERR, "Unable to parse recipient DN '%s'", recipient);
            OSSL_CMP_CTX_delete(ctx);
            return CMP_R_INVALID_PARAMETERS;
        }
    } else if (NULL == cert) {
        if (sk_X509_num(untrusted) > 0) {
            rcp = X509_NAME_dup((X509_get_subject_name(sk_X509_value(untrusted, 0))));
        } else {
            LOG(FL_WARN, "No explicit recipient, no cert, and no untrusted certs given; resorting to NULL DN");
            rcp = X509_NAME_new();
        }
        if (NULL == rcp) {
            LOG(FL_ERR, "Internal error like out of memory obtaining recipient DN", recipient);
            OSSL_CMP_CTX_delete(ctx);
            return CMP_R_RECIPIENT;
        }
    }
    if (rcp != NULL) {/* else CMPforOpenSSL uses cert issuer */
        bool rv = OSSL_CMP_CTX_set1_recipient(ctx, rcp);
        X509_NAME_free(rcp);
        if (!rv)
            goto err;
    }

    if (digest != NULL) {
        int nid = OBJ_ln2nid(digest);
        if (nid == NID_undef) {
            LOG(FL_ERR, "Bad digest algorithm name: '%s'", digest);
            OSSL_CMP_CTX_delete(ctx);
            return CMP_R_UNKNOWN_ALGORITHM_ID;
        }
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_DIGEST_ALGNID, nid)
            || !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_OWF_ALGNID, nid)) {
            goto err;
        }
    }

    if ((transfer_fn != NULL && !OSSL_CMP_CTX_set_transfer_cb(ctx, transfer_fn)) ||
        (total_timeout >= 0 && !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_TOTALTIMEOUT, total_timeout))) {
        goto err;
    }
    if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IMPLICITCONFIRM, implicit_confirm)) {
        goto err;
    }
    if (new_cert_truststore != NULL
        && (!OSSL_CMP_CTX_set_certConf_cb(ctx, OSSL_CMP_certConf_cb) ||
            !OSSL_CMP_CTX_set_certConf_cb_arg(ctx, new_cert_truststore) ||
            !X509_STORE_up_ref(new_cert_truststore))) {
        goto err;
    }

    *pctx = ctx;
    return CMP_OK;

 err:
    OSSL_CMP_CTX_delete(ctx);
    return CMPOSSL_error();
}

#ifndef SEC_NO_TLS
static const char *tls_error_hint(unsigned long err)
{
    switch(ERR_GET_REASON(err)) {
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
    case SSL_AD_REASON_OFFSET+TLS1_AD_UNKNOWN_CA:
        return "Server did not accept our TLS certificate, likely due to mismatch with server's trust anchor or missing revocation status";
    case SSL_AD_REASON_OFFSET+SSL3_AD_HANDSHAKE_FAILURE:
        return "Server requires our TLS certificate but did not receive one";
    default: /* no error or no hint available for error */
        return NULL;
    }
}

/* TODO remove when OSSL_CMP_proxy_connect is available and used */
/* from apps.h */
# ifndef openssl_fdset
#  if defined(OPENSSL_SYSNAME_WIN32) \
   || defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WINCE)
#   define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
#  else
#   define openssl_fdset(a,b) FD_SET(a, b)
#  endif
# endif
/* wait if timeout > 0. returns < 0 on error, 0 on timeout, > 0 on success */
static int socket_wait(int fd, int for_read, int timeout)
{
    fd_set confds;
    struct timeval tv;

    if (timeout <= 0)
        return 0;

    FD_ZERO(&confds);
    openssl_fdset(fd, &confds);
    tv.tv_usec = 0;
    tv.tv_sec = timeout;
    return select(fd + 1, for_read ? &confds : NULL,
                  for_read ? NULL : &confds, NULL, &tv);
}

/* TODO remove when OSSL_CMP_proxy_connect is available and used */
/* wait if timeout > 0. returns < 0 on error, 0 on timeout, > 0 on success */
static int bio_wait(BIO *bio, int timeout) {
    int fd;

    if (BIO_get_fd(bio, &fd) <= 0)
        return -1;
    return socket_wait(fd, BIO_should_read(bio), timeout);
}
/* copied from s_client with simplifications and trivial changes */
/* TODO replace by OSSL_CMP_proxy_connect() when available */
#undef BUFSIZZ
#define BUFSIZZ 1024*8
#define HTTP_PREFIX "HTTP/"
#define HTTP_VERSION "1." /* or, e.g., "1.1" */
#define HTTP_VERSION_MAX_LEN 3
static int proxy_connect(OSSL_CMP_CTX *ctx, BIO *bio)
{
    char *mbuf = OPENSSL_malloc(BUFSIZZ);
    int mbuf_len = 0;
    int rv;
    int ret = 0;
    BIO *fbio = BIO_new(BIO_f_buffer());
    time_t max_time = ctx->msgtimeout > 0 ? time(NULL) + ctx->msgtimeout : 0;

    if (mbuf == NULL || fbio == NULL) {
        LOG(FL_ERR, "out of memory");
        goto end;
    }
    BIO_push(fbio, bio);
    /* CONNECT seems only to be specified for HTTP/1.1 in RFC 2817/7231 */
    BIO_printf(fbio, "CONNECT %s:%d "HTTP_PREFIX"1.1\r\n",
               ctx->serverName, ctx->serverPort);
    /*
     * Workaround for broken proxies which would otherwise close
     * the connection when entering tunnel mode (eg Squid 2.6)
     */
    BIO_printf(fbio, "Proxy-Connection: Keep-Alive\r\n");

#ifdef OSSL_CMP_SUPPORT_PROXYUSER /* TODO is not yet supported */
    /* Support for basic (base64) proxy authentication */
    char *proxyuser = NULL;
    char *proxypass = NULL;
    #define base64encode(str, len) OPENSSL_strdup(str)
    if (proxyuser != NULL) {
        size_t l;
        char *proxyauth, *proxyauthenc;

        l = strlen(proxyuser);
        if (proxypass != NULL)
            l += strlen(proxypass);
        proxyauth = OPENSSL_malloc(l + 2);
        snprintf(proxyauth, l + 2, "%s:%s", proxyuser, (proxypass != NULL) ? proxypass : "");
        proxyauthenc = base64encode(proxyauth, strlen(proxyauth));
        BIO_printf(fbio, "Proxy-Authorization: Basic %s\r\n", proxyauthenc);
        OPENSSL_clear_free(proxyauth, strlen(proxyauth));
        OPENSSL_clear_free(proxyauthenc, strlen(proxyauthenc));
    }
#endif
    BIO_printf(fbio, "\r\n");
flush_retry:
    if(!BIO_flush(fbio))
        /* potentially needs to be retried if BIO is non-blocking */
        if (BIO_should_retry(fbio))
                goto flush_retry;
retry:
    rv = bio_wait(fbio, (int)(max_time - time(NULL)));
    if (rv <= 0) {
        LOG(FL_ERR, "HTTP CONNECT %s\n", rv == 0 ? "timed out" : "failed waiting for data");
        goto end;
    }

    mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
    /* as the BIO doesn't block, we need to wait that the first line comes in */
    if (mbuf_len < (int)strlen(HTTP_PREFIX""HTTP_VERSION" 200")) {
        goto retry;
    }
    /* RFC 7231 4.3.6: any 2xx status code is valid */
    if (strncmp(mbuf, HTTP_PREFIX, strlen(HTTP_PREFIX) != 0)) {
        LOG(FL_ERR, "HTTP CONNECT failed, non-HTTP response");
        goto end;
    }
    char *mbufp = mbuf + strlen(HTTP_PREFIX);
    if (strncmp(mbufp, HTTP_VERSION, strlen(HTTP_VERSION)) != 0) {
        LOG(FL_ERR, "HTTP CONNECT failed, bad HTTP version %.*s", HTTP_VERSION_MAX_LEN, mbufp);
        goto end;
    }
    mbufp += HTTP_VERSION_MAX_LEN;
    if (strncmp(mbufp, " 2", strlen(" 2")) != 0) {
        mbufp += 1;
        LOG(FL_ERR, "HTTP CONNECT failed: %.*s ", (int)(mbuf_len - (mbufp - mbuf)), mbufp);
        goto end;
    }

    /* TODO: this does not necessarily catch the case when the full HTTP
             response came in in more than a single TCP message */
    /* Read past all following headers */
    do {
        mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
    } while (mbuf_len > 2);

    ret = 1;
end:
    if (fbio != NULL) {
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
    }
    OPENSSL_free(mbuf);
    return ret;
}


static BIO *tls_http_cb(OSSL_CMP_CTX *ctx, BIO *hbio, unsigned long detail)
{
    SSL_CTX *ssl_ctx = OSSL_CMP_CTX_get_http_cb_arg(ctx);
    BIO *sbio = NULL;

    if (detail == 1) { /* connecting */
        SSL *ssl;

        if ((ctx->proxyName != NULL && ctx->proxyPort != 0
             && !proxy_connect(ctx, hbio))
            || (sbio = BIO_new(BIO_f_ssl())) == NULL) {
            hbio = NULL;
            goto end;
        }
        if ((ssl = SSL_new(ssl_ctx)) == NULL) {
            BIO_free(sbio);
            hbio = sbio = NULL;
            goto end;
        }

        SSL_set_tlsext_host_name(ssl, ctx->serverName);

        SSL_set_connect_state(ssl);
        BIO_set_ssl(sbio, ssl, BIO_CLOSE);

        hbio = BIO_push(sbio, hbio);
    } else { /* disconnecting */
        const char *hint = tls_error_hint(detail);
        if (hint != NULL)
            ERR_add_error_data(1, hint);
        /* as a workaround for OpenSSL double free, do not pop the sbio, but
           rely on BIO_free_all() done by OSSL_CMP_PKIMESSAGE_http_perform() */
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

CMP_err CMPclient_setup_HTTP(OSSL_CMP_CTX *ctx,
                             const char *server, const char *path,
                             int timeout, OPTIONAL SSL_CTX *tls,
                             OPTIONAL const char *proxy)
{
    char buf[80+1];
    int port;

    if (NULL == ctx || NULL == server || NULL == path) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }
#ifdef SEC_NO_TLS
    if (tls != NULL) {
        LOG(FL_ERR, "TLS is not supported in this build");
        return CMP_R_INVALID_PARAMETERS;
    }
#endif

    snprintf(buf, sizeof(buf), "%s", server);
    port = UTIL_parse_server_and_port(buf);
    if (port < 0) {
        return CMP_R_INVALID_PARAMETERS;
    }
    if (!OSSL_CMP_CTX_set1_serverName(ctx, buf) ||
        (port > 0 && !OSSL_CMP_CTX_set_serverPort(ctx, port))) {
        goto err;
    }

    const char *proxy_env = getenv("http_proxy");
    if (proxy_env != NULL) {
        proxy = proxy_env;
    }
    if (proxy != NULL && proxy[0] == '\0')
        proxy = NULL;
    if (proxy != NULL) {
        const char *http_prefix = "http://";
        if (strncmp(proxy, http_prefix, strlen(http_prefix)) == 0) {
            proxy += strlen(http_prefix);
        }
        const char *no_proxy = getenv("no_proxy");
        if (no_proxy == NULL || strstr(no_proxy, buf/* server*/) == NULL) {
            snprintf(buf, sizeof(buf), "%s", proxy);
            port = UTIL_parse_server_and_port(buf);
            if (port < 0) {
                return CMP_R_INVALID_PARAMETERS;
            }
            if (!OSSL_CMP_CTX_set1_proxyName(ctx, buf) ||
                (port > 0 && !OSSL_CMP_CTX_set_proxyPort(ctx, port))) {
                goto err;
            }
        } else {
            proxy = NULL;
        }
    }
    if (!OSSL_CMP_CTX_set1_serverPath(ctx, path) ||
        (timeout >= 0 && !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_MSGTIMEOUT, timeout))) {
        goto err;
    }

#ifndef SEC_NO_TLS
    if (tls != NULL) {
        if (server != NULL &&
            !STORE_set1_host_ip(SSL_CTX_get_cert_store(tls), server, server)) {
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

    LOG(FL_INFO, "contacting %s%s%s%s%s", server, path[0] == '/' ? "" : "/", path,
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
    if (NULL == ctx) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }

    if ((old_cert != NULL && !OSSL_CMP_CTX_set1_oldClCert(ctx, old_cert)) ||
        (new_key  != NULL && !OSSL_CMP_CTX_set1_newPkey(ctx, new_key))) {
        goto err;
    }

    if (subject != NULL) {
        X509_NAME *n = UTIL_parse_name(subject, MBSTRING_ASC, false);
        if (NULL == n) {
            LOG(FL_ERR, "Unable to parse subject DN '%s'", subject);
            return CMP_R_INVALID_PARAMETERS;
        }
        if (!OSSL_CMP_CTX_set1_subjectName(ctx, n)) {
            X509_NAME_free(n);
            goto err;
        }
        X509_NAME_free(n);
    } /* TODO maybe else take subjectName (for sender default) from oldCert or p10cr */

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

    if (NULL == ctx || NULL == new_creds) {
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
    if (NULL == newcert) {
        goto err;
    }

    EVP_PKEY *new_key = OSSL_CMP_CTX_get0_newPkey(ctx); /* NULL in case P10CR */
    STACK_OF(X509) *untrusted = OSSL_CMP_CTX_get0_untrusted_certs(ctx); /* includes extraCerts */
    STACK_OF(X509) *chain = OSSL_CMP_build_cert_chain(untrusted, newcert);
    if (chain != NULL) {
        X509* new_cert = sk_X509_shift(chain);
        X509_free(new_cert);
    } else {
        LOG(FL_WARN, "Could not build proper chain for newly enrolled cert, resorting to all untrusted certs");
        chain = X509_chain_up_ref(untrusted);
    }

    CREDENTIALS *creds = CREDENTIALS_new(new_key, newcert, chain, NULL, NULL);
    CERTS_free(chain);
    if (NULL == creds) {
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
    if (NULL == new_key || NULL == subject) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }
    CMP_err err = CMPclient_setup_certreq(ctx, new_key, NULL/* old_cert */,
                                          subject, exts, NULL/* csr */);
    if (err == CMP_OK) {
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT, 1);
        err = CMPclient_enroll(ctx, new_creds, CMP_IR);
    }
    return err;
}

CMP_err CMPclient_bootstrap(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                            const EVP_PKEY *new_key,
                            const char *subject,
                            OPTIONAL const X509_EXTENSIONS *exts)
{
    if (NULL == new_key || NULL == subject) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }
    CMP_err err = CMPclient_setup_certreq(ctx, new_key, NULL/* old_cert */,
                                          subject, exts, NULL/* csr */);
    if (err == CMP_OK) {
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT, 1);
        err = CMPclient_enroll(ctx, new_creds, CMP_CR);
    }
    return err;
}

CMP_err CMPclient_pkcs10(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                         const X509_REQ *csr)
{
    if (NULL == csr) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }

    CMP_err err = CMPclient_setup_certreq(ctx, NULL/* new_key */,
                                          NULL/* old_cert */, NULL/* subject */,
                                          NULL/* exts */, csr);
    if (err == CMP_OK) {
        err = CMPclient_enroll(ctx, new_creds, CMP_P10CR);
    }
    return err;
}

CMP_err CMPclient_update(OSSL_CMP_CTX *ctx, CREDENTIALS **new_creds,
                         const EVP_PKEY *new_key)
{
    if (NULL == new_key) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }
    CMP_err err = CMPclient_setup_certreq(ctx, new_key, NULL/* old_cert */,
                                          NULL/* subject */, NULL/* exts */,
                                          NULL/* csr */);
    if (err == CMP_OK) {
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT, 0);
        err = CMPclient_enroll(ctx, new_creds, CMP_KUR);
    }
    return err;
}

CMP_err CMPclient_revoke(OSSL_CMP_CTX *ctx, const X509 *cert, int reason)
{
    if (NULL == ctx || NULL == cert) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }

    if ((reason >= CRL_REASON_UNSPECIFIED &&
         !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_REVOCATION_REASON, reason)) ||
        !OSSL_CMP_CTX_set1_oldClCert(ctx, cert) ||
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
    OSSL_CMP_print_errors(ctx);
#ifndef SEC_NO_TLS
    SSL_CTX_free(OSSL_CMP_CTX_get_http_cb_arg(ctx));
#endif
    X509_STORE_free(OSSL_CMP_CTX_get_certConf_cb_arg(ctx));
    OSSL_CMP_CTX_delete(ctx);
/* better not do here:
    STORE_EX_free_index();
    LOG_close();
*/
}


/*
 * Support functionality
 */

/* X509_STORE helpers */

inline
STACK_OF(X509) *CERTS_load(const char *files, OPTIONAL const char *desc)
{
    return FILES_load_certs_multi(files, FORMAT_PEM, NULL/* pass */, desc);
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
STACK_OF(X509_CRL) *CRLs_load(const char *files, OPTIONAL const char *desc)
{
    return FILES_load_crls_multi(files, FORMAT_ASN1, desc);
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
