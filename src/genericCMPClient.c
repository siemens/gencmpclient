/*!*****************************************************************************
 * @file   genericCMPClient.c
 * @brief  generic CMP client library implementation
 *
 * @author David von Oheimb, CT RDA ITS SEA, David.von.Oheimb@siemens.com
 *
 * @copyright (c) Siemens AG 2018 all rights reserved
 ******************************************************************************/

#include <string.h>
#include <SecUtils/credentials/verify.h>
#include <genericCMPClient.h>

static int CMPOSSL_error()
{
    int err = ERR_GET_REASON(ERR_peek_last_error());
    if (err == 0) { /* check for wrong old CMPforOpenSSL behavior */
        err = -100;
    }
    return err;
}

/*!
 * callback validating that the new certificate can be verified, using
 * ctx->certConf_cb_arg, which has been initialized using opt_out_trusted, and
 * ctx->untrusted_certs, which at this point already contains ctx->extraCertsIn.
 * Returns -1 on acceptance, else a OSSL_CMP_PKIFAILUREINFO bit number.
 * Quoting from RFC 4210 section 5.1. Overall PKI Message:
       The extraCerts field can contain certificates that may be useful to
       the recipient.  For example, this can be used by a CA or RA to
       present an end entity with certificates that it needs to verify its
       own new certificate (if, for example, the CA that issued the end
       entity's certificate is not a root CA for the end entity).  Note that
       this field does not necessarily contain a certification path; the
       recipient may have to sort, select from, or otherwise process the
       extra certificates in order to use them.
 * Note: While often handy, there is no hard requirement by CMP that an EE must
 * be able to validate the certs it gets enrolled. This callback is used by default.
^<*/
/* TODO replace by OSSL_CMP_certConf_cb() when available */
static int CMP_certConf_cb(OSSL_CMP_CTX *ctx, const X509 *cert, int failure, const char **text)
{
    X509_STORE *out_trusted = OSSL_CMP_CTX_get_certConf_cb_arg(ctx);
    (void)text; /* make (artificial) use of 'text' to prevent compiler warning */

    if (failure >= 0) { /* accept any error flagged by CMP core library */
        return failure;
    }

    /* TODO: load caPubs [OSSL_CMP_CTX_caPubs_get1(ctx)] as additional trusted
       certs during IR and if MSG_SIG_ALG is used, cf. RFC 4210, 5.3.2 */

    if (out_trusted != NULL &&
        !OSSL_CMP_validate_cert_path(ctx, out_trusted, cert, true)) {
        failure = OSSL_CMP_PKIFAILUREINFO_incorrectData;
    }

    if (failure >= 0) {
        char *str = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        OSSL_CMP_printf(ctx, FL_ERR,
                   "Failed to validate newly enrolled certificate with subject: %s",
                   str);
        OPENSSL_free(str);
    }
    return failure;
}

CMP_err CMPclient_prepare(OSSL_CMP_CTX **pctx, OPTIONAL OSSL_cmp_log_cb_t log_fn,
      /* both for CMP: */ OPTIONAL X509_STORE *cmp_truststore,
                          OPTIONAL const STACK_OF(X509) *untrusted,
                          OPTIONAL const CREDENTIALS *creds,
                          OPTIONAL const char *digest,
                          OPTIONAL OSSL_cmp_transfer_cb_t transfer_fn, int total_timeout,
                          OPTIONAL X509_STORE *new_cert_truststore, bool implicit_confirm)
{
    OSSL_CMP_CTX *ctx = NULL;

    /* "copy" trust stores regardless of success */
    if (cmp_truststore != NULL) {
        X509_STORE_up_ref(cmp_truststore);
    }
    if (new_cert_truststore != NULL) {
        X509_STORE_up_ref(new_cert_truststore);
    }

    if (NULL == pctx) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }

    LOG_init((LOG_cb_t)log_fn);
    if (!OSSL_CMP_log_init() || /* this call needs to be done first */
        pctx == NULL ||
        NULL == (ctx = OSSL_CMP_CTX_create()) ||
        !OSSL_CMP_CTX_set_log_cb(ctx, log_fn)) {
        goto err;
    }
    if ((cmp_truststore != NULL && !OSSL_CMP_CTX_set0_trustedStore(ctx, cmp_truststore)) ||
        (untrusted      != NULL && !OSSL_CMP_CTX_set1_untrusted_certs(ctx, untrusted))) {
        goto err;
    }

    if (creds != NULL) {
        const EVP_PKEY *pkey = CREDENTIALS_get_pkey(creds);
        const X509 *cert = CREDENTIALS_get_cert(creds);
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
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_UNPROTECTED_SEND, 1)) {
            goto err;
        }
    }

    if (digest != NULL) {
        int nid = OBJ_ln2nid(digest);
        if (nid == NID_undef) {
            OSSL_CMP_printf(ctx, FL_ERR, "Bad digest algorithm name: '%s'", digest);
            OSSL_CMP_CTX_delete(ctx);
            return CMP_R_UNKNOWN_ALGORITHM_ID;
        }
        if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_DIGEST_ALGNID, nid)) {
            goto err;
        }
    }

    if ((transfer_fn != NULL && !OSSL_CMP_CTX_set_transfer_cb(ctx, transfer_fn)) ||
        (total_timeout >= 0 && !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_TOTALTIMEOUT, total_timeout))) {
        goto err;
    }
    if (new_cert_truststore != NULL &&
        (!OSSL_CMP_CTX_set_certConf_cb(ctx, CMP_certConf_cb) ||
         !OSSL_CMP_CTX_set_certConf_cb_arg(ctx, new_cert_truststore))) {
        goto err;
    }
    if (!OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_IMPLICITCONFIRM, implicit_confirm)) {
        goto err;
    }

    *pctx = ctx;
    return CMP_OK;

 err:
    OSSL_CMP_CTX_delete(ctx);
    return CMPOSSL_error();
}

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

static BIO *tls_http_cb(OSSL_CMP_CTX *ctx, BIO *hbio, unsigned long detail)
{
    SSL_CTX *ssl_ctx = OSSL_CMP_CTX_get_http_cb_arg(ctx);
    BIO *sbio = NULL;
    if (detail == 1) { /* connecting */
        sbio = BIO_new_ssl(OSSL_CMP_CTX_get_http_cb_arg(ctx), true/* client */);
        hbio = sbio ? BIO_push(sbio, hbio): NULL;
    } else { /* disconnecting */
        const char *hint = tls_error_hint(detail);
        if (hint != NULL)
            OSSL_CMP_add_error_data(hint);
        /* as a workaround for OpenSSL double free, do not pop the sbio, but
           rely on BIO_free_all() done by OSSL_CMP_PKIMESSAGE_http_perform() */
    }
    if (ssl_ctx != NULL) {
        X509_STORE *ts = SSL_CTX_get_cert_store(ssl_ctx);
        if (ts != NULL) {
            /* indicate if OSSL_CMP_MSG_http_perform() with TLS is active */
            (void)X509_STORE_set_ex_data(ts, X509_STORE_EX_DATA_SBIO, sbio);
        }
    }
    return hbio;
}

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
    if (proxy != NULL && proxy[0] != '\0') {
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
        }
    }

    if (!OSSL_CMP_CTX_set1_serverPath(ctx, path) ||
        (timeout >= 0 && !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_MSGTIMEOUT, timeout))) {
        goto err;
    }

    if (tls != NULL) {
        if (!OSSL_CMP_CTX_set_http_cb(ctx, tls_http_cb) ||
            !OSSL_CMP_CTX_set_http_cb_arg(ctx, (void *)tls)) {
            goto err;
        }
        if (server != NULL &&
            !STORE_set1_host_ip(SSL_CTX_get_cert_store(tls), server, server)) {
            goto err;
        }
    }

    return CMP_OK;

    err:
    return CMPOSSL_error();
}

/* TODO remove when OSSL_CMP_CTX_set1_reqExtensions() has become available */
static X509_EXTENSIONS *exts_dup(X509_EXTENSIONS *extin /* may be NULL */)
{
    X509_EXTENSIONS *exts = sk_X509_EXTENSION_new_null();
    if (exts == NULL) {
        goto err;
    }
    if (extin != NULL) {
        int i;
        for (i = 0; i < sk_X509_EXTENSION_num(extin); i++) {
            X509_EXTENSION *ext = X509_EXTENSION_dup(sk_X509_EXTENSION_value(extin, i));
            if (!sk_X509_EXTENSION_push(exts, ext)) {
                goto err;
            }
        }
    }
    return exts;
 err:
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return NULL;
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
            OSSL_CMP_printf(ctx, FL_ERR, "Unable to parse subject DN '%s'", subject);
            return CMP_R_INVALID_PARAMETERS;
        }
        if (!OSSL_CMP_CTX_set1_subjectName(ctx, n)) {
            X509_NAME_free(n);
            goto err;
        }
        X509_NAME_free(n);
    }

    if (exts != NULL) {
        X509_EXTENSIONS *exts_copy = exts_dup((X509_EXTENSIONS *)exts); /* TODO use instead OSSL_CMP_CTX_set1_reqExtensions() when available */
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
        OSSL_CMP_printf(ctx, FL_ERR, "Argument must be CMP_IR, CMP_CR, CMP_P10CR, or CMP_KUR");
	return CMP_R_INVALID_PARAMETERS;
	break;
    }
    if (NULL == newcert) {
	goto err;
    }

    EVP_PKEY *new_key = OSSL_CMP_CTX_get0_newPkey(ctx); /* NULL in case P10CR */
    STACK_OF(X509) *untrusted = OSSL_CMP_CTX_get0_untrusted_certs(ctx); /* includes extraCerts */
    STACK_OF(X509) *chain = OSSL_CMP_build_cert_chain(untrusted, newcert);
    if (NULL == chain) {
        chain = X509_chain_up_ref(untrusted);
    }

    CREDENTIALS *creds = CREDENTIALS_new(new_key, newcert, chain, NULL, NULL);
    sk_X509_pop_free(chain, X509_free);
    if (NULL == creds) {
	return ERR_R_MALLOC_FAILURE;
    }
    *new_creds = creds;
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
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_SUBJECTALTNAME_NODEFAULT, 1);
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
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_SUBJECTALTNAME_NODEFAULT, 1);
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
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_SUBJECTALTNAME_NODEFAULT, 0);
        err = CMPclient_enroll(ctx, new_creds, CMP_KUR);
    }
    return err;
}

CMP_err CMPclient_revoke(OSSL_CMP_CTX *ctx, const X509 *cert, int reason)
{
    if (NULL == ctx || NULL == cert) {
        return ERR_R_PASSED_NULL_PARAMETER;
    }

    if ((reason >= CRL_REASON_NONE &&
	 !OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_CTX_OPT_REVOCATION_REASON, reason)) ||
	!OSSL_CMP_CTX_set1_oldClCert(ctx, cert) ||
        !OSSL_CMP_exec_RR_ses(ctx)) {
	goto err;
    }
    return CMP_OK;

    err:
    return CMPOSSL_error();
}

void CMPclient_finish(OSSL_CMP_CTX *ctx)
{
    SSL_CTX_free(OSSL_CMP_CTX_get_http_cb_arg(ctx));
    OSSL_CMP_CTX_delete(ctx);
    LOG_close();
}


