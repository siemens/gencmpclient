/*-
 * @file   genericCMPClient_util.c
 * @brief  generic CMP client library helper implementation
 *
 * @author David von Oheimb, Siemens AG, David.von.Oheimb@siemens.com
 *
 *  Copyright (c) 2024 Siemens AG
 *
 *  Licensed under the Apache License 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You can obtain a copy in the file LICENSE in the source distribution
 *  or at https://www.openssl.org/source/license.html
 *  SPDX-License-Identifier: Apache-2.0
 */

// util.c:

static void UTIL_erase_mem(void *dst, size_t len)
{
    if (dst != NULL)
        OPENSSL_cleanse(dst, len);
}

static void UTIL_cleanse(char *str)
{
    if (str != NULL)
        UTIL_erase_mem((void *)str, strlen(str));
}

static void UTIL_cleanse_free(OPTIONAL char *str)
{
    UTIL_cleanse(str);
    OPENSSL_free(str);
}

// log.c:

#include <syslog.h>

static const char *const GENCMP_NAME = "genCMPClient";
static const size_t loc_len = 256;

/*!< these variables are shared between threads */
static LOG_cb_t LOG_fn = 0;
static const char *app_name = GENCMP_NAME;
static severity verbosity = LOG_WARNING;
BIO *bio_err = 0;
BIO *bio_trace = 0;

static void log_close_bios(void)
{
    if (bio_trace != NULL) {
        (void)BIO_flush(bio_trace);
        BIO_free(bio_trace);
        bio_trace = NULL;
    }
    if (bio_err != NULL) {
        (void)BIO_flush(bio_err);
        BIO_free(bio_err);
        bio_err = NULL;
    }
}

void LOG_close(void)
{
    log_close_bios();
}

void LOG_init(OPTIONAL LOG_cb_t log_fn)
{
    LOG_close(); /* flush any pending output and free any previous resources */

    if (log_fn != NULL)
        LOG_fn = log_fn;
}

void LOG_set_verbosity(severity level)
{
    if (level < LOG_EMERG || level > LOG_TRACE) {
        fprintf(stderr, "error: logging verbosity level %d out of range (0 .. 8) for %s\n",
                level, app_name);
        return;
    }

    log_close_bios();

    verbosity = level;

#ifndef NDEBUG
    if (level >= LOG_ERR) {
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
        if (bio_err == NULL)
            fprintf(stderr, "warning: cannot open bio_err for low-level error reporting of %s\n",
                    app_name);
    }
    if (level >= LOG_TRACE) {
        bio_trace = BIO_new_fp(stdout, BIO_NOCLOSE);
        if (bio_trace == NULL)
            fprintf(stderr, "warning: cannot open bio_trace for detailed debugging output of %s\n",
                    app_name);
    }
#endif
}

void LOG_set_name(OPTIONAL const char *name)
{
    app_name = name != NULL ? name : GENCMP_NAME;
}

static bool LOG_generic(OPTIONAL const char *func, OPTIONAL const char *file, int lineno,
                        severity level, const char *msg, bool use_syslog, bool use_console)
{
    if (level > verbosity
#ifdef NDEBUG
        /* output DEBUG level messages only if debugging is enabled at build time */
        || level >= LOG_DEBUG
#endif
        )
        return true;

    if (func == NULL)
        func = "(no function)";
    if (file == NULL)
        file = "(no file)";
    if (msg == NULL) /* just in case */
        msg = "(no message)";

    if (use_syslog)
        syslog(level, "%s: %.50s():%.60s:%d: %.256s", app_name, func, file, lineno, msg);

    if (!use_console)
        return true;

    /* print everything to stdout in order to prevent order mismatch with portions on stderr */
    FILE *fd = /* level <= LOG_WARNING ? stderr : */ stdout;

    char loc[loc_len];
    memset(loc, 0x00, loc_len);
    int len = snprintf(loc, sizeof(loc), "%s", app_name);
#ifndef NDEBUG
    /* print fct name, source file name, and lineno only if debugging is enabled at build time */
    (void)snprintf(loc + len, sizeof(loc) - len, ":%s():%s:%d:", func, file, lineno);
#endif

    /* print string corresponding to level */
    char *lvl = 0;
    switch (level) {
    case LOG_EMERG:
        lvl = "EMERGENCY";
        break;
    case LOG_ALERT:
        lvl = "ALERT";
        break;
    case LOG_CRIT:
        lvl = "CRITICAL";
        break;
    case LOG_ERR:
        lvl = "ERROR";
        break;
    case LOG_WARNING:
        lvl = "WARNING";
        break;
    case LOG_NOTICE:
        lvl = "NOTICE";
        break;
    case LOG_INFO:
        lvl = "INFO";
        break;
    case LOG_DEBUG:
        lvl = "DEBUG";
        break;
    case LOG_TRACE:
        lvl = "TRACE";
        break;
    default:
        lvl = "(UNKNOWN SEVERITY)";
        break;
    }

    /* print message, making sure that newline is printed  */
    len = strlen(msg);
    const int msg_nl = len > 0 && msg[len - 1] == '\n';
    const int ret = fprintf(fd, "%s %s: %s%s", loc, lvl, msg, msg_nl ? "" : "\n");

    /* make sure that printing is done right away, return info on success  */
    return fflush(fd) != EOF && ret >= 0;
}

static bool LOG_default(OPTIONAL const char *func, OPTIONAL const char *file,
                        int lineno, severity level, const char *msg)
{
    return LOG_generic(func, file, lineno, level, msg, 1, 1);
}

bool LOG_console(OPTIONAL const char *func, OPTIONAL const char *file,
                 int lineno, severity level, const char *msg)
{
    return LOG_generic(func, file, lineno, level, msg, 0, 1);
}

/*
 * Function used for outputting error/warn/debug messages depending on callback.
 * If no specific callback function is set, the function LOG_default() is used.
 */
bool LOG(OPTIONAL const char *func, OPTIONAL const char *file,
         int lineno, severity level, const char *fmt, ...)
{
    va_list arg_ptr;
    char msg[1024];
    bool res;

    va_start(arg_ptr, fmt);
    BIO_vsnprintf(msg, sizeof(msg), fmt, arg_ptr);
    res = (LOG_fn ? *LOG_fn : &LOG_default)(func, file, lineno, level, msg);
    va_end(arg_ptr);
    return res;
}

// cert.c:

/*
 * dn is expected to be in the format "/type0=value0/type1=value1/type2=..."
 * where characters may be escaped by '\'.
 * The NULL-DN may be given as "/" or "".
 */
/* adapted from OpenSSL:apps/lib/apps.c */
X509_NAME *UTIL_parse_name(const char *dn, long chtype, bool multirdn)
{
    size_t buflen = strlen(dn) + 1; /*
                                     * to copy the types and values.
                                     * Due to escaping, the copy can only become shorter
                                     */
    char *buf = OPENSSL_malloc(buflen);
    size_t max_ne = buflen / (1 + 1) + 1; /* maximum number of name elements */
    const char **ne_types = OPENSSL_malloc(max_ne * sizeof(char *));
    char **ne_values = OPENSSL_malloc(max_ne * sizeof(char *));
    int *mval = OPENSSL_malloc(max_ne * sizeof(int));
    const char *sp = dn;
    char *bp = buf;
    int i, ne_num = 0;
    X509_NAME *n = 0;
    int nid;

    if (buf == NULL || ne_types == NULL || ne_values == NULL || mval == NULL) {
        LOG_err("Malloc error");
        goto error;
    }

    /* no multi-valued RDN by default */
    mval[ne_num] = 0;

    if (*sp != '\0' && *sp++ != '/') { /* skip leading '/' */
        LOG(FL_ERR, "DN '%s' does not start with '/'.", dn);
        goto error;
    }

    while (*sp != '\0') {
        /* collect type */
        ne_types[ne_num] = bp;
        /* parse element name */
        while (*sp != '=') {
            if (*sp == '\\') { /* is there anything to escape in the * type...? */
                if (*++sp != '\0') {
                    *bp++ = *sp++;
                } else {
                    LOG(FL_ERR, "Escape character at end of DN '%s'", dn);
                    goto error;
                }
            } else if (*sp == '\0') {
                LOG(FL_ERR, "End of string encountered while processing type of DN '%s' element #%d",
                    dn, ne_num);
                goto error;
            } else {
                *bp++ = *sp++;
            }
        }
        sp++;
        *bp++ = '\0';
        /* parse element value */
        ne_values[ne_num] = bp;
        while (*sp != '\0') {
            if (*sp == '\\') {
                if (*++sp != '\0') {
                    *bp++ = *sp++;
                } else {
                    LOG(FL_ERR, "Escape character at end of DN '%s'", dn);
                    goto error;
                }
            } else if (*sp == '/') { /* start of next element */
                sp++;
                /* no multi-valued RDN by default */
                mval[ne_num + 1] = 0;
                break;
            } else if (*sp == '+' && multirdn) {
                /* a not escaped + signals a multi-valued RDN */
                sp++;
                mval[ne_num + 1] = -1;
                break;
            } else {
                *bp++ = *sp++;
            }
        }
        *bp++ = '\0';
        ne_num++;
    }

    if ((n = X509_NAME_new()) == NULL)
        goto error;

    for (i = 0; i < ne_num; i++) {
        if ((nid = OBJ_txt2nid(ne_types[i])) == NID_undef) {
            LOG(FL_WARN, "DN '%s' attribute %s has no known NID, skipped", dn, ne_types[i]);
            continue;
        }

        if (ne_values[i] == NULL) {
            LOG(FL_WARN, "No value provided for DN '%s' attribute %s, skipped", dn, ne_types[i]);
            continue;
        }

        if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        (unsigned char *)ne_values[i], -1, -1, mval[i])) {
            ERR_print_errors(bio_err);
            LOG(FL_ERR, "Error adding name attribute '/%s=%s'", ne_types[i], ne_values[i]);
            X509_NAME_free(n);
            n = 0;
            goto error;
        }
    }

error:
    OPENSSL_free(ne_values);
    OPENSSL_free(ne_types);
    OPENSSL_free(mval);
    OPENSSL_free(buf);
    return n;
}

static void cert_msg(const char *func, const char *file, int lineno,
                     OSSL_CMP_severity level, ossl_unused OSSL_CMP_CTX *ctx,
                     const char *source, X509 *cert, const char *msg)
{
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

    LOG(func, file, lineno, level,
        level == OSSL_CMP_LOG_WARNING ? "WARN" : "ERR",
        "certificate from '%s' with subject '%s' %s",
        source, subj, msg);
    OPENSSL_free(subj);
}

/* use |type_CA| -1 (no CA type check) or 0 (must be EE) or 1 (must be CA) */
static int ossl_X509_check(OSSL_CMP_CTX *ctx, const char *source, X509 *cert,
                           int type_CA, const X509_VERIFY_PARAM *vpm)
{
    uint32_t ex_flags = X509_get_extension_flags(cert);
    int res = X509_cmp_timeframe(vpm, X509_get0_notBefore(cert),
                                 X509_get0_notAfter(cert));
    int ret = res == 0;
    OSSL_CMP_severity level =
        vpm == NULL ? OSSL_CMP_LOG_WARNING : OSSL_CMP_LOG_ERR;

    if (!ret)
        cert_msg(OPENSSL_FUNC, OPENSSL_FILE, OPENSSL_LINE, level, ctx,
                 source, cert, res > 0 ? "has expired" : "not yet valid");
    if (type_CA >= 0 && (ex_flags & EXFLAG_V1) == 0) {
        int is_CA = (ex_flags & EXFLAG_CA) != 0;

        if ((type_CA != 0) != is_CA) {
            cert_msg(OPENSSL_FUNC, OPENSSL_FILE, OPENSSL_LINE, level, ctx,
                     source, cert,
                     is_CA ? "is not an EE cert" : "is not a CA cert");
            ret = 0;
        }
    }
    return ret;
}

int ossl_X509_check_all(OSSL_CMP_CTX *ctx, const char *source,
                        STACK_OF(X509) *certs,
                        int type_CA, const X509_VERIFY_PARAM *vpm)
{
    int i;
    int ret = 1;

    for (i = 0; i < sk_X509_num(certs /* may be NULL */); i++)
        ret = ossl_X509_check(ctx, source,
                              sk_X509_value(certs, i), type_CA, vpm)
            && ret; /* Having 'ret' after the '&&', all certs are checked. */
    return ret;
}

// credentials.c:

CREDENTIALS *CREDENTIALS_new(OPTIONAL const EVP_PKEY *pkey, const OPTIONAL X509 *cert,
                             OPTIONAL const STACK_OF(X509)  *chain, OPTIONAL const char *pwd,
                             OPTIONAL const char *pwdref)
{
    const char *pass = pwd;
    CREDENTIALS *res;

    if (pwd != NULL && strncmp(pwd, sec_PASS_STR, strlen(sec_PASS_STR)) == 0)
        pass = pwd + strlen(sec_PASS_STR);

    if (pkey != NULL && cert != NULL && !X509_check_private_key((X509 *)cert, (EVP_PKEY *)pkey)) {
        LOG_err("Private key and public key in cert do not match");
        return NULL;
    }

    res = OPENSSL_malloc(sizeof(*res));
    if (res == NULL) {
        LOG(FL_ERR, "Out of memory");
        return NULL;
    }

    res->pkey = (EVP_PKEY *)pkey;
    if (pkey != NULL && !EVP_PKEY_up_ref(res->pkey))
        res->pkey = NULL;
    res->cert = (X509 *)cert;
    if (cert != NULL && !X509_up_ref(res->cert))
        res->cert = NULL;
    res->chain = NULL;
    if (chain != NULL)
        res->chain = X509_chain_up_ref((STACK_OF(X509)*)chain);
    res->pwd = OPENSSL_strdup(pass);
    res->pwdref = OPENSSL_strdup(pwdref);

    if ((pkey != NULL && res->pkey == NULL)
        || (cert != NULL && res->cert == NULL)
        || (chain != NULL && res->chain == NULL)
        || (pass != NULL && res->pwd == NULL)
        || (pwdref != NULL && res->pwdref == NULL)) {
        CREDENTIALS_free(res);
        LOG(FL_ERR, "Out of memory");
        res = NULL;
    }
    return res;
}

void CREDENTIALS_free(OPTIONAL CREDENTIALS *creds)
{
    if (creds != NULL) {
        EVP_PKEY_free(creds->pkey);
        X509_free(creds->cert);
        CERTS_free(creds->chain);
        UTIL_cleanse_free(creds->pwd);
        OPENSSL_free(creds->pwdref);
        OPENSSL_free(creds);
    }
}

// conn.c:

static const char *const CONN_scheme_postfix = "://";

static const char *skip_scheme(const char *str)
{
    const char *scheme_end = strstr(str, CONN_scheme_postfix);

    if (scheme_end != NULL)
        str = scheme_end + strlen(CONN_scheme_postfix);
    return str;
}

static char *CONN_get_host(const char *uri)
{
    char *str = NULL;

    if (uri != NULL) {
        char *end;
        size_t len;

        uri = skip_scheme(uri);
        end = strrchr(uri, ':');
        if (end == NULL)
            end = strchr(uri, '/');
        len = end != NULL ? (size_t)(end - uri) : strlen(uri);
        str = OPENSSL_strndup(uri, len);
        if (str == NULL)
            LOG_err("Out of memory");
    }
    return str;
}

// store.c:

typedef struct STORE_ex_st
{
#ifndef GENCMP_NO_TLS
    BIO *tls_bio; /* indicates CMP_PKIMESSAGE_http_perform() with TLS is active */
#endif
    const char *desc; /* description to be used for diagnostic purposes */
    const char *host; /* expected host name in cert, for diagnostic purposes */
#if 0
    CONN_load_crl_cb_t crl_cb;
    OPTIONAL void *crl_cb_arg;
    revstatus_access cdps;
    revstatus_access ocsp;
#endif
} STORE_EX; /* extension data for OpenSSL X509_STORE */

static int STORE_EX_data_idx = -1;

bool STORE_EX_check_index(void)
{
    return STORE_EX_data_idx != -1;
}

__attribute__((destructor))
static void STORE_EX_free_index(void) /* unused? */
{
    if (STORE_EX_data_idx != -1) {
        CRYPTO_free_ex_index(CRYPTO_EX_INDEX_X509_STORE, STORE_EX_data_idx);
        STORE_EX_data_idx = -1;
    }
}

static STORE_EX *STORE_get_ex_data(X509_STORE *store)
{
    STORE_EX *res = 0;

    if (store == NULL) {
        LOG(FL_ERR, "null argument");
    } else {
        res = X509_STORE_get_ex_data(store, STORE_EX_data_idx);
        if (res == NULL)
            LOG(FL_ERR, "STORE_EX not found");
    }
    return res;
}

/* all params may be null pointer; does not consume cert or certs */
X509_STORE *STORE_create(OPTIONAL X509_STORE *store, OPTIONAL const X509 *cert,
                         OPTIONAL const STACK_OF(X509) *certs)
{
    int i;

    if (store == NULL) {
        if (!STORE_EX_check_index())
            return 0;

        store = X509_STORE_new();
        if (store == NULL)
            goto oom;
    }
    X509_STORE_set_verify_cb(store, X509_STORE_CTX_print_verify_cb
                             /* TODO better: CREDENTIALS_print_cert_verify_cb */);

#if 0 /* better not trust unclear default store */
    if (X509_STORE_set_default_paths(store) != 1) {
        LOG_err("Cannot load the system-wide trusted certificates");
        STORE_free(store);
        return 0;
    }
#endif

    int n = certs ? sk_X509_num(certs) : 0;
    for (i = cert ? -1 : 0; i < n; i++) {
        if (i != -1)
            cert = sk_X509_value(certs, i);
        if (!X509_STORE_add_cert(store, (X509 *)cert)) {
            STORE_free(store);
            goto oom;
        }
    }
    return store;

oom:
    LOG_err("Out of memory creating trust store");
    return 0;
}

static bool STORE_set1_host(X509_STORE *store, OPTIONAL const char *host)
{
    STORE_EX *ex_data = STORE_get_ex_data(store);

    if (ex_data == NULL)
        return false;
    OPENSSL_free((char *)ex_data->host);
    ex_data->host = OPENSSL_strdup(host);
    return true;
}

const char *STORE_get0_host(X509_STORE *store)
{
    const STORE_EX *ex_data = STORE_get_ex_data(store);

    return ex_data != NULL ? ex_data->host : 0;
}

#ifndef GENCMP_NO_TLS
bool STORE_set0_tls_bio(X509_STORE *store, OPTIONAL BIO *bio)
{
    STORE_EX *ex_data = STORE_get_ex_data(store);

    return ex_data != NULL ? (ex_data->tls_bio = bio, true) : false;
}
#endif

bool STORE_set1_host_ip(X509_STORE *ts, const char *name, const char *ip)
{
    if (ts == NULL) {
        LOG_err("null pointer argument");
        return false;
    }
    X509_VERIFY_PARAM *ts_vpm = X509_STORE_get0_param(ts);

    /* first clear any host names, IP addresses, and email addresses */
    if (!STORE_set1_host(ts, 0)
        || !X509_VERIFY_PARAM_set1_host(ts_vpm, 0, 0)
        || !X509_VERIFY_PARAM_set1_ip(ts_vpm, 0, 0)
        || !X509_VERIFY_PARAM_set1_email(ts_vpm, 0, 0)) {
        LOG_err("Could not clear host name and IP address from store");
        return false;
    }

    if (name == NULL && ip == NULL)
        return true;

    char *name_str = CONN_get_host(name);
    if (name != NULL && name_str == NULL)
        return false;

    char *ip_str = CONN_get_host(ip);
    if (ip != NULL && ip_str == NULL) {
        OPENSSL_free(name_str);
        return false;
    }

    X509_VERIFY_PARAM_set_hostflags(ts_vpm,
                                    X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT |
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    bool res = true;
    if (ip_str != NULL && !X509_VERIFY_PARAM_set1_ip_asc(ts_vpm, ip_str))
        res = false;
    if (name_str != NULL && (ip_str == NULL || (res && strcmp(name, ip) == 0))) {
        /*
         * Unfortunately there is no OpenSSL API function for retrieving the
         * hostname/ip entries in X509_VERIFY_PARAM. So we store the host value
         * in ex_data for use in CREDENTIALS_print_cert_verify_cb().
         */
        res = X509_VERIFY_PARAM_set1_host(ts_vpm, name_str, 0);
        if (res)
            res = STORE_set1_host(ts, name_str);
    }
    if (!res)
        LOG(FL_ERR, "Could not set host name '%s' and/or IP address '%s' in store",
            name_str != NULL ? name_str : "", ip_str != NULL ? ip_str : "");
    OPENSSL_free(ip_str);
    OPENSSL_free(name_str);
    return res;
}
