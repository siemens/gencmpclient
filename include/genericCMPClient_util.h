/*-
 * @file   genericCMPClient_util.h
 * @brief  generic CMP client library helper declarations
 *
 * @author David von Oheimb, Siemens AG, David.von.Oheimb@siemens.com
 *
 *  Copyright (c) 2024 Siemens AG
 *  Licensed under the Apache License 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You can obtain a copy in the file LICENSE in the source distribution
 *  or at https://www.openssl.org/source/license.html
 *  SPDX-License-Identifier: Apache-2.0
 */

#ifndef GENERIC_CMP_CLIENT_UTIL_H
# define GENERIC_CMP_CLIENT_UTIL_H

# include <openssl/err.h>
# include <openssl/cmp.h>

/* basic.h: */
# define OPTIONAL /*!< marker for non-required parameter, i.e., null pointer allowed */
# if !defined __cplusplus && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L)
typedef enum {
    false = 0,
    true = 1
} bool; /*!< Boolean value */
# endif
typedef struct credentials CREDENTIALS;

/* util.h: */
#if defined(_WIN32) && !defined(strncasecmp)
    #define strncasecmp _strnicmp
#endif
# define OPENSSL_V_3_0_0 0x30000000L
# define OPENSSL_V_3_5_0 0x30500000L
# define OPENSSL_V_4_0_0 0x40000000L
# define UTIL_setup_openssl(version, build_name) /* no-op */
/* Check if |pre|, which must be a string literal, is a prefix of |str| */
#define HAS_PREFIX(str, pre) (strncmp(str, pre "", sizeof(pre) - 1) == 0)
/* As before, and if check succeeds, advance |str| past the prefix |pre| */
#define CHECK_AND_SKIP_PREFIX(str, pre) (HAS_PREFIX(str, pre) ? ((str) += sizeof(pre) - 1, 1) : 0)
/* Check if the string literal |p| is a case-insensitive prefix of |s| */
#define HAS_CASE_PREFIX(s, p) (strncasecmp(s, p "", sizeof(p) - 1) == 0)
/* As before, and if check succeeds, advance |str| past the prefix |pre| */
#define CHECK_AND_SKIP_CASE_PREFIX(str, pre) (HAS_CASE_PREFIX(str, pre) ? ((str) += sizeof(pre) - 1, 1) : 0)
int UTIL_atoint(const char *str); /* returns INT_MIN on error */
void UTIL_cleanse_free(OPTIONAL char *str);
char *UTIL_first_item(char *str);
char *UTIL_next_item(char *opt); /* in list separated by comma and/or spaces */
const char *UTIL_file_ext(OPTIONAL const char *filename);

/* log.h: */
extern BIO *bio_err; /* for low-level error output if verbosity >= LOG_DEBUG */
extern BIO *bio_trace; /* for detailed debugging output if verbosity >= LOG_TRACE */
typedef OSSL_CMP_severity severity;
# define LOG_EMERG   0  /*!< A panic condition was reported to all processes */
# define LOG_ALERT   1  /*!< A condition that should be corrected immediately */
# define LOG_CRIT    2  /*!< A critical condition */
# define LOG_ERR     3  /*!< An error message */
# define LOG_WARNING 4  /*!< A warning message */
# define LOG_NOTICE  5  /*!< A condition requiring special handling */
# define LOG_INFO    6  /*!< A general information message */
# define LOG_DEBUG   7  /*!< A message useful for debugging programs */
# define LOG_TRACE   8  /*!< A verbose message useful for detailed debugging */
# define LOG_FUNC_FILE_LINE OPENSSL_FUNC, OPENSSL_FILE, OPENSSL_LINE
# define FL_EMERG LOG_FUNC_FILE_LINE, LOG_EMERG  /*!< panic condition reported to all processes. */
# define FL_ALERT LOG_FUNC_FILE_LINE, LOG_ALERT  /*!< condition to be corrected immediately. */
# define FL_FATAL FL_ALERT                       /*!< condition to be corrected immediately. */
# define FL_CRIT LOG_FUNC_FILE_LINE, LOG_CRIT    /*!< critical condition. */
# define FL_ERR LOG_FUNC_FILE_LINE, LOG_ERR      /*!< error message. */
# define FL_WARN LOG_FUNC_FILE_LINE, LOG_WARNING /*!< warning message. */
# define FL_NOTE LOG_FUNC_FILE_LINE, LOG_NOTICE  /*!< condition requiring special handling. */
# define FL_INFO LOG_FUNC_FILE_LINE, LOG_INFO    /*!< general information message. */
# define FL_DEBUG LOG_FUNC_FILE_LINE, LOG_DEBUG  /*!< message useful for debugging. */
# define FL_TRACE LOG_FUNC_FILE_LINE, LOG_TRACE  /*!< verbose message for detailed debugging. */
typedef bool (*LOG_cb_t)(OPTIONAL const char *func, OPTIONAL const char *file,
                         int lineno, severity level, const char *msg);
void LOG_init(OPTIONAL LOG_cb_t log_fn);
void LOG_set_name(OPTIONAL const char *name);
void LOG_set_verbosity(severity level);
bool LOG(OPTIONAL const char *func, OPTIONAL const char *file,
         int lineno, severity level, const char *fmt, ...);
bool LOG_syslog(OPTIONAL const char *func, OPTIONAL const char *file,
                int lineno, severity level, const char *msg);
bool LOG_console(OPTIONAL const char *func, OPTIONAL const char *file,
                 int lineno, severity level, const char *msg);
# define LOG_alert(msg) LOG(FL_ALERT, msg) /*!< simple alert message */
# define LOG_err(msg) LOG(FL_ERR, msg)     /*!< simple error message */
# define LOG_warn(msg) LOG(FL_WARN, msg)   /*!< simple warning message */
# define LOG_info(msg) LOG(FL_INFO, msg)   /*!< simple information message */
# define LOG_debug(msg) LOG(FL_DEBUG, msg) /*!< simple debug message */
# define LOG_trace(msg) LOG(FL_TRACE, msg) /*!< simple trace message */
void LOG_close(void);

/* uta_api.h: */
typedef void uta_ctx; /* dummy */

/* config.h: */
/* extended from opt.h */
#define OPT_REQUIRED 0x8000U
#define OPT_EMPTY_OK 0x4000U /* ignored unless OPT_REQUIRED is set */
typedef enum
{
    OPT_TXT, /** String variable receives a pointer to the option argument */
    OPT_SEL, /** enumeration of selectable tags, index returned in 'int1' choice */
    OPT_NUM, /** Long integer variable receives the decimal number given as argument */
    OPT_INT, /** As before, but regular integer variable */
    OPT_POS_INT, /** As before, but restriction to positive integers */
    OPT_BOOL,/** Boolean variable receives a truth value */
    OPT_TXT_REQUIRED  = OPT_TXT  | OPT_REQUIRED,
    OPT_SEL_REQUIRED  = OPT_SEL  | OPT_REQUIRED,
    OPT_NUM_REQUIRED  = OPT_NUM  | OPT_REQUIRED,
    OPT_INT_REQUIRED  = OPT_INT  | OPT_REQUIRED,
    OPT_POS_INT_REQUIRED  = OPT_POS_INT | OPT_REQUIRED,
    OPT_BOOL_REQUIRED = OPT_BOOL | OPT_REQUIRED,
} opttype_t; /** all possible selector values for union in below varref_union */

union varval_union {
    const char *txt; /** String value */
    long num;  /** Long integer value, or vpm_opt */
    int  int1; /** Integer/selection value, may be restricted to being positive */
    bool bit;  /** Boolean value */
};

union varref_union {
    const char **txt; /** Pointer to string variable, or null */
    long *num;  /** Pointer to long integer variable */
    int  *int1; /** Pointer to regular integer variable */
    bool *bit;  /** Pointer to Boolean variable */
};

typedef struct opt_t
{
    const char *name; /** option name */
    opttype_t type;   /** option type, selects in below unions */
    union varval_union default_value; /** default value for the option */
    union varref_union varref_u; /** reference to the variable to receive the option value */
    const char *help_str; /** a short description of the option for help output */
    const char **selectable; /** values to choose from with OPT_SEL, NULL-terminated array */
} opt_t; /** an option with its name, type, default value, variable,
             optional help string, and optional selectable tags */

#define OPT_END { NULL, OPT_BOOL, {.bit = false}, {.bit = NULL}, NULL}
CONF *CONF_load_config(OPTIONAL ossl_unused uta_ctx *ctx, const char *file);
bool CONF_entry_in_sections(const CONF *conf, const char *sections, const char *entry);
bool CONF_read_check_options(const CONF *conf, const char *source,
                             const char *sections, const opt_t *opts);


/* credentials.h: */
struct credentials
{
    OPTIONAL EVP_PKEY *pkey;        /*!< can refer to HW key store via engine */
    OPTIONAL X509 *cert;            /*!< related certificate */
    OPTIONAL STACK_OF(X509) *chain; /*!< intermediate/extra certs for cert */
    OPTIONAL char *pwd;             /*!< alternative password (shared secret) */
    OPTIONAL char *pwdref;          /*!< reference identifying the password */
} /* CREDENTIALS */;
CREDENTIALS *CREDENTIALS_new(OPTIONAL const EVP_PKEY *pkey, OPTIONAL const X509 *cert,
                             OPTIONAL const STACK_OF(X509)  *chain, OPTIONAL const char *pwd,
                             OPTIONAL const char *pwdref);
void CREDENTIALS_free(OPTIONAL CREDENTIALS *creds);

/* credentials.c: */
# define CREDENTIALS_get_pkey(creds)   (creds)->pkey
# define CREDENTIALS_get_cert(creds)   (creds)->cert
# define CREDENTIALS_get_chain(creds)  (creds)->chain
# define CREDENTIALS_get_pwd(creds)    (creds)->pwd
# define CREDENTIALS_get_pwdref(creds) (creds)->pwdref

/* files.h: */
/*! supported format for security-related files */
/* taken over from OpenSSL:apps/include/apps.h */
enum
{
    B_FORMAT_TEXT = 0x8000
};
typedef enum
{
    FORMAT_UNDEF = 0,               /*! undefined file format */
    FORMAT_TEXT = 1 | B_FORMAT_TEXT,/* Generic text */
    FORMAT_ASN1 = 4,                /*! ASN.1/DER */
    FORMAT_PEM = 5 | B_FORMAT_TEXT, /*! PEM */
    FORMAT_PKCS12 = 6,              /*! PKCS#12 */
    FORMAT_ENGINE = 8,              /*! crypto engine, which is not really a file format */
    FORMAT_HTTP = 13                /*! download using HTTP */
} file_format_t;                  /*! type of format for security-related files or other input */
/**< string constants used for the 'source' parameter of some credentials load/store functions */
static const char* const sec_PASS_STR = "pass:";
static const char* const sec_ENGINE_STR = "engine:";
static const char* const sec_ENV_STR = "env:";
static const char* const sec_FILE_STR = "file:";
static const char* const sec_FD_STR = "fd:";
static const char* const sec_STDIN_STR = "stdin";
static const int sec_PASS_MAX_LEN = 256;
char* FILES_get_pass(OPTIONAL const char* source, OPTIONAL const char* desc);

/* key.h: */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0
EVP_PKEY *KEY_new_ex(const char *spec, OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq);
#define SECUTILS_RSA_STR "RSA"
#define SECUTILS_EC_STR  "EC"
bool KEY_type_supported(const char *spec,
                        OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq);
#endif
#define KEY_free EVP_PKEY_free

/* cert.h: */
# include <ctype.h> /* needed for UTIL_SKIP_SCHEME() */
/* Advance string pointer s, which must a modifiable lvalue, past scheme according to RFC 3986: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
#define UTIL_SKIP_SCHEME(s)                                                        \
    do {                                                                           \
        if (isalpha(*(s)))                                                         \
            while (*(s) != '\0' && (isalnum(*(s)) || strchr("+-.", *(s)) != NULL)) \
                (s)++;                                                             \
    } while (0)
#define UTIL_SCHEME_SUFFIX "://"
X509_NAME *UTIL_parse_name(const char *dn, int chtype, bool multirdn);
int UTIL_cmp_timeframe(OPTIONAL const X509_VERIFY_PARAM *vpm,
                       OPTIONAL const ASN1_TIME *start, OPTIONAL const ASN1_TIME *end);
#define CERTS_free(certs) sk_X509_pop_free(certs, X509_free)
#define CRLs_free(crls) sk_X509_CRL_pop_free(crls, X509_CRL_free)
bool CERT_check(const char *src, OPTIONAL X509 *cert, int type_CA,
                OPTIONAL const X509_VERIFY_PARAM *vpm);
bool CERT_check_all(const char *src, OPTIONAL STACK_OF(X509) *certs, int type_CA,
                    OPTIONAL const X509_VERIFY_PARAM *vpm); /* used by CMPclient_caCerts() */

/* certstatus.h: */
#define X509_V_FLAG_NONFINAL_CHECK  0x10000000 /* do not log failure as error */
#define X509_V_FLAG_OCSP_STAPLING 0x2000000 /* Use OCSP stapling (for TLS) */

/* crls.h: */
bool CRL_check(const char *src, OPTIONAL X509_CRL *crl, OPTIONAL const X509_VERIFY_PARAM *vpm);

/* store.h: */
# define STORE_set1_desc(store, desc) true /* no-op */
/* with GENCMP_NO_SECUTILS, not supported before 3.0: */
# define STORE_set1_host(store, host) (OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0)
bool STORE_set1_host_ip(X509_STORE *ts, OPTIONAL const char *name, OPTIONAL const char *ip);
const char *STORE_get0_host(const X509_STORE *store);
/* would be needed only with CREDENTIALS_print_cert_verify_cb(): */
#  define STORE_EX_check_index() true
#  define STORE_set0_tls_bio(store, bio) true
X509_STORE *STORE_create(OPTIONAL X509_STORE *store, OPTIONAL const X509 *cert,
                         OPTIONAL const STACK_OF(X509) *certs);
# define STORE_free(store) X509_STORE_free(store)

/* conn.h: */
static const char* const CONN_scheme_postfix = "://";
static const char* const CONN_http_prefix = OSSL_HTTP_PREFIX;
static const char* const CONN_https_prefix = OSSL_HTTPS_PREFIX;
#define CONN_IS_HTTP( uri) ((uri) != NULL && HAS_CASE_PREFIX(uri, OSSL_HTTP_PREFIX ))
#define CONN_IS_HTTPS(uri) ((uri) != NULL && HAS_CASE_PREFIX(uri, OSSL_HTTPS_PREFIX))
#define CONN_IS_IP_ADDR(host) CONN_is_IP_address(host)
bool CONN_is_IP_address(OPTIONAL const char *host);

/* tls.h: */
#ifndef GENCMP_NO_TLS
#include <openssl/ssl.h>
#define TLS_init() true /* initialize OpenSSL's SSL lib, no needed at least since 3.0 */
static const char* const STRONG_CIPHER_SUITES = "ECDHE-ECDSA-AES256-GCM-SHA384";
static const char* const INTEGRITY_ONLY_CIPHER_SUITES = "NULL-SHA256:ECDHE-ECDSA-NULL-SHA";
static const char* const INTEGRITY_ONLY_CIPHER_SUITES_MARK = "NULL-";
static const char* const HIGH_CIPHER_SUITES = "HIGH:!ADH:!LOW:!EXP:!MD5:@STRENGTH";
static const char* const HIGH_CIPHER_SUITES_MARK = "HIGH";

static const int INTEGRITY_ONLY_SECURITY_LEVEL = 0;
static const int HIGH_SECURITY_LEVEL = 2;
static const int STRONG_SECURITY_LEVEL = 3;
SSL_CTX *TLS_CTX_new(OPTIONAL SSL_CTX *ssl_ctx,
                     int client, OPTIONAL X509_STORE *truststore,
                     OPTIONAL const STACK_OF(X509)  *untrusted,
                     OPTIONAL const CREDENTIALS *creds,
                     OPTIONAL const char *ciphers, int security_level,
                     OPTIONAL X509_STORE_CTX_verify_cb verify_cb);
#define TLS_CTX_free SSL_CTX_free
#endif

#endif /* GENERIC_CMP_CLIENT_UTIL_H */
