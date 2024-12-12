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

/* basic.h: */
# define OPTIONAL /*!< marker for non-required parameter, i.e., null pointer allowed */
# ifndef __cplusplus
typedef enum {
    false = 0,
    true = 1
} bool; /*!< Boolean value */
# endif
typedef struct credentials CREDENTIALS;

/* util.h: */
# define OPENSSL_V_3_0_0 0x30000000L
# define UTIL_setup_openssl(version, build_name) /* no-op */

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
bool LOG_console(OPTIONAL const char *func, OPTIONAL const char *file,
                 int lineno, severity level, const char *msg);
# define LOG_alert(msg) LOG(FL_ALERT, msg) /*!< simple alert message */
# define LOG_err(msg) LOG(FL_ERR, msg)     /*!< simple error message */
# define LOG_warn(msg) LOG(FL_WARN, msg)   /*!< simple warning message */
# define LOG_info(msg) LOG(FL_INFO, msg)   /*!< simple information message */
# define LOG_debug(msg) LOG(FL_DEBUG, msg) /*!< simple debug message */
# define LOG_trace(msg) LOG(FL_TRACE, msg) /*!< simple trace message */

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
static const char *const sec_PASS_STR = "pass:";

/* cert.h: */
X509_NAME *UTIL_parse_name(const char *dn, int chtype, bool multirdn);
# define CERTS_free(certs) sk_X509_pop_free(certs, X509_free)
bool CERT_check_all(const char *uri, OPTIONAL STACK_OF(X509) *certs, int type_CA,
                    OPTIONAL const X509_VERIFY_PARAM *vpm); /* used by CMPclient_caCerts() */

/* store.h: */
# ifndef GENCMP_NO_TLS
bool STORE_set1_host_ip(X509_STORE *ts, OPTIONAL const char *name, OPTIONAL const char *ip);
const char *STORE_get0_host(const X509_STORE *store);
/* would be needed only with CREDENTIALS_print_cert_verify_cb(): */
#  define STORE_EX_check_index() true
#  define STORE_set0_tls_bio(store, bio) true
# endif
X509_STORE *STORE_create(OPTIONAL X509_STORE *store, OPTIONAL const X509 *cert,
                         OPTIONAL const STACK_OF(X509) *certs);
# define STORE_free(store) X509_STORE_free(store)

# ifndef GENCMP_NO_TLS
/* conn.h: */
#  define CONN_IS_IP_ADDR(host) ((host) != NULL && ((*(host) >= '0' && *(host) <= '9') || *(host) == '[')) // TODO improve

/* tls.h: */
#  define TLS_init() true /* initialize OpenSSL's SSL lib, no needed at least since 3.0 */
# endif

#endif /* GENERIC_CMP_CLIENT_UTIL_H */
