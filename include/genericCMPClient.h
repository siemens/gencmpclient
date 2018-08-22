/*!*****************************************************************************
 * @file   genericCMPClient.h
 * @brief  generic CMP client library API
 *
 * @author David von Oheimb, CT RDA ITS SEA, David.von.Oheimb@siemens.com
 *
 * @copyright (c) Siemens AG, 2018. The Siemens Inner Source License - 1.1
 ******************************************************************************/

#ifndef GENERIC_CMP_CLIENT_H
#define GENERIC_CMP_CLIENT_H

/* for low-level CMP API, in particular, type CMP_CTX */
#include <openssl/cmp.h>
#ifndef LOCAL_DEFS
#include <SecUtils/log.h>
#include <SecUtils/credentials.h>
#include <SecUtils/extensions.h>

#include <SecUtils/key.h>
#include <SecUtils/files.h>
#include <SecUtils/store.h>
#include <SecUtils/tls.h>
#define TLS_new(truststore, creds, ciphers) TLS_CTX_new(1, truststore, creds, ciphers)
#define TLS_free(tls) TLS_CTX_free(tls)

#endif

typedef int bool; /* Boolean value: FALSE or TRUE */

/* error codes are defined in openssl/cmperr.h */
typedef int CMP_err; /* should better be defined and used in openssl/cmp.h */
#define CMP_OK 0

#define CMP_IR    V_CMP_PKIBODY_IR
#define CMP_CR    V_CMP_PKIBODY_CR
#define CMP_P10CR V_CMP_PKIBODY_P10CR
#define CMP_KUR   V_CMP_PKIBODY_KUR
#define CMP_RR    V_CMP_PKIBODY_RR

#ifdef LOCAL_DEFS

/* log callback function */
/* these two decls are going to be moved to openssl/cmp.h */
/* declarations resemble those from bio/bss_log.c and syslog.h */
typedef enum {LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERROR,
              LOG_WARN, LOG_NOTE, LOG_INFO, LOG_DEBUG} severity;
typedef bool (*cmp_log_cb_t_) (OPTIONAL const char *file, int lineno,
                              severity level, const char *msg);


#define OPTIONAL /* this marker will get ignored by compiler */

typedef struct credentials {
    OPTIONAL EVP_PKEY *pkey;        /*!< can refer to HW key store via engine */
    OPTIONAL X509     *cert;        /*!< related certificate */
    OPTIONAL STACK_OF(X509) *chain; /*!< intermediate/extra certs for cert */
    OPTIONAL const char *pwd;       /*!< alternative: password (shared secret) */
    OPTIONAL const char *pwdref;    /*!< reference identifying the password */
} CREDENTIALS;

CREDENTIALS *CREDENTIALS_new(OPTIONAL const EVP_PKEY *pkey, const OPTIONAL X509 *cert,
                             OPTIONAL const STACK_OF(X509) *chain,
                             OPTIONAL const char *pwd, OPTIONAL const char *pwdref);
void CREDENTIALS_free(CREDENTIALS *creds); /* is not called by CMPclient_finish() */

#endif /* LOCAL_DEFS */

/* CMP client core functions */
/* must be called first */
CMP_err CMPclient_prepare(CMP_CTX **pctx, OPTIONAL cmp_log_cb_t log_fn,
      /* both for CMP: */ OPTIONAL X509_STORE *cmp_truststore,
                          OPTIONAL const STACK_OF(X509) *untrusted,
                          OPTIONAL const CREDENTIALS *creds,
                          OPTIONAL const char *digest,
                          OPTIONAL cmp_transfer_cb_t transfer_fn, int total_timeout,
                          OPTIONAL X509_STORE *new_cert_truststore, bool implicit_confirm);

/* must be called next in case the transfer_fn is NULL, which implies HTTP_transfer;
   copies server address (of the form "<name>[:<port>]") and HTTP path */
CMP_err CMPclient_setup_HTTP(CMP_CTX *ctx, const char *server, const char *path,
                             int timeout, OPTIONAL SSL_CTX *tls,
                             OPTIONAL const char *proxy);

/*!*****************************************************************************
* @brief fill the cert template used for certificate requests (ir/cr/p10cr/kur)
*
* @param ctx CMP context to read default values from and to be updated
* @param new_key key pait to be certified; defaults to creds->key
* @param old_cert reference cert to be updated (kur), defaults to creds->cert
* @param subject to use; defaults to subject of reference cert for KUR, while
         this default is is not used for IR and CR if the exts arg contains SANs
         Subject DN is of the form "/<type0>=<value0>/<type1>=<value1>..."
* @param exts X509 extensions to use; SANs default to SANs in the reference cert
* @param csr PKCS#10 request to use for P10CR; this ignores any other args given
* @note all const parameters are copied (and need to be freed by the caller)
* @return CMP_OK on success, else CMP error code
*******************************************************************************/
CMP_err CMPclient_setup_certreq(CMP_CTX *ctx,
                                OPTIONAL const EVP_PKEY *new_key,
                                OPTIONAL const X509 *old_cert,
                                OPTIONAL const char *subject,
                                OPTIONAL const X509_EXTENSIONS *exts,
                                OPTIONAL const X509_REQ *csr);

/* either CMPclient_enroll() or its special cases (CMPclient_imprint(),
CMPclient_bootstrap(), CMPclient_pkcs10(), or CMPclient_update())
or CMPclient_revoke() can be called next, only once for the given ctx */
/* the structure returned in *new_creds must be freed by the caller */
/*!*****************************************************************************
* @brief perform the given type of certificate request (ir/cr/p10cr/kur)
*
* @param ctx CMP context to be read and updated
* @param new_creds pointer to variable where to store newly enrolled credentials
* @param type the request to be performed: CMP_IR, CMP_CR, CMP_P10CR, or CMP_KUR
* @return CMP_OK on success, else CMP error code
*******************************************************************************/
CMP_err CMPclient_enroll(CMP_CTX *ctx, CREDENTIALS **new_creds, int type);
CMP_err CMPclient_imprint(CMP_CTX *ctx, CREDENTIALS **new_creds,
                          const EVP_PKEY *new_key,
                          const char *subject,
                          OPTIONAL const X509_EXTENSIONS *exts);
CMP_err CMPclient_bootstrap(CMP_CTX *ctx, CREDENTIALS **new_creds,
                            const EVP_PKEY *new_key,
                            const char *subject,
                            OPTIONAL const X509_EXTENSIONS *exts);
CMP_err CMPclient_pkcs10(CMP_CTX *ctx, CREDENTIALS **new_creds,
                         const X509_REQ *csr);
CMP_err CMPclient_update(CMP_CTX *ctx, CREDENTIALS **new_creds,
                         const EVP_PKEY *new_key);

/* reason codes are defined in openssl/x509v3.h */
CMP_err CMPclient_revoke(CMP_CTX *ctx, const X509 *cert, int reason);

/* must be called after any of the above activities */
/* does not free any creds, truststore, tls, new_key, or exts, so they can be reused */
void CMPclient_finish(CMP_CTX *ctx);

#ifdef LOCAL_DEFS
/* CREDENTIALS helpers */
/* certs is name of a file in PKCS#12 format; primary cert is of client */
/* source for private key may be "file:[pass:<pwd>]" or "engine:<id>" */
CREDENTIALS *CREDENTIALS_load(const char *certs, const char *key,
                              const char *source,
                              OPTIONAL const char *desc/* for error msgs */);
/* file is name of file to write in PKCS#12 format */
bool CREDENTIALS_save(const CREDENTIALS *creds, const char *file,
                      const char *source, OPTIONAL const char *desc);


/* X509_STORE helpers */
/* trusted_certs is name of a file in PEM or PKCS#12 format */
X509_STORE *STORE_load(const char *trusted_certs,
                       OPTIONAL const char *desc/* for error msgs */);
STACK_OF(X509_CRL) *CRLs_load(const char *file, OPTIONAL const char *desc);
/* also sets certificate verification callback */
/* does not consume vpm; copies any CRLs_url and OCSP_url to static buffers */
bool STORE_set_parameters(X509_STORE *truststore,
                          OPTIONAL const X509_VERIFY_PARAM *vpm,
                          OPTIONAL const STACK_OF(X509_CRL) *crls,
                          OPTIONAL const char *CRLs_url, bool use_CDPs,
                          OPTIONAL const char *OCSP_url, bool use_AIAs);
void STORE_free(X509_STORE *truststore); /* also frees copies of OCSP_url and OCSP_url */


/* EVP_PKEY helpers */
/* spec may be "RSA:<length>" or "EC:<curve>" */
EVP_PKEY *KEY_new(const char *spec); /* can be used as new_key parameter */
void KEY_free(EVP_PKEY *pkey); /* is not called by CMPclient_finish() */


/* SSL_CTX helpers for HTTPS */
/* does not consume any of its arguments */
SSL_CTX *TLS_new(OPTIONAL const X509_STORE *truststore,
                 OPTIONAL const CREDENTIALS *creds,
                 OPTIONAL const char *ciphers);
void TLS_free(SSL_CTX *tls); /* is not called by CMPclient_finish() */

/* X509_EXTENSIONS helpers */
X509_EXTENSIONS *EXTENSIONS_new(void);

/* add optionally critical Subject Alternative Names (SAN) to exts */
bool EXTENSIONS_add_SANs(X509_EXTENSIONS *exts, const char *spec);
/* add other extensions such as (extended) key usage, constraints, policies */
bool EXTENSIONS_add_key_usages(X509_EXTENSIONS *exts, const char *name,
                               const char *spec, OPTIONAL BIO *sections);

void EXTENSIONS_free(X509_EXTENSIONS *exts);

#endif /* LOCAL_DEFS */

#endif /* GENERIC_CMP_CLIENT_H */
