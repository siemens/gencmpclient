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

/* for low-level CMP API, in particular, type OSSL_CMP_CTX */
#include <openssl/cmp.h>
typedef OSSL_CMP_CTX CMP_CTX; /* for abbreviation and backward compatibility */


#ifdef LOCAL_DEFS

#ifndef __cplusplus
typedef enum { false = 0, true = 1 } bool; /* Boolean value */
#endif

#define OPTIONAL /*!< marker for non-required parameter, i.e., NULL allowed */

typedef struct credentials {
    OPTIONAL EVP_PKEY *pkey;        /*!< can refer to HW key store via engine */
    OPTIONAL X509     *cert;        /*!< related certificate */
    OPTIONAL STACK_OF(X509) *chain; /*!< intermediate/extra certs for cert */
    OPTIONAL const char *pwd;       /*!< alternative: password (shared secret) */
    OPTIONAL const char *pwdref;    /*!< reference identifying the password */
} CREDENTIALS;

typedef enum {LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR,
              LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG} severity;
typedef int (*LOG_cb_t) (OPTIONAL const char *file, int lineno, severity level, const char *msg);
void LOG_close(void);

#else /* LOCAL_DEFS */

#include <SecUtils/credentials/credentials.h>
#include <SecUtils/util/log.h>

#endif /* LOCAL_DEFS */


typedef int CMP_err;
#define CMP_OK 0
#define CMP_R_LOAD_CERTS   255
#define CMP_R_LOAD_CREDS   254
#define CMP_R_GENERATE_KEY 253
#define CMP_R_STORE_CREDS  252
/* further error codes are defined in openssl/cmperr.h */

#define CMP_IR    OSSL_CMP_PKIBODY_IR
#define CMP_CR    OSSL_CMP_PKIBODY_CR
#define CMP_P10CR OSSL_CMP_PKIBODY_P10CR
#define CMP_KUR   OSSL_CMP_PKIBODY_KUR
#define CMP_RR    OSSL_CMP_PKIBODY_RR

/* CMP client core functions */
/* should be called once, as soon as the application starts */
CMP_err CMPclient_init(OPTIONAL OSSL_cmp_log_cb_t log_fn);

/* must be called first */
CMP_err CMPclient_prepare(CMP_CTX **pctx, OPTIONAL OSSL_cmp_log_cb_t log_fn,
      /* both for CMP: */ OPTIONAL X509_STORE *cmp_truststore,
                          OPTIONAL const STACK_OF(X509) *untrusted,
                          OPTIONAL const CREDENTIALS *creds,
                          OPTIONAL const char *digest,
                          OPTIONAL OSSL_cmp_transfer_cb_t transfer_fn, int total_timeout,
                          OPTIONAL X509_STORE *new_cert_truststore, bool implicit_confirm);

/* must be called next in case the transfer_fn is NULL, which implies HTTP_transfer */
/* copies server and proxy address (of the form "<name>[:<port>]") and HTTP path */
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
                                OPTIONAL const X509_REQ *p10csr);

/* either the internal CMPclient_enroll() or the specific CMPclient_imprint(),
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
                          const EVP_PKEY *new_key, const char *subject,
                          OPTIONAL const X509_EXTENSIONS *exts);
CMP_err CMPclient_bootstrap(CMP_CTX *ctx, CREDENTIALS **new_creds,
                            const EVP_PKEY *new_key, const char *subject,
                            OPTIONAL const X509_EXTENSIONS *exts);
CMP_err CMPclient_pkcs10(CMP_CTX *ctx, CREDENTIALS **new_creds,
                         const X509_REQ *csr);
CMP_err CMPclient_update(CMP_CTX *ctx, CREDENTIALS **new_creds,
                         const EVP_PKEY *new_key);

/* reason codes are defined in openssl/x509v3.h */
CMP_err CMPclient_revoke(CMP_CTX *ctx, const X509 *cert, int reason);

/* must be called after any of the above activities */
void CMPclient_finish(CMP_CTX *ctx);

/* CREDENTIALS helpers */
CREDENTIALS *CREDENTIALS_new(OPTIONAL const EVP_PKEY *pkey, const OPTIONAL X509 *cert,
                             OPTIONAL const STACK_OF(X509) *chain,
                             OPTIONAL const char *pwd, OPTIONAL const char *pwdref);
void CREDENTIALS_free(OPTIONAL CREDENTIALS *creds);
CREDENTIALS *CREDENTIALS_load(const char *certs, const char *key,
                              const char *source,
                              OPTIONAL const char *desc/* for error msgs */);
bool CREDENTIALS_save(const CREDENTIALS *creds, const char *file, const char *keyfile,
                      const char *source, OPTIONAL const char *desc);


/* X509_STORE helpers */
X509_STORE *STORE_load(const char *trusted_certs, OPTIONAL const char *desc);
STACK_OF(X509_CRL) *CRLs_load(const char *files, OPTIONAL const char *desc);
void CRLs_free(OPTIONAL STACK_OF(X509_CRL) *crls);
bool STORE_add_crls(X509_STORE* truststore, OPTIONAL const STACK_OF(X509_CRL) * crls);
/* also sets certificate verification callback: */
bool STORE_set_parameters(X509_STORE *truststore,
                          OPTIONAL const X509_VERIFY_PARAM *vpm,
                          OPTIONAL const STACK_OF(X509_CRL) *crls,
                          bool use_CDPs, OPTIONAL const char *CRLs_url,
                          bool use_AIAs, OPTIONAL const char *OCSP_url);
void STORE_free(OPTIONAL X509_STORE *truststore);

/* EVP_PKEY helpers */
EVP_PKEY *KEY_new(const char *spec); /* spec may be "RSA:<length>" or "EC:<curve>" */
void KEY_free(OPTIONAL EVP_PKEY *pkey);

/* SSL_CTX helpers for HTTPS */
SSL_CTX *TLS_new(OPTIONAL const X509_STORE *truststore,
                 OPTIONAL const CREDENTIALS *creds,
                 OPTIONAL const char *ciphers, int security_level);
void TLS_free(OPTIONAL SSL_CTX *tls);

/* X509_EXTENSIONS helpers */
X509_EXTENSIONS *EXTENSIONS_new(void);
/* add optionally critical Subject Alternative Names (SAN) to exts */
bool EXTENSIONS_add_SANs(X509_EXTENSIONS *exts, const char *spec);
/* add extension such as (extended) key usages, basic constraints, policies */
bool EXTENSIONS_add_ext(X509_EXTENSIONS *exts, const char *name,
                        const char* spec, OPTIONAL BIO* sections);
void EXTENSIONS_free(OPTIONAL X509_EXTENSIONS *exts);


#endif /* GENERIC_CMP_CLIENT_H */
