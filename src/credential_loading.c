/*-
 * @file   credential_loading.c
 * @brief  generic CMP client CLI helper functions like in OpenSSL apps
 *
 * @author David von Oheimb, Siemens AG, David.von.Oheimb@siemens.com
 *
 *  Copyright 2007-2025 The OpenSSL Project Authors. All Rights Reserved.
 *  Copyright (c) 2025 Siemens AG
 *
 *  Licensed under the Apache License 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You can obtain a copy in the file LICENSE in the source distribution
 *  or at https://www.openssl.org/source/license.html
 *  SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/core_names.h>
#include <openssl/http.h>
#include <openssl/pem.h>

#ifndef GENCMP_NO_SECUTILS
#include <secutils/credentials/credentials.h>
#include <secutils/credentials/store.h>
#include <secutils/credentials/cert.h>
#include <secutils/connections/conn.h> /* for CONN_IS_HTTP[S] */
#include <secutils/certstatus/crls.h> /* for CRL_check() and CERT_check() */
#include <secutils/util/log.h>
#endif

#ifdef SECUTILS_USE_ICV
# include <secutils/storage/files_icv.h> /* for FILES_check_icv */
#endif

#include <genericCMPClient.h> /* for CRLs_free() */
#include <credential_loading.h>

/* from OpenSSL/apps/lib/app_libctx.c: */
static OSSL_LIB_CTX *app_libctx = NULL;
static const char *app_propq = NULL;

int app_set_propq(OPTIONAL const char *arg)
{
    app_propq = arg;
    return 1;
}

const char *app_get0_propq(void)
{
    return app_propq;
}

OSSL_LIB_CTX *app_get0_libctx(void)
{
    return app_libctx;
}

OSSL_LIB_CTX *app_create_libctx(void)
{
    /*
     * Load the NULL provider into the default library context and create a
     * library context which will then be used for any OPT_PROV options.
     */
    if (app_libctx == NULL) {
        if (!app_provider_load(NULL, "null")) {
            LOG(FL_ERR, "Failed to create null provider");
            return NULL;
        }
        app_libctx = OSSL_LIB_CTX_new();
    }
    if (app_libctx == NULL)
        LOG(FL_ERR, "Failed to create library context");
    return app_libctx;
}

/* from OpenSSL/apps/lib/app_provider.c: */

DEFINE_STACK_OF(OSSL_PROVIDER)
static STACK_OF(OSSL_PROVIDER) *app_providers = NULL;

static void provider_free(OSSL_PROVIDER *prov)
{
    OSSL_PROVIDER_unload(prov);
}

void app_providers_cleanup(void)
{
    sk_OSSL_PROVIDER_pop_free(app_providers, provider_free);
    app_providers = NULL;
}

int app_set_provider_path(OPTIONAL const char *path)
{
    if (path != NULL && *path == '\0')
        path = NULL;
    return OSSL_PROVIDER_set_default_search_path(app_libctx, path);
}

int app_provider_load(OPTIONAL OSSL_LIB_CTX *libctx, const char *provider_name)
{
    OSSL_PROVIDER *prov;

    prov = OSSL_PROVIDER_load(libctx, provider_name);
    if (prov == NULL) {
        LOG(FL_ERR, "unable to load provider %s\n"
            "Hint: use -provider-path option or OPENSSL_MODULES environment variable.",
            provider_name);
        ERR_print_errors(bio_err);
        return 0;
    }
    if (app_providers == NULL)
        app_providers = sk_OSSL_PROVIDER_new_null();
    if (app_providers == NULL
        || !sk_OSSL_PROVIDER_push(app_providers, prov)) {
        app_providers_cleanup();
        return 0;
    }
    return 1;
}

/* mostly from OpenSSL/apps/lib/apps_ui.c: */

#include <openssl/ui.h>

static UI_METHOD *ui_method = NULL;
static const UI_METHOD *ui_base_method = NULL;

#define PW_MIN_LENGTH 4
typedef struct pw_cb_data {
    const void *password;
    const char *prompt_info;
} PW_CB_DATA;

static int ui_open(UI *ui)
{
    int (*opener)(UI *ui) = UI_method_get_opener(ui_base_method);

    if (opener != NULL)
        return opener(ui);
    return 1;
}

static int ui_read(UI *ui, UI_STRING *uis)
{
    int (*reader)(UI *ui, UI_STRING *uis) = NULL;

    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
        && UI_get0_user_data(ui)) {
        switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY:
            {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;

                if (password != NULL)
                    UI_set_result(ui, uis, password);
                return 1; /* also on password == NULL */
            }
            break;
        case UIT_NONE:
        case UIT_BOOLEAN:
        case UIT_INFO:
        case UIT_ERROR:
            break;
        }
    }

    reader = UI_method_get_reader(ui_base_method);
    if (reader != NULL)
        return reader(ui, uis);
    /* Default to the empty password if we've got nothing better */
    UI_set_result(ui, uis, "");
    return 1;
}

static int ui_write(UI *ui, UI_STRING *uis)
{
    int (*writer)(UI *ui, UI_STRING *uis) = NULL;

    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
        && UI_get0_user_data(ui)) {
        switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY:
            {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;

                if (password != NULL)
                    return 1;
            }
            break;
        case UIT_NONE:
        case UIT_BOOLEAN:
        case UIT_INFO:
        case UIT_ERROR:
            break;
        }
    }

    writer = UI_method_get_writer(ui_base_method);
    if (writer != NULL)
        return writer(ui, uis);
    return 1;
}

static int ui_close(UI *ui)
{
    int (*closer)(UI *ui) = UI_method_get_closer(ui_base_method);

    if (closer != NULL)
        return closer(ui);
    return 1;
}

/* object_name defaults to prompt_info from ui user data if present */
static char *ui_prompt_construct(UI *ui, const char *phrase_desc,
                                 const char *object_name)
{
    PW_CB_DATA *cb_data = (PW_CB_DATA *)UI_get0_user_data(ui);

    if (phrase_desc == NULL)
        phrase_desc = "pass phrase";
    if (object_name == NULL && cb_data != NULL)
        object_name = cb_data->prompt_info;
    return UI_construct_prompt(NULL, phrase_desc, object_name);
}

int set_base_ui_method(const UI_METHOD *ui_meth)
{
    if (ui_meth == NULL)
        ui_meth = UI_null();
    ui_base_method = ui_meth;
    return 1;
}

int setup_ui_method(void)
{
    ui_base_method = UI_null();
#ifndef OPENSSL_NO_UI_CONSOLE
    ui_base_method = UI_OpenSSL();
#endif
    ui_method = UI_create_method("OpenSSL application user interface");
    return ui_method != NULL
        && 0 == UI_method_set_opener(ui_method, ui_open)
        && 0 == UI_method_set_reader(ui_method, ui_read)
        && 0 == UI_method_set_writer(ui_method, ui_write)
        && 0 == UI_method_set_closer(ui_method, ui_close)
        && 0 == UI_method_set_prompt_constructor(ui_method, ui_prompt_construct);
}

void destroy_ui_method(void)
{
    if (ui_method != NULL) {
        UI_destroy_method(ui_method);
        ui_method = NULL;
    }
}

static const UI_METHOD *get_ui_method(void)
{
    return ui_method;
}

/* from OpenSSL/apps/lib/apps.c: */

static const char *format2string(file_format_t format)
{
    switch (format) {
    case FORMAT_PEM:
        return "PEM";
    case FORMAT_ASN1:
        return "DER";
    default:
        return NULL;
    }
}

static void unbuffer(FILE *fp)
{
/*
 * On VMS, setbuf() will only take 32-bit pointers, and a compilation
 * with /POINTER_SIZE=64 will give off a MAYLOSEDATA2 warning here.
 * However, we trust that the C RTL will never give us a FILE pointer
 * above the first 4 GB of memory, so we simply turn off the warning
 * temporarily.
 */
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma environment save
# pragma message disable maylosedata2
#endif
    setbuf(fp, NULL);
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma environment restore
#endif
}

/* Set type expectation, but set to 0 if objects of multiple types expected. */
#define SET_EXPECT(val) \
    (expect = expect < 0 ? (val) : (expect == (val) ? (val) : 0))
#define SET_EXPECT1(pvar, val) \
    if ((pvar) != NULL) { \
        *(pvar) = NULL; \
        SET_EXPECT(val); \
    }
/* Provide (error msg) text for some of the credential types to be loaded. */
#define FAIL_NAME \
    (ppkey != NULL ? "private key" : ppubkey != NULL ? "public key" :  \
     pparams != NULL ? "key parameters" :                              \
     pcert != NULL ? "certificate" : pcerts != NULL ? "certificate(s)" : \
     pcrl != NULL ? "CRL" : pcrls != NULL ? "CRLs" : NULL)
/*
 * Load those types of credentials for which the result pointer is not NULL.
 * Reads from stdin if 'uri' is NULL and 'maybe_stdin' is true.
 * 'format' parameter may be FORMAT_PEM, FORMAT_ASN1, or FORMAT_UNDEF (0) for no hint.
 * desc may contain more detail on the credential(s) to be loaded for error msg
 * For non-NULL ppkey, pcert, and pcrl the first suitable value found is loaded.
 * If pcerts is non-NULL and *pcerts == NULL then a new cert list is allocated.
 * If pcerts is non-NULL then all available certificates are appended to *pcerts
 * except any certificate assigned to *pcert.
 * min_certs specifies the minimum total number of certs expected to load.
 * If pcrls is non-NULL and *pcrls == NULL then a new list of CRLs is allocated.
 * If pcrls is non-NULL then all available CRLs are appended to *pcrls
 * except any CRL assigned to *pcrl.
 * min_crls specifies the minimum total number of CRLs expected to load.
 */

static
bool load_key_certs_crls(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                         OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                         OPTIONAL const char *pass, OPTIONAL const char *desc, bool quiet,
                         OPTIONAL EVP_PKEY **ppkey, OPTIONAL EVP_PKEY **ppubkey,
                         OPTIONAL EVP_PKEY **pparams,
                         OPTIONAL X509 **pcert, OPTIONAL STACK_OF(X509) **pcerts, int min_certs,
                         OPTIONAL X509_CRL **pcrl, OPTIONAL STACK_OF(X509_CRL) **pcrls, int min_crls)
{
    PW_CB_DATA ui_data = {pass, uri};
    OSSL_STORE_CTX *ctx = NULL;
    int ncerts = 0, ncrls = 0, expect = -1;
    const char *failed = FAIL_NAME;
    const char *input_type;
    OSSL_PARAM itp[2];
    const OSSL_PARAM *params = NULL;

    /* 'failed' describes type of credential to load for potential error msg */
    if (failed == NULL) {
        if (!quiet)
            LOG(FL_ERR, "Internal error: nothing was requested to load from %s",
                uri != NULL ? uri : "<stdin>");
        return false;
    }

    BUF_MEM *bptr = NULL;
    BIO *bio_mem = BIO_new(BIO_s_mem());
    if (bio_mem == NULL) {
        if (!quiet)
            LOG(FL_ERR, "Out of memory in load_key_certs_crls()");
        return false;
    }

    /* suppress any extraneous errors left over from failed parse attempts */
    ERR_set_mark();

    SET_EXPECT1(ppkey, OSSL_STORE_INFO_PKEY);
    SET_EXPECT1(ppubkey, OSSL_STORE_INFO_PUBKEY);
    SET_EXPECT1(pparams, OSSL_STORE_INFO_PARAMS);
    SET_EXPECT1(pcert, OSSL_STORE_INFO_CERT);
    /*
     * Up to here, the follwing holds.
     * If just one of the ppkey, ppubkey, pparams, and pcert function parameters
     * is nonzero, expect > 0 indicates which type of credential is expected.
     * If expect == 0, more than one of them is nonzero (multiple types expected).
     */

    if (pcerts != NULL) {
        if (*pcerts == NULL && (*pcerts = sk_X509_new_null()) == NULL) {
            if (!quiet)
                BIO_printf(bio_mem, "Out of memory loading");
            goto end;
        }
        /*
         * Adapt the 'expect' variable:
         * set to OSSL_STORE_INFO_CERT if no other type is expected so far,
         * otherwise set to 0 (indicating that multiple types are expected).
         */
        SET_EXPECT(OSSL_STORE_INFO_CERT);
    }
    SET_EXPECT1(pcrl, OSSL_STORE_INFO_CRL);
    if (pcrls != NULL) {
        if (*pcrls == NULL && (*pcrls = sk_X509_CRL_new_null()) == NULL) {
            if (!quiet)
                BIO_printf(bio_mem, "Out of memory loading");
            goto end;
        }
        /*
         * Adapt the 'expect' variable:
         * set to OSSL_STORE_INFO_CRL if no other type is expected so far,
         * otherwise set to 0 (indicating that multiple types are expected).
         */
        SET_EXPECT(OSSL_STORE_INFO_CRL);
    }

    if ((input_type = format2string(format)) != NULL) {
        itp[0] = OSSL_PARAM_construct_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE,
                                                  (char *)input_type, 0);
        itp[1] = OSSL_PARAM_construct_end();
        params = itp;
    }

    const UI_METHOD *ui_meth = pass == NULL ? NULL : get_ui_method(); // TODO remove NULL case (added as a workaround), which should not be needed
    if (uri == NULL) {
        BIO *bio;

        if (!maybe_stdin) {
            if (!quiet)
                BIO_printf(bio_mem, "No filename or uri specified for loading\n");
            goto end;
        }
        uri = "<stdin>";
        unbuffer(stdin);
        bio = BIO_new_fp(stdin, 0);
        if (bio != NULL) {
            ctx = OSSL_STORE_attach(bio, "file", libctx, propq,
                                    ui_meth, &ui_data, params,
                                    NULL, NULL);
            BIO_free(bio);
        }
    } else {
        ctx = OSSL_STORE_open_ex(uri, libctx, propq, ui_meth, &ui_data,
                                 params, NULL, NULL);
    }
    if (ctx == NULL) {
        if (!quiet)
            BIO_printf(bio_mem, "Could not open file or uri for loading");
        goto end;
    }
    /* expect == 0 means here multiple types of credentials are to be loaded */
    if (expect > 0 && !OSSL_STORE_expect(ctx, expect)) {
        if (!quiet)
            BIO_printf(bio_mem, "Internal error trying to load");
        goto end;
    }

    failed = NULL;
    /* from here, failed != NULL only if actually an error has been detected */

    while ((ppkey != NULL || ppubkey != NULL || pparams != NULL
            || pcert != NULL || pcerts != NULL || pcrl != NULL || pcrls != NULL)
           && !OSSL_STORE_eof(ctx)) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
        int type, ok = 1;

        /*
         * This can happen (for example) if we attempt to load a file with
         * multiple different types of things in it - but the thing we just
         * tried to load wasn't one of the ones we wanted, e.g. if we're trying
         * to load a certificate but the file has both the private key and the
         * certificate in it. We just retry until eof.
         */
        if (info == NULL)
            continue;

        type = OSSL_STORE_INFO_get_type(info);
        switch (type) {
        case OSSL_STORE_INFO_PKEY:
            if (ppkey != NULL) {
                ok = (*ppkey = OSSL_STORE_INFO_get1_PKEY(info)) != NULL;
                if (ok)
                    ppkey = NULL;
                break;
            }
            /*
             * An EVP_PKEY with private parts also holds the public parts,
             * so if the caller asked for a public key, and we got a private
             * key, we can still pass it back.
             */
            /* fall through */
        case OSSL_STORE_INFO_PUBKEY:
            if (ppubkey != NULL) {
                ok = (*ppubkey = OSSL_STORE_INFO_get1_PUBKEY(info)) != NULL;
                if (ok)
                    ppubkey = NULL;
            }
            break;
        case OSSL_STORE_INFO_PARAMS:
            if (pparams != NULL) {
                ok = (*pparams = OSSL_STORE_INFO_get1_PARAMS(info)) != NULL;
                if (ok)
                    pparams = NULL;
            }
            break;
        case OSSL_STORE_INFO_CERT:
            if (pcert != NULL) {
                ok = (*pcert = OSSL_STORE_INFO_get1_CERT(info)) != NULL;
                if (ok)
                    pcert = NULL;
            } else if (pcerts != NULL) {
                ok = X509_add_cert(*pcerts,
                                   OSSL_STORE_INFO_get1_CERT(info),
                                   X509_ADD_FLAG_DEFAULT);
            }
            ncerts += ok;
            break;
        case OSSL_STORE_INFO_CRL:
            if (pcrl != NULL) {
                ok = (*pcrl = OSSL_STORE_INFO_get1_CRL(info)) != NULL;
                if (ok)
                    pcrl = NULL;
            } else if (pcrls != NULL) {
                ok = sk_X509_CRL_push(*pcrls, OSSL_STORE_INFO_get1_CRL(info));
            }
            ncrls += ok;
            break;
        default:
            /* skip any other type; ok stays == 1 */
            break;
        }
        OSSL_STORE_INFO_free(info);
        if (!ok) {
            failed = OSSL_STORE_INFO_type_string(type);
            if (!quiet)
                BIO_printf(bio_mem, "Error reading");
            break;
        }
    }

 end:
    OSSL_STORE_close(ctx);

    /* see if any of the requested types of credentials was not found */
    if (failed == NULL) {
        if (ncerts >= min_certs)
            pcerts = NULL;
        if (ncrls >= min_crls)
            pcrls = NULL;
        failed = FAIL_NAME; /* non-NULL if pcerts != NULL || pcrls != NULL */
        if (failed != NULL && !quiet) {
            BIO_printf(bio_mem, "Could not find or decode");
            if (pcerts != NULL)
                BIO_printf(bio_mem, " at least %d", min_certs);
            else if (pcrls != NULL)
                BIO_printf(bio_mem, " at least %d", min_crls);
        }
    }

    if (failed != NULL && !quiet) {
        unsigned long err = ERR_peek_last_error();

        /* continue the error message with the type of credential affected */
        if (desc != NULL && (strstr(desc, failed) != NULL
                             || (ppkey != NULL) + (ppubkey != NULL) + (pparams != NULL)
                             + (pcert != NULL) + (pcerts != NULL)
                             + (pcrl != NULL) + (pcrls != NULL) > 1)) {
            BIO_printf(bio_mem, " %s", desc);
        } else {
            BIO_printf(bio_mem, " %s", failed);
            if (desc != NULL)
                BIO_printf(bio_mem, " of %s", desc);
        }
        if (uri != NULL)
            BIO_printf(bio_mem, " from %s", uri);
        if (ERR_SYSTEM_ERROR(err)) {
            /* provide more readable diagnostic output */
            BIO_printf(bio_mem, ": %s", strerror(ERR_GET_REASON(err)));
            ERR_pop_to_mark();
            ERR_set_mark();
        }
        BIO_printf(bio_mem, "\n");
        (void)BIO_flush(bio_mem);
        BIO_get_mem_ptr(bio_mem, &bptr);
        LOG(FL_ERR, "%.*s", bptr->length, bptr->data);
        ERR_print_errors(bio_err);
    }
    if (quiet || failed == NULL)
        /* clear any suppressed or spurious errors */
        ERR_pop_to_mark();
    else
        ERR_clear_last_mark();

    BIO_free(bio_mem);
    if (failed != NULL) {
        if (ppkey != NULL) {
            EVP_PKEY_free(*ppkey);
            *ppkey = NULL;
        }
        if (ppubkey != NULL) {
            EVP_PKEY_free(*ppubkey);
            *ppubkey = NULL;
        }
        if (pparams != NULL) {
            EVP_PKEY_free(*pparams);
            *pparams = NULL;
        }
        if (pcert != NULL) {
            X509_free(*pcert);
            *pcert = NULL;
        }
        if (pcerts != NULL) {
            sk_X509_pop_free(*pcerts, X509_free);
            *pcerts = NULL;
        }
        if (pcrl != NULL) {
            X509_CRL_free(*pcrl);
            *pcrl = NULL;
        }
        if (pcrls != NULL) {
            sk_X509_CRL_pop_free(*pcrls, X509_CRL_free);
            *pcrls = NULL;
        }
    }
    return failed == NULL;
}

EVP_PKEY *CREDS_load_key(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                         OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                         OPTIONAL const char *source, OPTIONAL const char *desc)
{
    char *pass;
    EVP_PKEY *pkey = NULL;

    LOG(FL_DEBUG, "Loading %s from %s", desc != NULL ? desc : "private key",
        uri != NULL ? uri : "<stdin>");
    pass = FILES_get_pass(source, desc);
    (void)load_key_certs_crls(libctx, propq, uri, format, maybe_stdin, pass, desc, desc == NULL,
                              &pkey, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0);
    UTIL_cleanse_free(pass);
    return pkey;
}

EVP_PKEY *CREDS_load_pubkey(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                            OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                            OPTIONAL const char *source, OPTIONAL const char *desc)
{
    char *pass;
    EVP_PKEY *pkey = NULL;

    if (desc == NULL)
        desc = "public key";
    LOG(FL_DEBUG, "Loading %s from %s", desc, uri != NULL ? uri : "<stdin>");
    pass = FILES_get_pass(source, desc);
    (void)load_key_certs_crls(libctx, propq, uri, format, maybe_stdin, pass, desc, false,
                              NULL, &pkey, NULL, NULL, NULL, 0, NULL, NULL, 0);
    UTIL_cleanse_free(pass);
    return pkey;
}

static BIO *bio_to_mem_bio(BIO *in, size_t max_len)
{
    char buf[4096];
    size_t total = 0;

    if (in == NULL)
        return NULL;

    BIO *mem = BIO_new(BIO_s_mem());
    if (mem == NULL)
        return NULL;

    for (;;) {
        int n = BIO_read(in, buf, sizeof(buf));
        if (n == 0)
            break; /* EOF */

        if (n > 0) {
            if (max_len != 0 && total + (size_t)n > max_len) {
                BIO_free(mem);
                return NULL;
            }

            if (BIO_write(mem, buf, n) != n) {
                BIO_free(mem);
                return NULL;
            }

            total += (size_t)n;
            continue;
        }

        if (BIO_should_retry(in))
            continue;

        BIO_free(mem);
        return NULL;
    }

    return mem;
}

static bool contains_str(const char *buf, size_t len, const char *str)
{
    size_t nlen = strlen(str);
    if (nlen == 0 || len < nlen)
        return false;

    const char *max = buf + len - nlen;
    while (buf <= max)
        if (memcmp(buf++, str, nlen) == 0)
            return true;
    return false;
}

static BIO *http_get_mem(const char *uri, OPTIONAL X509_STORE *tls_ts, int timeout,
                         const char *str, bool *found, const char *desc)
{
    *found = false;
    if (CONN_IS_HTTPS(uri) || tls_ts != NULL) {
        LOG(FL_ERR, "Loading %s over HTTPS is not yet supported; uri=%s", desc, uri);
        return NULL;
    }
    if ((CONN_IS_HTTP(uri) || CONN_IS_HTTPS(uri)) && timeout < 0) {
        LOG(FL_ERR, "Loading %s via HTTP(S) not allowed; uri = %s\n",
            desc, uri);
        return NULL;
    }
    BIO *res = OSSL_HTTP_get(uri, NULL /* proxy */, NULL /* no_proxy */,
                             NULL /* bio */, NULL /* rbio */, NULL /* cb */, NULL /* arg */,
                             0 /* buf_size */, NULL /* headers */,
                             NULL /* expected_ct */, 0 /* expect_asn1 */,
                             1024 * 1024 /* max_resp_len */, timeout);
    if (res == NULL) {
        LOG(FL_ERR, "Unable to download %s from %s\n", desc, uri);
        return NULL;
    }
    if (str == NULL)
        return res;

    BIO *mem = bio_to_mem_bio(res, 0);
    BIO_free(res);
    if (mem == NULL) {
        LOG(FL_ERR, "Error reading %s data received from %s", desc, uri);
        return NULL;
    }

    char *data = NULL;
    long len = BIO_get_mem_data(mem, &data);
    if (len <= 0 || data == NULL) {
        LOG(FL_ERR, "Error peeking at %s data received from %s", desc, uri);
        BIO_free(mem);
        return NULL;
    }

    *found = contains_str(data, (size_t)len, str);
    return mem;
}

X509 *CREDS_load_cert(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                      OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                      OPTIONAL X509_STORE *tls_ts, int timeout, OPTIONAL const char *source, OPTIONAL const char *desc,
                      int type_CA, OPTIONAL const X509_VERIFY_PARAM *vpm)
{
    char *pass;
    X509 *cert = NULL;
    const char *orig_desc = desc;

    if (desc == NULL)
        desc = "certificate";
    const char *uri_or_stdin = uri != NULL ? uri : "<stdin>";
    LOG(FL_DEBUG, "Loading %s from %s", desc, uri_or_stdin);
    if (CONN_IS_HTTP(uri) || CONN_IS_HTTPS(uri)) {
        bool is_pem;
        BIO *mem = http_get_mem(uri, tls_ts, timeout,
                                "-----BEGIN CERTIFICATE-----", &is_pem, desc);
        if (mem != NULL) {
            cert = is_pem ? PEM_read_bio_X509(mem, NULL, NULL, NULL) : d2i_X509_bio(mem, NULL);
            BIO_free(mem);
            if (cert == NULL)
                LOG(FL_ERR, "Unable to decode %s from %s", desc, uri);
        }
    } else {
        pass = FILES_get_pass(source, desc);
        (void)load_key_certs_crls(libctx, propq, uri, format, maybe_stdin, pass, desc, orig_desc == NULL,
                                  NULL, NULL, NULL, &cert, NULL, 1, NULL, NULL, 0);
        UTIL_cleanse_free(pass);
    }
    if (!CERT_check(uri_or_stdin, cert, type_CA, vpm) && vpm != NULL) {
        X509_free(cert);
        cert = NULL;
    }
    if (cert == NULL && orig_desc != NULL)
        LOG(FL_ERR, "Unable to load %s from %s\n", desc, uri_or_stdin);
    return cert;
}

static bool check_cert_chain(const char *src, int type_CA, OPTIONAL const X509_VERIFY_PARAM *vpm,
                             OPTIONAL X509 **cert, OPTIONAL STACK_OF(X509) **certs)
{ /* unfortunately, 'src' (used in diagnostics) is not specific per cert being checked */
    bool res = true;

    if (cert != NULL && !CERT_check(src, *cert, certs == NULL ?
                                    type_CA : 0 /* tentatively warn on CA cert */, vpm)
        && certs == NULL /* non-strict if also cert list loaded */
        && vpm != NULL /* non-strict if vpm == NULL; TODO better adapt CERT_check() */)
        res = false;
    if (certs != NULL && !CERT_check_all(src, *certs,
                                         cert == NULL ? type_CA : 1 /* warn on non-CA certs */, vpm)
        && cert == NULL /* non-strict if also cert loaded */
        && vpm != NULL /* non-strict if vpm == NULL; TODO better adapt CERT_check() */)
        res = false;
    return res;
}

STACK_OF(X509) *CREDS_load_certs(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                                 const char *srcs, file_format_t format, bool maybe_stdin,
                                 OPTIONAL X509_STORE *tls_ts, int timeout,
                                 OPTIONAL const char *source, OPTIONAL const char *desc,
                                 int min_num, int type_CA, OPTIONAL X509_VERIFY_PARAM *vpm)
{
    char *pass;
    STACK_OF(X509) *certs = NULL;
    char *src, *next, *names;

    if (desc == NULL)
        desc = "certs";
    if (!CONN_IS_HTTP(srcs)) /* well, this suppresses output also if only part of the srcs is HTTP-based */
        LOG(FL_DEBUG, "Loading %s from %s", desc, srcs);
    pass = FILES_get_pass(source, desc);

    if ((names = OPENSSL_strdup(srcs)) == NULL)
        goto oom;
    for (src = UTIL_first_item(names); src != NULL; src = next) {
        next = UTIL_next_item(src); /* must do this here to split string */

        if (CONN_IS_HTTP(src) || CONN_IS_HTTPS(src)) {
#if 0 // TODO 
            bool is_pem;
            BIO *mem = http_get_mem(src, tls_ts, timeout,
                                    "-----BEGIN CERTIFICATE-----", &is_pem, desc);
#else
            (void)tls_ts, (void)timeout;
            LOG(FL_ERR, "Loading %s via HTTP(S) not yet supported; uri = %s\n",
                desc, src);
            goto err;
#endif
        } else {
            if (!load_key_certs_crls(libctx, propq, src,
                                     format, maybe_stdin, pass, desc, false,
                                     NULL, NULL, NULL, NULL /* cert */, &certs,
                                     min_num, NULL, NULL, 0))
                goto err;
        }
    }

    if (sk_X509_num(certs) < min_num) {
        LOG(FL_ERR, "Could not load at least %d %s from %s\n", min_num, desc, srcs);
        goto err;
    }
    if (!check_cert_chain(srcs, type_CA, vpm, NULL /* cert */, &certs))
        LOG(FL_WARN, "Ignoring error(s) checking %s from '%s' because for trust anchors such checks are generally not required",
            desc, srcs);
    goto end;

 oom:
    LOG(FL_ERR, "out of memory");
 err:
    CERTS_free(certs);
    certs = NULL;
 end:
    OPENSSL_free(names);
    UTIL_cleanse_free(pass);
    return certs;
}

X509_CRL *CREDS_load_crl(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                         OPTIONAL const char *uri, file_format_t format, bool maybe_stdin,
                         OPTIONAL X509_STORE *tls_ts, int timeout, OPTIONAL const char *desc,
                         OPTIONAL const X509_VERIFY_PARAM *vpm)
{
    X509_CRL *crl = NULL;

    if (desc == NULL)
        desc = "CRL";
    const char *uri_or_stdin = uri != NULL ? uri : "<stdin>";
    LOG(FL_DEBUG, "Loading %s from %s", desc, uri_or_stdin);
    if (CONN_IS_HTTP(uri) || CONN_IS_HTTPS(uri)) {
        bool is_pem;
        BIO *mem = http_get_mem(uri, tls_ts, timeout, "-----BEGIN X509 CRL-----", &is_pem, desc);
        if (mem != NULL) {
            crl = is_pem ? PEM_read_bio_X509_CRL(mem, NULL, NULL, NULL) : d2i_X509_CRL_bio(mem, NULL);
            BIO_free(mem);
            if (crl == NULL)
                LOG(FL_ERR, "Unable to decode %s from %s", desc, uri);
        }
    } else {
        (void)load_key_certs_crls(libctx, propq,
                                  uri, format, maybe_stdin, NULL, desc, false,
                                  NULL, NULL,  NULL, NULL, NULL, 0, &crl, NULL, 1);
    }
    if (!CRL_check(uri_or_stdin, crl, vpm) && vpm != NULL) {
        X509_CRL_free(crl);
        crl = NULL;
    }
    if (crl == NULL)
        LOG(FL_ERR, "Unable to load %s from %s\n", desc, uri_or_stdin);
    return crl;
}

STACK_OF(X509_CRL) *CREDS_load_crls(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                                    const char *srcs, file_format_t format, bool maybe_stdin,
                                    OPTIONAL X509_STORE *tls_ts, int timeout,
                                    OPTIONAL const char *desc, int min_num,
                                    OPTIONAL const X509_VERIFY_PARAM *vpm)
{
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *crls = NULL, *all_crls = NULL;
    char *src, *next, *names = OPENSSL_strdup(srcs);

    if (desc == NULL)
        desc = "CRLs";
    if (!CONN_IS_HTTP(srcs)) /* well, this suppresses output also if only part of the srcs is HTTP-based */
        LOG(FL_DEBUG, "Loading %s from %s", desc, srcs);

    if (names == NULL || (all_crls = sk_X509_CRL_new_null()) == NULL)
        goto oom;
    for (src = UTIL_first_item(names); src != NULL; src = next) {
        next = UTIL_next_item(src); /* must do this here to split string */


        if (CONN_IS_HTTP(src) || CONN_IS_HTTPS(src)) {
            if ((crl = CREDS_load_crl(libctx, propq, src, format, maybe_stdin,
                                      tls_ts, timeout, desc, vpm)) == NULL)
                goto err;
            goto handle_crl;
        } else {
            if (!load_key_certs_crls(libctx, propq, src, format, maybe_stdin, NULL, desc, false,
                                     NULL, NULL, NULL, NULL, NULL, 0, NULL, &crls, 0))
                goto err;
        }
        while (sk_X509_CRL_num(crls) > 0) { /* effectively skipped on error */
            crl = sk_X509_CRL_shift(crls);
        handle_crl:
            if (!CRL_check(src, crl, vpm) && vpm != NULL)
                goto err;
            if (!sk_X509_CRL_push(all_crls, crl))
                goto oom;
            crl = NULL;
        }
        sk_X509_CRL_free(crls);
        crls = NULL;
    }
    if (sk_X509_CRL_num(all_crls) < min_num) {
        LOG(FL_ERR, "Could not load at least %d %s from %s", min_num, desc, srcs);
        goto err;
    }
    goto end;

 oom:
    LOG(FL_ERR, "out of memory");
 err:
    X509_CRL_free(crl);
    CRLs_free(crls);
    CRLs_free(all_crls);
    all_crls = NULL;
 end:
    OPENSSL_free(names);
    return all_crls;
}

bool CREDS_load_credentials(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                            OPTIONAL const char *certs, OPTIONAL const char *key,
                            file_format_t format, bool maybe_stdin,
                            OPTIONAL const char *source, OPTIONAL const char *desc,
                            int type_CA, OPTIONAL X509_VERIFY_PARAM *vpm,
                            OPTIONAL EVP_PKEY **pkey, OPTIONAL X509 **cert,
                            OPTIONAL STACK_OF(X509) **chain)
{
    const char *orig_desc = desc;
    bool joint_credentials = certs != NULL && key != NULL && strcmp(certs, key) == 0;
    char *pass;
    bool res = false;

    if (pkey != NULL)
        *pkey = NULL;
    if (cert != NULL)
        *cert = NULL;
    if (chain != NULL)
        *chain = NULL;
    if (certs == NULL && key == NULL)
        return true;

    if (orig_desc == NULL)
        desc = certs == NULL ? "private key" :
            (key == NULL ? "certificate(s)" : "private key and certificate(s)");
    if (format == FORMAT_HTTP
        || CONN_IS_HTTP(certs) || CONN_IS_HTTPS(certs)
        || CONN_IS_HTTP(key) || CONN_IS_HTTPS(key)) {
        LOG(FL_ERR, "Loading %s via HTTP(S) is not allowed; certs uri=%s, key uri=%s",
            desc, certs != NULL ? certs : "(none)", key != NULL ? key : "(none)");
        return false;
    }

    const char *src1 = key != NULL ? key : certs;
    const char *sep = "", *src2 = "";
    if (key != NULL && certs != NULL && !joint_credentials)
        sep = "' and '", src2 = certs;
    LOG(FL_DEBUG, "Loading %s from '%s%s%s'", desc, src1, sep, src2);

    pass = FILES_get_pass(source, desc);
    if (joint_credentials) {
        if (orig_desc == NULL)
            desc = "both private key and related certificate(s)";
        res = load_key_certs_crls(libctx, propq, certs /* == key */,
                                  format, maybe_stdin, pass, desc, true /* quiet on this first try */,
                                  pkey, NULL, NULL, cert, chain, 1, NULL, NULL, 0);
    }
    if (!res) {
        if (orig_desc == NULL)
            desc = "private key";
        if (pkey != NULL) {
            EVP_PKEY_free(*pkey);
            *pkey = NULL;
        }
        if (key != NULL && pkey != NULL
            && !load_key_certs_crls(libctx, propq, key, format, maybe_stdin, pass, desc, orig_desc == NULL,
                                    pkey, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0))
            goto err;
        if (orig_desc == NULL)
            desc = "certificate(s)";
        if (certs != NULL && (cert != NULL || chain != NULL)) {
            if (!load_key_certs_crls(libctx, propq, certs,
                                     format, maybe_stdin, pass, desc, orig_desc == NULL,
                                     NULL, NULL, NULL, cert, chain, 1, NULL, NULL, 0))
                goto err;
        }
    }
    UTIL_cleanse_free(pass);
    pass = NULL;
    if (orig_desc == NULL)
        desc = "certificate(s)";
    res = (cert == NULL && chain == NULL)
        || check_cert_chain(certs, type_CA, vpm, cert, chain);
    if (res)
        return true;

    LOG(FL_ERR, "Error(s) checking %s from %s", desc, certs == NULL ? "<stdin>" : certs);
    if (cert != NULL) {
        X509_free(*cert);
        *cert = NULL;
    }
    if (chain != NULL) {
        CERTS_free(*chain);
        *chain = NULL;
    }

err:
    if (pkey != NULL) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }
    UTIL_cleanse_free(pass);
    if (orig_desc != NULL)
        LOG(FL_ERR, "Could not load %s from '%s%s%s'", desc, src1, sep, src2);
    return false;
}

CREDENTIALS *CREDS_load(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                        OPTIONAL const char *certs, OPTIONAL const char *key,
                        OPTIONAL const char *source,
                        OPTIONAL const char *desc,
                        OPTIONAL X509_VERIFY_PARAM *vpm)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *chain = NULL;
    CREDENTIALS *res = NULL;

    if (!CREDS_load_credentials(libctx, propq, certs, key, FORMAT_UNDEF, false /* maybe_stdin */,
                                source, desc, -1, vpm, &pkey, &cert, &chain))
        return NULL;

    if (pkey != NULL && cert != NULL && !X509_check_private_key(cert, pkey)) {
        if (desc != NULL)
            LOG(FL_ERR, "for %s, key from '%s' and cert from '%s' do not match",
                desc, key, certs);
    } else {
        res = CREDENTIALS_new(pkey, cert, chain, NULL, NULL);
    }
    EVP_PKEY_free(pkey);
    X509_free(cert);
    CERTS_free(chain);
    return res;
}

/*
 * extend or create cert store structure with cert(s) read from file
 */
bool STORE_load_more_check_ex(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                              X509_STORE **pstore, const char *uri,
                              file_format_t format,
                              OPTIONAL X509_STORE *tls_ts, int timeout,
                              OPTIONAL const char *source,
                              OPTIONAL const char *desc, int min_certs,
                              OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx *ctx)
{
    if (desc == NULL)
        desc = "trusted cert(s)";
    if (uri == NULL) {
        LOG_err("null pointer uri argument");
        uri = "(NULL)";
        goto err;
    }
    if (pstore == NULL) {
        LOG_err("null pointer pstore argument");
        goto err;
    }
    /* LOG(FL_DEBUG, ...) will be done by CREDS_load_certs_ex() */

    const char *store_desc = desc;
    if (store_desc != NULL) {
        CHECK_AND_SKIP_PREFIX(store_desc, "trusted cert(s) for ");
        CHECK_AND_SKIP_PREFIX(store_desc, "trusted certs for ");
        CHECK_AND_SKIP_PREFIX(store_desc, "trusted certificates for ");
    }

    if (ctx == NULL
#ifdef SECUTILS_USE_ICV
        || CONN_IS_HTTP(uri) || CONN_IS_HTTPS(uri) || FILES_check_icv(ctx, uri)
#endif
        ) {
        STACK_OF(X509) *certs = NULL;

        certs = CREDS_load_certs(libctx, propq, uri, format, false /* maybe_stdin */,
                                 tls_ts, CONN_IS_HTTP(uri) ? -1 : timeout,
                                 source, desc, min_certs,
                                 vpm != NULL ? 1 /* strictly check CA */ : -1, vpm);
        if (certs == NULL)
            return false;

        if (vpm == NULL)
            (void)CERT_check_all(uri, certs, 1 /* warn on non-CA certs */, NULL);
        *pstore = STORE_create(*pstore, 0, certs);
        CERTS_free(certs);
        return *pstore != NULL && STORE_set1_desc(*pstore, store_desc);
    }

err:
    LOG(FL_ERR, "Could not load %s from %s", desc, uri);
    return false;
}

X509_STORE *STORE_load_check_ex(OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq,
                                const char *srcs, file_format_t format,
                                OPTIONAL X509_STORE *tls_ts, int timeout,
                                OPTIONAL const char *source, OPTIONAL const char *desc,
                                int min_certs_per_file,
                                OPTIONAL X509_VERIFY_PARAM *vpm, OPTIONAL uta_ctx *ctx)

{
    X509_STORE *store = NULL;

    if (srcs == NULL) {
        LOG_err("null pointer srcs arg");
        return 0;
    }

    char *names = OPENSSL_strdup(srcs);
    if (names == NULL) {
        LOG_err("Out of memory");
        return 0;
    }

    char *uri;
    char *next;
    for (uri = UTIL_first_item(names); uri != NULL; uri = next) {
        next = UTIL_next_item(uri); /* must do this here to split string */
        if (!STORE_load_more_check_ex(libctx, propq, &store, uri, format,
                                      tls_ts, timeout, source, desc, min_certs_per_file, vpm, ctx)) {
            X509_STORE_free(store);
            store = NULL;
            break;
        }
    }

    OPENSSL_free(names);
    return store;
}

#ifdef GENCMP_NO_SECUTILS

static bool FMT_istext(file_format_t format)
{
    return ((unsigned)format & (unsigned)B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

static BIO *dup_bio_in(file_format_t format)
{
    return BIO_new_fp(stdin,
        BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
}

static BIO *dup_bio_out(file_format_t format)
{
    BIO *b = BIO_new_fp(stdout,
        BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));

#ifdef OPENSSL_SYS_VMS
    if (b != NULL && FMT_istext(format)) {
        BIO *btmp = BIO_new(BIO_f_linebuffer());

        if (btmp == NULL) {
            BIO_free(b);
            return NULL;
        }
        b = BIO_push(btmp, b);
    }
#endif

    return b;
}

#define MODESTR_LEN1 3 /* strlen("rb") + 1 */
static BIO *bio_open_default_(const char *filename, char mode,
                              file_format_t format, bool quiet)
{
    BIO *ret;

    if (filename == NULL) {
        LOG(FL_ERR, "null filename argument");
        return NULL;
    }
    if (/* filename == NULL || */ strcmp(filename, "-") == 0) {
        ret = mode == 'r' ? dup_bio_in(format) : dup_bio_out(format);
        if (quiet)
            ERR_clear_error();
        if (quiet || ret != NULL)
            return ret;
        LOG(FL_ERR, "cannot open %s, %s", mode == 'r' ? "stdin" : "stdout", strerror(errno));
    } else {
        char modestr[MODESTR_LEN1];

        CHECK_AND_SKIP_PREFIX(filename, "file:");
        snprintf(modestr, MODESTR_LEN1, "%c%c", mode, FMT_istext(format) ? '\0' : 'b');
        ret = BIO_new_file(filename, modestr);
        if (quiet)
            ERR_clear_error();
        if (quiet || ret != NULL)
            return ret;
        LOG(FL_ERR, "cannot open file '%s' for mode '%c', %s", filename, mode, strerror(errno));
    }
    (void)ERR_print_errors(bio_err);
    return NULL;
}


static BIO *bio_open_default(const char *filename, char mode, file_format_t format)
{
    return bio_open_default_(filename, mode, format, false);
}


static int password_callback(char *buf, int bufsiz, ossl_unused int verify, void *cb_tmp)
{
    size_t len = 0;
    const char *password = NULL;
    PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

    if (cb_data != NULL && cb_data->password != NULL)
        password = cb_data->password;

    if (password != NULL) {
        len = strlen(password);
        if (len > (size_t)bufsiz)
            len = (size_t)bufsiz;
        memcpy(buf, password, len);
    }
    return (int)len;
}

bool FILES_store_key(const EVP_PKEY *pkey, const char *file, file_format_t format,
                     OPTIONAL const char *source, OPTIONAL const char *desc)
{
    char mode = 'w';
    BIO *bio = NULL;
    PW_CB_DATA cb_data;
    char *pass = FILES_get_pass(source, desc);
    bool result = false;

    LOG(FL_INFO, "Storing private key in file '%s'", file);
    if (format == FORMAT_PKCS12 && mode == 'w') {
        LOG(FL_ERR, "Writing keys in PKCS#12 file format not supported with GENCMP_NO_SECUTILS=");
        goto end;
    }
    if (format != FORMAT_PEM && format != FORMAT_ASN1) {
        LOG(FL_ERR, "Unsupported format (%d) or mode '%c' for storing %s",
            format, mode, desc != NULL ? desc : file);
        goto end;
    }

    cb_data.password = pass;
    cb_data.prompt_info = file;

    /* create bio and connect it with the file */
    if ((bio = bio_open_default(file, mode, format)) == NULL)
        goto end;

    /* Write the private key to file */
    const EVP_CIPHER *enc = pass == NULL ? NULL : EVP_aes_256_cbc();
    if (format == FORMAT_ASN1)
        result = pass == NULL ? i2d_PrivateKey_bio(bio, (EVP_PKEY *)pkey) > 0
                              : i2d_PKCS8PrivateKey_bio(bio, (EVP_PKEY*)pkey, enc, NULL, 0, password_callback, &cb_data) > 0;
    else if (format == FORMAT_PEM)
        result = PEM_write_bio_PrivateKey(bio, (EVP_PKEY*)pkey, enc, NULL, 0, password_callback, &cb_data) != 0;
    if (!result) {
        if (desc != NULL)
            LOG(FL_ERR, "failed to write %s", desc);
        goto end;
    }
    result = true;

 end:
    UTIL_cleanse_free(pass);
    BIO_free(bio);
    return result;
}

int FILES_store_certs(OPTIONAL const STACK_OF(X509) *certs, const char *file,
                      file_format_t format, OPTIONAL const char *desc)
{
    int n = sk_X509_num(certs);
    BIO *bio = 0;
    int i;
    X509 *cert = 0;

    if (n < 0)
        n = 0;
    LOG(FL_INFO, "storing %d certificate%s%s%s in file '%s'", n, n == 1 ? "" : "s",
        desc == 0 ? "" : " of ", desc == 0 ? "" : desc, file);
    if (format == FORMAT_PKCS12) {
        LOG(FL_ERR, "Writing certs in PKCS#12 file format not supported with GENCMP_NO_SECUTILS=");
        return false;
    }

    if (format != FORMAT_ASN1 && format != FORMAT_PEM) {
        LOG(FL_ERR, "unsupported output format (%d) for %s", format, desc != NULL ? desc : "certs");
        n = -1;
        goto err;
    }
    if (n > 1 && format == FORMAT_ASN1)
        LOG(FL_WARN, "jointly saving more than one certificate in DER format");

    if ((bio = bio_open_default(file, 'w', format)) == NULL) {
        LOG(FL_ERR, "cannot open file '%s' for writing %s", file, desc != NULL ? desc : "certs");
        n = -1;
        goto err;
    }
    for (i = 0; i < n; i++) {
        cert = sk_X509_value(certs, i);
        if ((format == FORMAT_PEM && !PEM_write_bio_X509(bio, cert)) ||
            (format == FORMAT_ASN1 && !i2d_X509_bio(bio, cert))) {
            LOG(FL_ERR, "cannot write %s certificates to file '%s'", desc, file);
            n = -1;
            goto err;
        }
    }

err:
    BIO_free(bio); /* may be NULL */
    return n;
}

int FILES_store_crls(const STACK_OF(X509_CRL) *crls, const char *file,
                     file_format_t format, OPTIONAL const char *desc)
{
    int n = sk_X509_CRL_num(crls);
    BIO *bio = 0;
    int i;
    X509_CRL *crl = 0;

    LOG(FL_INFO, "storing %d CRL%s%s%s in file '%s'", n < 0 ? 0: n, n == 1 ? "" : "s",
        desc == 0 ? "" : " of ", desc == 0 ? "" : desc, file);
    if (format != FORMAT_ASN1 && format != FORMAT_PEM) {
        LOG(FL_ERR, "unsupported output format (%d) for %s", format, desc != NULL ? desc : "CRLs");
        n = -1;
        goto err;
    }
    if (n > 1 && format == FORMAT_ASN1)
        LOG(FL_WARN, "saving more than one certificate in DER format");

    if ((bio = bio_open_default(file, 'w', format)) == NULL) {
        LOG(FL_ERR, "cannot open file '%s' for writing %s", file, desc != NULL ? desc : "CRLs");
        n = -1;
        goto err;
    }
    for (i = 0; i < n; i++) {
        crl = sk_X509_CRL_value(crls, i);
        if ((format == FORMAT_PEM && !PEM_write_bio_X509_CRL(bio, crl)) ||
            (format == FORMAT_ASN1 && !i2d_X509_CRL_bio(bio, crl))) {
            LOG(FL_ERR, "cannot write CRLs to file '%s'", file);
            n = -1;
            goto err;
        }
    }

err:
    BIO_free(bio); /* may be NULL; */
    return n;
}

#endif /* def GENCMP_NO_SECUTILS */
