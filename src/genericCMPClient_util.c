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

#include <genericCMPClient_util.h>

/* util.c: */

int UTIL_atoint(const char *str)
{
    char *tailptr = 0;
    long res = strtol(str, &tailptr, 10);

    if (*tailptr != '\0' || res < INT_MIN || res > INT_MAX)
        return INT_MIN;
    return (int)res;
}

static
void UTIL_erase_mem(void *dst, size_t len)
{
    if (dst != NULL)
        OPENSSL_cleanse(dst, len);
}

static
void UTIL_cleanse(char *str)
{
    if (str != NULL)
        UTIL_erase_mem((void *)str, strlen(str));
}

void UTIL_cleanse_free(OPTIONAL char *str)
{
    UTIL_cleanse(str);
    OPENSSL_free(str);
}

char *UTIL_first_item(char *str)
{
    if (str == NULL)
        return NULL;

    /* skip any initial separators (comma or whitespace) */
    while (*str == ',' || isspace(*str))
        str++;
    return *str == '\0' ? NULL : str;
}

char *UTIL_next_item(char *opt) /* in list separated by comma and/or spaces */
{
    /* advance to separator (comma or whitespace), if any */
    while (*opt != '\0' && *opt != ',' && !isspace(*opt)) {
        if (*opt == '\\' && opt[1] != '\0') {
            /* skip and unescape '\'-escaped char */
            memmove(opt, opt + 1, strlen(opt));
        }
        opt++;
    }
    if (*opt != '\0') {
        int found_comma = *opt == ',';

        /* terminate current item */
        *opt++ = '\0';
        /* skip over any further separators, but only one comma */
        while ((!found_comma && *opt == ',' && (found_comma = 1))
               || isspace(*opt))
            opt++;
    }
    return *opt == '\0' ? NULL : opt; /* NULL indicates end of input */
}

const char* UTIL_file_ext(OPTIONAL const char* filename)
{
    const char* ext = 0;
    const char* next = filename;
    if (filename != NULL) {
        do {
            ext = next;
            next = strchr(next, '.');
            if (next != NULL)
                next++;
        } while(next);
    }
    return ext;
}

/* log.c: */

#ifdef _WIN32
  /* Windows doesn't have syslog, so we'll use Windows Event Log or just disable syslog */
  #define LOG_EMERG   0
  #define LOG_ALERT   1
  #define LOG_CRIT    2
  #define LOG_ERR     3
  #define LOG_WARNING 4
  #define LOG_NOTICE  5
  #define LOG_INFO    6
  #define LOG_DEBUG   7
  static void syslog(int priority, const char *format, ...) {
    /* Stub implementation for Windows - could be enhanced to use Windows Event Log */
    (void)priority;
    (void)format;
  }
#else
  #include <syslog.h>
#endif

#define GENCMP_NAME "genCMPClient"
#define loc_len 256

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

static
bool LOG_generic(OPTIONAL const char *func, OPTIONAL const char *file, int lineno,
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
#ifndef NDEBUG
    int len = snprintf(loc, sizeof(loc), "%s", app_name);
    if (len < 0)
        len = 0; /* on error, cannot assume any string written to loc buffer */
    /* print fct name, source file name, and lineno only if debugging is enabled at build time */
    if (snprintf(loc + len, sizeof(loc) - (size_t)len, ":%s():%s:%d:", func, file, lineno) < 0)
        loc[0] = '\0'; /* on error, resort to empty string */
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
    size_t msg_len = strlen(msg);
    const int msg_nl = msg_len > 0 && msg[msg_len - 1] == '\n';
    const int ret = fprintf(fd, "%s %s: %s%s", loc, lvl, msg, msg_nl ? "" : "\n");

    /* make sure that printing is done right away, return info on success  */
    return fflush(fd) != EOF && ret >= 0;
}

static
bool LOG_default(OPTIONAL const char *func, OPTIONAL const char *file,
                 int lineno, severity level, const char *msg)
{
    return LOG_generic(func, file, lineno, level, msg, 1, 1);
}

bool LOG_syslog(OPTIONAL const char *func, OPTIONAL const char *file,
                 int lineno, severity level, const char *msg)
{
    return LOG_generic(func, file, lineno, level, msg, 1, 0);
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

/* config.c: */
CONF *CONF_load_config(OPTIONAL ossl_unused uta_ctx *ctx, const char *file)
{
    CONF *conf = NULL;
    long errorline = -1; /* line in the config file where a failure occurred */

    if (ctx != NULL) {
        LOG(FL_ERR, "ICV-based integrity projection not supported with GENCMP_NO_SECUTILS");
        return NULL;
    }

#ifdef DEBUG
    LOG(FL_ERR, "Loading configuration from file: %s", file);
#endif
    conf = NCONF_new(NCONF_default());
    if (conf == NULL) {
        LOG(FL_ERR, "Out of memory");
        return NULL;
    }
    if (NCONF_load(conf, file, &errorline) <= 0) {
        if (errorline <= 0)
            LOG(FL_ERR, "Cannot open the config file: %s", file);
        else
            LOG(FL_ERR, "Error on line %ld in config file: %s", errorline, file);
        NCONF_free(conf);
        conf = NULL;
    }
    return conf;
}

#define SECTION_NAME_MAX 40 /* max length of section name */
/* get previous name from a comma-separated list of names */
static const char *prev_item(char item[], const char *opt, const char *end)
{
    if (end == opt)
        return 0;
    const char *beg = end;
    while (beg != opt && beg[-1] != ',' && !isspace(beg[-1]))
        beg--;
    size_t len = (size_t)(end - beg);
    if (len > SECTION_NAME_MAX)
        len = SECTION_NAME_MAX;
    if (len != 0)
        strncpy(item, beg, len);
    item[len] = '\0';
    if (end - beg > SECTION_NAME_MAX) {
        LOG(FL_WARN,
            "using only first %d characters of section name starting with \"%s\"",
            SECTION_NAME_MAX, item);
    }
    while (beg != opt && (beg[-1] == ',' || isspace(beg[-1])))
        beg--;
    return beg;
}

bool CONF_entry_in_sections(const CONF *conf, const char *sections, const char *entry)
{
    static char section[SECTION_NAME_MAX+1];
    const char *end = sections + strlen(sections);
    while ((end = prev_item(section, sections, end)) != NULL) {
        STACK_OF(CONF_VALUE) *entries = NCONF_get_section(conf, section);
        int i, n = sk_CONF_VALUE_num(entries);

        for (i = 0; i < n; ++i) {
            CONF_VALUE *v = sk_CONF_VALUE_value(entries, i);
            if (v != NULL && v->name != NULL && strcmp(v->name, entry) == 0)
                return true;
        }
    }
    return false;
}

/* also covers unnamed initial part of config file (implicit default section) */
static bool conf_entry_in_sections_or_default(const CONF *conf,
                                              const char *sections, const char *entry)
{
    return CONF_entry_in_sections(conf, sections, entry)
        || ((strstr(sections, "default") == NULL)
            && CONF_entry_in_sections(conf, "default", entry));
}

/* get str value for name from a comma-separated hierarchy of config sections */
static const char *conf_get_string(const CONF *conf, const char *sections,
                                   const char *name)
{
    static char section[SECTION_NAME_MAX+1];
    const char *end = sections + strlen(sections);
    while ((end = prev_item(section, sections, end)) != NULL) {
        const char *res;
        if ((res = NCONF_get_string(conf, section, name)) != NULL)
            return res;
    }
    return NULL;
}

/* Parse a long integer, put it into *result; return false on failure */
static bool parse_long(const char *str, long *result)
{
    int errno_bak = errno;
    long res = 0;
    char *endp = 0;

    if (str == NULL || result == NULL) {
        LOG(FL_ERR, "null argument");
        return false;
    }
    errno = 0;
    res = strtol(str, &endp, 0);
    if (*endp != '\0' || endp == str
        || ((res == LONG_MAX || res == LONG_MIN) && errno == ERANGE)
        || (res == 0 && errno != 0)) {
        LOG(FL_ERR, "Can't parse \"%s\" as a long number", str);
        errno = errno_bak;
        return false;
    }
    *result = res;
    errno = errno_bak;
    return true;
}

/* get long val for name from a comma-separated hierarchy of config sections */
static bool conf_get_number_e(const CONF *conf, const char *sections,
                              const char *name, long *p_result)
{
    const char *str = conf_get_string(conf, sections, name);
    return str == NULL ? false : parse_long(str, p_result);
}

bool CONF_read_options(const CONF *conf, const char *sections, const opt_t *opt)
{
    const char *str;
    long val = 0;
    if (conf == NULL || sections == NULL || opt == NULL) {
        LOG(FL_ERR, "null argument");
        return false;
    }

    for (; opt->name != NULL; opt++) {
        if (opt->varref_u.txt == NULL)
            continue; /* skip if no variable reference given */
        switch(opt->type) {
        case OPT_NUM:
        case OPT_NUM_REQUIRED:
            /* restores default value if empty string is given */
            str = conf_get_string(conf, sections, opt->name);
            if (str != NULL) {
                if (str[0] == '\0') {
                    *opt->varref_u.num = opt->default_value.num;
                    break;
                }
                /* stores the value from the key opt->name into the opt->varref_u.num */
                if (!conf_get_number_e(conf, sections, opt->name, opt->varref_u.num))
                    return false;
            } else {
                ERR_clear_error(); /* option not provided */
            }
            break;
        case OPT_TXT:
        case OPT_TXT_REQUIRED:
            /* stores the value from the key opt->name in opt->varref_u.txt */
            str = conf_get_string(conf, sections, opt->name);
            if (str != NULL)
                *opt->varref_u.txt = str[0] == '\0' ? opt->default_value.txt : str;
            else
                ERR_clear_error(); /* option not provided */
            break;
        case OPT_BOOL:
        case OPT_BOOL_REQUIRED:
            /* restores default value if empty string is given */
            str = conf_get_string(conf, sections, opt->name);
            if (str != NULL) {
                if (str[0] == '\0') {
                    *opt->varref_u.bit = opt->default_value.bit;
                    break;
                }
                if (!conf_get_number_e(conf, sections, opt->name, &val))
                    return false;
                if (val < 0 || val > 1) {
                    LOG(FL_ERR, "value %ld is out of range for Boolean; must be 0 or 1", val);
                    return false;
                }
                *opt->varref_u.bit = (bool)val;
            } else {
                ERR_clear_error(); /* option not provided */
            }
            break;
            default:
                LOG(FL_ERR, "internal: unsupported type '%d' for option '%s'", opt->type, opt->name);
                return false;
                break;
        }
    }

    return true;
}


bool CONF_read_check_options(const CONF *conf, const char *sections, const opt_t *opts)
{
    STACK_OF(CONF_VALUE) *sk;
    int i;
    const opt_t *opt;
    bool ok = true;

    if (!CONF_read_options((CONF *)conf, sections, opts)) {
        LOG(FL_ERR, "Failed reading and parsing [%s] section", sections);
        return false;
    }

    /* give warnings on extra/unknown and thus unused section entries */
    sk = NCONF_get_section(conf, sections);
    for (i = 0; i < sk_CONF_VALUE_num(sk); i++) {
        CONF_VALUE *cv = sk_CONF_VALUE_value(sk, i);
        bool known = false;

        for (opt = opts; opt->name != NULL; opt++) {
            if (strcmp(cv->name, opt->name) == 0) {
                known = true;
                break;
            }
        }
        if (!known) {
            LOG(FL_WARN, "Ignoring unknown entry '%s' configured in section [%s]\n",
                cv->name, sections);
        }
    }

    /* throw errors on missing required entries */
    for (opt = opts; opt->name != NULL; opt++) {
        if ((opt->type & OPT_REQUIRED) != 0) {
            const char *val = conf_get_string(conf, sections, opt->name);

            if (!conf_entry_in_sections_or_default(conf, sections, opt->name)) {
                LOG(FL_ERR, "Missing required entry '%s' in section(s): %s\n",
                    opt->name, sections);
                ok = false;
            } else if (val == NULL || val[0] == '\0') {
                LOG(FL_ERR, "Empty value given for required entry '%s' in section(s) %s\n",
                    opt->name, sections);
                ok = false;
            }
        }
    }
    return ok;
}

/* files.c: */
static bool istext(file_format_t format)
{
    return ((unsigned)format & (unsigned) B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

static BIO* dup_bio_in(file_format_t format)
{
    return BIO_new_fp(stdin, BIO_NOCLOSE | (istext(format) ? BIO_FP_TEXT : 0));
}

char* FILES_get_pass(OPTIONAL const char* source, OPTIONAL const char* desc)
{
    BIO* bio = 0;
    char buf[256 /* sec_PASS_MAX_LEN */ + 1];
    const char* pass = 0;

    if (source == NULL) {
        return 0; /* no password is fine */
    } else if (strncmp(source, sec_PASS_STR, strlen(sec_PASS_STR)) == 0) {
        pass = source + strlen(sec_PASS_STR);
    }
#ifndef OPENSSL_NO_ENGINE
    else if (strncmp(source, sec_ENGINE_STR, strlen(sec_ENGINE_STR)) == 0) {
        pass = source + strlen(sec_ENGINE_STR);
    }
#endif
    else if (strncmp(source, sec_ENV_STR, strlen(sec_ENV_STR)) == 0) {
        pass = getenv(source + strlen(sec_ENV_STR));
        if (pass == NULL) {
            LOG(FL_ERR, "No environment variable %s\n", source + strlen(sec_ENV_STR));
        }
    }
    else if (strncmp(source, sec_FILE_STR, strlen(sec_FILE_STR)) == 0) {
        bio = BIO_new_file(source + strlen(sec_FILE_STR), "r");
        if (bio == NULL) {
            LOG(FL_ERR, "Cannot open file %s\n", source + strlen(sec_FILE_STR));
        }
    }
#if !defined(_WIN32)
    /*
     * Under _WIN32, which covers even Win64 and CE, file
     * descriptors referenced by BIO_s_fd are not inherited
     * by child process and therefore below is not an option.
     * It could have been an option if bss_fd.c was operating
     * on real Windows descriptors, such as those obtained
     * with CreateFile.
     */
    else if (strncmp(source, sec_FD_STR, strlen(sec_FD_STR)) == 0) {
        int i = atoi(source + strlen(sec_FD_STR));
        if (i >= 0) {
            bio = BIO_new_fd(i, BIO_NOCLOSE);
        }
        if (i < 0 || bio == NULL) {
            LOG(FL_ERR, "Cannot access file descriptor %s\n", source + strlen(sec_FD_STR));
        }
        /* Cannot do BIO_gets on an fd BIO so add a buffering BIO */
        bio = BIO_push(BIO_new(BIO_f_buffer()), bio);
    }
#endif
    else if (strcmp(source, sec_STDIN_STR) == 0) {
        bio = dup_bio_in(FORMAT_TEXT);
        if (bio == NULL) {
            LOG(FL_ERR, "Cannot open BIO for stdin");
        }
    } else {
        pass = source;
        LOG(FL_WARN, "No 'pass:' or 'engine:' or 'env:' or 'file:' or 'fd:' prefix or 'stdin' found; assuming plain password for '%s'",
            desc != NULL ? desc : "key");
    }
    if (bio != NULL) {
        if (BIO_gets(bio, buf, sec_PASS_MAX_LEN + 1) <= 0) {
            LOG(FL_ERR, "Error reading password from BIO");
        } else {
            char* tmp = strchr(buf, '\n');
            if (tmp != NULL) {
                *tmp = '\0';
            }
            pass = buf;
        }
        BIO_free_all(bio);
    }
    return OPENSSL_strdup(pass);
}

/* key.c: */

#if OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0
EVP_PKEY *KEY_new_ex(const char *spec, OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq)
{
    if (spec == NULL) {
        LOG(FL_ERR, "null pointer argument");
        return NULL;
    }
    if (libctx != NULL) {
        LOG(FL_ERR, "libctx not supported by OpenSSL < 3.0");
        return NULL;
    }
    if (propq != NULL) {
        LOG(FL_ERR, "provider property query not supported by OpenSSL < 3.0");
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    int type = EVP_PKEY_NONE;
    const char *name = spec;
    int nbits = 0, nid = 0;

    if (CHECK_AND_SKIP_CASE_PREFIX(spec, SECUTILS_RSA_STR)) {
        type = EVP_PKEY_RSA;
        name = SECUTILS_RSA_STR;
    } else if ('0' <= *spec && *spec <= '9') {
        type = EVP_PKEY_RSA;
        name = SECUTILS_RSA_STR;
    } else if (CHECK_AND_SKIP_CASE_PREFIX(spec, SECUTILS_EC_STR)
               && *spec != '\0' && strchr(" -_:", *spec) != NULL) {
        type = EVP_PKEY_EC;
        name = SECUTILS_EC_STR;
    } else {
        spec = name;

        /* Backward compatibility: treat bare EC curve names as EC parameters. */
         int curve_nid = OBJ_sn2nid(spec);
         if (curve_nid == 0)
             curve_nid = EC_curve_nist2nid(spec);
         if (curve_nid != 0) {
             type = EVP_PKEY_EC;
             name = SECUTILS_EC_STR;
         }
#if OPENSSL_VERSION_NUMBER < OPENSSL_V_3_5_0
         else {
             /* For OpenSSL < 3.5, treat everything else as an EC curve name. */
             type = EVP_PKEY_EC;
             name = SECUTILS_EC_STR;
         }
#endif
    }
    if (type != EVP_PKEY_NONE && *spec != '\0' && strchr(" -_:", *spec) != NULL) {
        spec++;
    }
    if (type == EVP_PKEY_RSA) { /* take spec as RSA key length */
        nbits = UTIL_atoint(spec);
        if (nbits < 1024 || 8192 < nbits)
        {
            LOG(FL_ERR, "bad RSA key length specification '%.40s'; must be integer between 1024 and 8192", spec);
            return NULL;
        }
    } else if (type == EVP_PKEY_EC) { /* take spec as ECC curve name */
        if (strcmp(spec, "secp192r1") == 0) {
            LOG(FL_INFO, "using EC curve name prime192v1 instead of secp192r1");
            nid = NID_X9_62_prime192v1;
        } else if(strcmp(spec, "secp256r1") == 0) {
            LOG(FL_INFO, "using EC curve name prime256v1 instead of secp256r1");
            nid = NID_X9_62_prime256v1;
        } else {
            nid = OBJ_sn2nid(spec);
        }
        if (nid == 0) {
            nid = EC_curve_nist2nid(spec);
        }
        if (nid == 0)
        {
            LOG(FL_ERR, "unknown EC curve name %.40s", spec);
            return NULL;
        }
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, name, propq);
    if (ctx == NULL) {
        LOG(FL_ERR, "failed to create key generation context for %.40s (propq=%.100s); algorithm may be unknown or required provider may be unavailable",
            name, propq != NULL ? propq : "(null)");
        goto end;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        LOG(FL_ERR, "failed to prepare generating %.40s key pair (propq=%.100s)",
            name, propq != NULL ? propq : "(null)");
        goto end;
    }

    if (type == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, nbits) <= 0) {
            LOG(FL_ERR, "Failed to set %d RSA bits", nbits);
            goto end;
        }
    } else if (type == EVP_PKEY_EC) {
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
            LOG(FL_ERR, "Failed to set EC curve nid = %d for %.40s", nid, spec);
            goto end;
        }
    } else {
        /* With OpenSSL >= 3.5; attempting to use full name/spec by itself, which may be sufficient, e.g., "ML-DSA-65" */
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        LOG(FL_ERR, "failed generating %.40s key pair", name);
        pkey = NULL;
    }

 end:
    EVP_PKEY_CTX_free(ctx);
    if (pkey == NULL)
        (void)ERR_print_errors(bio_err);
    return pkey;

}

/* supports most of the spec syntax options of KEY_new_ex() */
bool KEY_type_supported(const char *spec,
                        OPTIONAL OSSL_LIB_CTX *libctx, OPTIONAL const char *propq)
{
    EVP_KEYMGMT *km;

    if (CHECK_AND_SKIP_CASE_PREFIX(spec, "RSA")) {
        int nbits;

        if (*spec != '\0' && strchr(" -_:", *spec) != NULL)
            spec++;
        nbits = UTIL_atoint(spec);
        if (1024 <= nbits && nbits <= 8192)
            return true;
    } else if (CHECK_AND_SKIP_CASE_PREFIX(spec, "EC")) {
        int curve_nid = OBJ_sn2nid(spec);

        if (*spec != '\0' && strchr(" -_:", *spec) != NULL)
            spec++;
        curve_nid = OBJ_sn2nid(spec);
        if (curve_nid == 0)
            curve_nid = EC_curve_nist2nid(spec);
        if (curve_nid != 0)
            return true;
    } else if ((km = EVP_KEYMGMT_fetch(libctx, spec, propq)) != NULL) {
        EVP_KEYMGMT_free(km);
        return true;
    }
    return false;
}
#endif

/* cert.c: */

/*
 * dn is expected to be in the format "/type0=value0/type1=value1/type2=..."
 * where characters may be escaped by '\'.
 * The NULL-DN may be given as "/" or "".
 */
/* adapted from OpenSSL:apps/lib/apps.c */
X509_NAME *UTIL_parse_name(const char *dn, int chtype, bool multirdn)
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

/*
 * Return 0 if time should not be checked or reference time is in range,
 * or else 1 if it is past the end, or -1 if it is before the start.
 * With OpenSSL before 4.0, invalid start and end times lead to not checking them.
 */
int UTIL_cmp_timeframe(OPTIONAL const X509_VERIFY_PARAM *vpm,
                       OPTIONAL const ASN1_TIME *start, OPTIONAL const ASN1_TIME *end)
{
#if OPENSSL_VERSION_NUMBER < OPENSSL_V_3_0_0
    unsigned long flags = vpm == NULL ? 0 : X509_VERIFY_PARAM_get_flags((X509_VERIFY_PARAM *)vpm);
    time_t ref_time;
    time_t *time = NULL;

    if ((flags & X509_V_FLAG_NO_CHECK_TIME) == 0) { /* otherwise ok */
        if ((flags & X509_V_FLAG_USE_CHECK_TIME) != 0) {
            ref_time = X509_VERIFY_PARAM_get_time(vpm);
            time = &ref_time;
        } /* else reference time is the current time */

        if (end != NULL && X509_cmp_time(end, time) < 0)
            return 1;
        if (start != NULL && X509_cmp_time(start, time) > 0)
            return -1;
    }
    return 0;
#elif OPENSSL_VERSION_NUMBER < 0x40000000L
    return X509_cmp_timeframe(vpm, start, end);
#else
    X509 *dummy_cert = X509_new(); /* needed as a workaround for OpenSSL API restriction */
    int res = 1, error;

    if (dummy_cert != NULL) {
        (void)X509_set1_notBefore(dummy_cert, start);
        (void)X509_set1_notAfter(dummy_cert, end);
        res = X509_check_certificate_times(vpm, dummy_cert, &error);
        X509_free(dummy_cert);
    }

    return res == 1 ? 0 : error == X509_V_ERR_CERT_NOT_YET_VALID ? -1:
        error == X509_V_ERR_CERT_HAS_EXPIRED ? 1 : 0;
#endif
}

static void cert_msg(OPTIONAL const char *func, OPTIONAL const char *file, int lineno,
                     severity level, const char *src, X509 *cert, const char *msg)
{
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

    LOG(func, file, lineno, level, "Certificate from '%s' with subject '%s' %s", src, subj, msg);
    OPENSSL_free(subj);
}

bool CERT_check(const char *src, OPTIONAL X509 *cert, int type_CA,
                OPTIONAL const X509_VERIFY_PARAM *vpm)
{
    if (cert == NULL)
        return true;
    int res = UTIL_cmp_timeframe(vpm, X509_get0_notBefore(cert), X509_get0_notAfter(cert));
    bool ret = res == 0;
    severity level = vpm == NULL ? LOG_WARNING : LOG_ERR;
    if (!ret)
        cert_msg(LOG_FUNC_FILE_LINE, level,
                 src, cert, res > 0 ? "has expired" : "not yet valid");
    uint32_t ex_flags = X509_get_extension_flags(cert);
    if (type_CA >= 0 && (ex_flags & EXFLAG_V1) == 0) {
        bool is_CA = (ex_flags & EXFLAG_CA) != 0;

        if ((type_CA == 1) != is_CA) {
            cert_msg(LOG_FUNC_FILE_LINE, level, src, cert,
                     is_CA ? "is not an EE cert" : "is not a CA cert");
            ret = false;
        }
    }
    return ret;
}

bool CERT_check_all(const char *src, OPTIONAL STACK_OF(X509) *certs, int type_CA,
                    OPTIONAL const X509_VERIFY_PARAM *vpm)
{
    int i;
    bool ret = true;

    for (i = 0; i < sk_X509_num(certs /* may be NULL */); i++)
        ret = CERT_check(src, sk_X509_value(certs, i), type_CA, vpm)
            && ret; /* Having 'ret' after the '&&', all certs are checked. */
    return ret;
}

bool CRL_check(const char *src, OPTIONAL X509_CRL *crl, OPTIONAL const X509_VERIFY_PARAM *vpm)
{
    int res;

    if (crl == NULL)
        return true;
    res = UTIL_cmp_timeframe(vpm, X509_CRL_get0_lastUpdate(crl), X509_CRL_get0_nextUpdate(crl));
    if (res != 0) {
        severity level = vpm == NULL ? LOG_WARNING : LOG_ERR;
        char *issuer = X509_NAME_oneline(X509_CRL_get_issuer(crl), 0, 0);

        LOG(LOG_FUNC_FILE_LINE, level, "CRL from '%s' issued by '%s' %s",
            src, issuer, res > 0 ? "has expired" : "is not yet valid");
        OPENSSL_free(issuer);
    }
    return res == 0;
}

/* credentials.c: */

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

/* all params may be null pointer; does not consume cert or certs */
X509_STORE *STORE_create(OPTIONAL X509_STORE *store, OPTIONAL const X509 *cert,
                         OPTIONAL const STACK_OF(X509) *certs)
{
    int i;

    if (store == NULL) {
#ifndef GENCMP_NO_TLS
        if (!STORE_EX_check_index())
            return 0;
#endif

        store = X509_STORE_new();
        if (store == NULL)
            goto oom;
    }
#if OPENSSL_VERSION_NUMBER >= OPENSSL_V_3_0_0
    X509_STORE_set_verify_cb(store, X509_STORE_CTX_print_verify_cb
                             /* could be more informative: CREDENTIALS_print_cert_verify_cb */);
#endif

#ifdef SECUTILS_TRUST_DEFAULT_STORE /* better not trust unclear default store */
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

#ifndef GENCMP_NO_TLS

/* conn.c: */

bool CONN_is_IP_address(OPTIONAL const char *host)
{
    if (host == NULL)
        return false;

    /* presume IPv6 address literal if host has the form "[<other-chars>]" */
    size_t len = strlen(host);
    if (len > 2 && *host == '[' && strchr(host + 1, '[') == NULL
            && strchr(host + 1, ']') == host + len - 1)
        return true;

    ERR_set_mark();
    ASN1_OCTET_STRING *str = a2i_IPADDRESS(host);
    ERR_pop_to_mark();
    ASN1_OCTET_STRING_free(str);
    return str != NULL;
}

static const char *skip_scheme(const char *str)
{
    const char *scheme_end = str;
    UTIL_SKIP_SCHEME(scheme_end);
    if (scheme_end != str && CHECK_AND_SKIP_PREFIX(scheme_end, UTIL_SCHEME_SUFFIX))
        str = scheme_end;
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

/* store.c: */
bool STORE_set1_host_ip(X509_STORE *ts, OPTIONAL const char *name, OPTIONAL const char *ip)
{
    if (ts == NULL) {
        LOG_err("null pointer argument");
        return false;
    }
    X509_VERIFY_PARAM *ts_vpm = X509_STORE_get0_param(ts);

    /* first clear any host names, IP addresses, and email addresses */
    if (
# if OPENSSL_VERSION_NUMBER < OPENSSL_V_3_0_0
        !STORE_set1_host(ts, 0) ||
# endif
        !X509_VERIFY_PARAM_set1_host(ts_vpm, 0, 0)
        || !X509_VERIFY_PARAM_set1_ip(ts_vpm, 0, 0)
        || !X509_VERIFY_PARAM_set1_email(ts_vpm, 0, 0)) {
        LOG_err("Could not clear host names and IP and email addresses from store");
        return false;
    }

    if (name == NULL && ip == NULL)
        return true;

    char *name_str = CONN_get_host(name);
    char *ip_str = NULL;
    if (name != NULL && name_str == NULL)
        return false;
    if (name != NULL && ip != NULL && strcmp(name, ip) == 0) {
        if (CONN_IS_IP_ADDR(name)) {
            ip_str = name_str;
            name = name_str = NULL;
        } else {
            ip = NULL;
        }
    } else {
        ip_str = CONN_get_host(ip);
        if (ip != NULL && ip_str == NULL) {
            OPENSSL_free(name_str);
            return false;
        }
    }

    X509_VERIFY_PARAM_set_hostflags(ts_vpm,
                                    X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT |
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    bool res = true;
    if (ip_str != NULL && !X509_VERIFY_PARAM_set1_ip_asc(ts_vpm, ip_str))
        res = false;
    if (name_str != NULL) {
        res = res && X509_VERIFY_PARAM_set1_host(ts_vpm, name_str, 0) != 0;
# if OPENSSL_VERSION_NUMBER < OPENSSL_V_3_0_0
        /*
         * Before OpenSSL 3.0, there was no API function for retrieving the
         * hostname/ip entries in X509_VERIFY_PARAM. So we stored the host value
         * in ex_data for use in CREDENTIALS_print_cert_verify_cb().
         * Since OpenSSL 3.0, this is no more needed as X509_VERIFY_PARAM_get0_host() is available.
         */
        res = res && STORE_set1_host(ts, name_str);
# endif
    }
    if (!res)
        LOG(FL_ERR, "Could not set host name '%s' and/or IP address '%s' in store",
            name_str != NULL ? name_str : "", ip_str != NULL ? ip_str : "");
    OPENSSL_free(ip_str);
    OPENSSL_free(name_str);
    return res;
}

const char *STORE_get0_host(const X509_STORE *store)
{
# if OPENSSL_VERSION_NUMBER < OPENSSL_V_3_0_0
    /*
     * Before OpenSSL 3.0, there is no OpenSSL API function for retrieving the
     * hostname/ip entries in X509_VERIFY_PARAM.
     * We could use ex_data, but do not support this with GENCMP_NO_SECUTILS.
     */
    (void)store; /* prevent compiler warning on unused parameter */
    return NULL;
# else
    /* first hostname set in store vpm: */
    return X509_VERIFY_PARAM_get0_host(X509_STORE_get0_param(store), 0);
# endif
}

#endif /* ndef GENCMP_NO_TLS */
