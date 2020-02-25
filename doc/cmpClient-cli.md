# NAME

cmpClient - client for the Certificate Management Protocol (RFC4210)

# SYNOPSIS

**cmpClient** (**imprint|bootstrap|update|revoke|pkcs10**) \[**-section** _CA_\]
**cmpClient** _options_

\[**-help**\]
\[**-config** _filename_\]
\[**-section** _names_\]

\[**-server** _address\[:port\]_\]
\[**-proxy** _\[http://\]address\[:port\]\[/path\]_\]
\[**-no\_proxy** _addresses_\]
\[**-path** _remote\_path_\]
\[**-msgtimeout** _seconds_\]
\[**-totaltimeout** _seconds_\]

\[**-trusted** _filenames_\]
\[**-untrusted** _sources_\]
\[**-srvcert** _filename_\]
\[**-recipient** _name_\]
\[**-expect\_sender** _name_\]
\[**-ignore\_keyusage**\]
\[**-unprotectederrors**\]
\[**-extracertsout** _filename_\]
\[**-cacertsout** _filename_\]

\[**-ref** _value_\]
\[**-secret** _arg_\]
\[**-cert** _filename_\]
\[**-key** _filename_\]
\[**-keypass** _arg_\]
\[**-digest** _name_\]
\[**-mac** _name_\]
\[**-extracerts** _sources_\]
\[**-unprotectedrequests**\]

\[**-cmd** _ir|cr|kur|p10cr|rr_\]
\[**-infotype** _name_\]
\[**-geninfo** _OID:int:N_\]

\[**-newkeytype** _ECC|RSA_\]
\[**-newkey** _filename_\]
\[**-newkeypass** _arg_\]
\[**-subject** _name_\]
\[**-issuer** _name_\]
\[**-days** _number_\]
\[**-reqexts** _name_\]
\[**-sans** _spec_\]
\[**-san\_nodefault**\]
\[**-policies** _name_\]
\[**-policy\_oid** _names_\]
\[**-policy\_oids\_critical**\]
\[**-popo** _number_\]
\[**-csr** _filename_\]
\[**-out\_trusted** _filenames_\]
\[**-implicitconfirm**\]
\[**-disableconfirm**\]
\[**-certout** _filename_\]

\[**-oldcert** _filename_\]
\[**-revreason** _number_\]

\[**-tls\_used**\]
\[**-tls\_cert** _filename_\]
\[**-tls\_key** _filename_\]
\[**-tls\_keypass** _arg_\]
\[**-tls\_extra** _filenames_\]
\[**-tls\_trusted** _filenames_\]
\[**-tls\_host** _name_\]

\[**-crls** _URLs_\]
\[**-use\_cdp**\]
\[**-cdp\_url** _URL_\]
\[**-use\_aia**\]
\[**-ocsp\_url** _URL_\]

# DESCRIPTION

The **cmpClient** command is a demo and test client implementation for the Certificate
Management Protocol (CMP) as defined in RFC 4210.
It can be used to request certificates from a CA server,
update their certificates,
request certificates to be revoked, and perform other CMP requests.

# USAGE

- **imprint|bootstrap|update|revoke|pkcs10**

    Select demo `use_case` of the cmpClient application. The corresponding CMP request
    will be executed with default settings. These settings could be adapt via the
    file 'config/demo.cnf'.

- List of options available for the `cmpClient` application:

# OPTIONS

- **-help**

    Display a summary of all options

- **-config** _filename_

    Configuration file to use.
    An empty string `""` means none.
    Default filename is `config/demo.cnf`.

- **-section** _names_

    Section(s) to use within config file defining CMP options.
    An empty string `""` means no specific section.
    Default is `default`.
    Multiple section names may be given, separated by commas and/or whitespace.
    Contents of sections named later may override contents of sections named before.
    In any case, as usual, the `[default]` section and finally the unnamed
    section (as far as present) can provide per-option fallback values.

## Message transfer options

- **-server** _address\[:port\]_

    The IP address or DNS hostname and optionally port (defaulting to 80)
    of the CMP server to connect to using HTTP/S transport.

- **-proxy** _\[http://\]address\[:port\]\[/path\]_

    The HTTP(S) proxy server to use for reaching the CMP server unless **no\_proxy**
    applies, see below.
    The optional "http://" prefix and any trailing path are ignored.
    Defaults to the environment variable `http_proxy` if set, else `HTTP_PROXY`
    in case no TLS is used, otherwise `https_proxy` if set, else `HTTPS_PROXY`.

- **-no\_proxy** _addresses_
List of IP addresses and/or DNS names of servers not use an HTTP(S) proxy for,
separated by commas and/or whitespace.
Default is from the environment variable `no_proxy` if set, else `NO_PROXY`.
- **-path** _remote\_path_

    HTTP path at the CMP server (aka CMP alias) to use for POST requests.
    Defaults to "/".

- **-msgtimeout** _seconds_

    Number of seconds (or 0 for infinite) a CMP message round trip is
    allowed to take before a timeout error is returned.
    Default is 120.

- **-totaltimeout** _seconds_

    Maximum number seconds an enrollment may take, including attempts polling for
    certificates on `waiting` PKIStatus.
    Default is 0 (infinite).

## Server authentication options

- **-trusted** _filenames_

    When verifying signature-based protection of CMP response messages,
    these are the CA certificate(s) to trust while checking certificate chains
    during CMP server authentication.
    This option gives more flexibility than the **-srvcert** option because
    it does not pin down the expected CMP server by allowing only one certificate.

    Multiple filenames may be given, separated by commas and/or whitespace.
    Each source may contain multiple certificates.

- **-untrusted** _sources_

    Non-trusted intermediate certificate(s) that may be useful
    for building certificate chains when verifying
    the CMP server (when checking signature-based CMP message protection),
    the own TLS client cert (when constructing the TLS client cert chain),
    stapled OCSP responses (when establishing TLS connections),
    and/or the newly enrolled certificate.
    These may get added to the extraCerts field sent in requests as far as needed.

    Multiple filenames may be given, separated by commas and/or whitespace.
    Each file may contain multiple certificates.

- **-srvcert** _filename_

    The specific CMP server certificate to use and directly trust (even if it is
    expired) when verifying signature-based protection of CMP response messages.
    May be set alternatively to the **-trusted** option
    if the certificate is available and only this one shall be accepted.

    If set, the issuer of the certificate is also used as the recipient of the CMP
    request and as the expected sender of the CMP response,
    overriding any potential **-recipient** option.

- **-recipient** _name_

    Distinguished Name (DN) of the CMP message recipient,
    i.e., the CMP server (usually a CA or RA entity).

    The argument must be formatted as _/type0=value0/type1=value1/type2=..._,
    characters may be escaped by `\` (backslash), no spaces are skipped.

    If a CMP server certificate is given with the **-srvcert** option, its subject
    name is taken as the recipient name and the **-recipient** option is ignored.
    If neither of the two are given, the recipient of the PKI message is
    determined in the following order: from the **-issuer** option if present,
    the issuer of old cert given with the **-oldcert** option if present,
    the issuer of the client certificate (**-cert** option) if present.

    Setting the recipient field in the CMP header is mandatory.
    If none of the above options allowing to derive the recipient name is given,
    no suitable value for the recipient in the PKIHeader is available.
    As last resort it is set to NULL-DN.

    When a response is received, its sender must match the recipient of the request.

- **-expect\_sender** _name_

    Distinguished Name (DN) of the expected sender of CMP response messages when
    MSG\_SIG\_ALG is used for protection.
    This can be used to ensure that only a particular entity is accepted
    to act as CMP server, and attackers are not able to use arbitrary certificates
    of a trusted PKI hieararchy to fraudulently pose as CMP server.
    Note that this option gives slightly more freedom than **-srvcert**,
    which pins down the server to a particular certificate,
    while **-expect\_sender** _name_ will continue to match after updates of the
    server cert.

    The argument must be formatted as _/type0=value0/type1=value1/type2=..._,
    characters may be escaped by `\` (backslash), no spaces are skipped.

    If not given, the subject DN of **-srvcert**, if provided, will be used.

- **-ignore\_keyusage**

    Ignore key usage restrictions in CMP signer certificates when verifying
    signature-based protection of incoming CMP messages,
    else `digitalSignature` must be allowed for signer certificate.

- **-unprotectederrors**

    Accept missing or invalid protection of negative responses from the server.
    This applies to the following message types and contents:

    - error messages
    - negative certificate responses (IP/CP/KUP)
    - negative revocation responses (RP)
    - negative PKIConf messages

    **WARNING:** This setting leads to unspecified behavior and it is meant
    exclusively to allow interoperability with server implementations violating
    RFC 4210, e.g.:

    - section 5.1.3.1 allows exceptions from protecting only for special
    cases:
    "There MAY be cases in which the PKIProtection BIT STRING is deliberately not
    used to protect a message \[...\] because other protection, external to PKIX, will
    be applied instead."
    - section 5.3.21 is clear on ErrMsgContent: "The CA MUST always sign it
    with a signature key."
    - appendix D.4 shows PKIConf having protection

- **-extracertsout** _filename_

    The file where to save any extra certificates received in the extraCerts field
    of response messages.

- **-cacertsout** _filename_

    The file where to save any CA certificates received in the caPubs field of
    initializiation response (ip) messages.

## Client authentication options

- **-ref** _value_

    Reference number/value to use as senderKID; this is required
    if no sender name can be determined from the **-cert** or <-subject> options and
    is typically used when authenticating with pre-shared key (password-based MAC).

- **-secret** _arg_

    Source of secret value to use for authenticating with pre-shared keys
    (password-based MAC).
    This takes precedence over the **-cert** option.

    For more information about the format of **arg** see the
    **PASS PHRASE ARGUMENTS** section in [openssl(1)](http://man.he.net/man1/openssl).

- **-cert** _filename_

    The client's currently existing certificate.
    Unless the **-secret** option indicating PBM is given,
    this will be used for signature-based message protection.
    Requires for the corresponding key to be given with **-key**.
    For IR this can be used for authenticating a request message
    using an external entity certificate as defined in appendix E.7 of RFC 4210.
    For KUR this is also used as certificate to be updated if the **-oldcert**
    option is not given.
    If the file includes further certs, they are appended to the untrusted certs.
    These may get added to the extraCerts field sent in requests as far as needed.

- **-key** _filename_

    The corresponding private key file for the client's current certificate given in
    the **-cert** option.

- **-keypass** _arg_

    Pass phrase source for the private key given with the **-key** option.
    Also used for **-cert** and **-oldcert** in case it is an encrypted PKCS#12 file.
    If not given here, the password will be prompted for if needed.

    For more information about the format of **arg** see the
    **PASS PHRASE ARGUMENTS** section in [openssl(1)](http://man.he.net/man1/openssl).

- **-digest** _name_

    Specifies name of supported digest to use in RFC 4210's MSG\_SIG\_ALG
    and as the one-way function (OWF) in MSG\_MAC\_ALG.
    If applicable, this is used for message protection and
    Proof-of-Possession (POPO) signatures.
    To see the list of supported digests, use **openssl list -digest-commands**.
    Defaults to `sha256`.

- **-mac** _name_

    Specifies name of supported digest to use as the MAC algorithm in MSG\_MAC\_ALG.
    To get the names of supported MAC algorithms use **openssl list -mac-algorithms**
    and possibly combine such a name with the name of a supported digest algorithm,
    e.g., hmacWithSHA256.
    Defaults to `hmac-sha1` as per RFC 4210.

- **-extracerts** _sources_

    Certificates to append in the extraCerts field when sending messages.

    Multiple filenames or URLs may be given, separated by commas and/or whitespace.
    Each source may contain multiple certificates.

- **-unprotectedrequests**

    Send messages without CMP-level protection.

## Generic message options

- **-cmd** _ir|cr|kur|p10cr|rr_

    CMP command to execute. Overrides `use_case` if present.
    Currently implemented commands are:

    - ir    - Initialization Request
    - cr    - Certificate Request
    - p10cr - PKCS#10 Certification Request (for legacy support)
    - kur   - Key Update Request
    - rr    - Revocation Request

    **ir** requests initialization of an End Entity into a PKI hierarchy by means of
    issuance of a first certificate.

    **cr** requests issuance of an additional certificate for an End Entity already
    initialized to the PKI hierarchy.

    **p10cr** requests issuance of an additional certificate similarly to **cr**
    but uses PKCS#10 CSR format.

    **kur** requests (key) update for an existing, given certificate.

    **rr** requests revocation of an existing, given certificate.

- **-infotype** _name_

    Set InfoType name to use for requesting specific info in **genm**,
    e.g., `signKeyPairTypes`.

- **-geninfo** _OID:int:N_

    generalInfo integer values to place in request PKIHeader with given OID,
    e.g., `1.2.3:int:987`.

## Certificate request options

- **-newkeytype** _ECC|RSA_

    The type of newly generated certificate. File to save this new key is specified
    with the **-newkey** option.

- **-newkey** _filename_

    The file containing the private or public key for the certificate requested
    in IR, CR or KUR.
    Default is the public key in the PKCS#10 CSR given with the **-csr** option,
    if any, or else the current client key, if given.

- **-newkeypass** _arg_

    Pass phrase source for the key given with the **-newkey** option.
    If not given here, the password will be prompted for if needed.

    For more information about the format of **arg** see the
    **PASS PHRASE ARGUMENTS** section in [openssl(1)](http://man.he.net/man1/openssl).

- **-subject** _name_

    X509 Distinguished Name (DN) of subject to use in the requested certificate
    template.
    For KUR, it defaults to the subject DN of the reference certificate
    (see **-oldcert**).
    This default is used for IR and CR only if no SANs are set.

    The argument must be formatted as _/type0=value0/type1=value1/type2=..._,
    characters may be escaped by `\` (backslash), no spaces are skipped.

    In case **-cert** is not set, for instance when using MSG\_MAC\_ALG,
    the subject DN is also used as sender of the PKI message.

- **-issuer** _name_

    X509 issuer Distinguished Name (DN) of the CA server
    to place in the requested certificate template in IR/CR/KUR.

    The argument must be formatted as _/type0=value0/type1=value1/type2=..._,
    characters may be escaped by `\` (backslash), no spaces are skipped.

    If neither **-srvcert** nor **-recipient** is available,
    the name given in this option is also set as the recipient of the CMP message.

- **-days** _number_

    Number of days the new certificate is requested to be valid for, counting from
    the current time of the host.
    Also triggers the explicit request that the
    validity period starts from the current time (as seen by the host).

- **-reqexts** _name_

    Name of section in OpenSSL config file defining certificate request extensions.

- **-sans** _spec_

    One or more IP addresses, DNS names, or URIs separated by commas or whitespace,
    to add as Subject Alternative Name(s) (SAN) certificate request extension.
    If the special element "critical" is given the SANs are flagged as critical.
    Cannot be used if any Subject Alternative Name extension is set via **-reqexts**.

- **-san\_nodefault**

    When Subject Alternative Names are not given via **-sans**
    nor defined via **-reqexts**,
    they are copied by default from the reference certificate (see **-oldcert**).
    This can be disabled by giving the **-san\_nodefault** option.

- **-policies** _name_

    Name of section in OpenSSL config file defining policies to be set
    as certificate request extension.
    This option cannot be used together with **-policy\_oids**.

- **-policy\_oids** _names_

    One or more OID(s), separated by commas and/or whitespace,
    to add as certificate policies request extension.
    This option cannot be used together with **-policies**.

- **-policy\_oids\_critical**

    Flag the policies given with **-policy\_oids** as critical.

- **-popo** _number_

    Proof-of-Possession (POPO) method to use for IR/CR/KUR; values: `-1`..<2> where
    `-1` = NONE, `0` = RAVERIFIED, `1` = SIGNATURE (default), `2` = KEYENC.

    Note that a signature-based POPO can only produced if a private key
    is provided via the **-newkey** or **-key** options.

- **-csr** _filename_

    CSR in PKCS#10 format to use in P10CR.
    This is for supporting legacy clients.

- **-out\_trusted** _filenames_

    Trusted certificate(s) to use for verifying the newly enrolled certificate.

    Multiple filenames may be given, separated by commas and/or whitespace.
    Each source may contain multiple certificates.

- **-implicitconfirm**

    Request implicit confirmation of newly enrolled certificates.

- **-disableconfirm**

    Do not send certificate confirmation message for newly enrolled certificate
    without requesting implicit confirmation
    to cope with broken servers not supporting implicit confirmation correctly.
    **WARNING:** This leads to behavior violating RFC 4210.

- **-certout** _filename_

    The file where the newly enrolled certificate should be saved.

## Certificate update and revocation options

- **-oldcert** _filename_

    The certificate to be updated (i.e., renewed or re-keyed) in KUR
    or to be revoked in RR.
    It must be given for RR, else it defaults to **-cert**.

    The reference certificate determined in this way, if any, is also used for
    deriving default subject DN and Subject Alternative Names for IR, CR, and KUR.
    Its issuer, if any, is used as default recipient in the CMP message header
    if neither **-srvcert**, **-recipient**, nor **-issuer** is available.

- **-revreason** _number_

    Set CRLReason to be included in revocation request (RR); values: `0`..`10`
    or `-1` for none (which is the default).

    Reason numbers defined in RFC 5280 are:

        CRLReason ::= ENUMERATED {
             unspecified             (0),
             keyCompromise           (1),
             cACompromise            (2),
             affiliationChanged      (3),
             superseded              (4),
             cessationOfOperation    (5),
             certificateHold         (6),
             -- value 7 is not used
             removeFromCRL           (8),
             privilegeWithdrawn      (9),
             aACompromise           (10)
         }

## TLS options

- **-tls\_used**

    Enable using TLS (even when other TLS\_related options are not set)
    when connecting to CMP server.

- **-tls\_cert** _filename_

    Client's TLS certificate.
    If the file includes further certificates,
    they are used for constructing the client cert chain provided to the TLS server.

- **-tls\_key** _filename_

    Private key for the client's TLS certificate.

- **-tls\_keypass** _arg_

    Pass phrase source for client's private TLS key **tls\_key**.
    Also used for **-tls\_cert** in case it is an encrypted PKCS#12 file.
    If not given here, the password will be prompted for if needed.

    For more information about the format of **arg** see the
    **PASS PHRASE ARGUMENTS** section in [openssl(1)](http://man.he.net/man1/openssl).

- **-tls\_extra** _filenames_

    Extra certificates to provide to TLS server during TLS handshake

- **-tls\_trusted** _filenames_

    Trusted certificate(s) to use for verifying the TLS server certificate.
    This implies hostname validation.

    Multiple filenames may be given, separated by commas and/or whitespace.
    Each source may contain multiple certificates.

- **-tls\_host** _name_

    Address to be checked (rather than **-server** address) during hostname
    validation.
    This may be a Common Name, a DNS name, or an IP address.

## Certificate status checking options, for both CMP and TLS

- **-crls** _URLs_

    Use given CRL(s) as primary source of certificate revocation information.
    The URLs argument may be a single element or a comma- or whitespace-separated
    list,
    each element starting with `http:` or `file:` or being a filename or pathname.

    This option enables CRL checking for, e.g., the CMP/TLS server certificate.

- **-use\_cdp**

    Enable CRL-based status checking and enable use of CDP entries in certificates.

- **-cdp\_url** _URL_

    Enable CRL-based status checking and use given URL as fallback
    certificate distribution point (CDP).

- **-use\_aia**

    Enable OCSP-based status checking and enable use of AIA entries in certificates.

- **-ocsp\_url** _URL_

    Enable OCSP-based status checking and use given OCSP responder URL as fallback.

# COPYRIGHT

Copyright (c) 2020 Siemens AG.

Licensed under the Apache License, Version 2.0
SPDX-License-Identifier: Apache-2.0
