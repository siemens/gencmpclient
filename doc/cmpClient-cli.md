# NAME

cmpClient - genCMPClient CLI for the Certificate Management Protocol (RFC4210)

# SYNOPSIS

**cmpClient** (**imprint|bootstrap|update|revoke|pkcs10**) \[**-section** _server_\]

In this simple style of invocation, the first argument of the application,
e.g., `bootstrap`, is mapped to using a section in `config/demo.cnf`.
The optional server argument may be used to reference a CMP server to be used,
where the default is `EJBCA`. This is also used as config section name.

**cmpClient** _options_

\[**-help**\]
\[**-config** _filename_\]
\[**-section** _names_\]
\[**-verbosity** _level_\]

Generic message options:

\[**-cmd** _ir|cr|kur|p10cr|rr_\]
\[**-infotype** _name_\]
\[**-geninfo** _OID:int:N_\]

Certificate enrollment options:

\[**-newkeytype** EC:_curve_|RSA-_len_\]
\[**-newkey** _filename_\]
\[**-newkeypass** _arg_\]
\[**-subject** _name_\]
\[**-issuer** _name_\]
\[**-days** _number_\]
\[**-reqexts** _name_\]
\[**-sans** _spec_\]
\[**-san\_nodefault**\]
\[**-policies** _name_\]
\[**-policy\_oids** _names_\]
\[**-policy\_oids\_critical**\]
\[**-popo** _number_\]
\[**-csr** _filename_\]
\[**-out\_trusted** _filenames_\]
\[**-verify\_hostname** _cn_\]
\[**-verify\_ip** _ip_\]
\[**-verify\_email** _email_\]
\[**-implicit\_confirm**\]
\[**-disable\_confirm**\]
\[**-certout** _filename_\]
\[**-chainout** _filename_\]

Certificate enrollment and revocation options:

\[**-oldcert** _filename_\]
\[**-revreason** _number_\]

Message transfer options:

\[**-server** _\[http://\]address\[:port\]_\]\[/path\]
\[**-path** _remote\_path_\]
\[**-proxy** _\[http://\]address\[:port\]\[/path\]_\]
\[**-no\_proxy** _addresses_\]
\[**-recipient** _name_\]
\[**-keep\_alive** _value_\]
\[**-msg\_timeout** _seconds_\]
\[**-total\_timeout** _seconds_\]

Server authentication options:

\[**-trusted** _filenames_\]
\[**-untrusted** _sources_\]
\[**-srvcert** _filename_\]
\[**-expect\_sender** _name_\]
\[**-ignore\_keyusage**\]
\[**-unprotected\_errors**\]
\[**-extracertsout** _filename_\]
\[**-extracerts\_dir** _dirname_\]
\[**-extracerts\_dir\_format** <_PEM|DER|P12_\]
\[**-cacertsout** _filename_\]
\[**-cacerts\_dir** _dirname_\]
\[**-cacerts\_dir\_format** <_PEM|DER|P12_\]

Client authentication and protection options:

\[**-ref** _value_\]
\[**-secret** _arg_\]
\[**-cert** _filename_\]
\[**-own\_trusted** _filenames_\]
\[**-key** _filename_\]
\[**-keypass** _arg_\]
\[**-digest** _name_\]
\[**-mac** _name_\]
\[**-extracerts** _sources_\]
\[**-unprotected\_requests**\]

TLS connection options:

\[**-tls\_used**\]
\[**-tls\_cert** _filename_\]
\[**-tls\_key** _filename_\]
\[**-tls\_keypass** _arg_\]
\[**-tls\_extra** _filenames_\]
\[**-tls\_trusted** _filenames_\]
\[**-tls\_host** _name_\]

Debugging options:

\[**-reqin**\] _filenames_
\[**-reqin\_new\_tid**\]
\[**-reqout**\] _filenames_
\[**-rspin**\] _filenames_
\[**-rspout**\] _filenames_

Certificate status checking options, for both CMP and TLS:

\[**-check\_all**\]
\[**-check\_any**\]
\[**-crls** _URLs_\]
\[**-use\_cdp**\]
\[**-cdps** _URLs_\]
\[**-cdp\_proxy** _address_\]
\[**-crl\_cache\_dir** _dirname_\]
\[**-crls\_timeout** _seconds_\]
\[**-use\_aia**\]
\[**-ocsp** _URLs_\]
\[**-ocsp\_timeout** _seconds_\]
\[**-ocsp\_last**\]
\[**-stapling**\]

Certificate verification options, for both CMP and TLS:

\[**-policy** _arg_\]
\[**-purpose** _purpose_\]
\[**-verify\_name** _name_\]
\[**-verify\_depth** _num_\]
\[**-auth\_level** _level_\]
\[**-attime** _timestamp_\]
\[**-ignore\_critical**\]
\[**-issuer\_checks**\]
\[**-policy\_check**\]
\[**-explicit\_policy**\]
\[**-inhibit\_any**\]
\[**-inhibit\_map**\]
\[**-x509\_strict**\]
\[**-extended\_crl**\]
\[**-use\_deltas**\]
\[**-policy\_print**\]
\[**-check\_ss\_sig**\]
\[**-trusted\_first**\]
\[**-suiteB\_128\_only**\]
\[**-suiteB\_128**\]
\[**-suiteB\_192**\]
\[**-partial\_chain**\]
\[**-no\_alt\_chains**\]
\[**-no\_check\_time**\]
\[**-allow\_proxy\_certs**\]

# DESCRIPTION

The **cmpClient** command is a demo and test client implementation
of the Certificate Management Protocol (CMP) as defined in RFC 4210.
It can be used to request certificates from a CA via a CMP server,
to update or revoke them, and to perform possibly other CMP requests.

# USAGE

- **imprint|bootstrap|pkcs10|update|revoke**

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

    Multiple section names may be given, separated by commas and/or whitespace
    (where in the latter case the whole argument must be enclosed in "...").
    Contents of sections named later may override contents of sections named before.
    In any case, as usual, the `[default]` section and finally the unnamed
    section (as far as present) can provide per-option fallback values.

- **-verbosity** _level_

    Level of verbosity for logging, error output, etc.
    0 = EMERG, 1 = ALERT, 2 = CRIT, 3 = ERR, 4 = WARN, 5 = NOTE,
    6 = INFO, 7 = DEBUG, 8 = TRACE.
    Defaults to 6 = INFO.
    The levels DEBUG and TRACE are most useful for certificate status check issues.

## Generic message options

- **-cmd** _ir|cr|kur|p10cr|rr_

    CMP command to execute.
    Overrides `use_case` if present.
    Currently implemented commands are:

    - ir    - Initialization Request
    - cr    - Certificate Request
    - p10cr - PKCS#10 Certification Request (for legacy support)
    - kur   - Key Update Request
    - rr    - Revocation Request

    **ir** requests initialization of an end entity into a PKI hierarchy
    by issuing a first certificate.

    **cr** requests issuing an additional certificate for an end entity already
    initialized to the PKI hierarchy.

    **p10cr** requests issuing an additional certificate similarly to **cr**
    but using legacy PKCS#10 CSR format.

    **kur** requests a (key) update for an existing certificate.

    **rr** requests revocation of an existing certificate.

- **-infotype** _name_

    Set InfoType name to use for requesting specific info in **genm**,
    e.g., `signKeyPairTypes`.

- **-geninfo** _values_

    A comma-separated list of InfoTypeAndValue to place in the generalInfo field of
    the PKIHeader of requests messages.
    Each InfoTypeAndValue gives an OID and an integer or string value of the form
    _OID_:int:_number_ or _OID_:str:_text_,
    e.g., `'1.2.3.4:int:56789, id-kp:str:name'`.

## Certificate enrollment options

- **-newkeytype** _spec_

    In case of IR, CR, or KUR,
    generate a new key of the given type for the requested certifiate.
    The _spec_ may be of the form "EC:_curve_" or "RSA-_length_".
    The key will be saved in the file specified with the **-newkey** option.

- **-newkey** _filename_

    The file to save the newly generated key (in case  **-newkeytype** is given).
    Otherwise the file to read the private or public key from
    for the certificate requested in IR, CR or KUR.
    Default is the public key in the PKCS#10 CSR given with the **-csr** option,
    if any, or else the current client key, if given.

- **-newkeypass** _arg_

    Pass phrase source for the key file given with the **-newkey** option.
    If not given here, the password will be prompted for if needed.

    This may be a plain password, which should be preceded by 'pass:',
    a key identifier preceded by 'engine:' to use with a crypto engine,
    the name of a environment variable preceded by 'env:' to read from,
    the name of a file preceded by 'file:' to read from,
    the numeric descriptor of a file preceded by 'fd:' to read from,
    or 'stdin' to indicate that the password input is to be read from STDIN.

- **-subject** _name_

    X509 Distinguished Name (DN) of subject to use in the requested certificate
    template.
    For KUR, it defaults to the public key
    in the PKCS#10 CSR given with the **-csr** option, if provided,
    or of the reference certificate (see **-oldcert**) if provided.
    This default is used for IR and CR only if no SANs are set.
    If the NULL-DN (`/`) is given then no subject is placed in the template.

    If provided and neither **-cert** nor **-oldcert** is given,
    the subject DN is used as fallback sender of outgoing CMP messages.

    Special characters may be escaped by `\` (backslash); whitespace is retained.
    Empty values are permitted, but the corresponding type will not be included.
    Giving a single `/` will lead to an empty sequence of RDNs (a NULL-DN).
    Multi-valued RDNs can be formed by placing a `+` character instead of a `/`
    between the AttributeValueAssertions (AVAs) that specify the members of the set.
    Example:

    `/DC=org/DC=OpenSSL/DC=users/UID=123456+CN=John Doe`
    The argument must be formatted as _/type0=value0/type1=value1/type2=..._.
    For details see the description of the **-recipient** option.

- **-issuer** _name_

    X509 issuer Distinguished Name (DN) of the CA server
    to place in the requested certificate template in IR/CR/KUR.
    If the NULL-DN (`/`) is given then no issuer is placed in the template.

    If provided and neither **-recipient** nor **-srvcert** is given,
    the issuer DN is used as fallback recipient of outgoing CMP messages.

    The argument must be formatted as _/type0=value0/type1=value1/type2=..._.
    For details see the description of the **-subject** option.

- **-days** _number_

    Number of days the new certificate is requested to be valid for, counting from
    the current time of the host.
    Also triggers the explicit request that the
    validity period starts from the current time (as seen by the host).

- **-reqexts** _name_

    Name of section in OpenSSL config file defining certificate request extensions.

- **-sans** _spec_

    One or more IP addresses, DNS names, or URIs separated by commas or whitespace
    (where in the latter case the whole argument must be enclosed in "...")
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

    PKCS#10 CSR in PEM or DER format containing a certificate request.
    With **-cmd** _p10cr_ it is used directly in a legacy P10CR message.
    When used with **-cmd** _ir_, _cr_, or _kur_, it is transformed into the
    respective regular CMP request.
    It may also be used with **-cmd** _rr_ to specify the certificate to be revoked
    via the included subject and public key.

- **-out\_trusted** _filenames_

    Trusted certificate(s) to use for verifying the newly enrolled certificate.

    Multiple filenames may be given, separated by commas and/or whitespace
    (where in the latter case the whole argument must be enclosed in "...").
    Each source may contain multiple certificates.

    The certificate verification options
    **-verify\_hostname**, **-verify\_ip**, and **-verify\_email**
    only affect the certificate verification enabled via this option.

- **-verify\_hostname** _name_

    When verification of the newly enrolled certificate is enabled (with the
    **-out\_trusted** option), check if any DNS Subject Alternative Name (or if no
    DNS SAN is included, the Common Name in the subject) equals the given _name_.

- **-verify\_ip** _ip_

    When verification of the newly enrolled certificate is enabled (with the
    **-out\_trusted** option), check if there is
    an IP address Subject Alternative Name matching the given IP address.

- **-verify\_email** _email_

    When verification of the newly enrolled certificate is enabled (with the
    **-out\_trusted** option), check if there is
    an email address Subject Alternative Name matching the given email address.

- **-implicit\_confirm**

    Request implicit confirmation of newly enrolled certificates.

- **-disable\_confirm**

    Do not send certificate confirmation message for newly enrolled certificate
    without requesting implicit confirmation
    to cope with broken servers not supporting implicit confirmation correctly.
    **WARNING:** This leads to behavior violating RFC 4210.

- **-certout** _filename_

    The file where the newly enrolled certificate should be saved.
    If **-newkey** and **-newkeytype** are given and **-cmd** is not _p10cr_
    then the related chain and key are stored in this file as well,
    else if **-chainout** is not given the the related chain is stored here as well.

- **-chainout** _filename_

    The file where the chain of the newly enrolled certificate should be saved.
    If **-newkey** and **-newkeytype** are given and **-cmd** is not _p10cr_
    this option is ignored.

## Certificate enrollment and revocation options

- **-oldcert** _filename_

    The certificate to be updated (i.e., renewed or re-keyed) in Key Update Request
    (KUR) messages or to be revoked in Revocation Request (RR) messages.
    For KUR the certificate to be updated defaults to **-cert**,
    and the resulting certificate is called _reference certificate_.
    For RR the certificate to be revoked can also be specified using **-csr**.

    The reference certificate, if any, is also used for
    deriving default subject DN and Subject Alternative Names and the
    default issuer entry in the requested certificate template of an IR/CR/KUR.
    Its subject is used as sender in CMP message headers if **-cert** is not given.
    Its issuer is used as default recipient in CMP message headers
    if neither **-recipient**, **-srvcert**, nor **-issuer** is given.

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

## Message transfer options

- **-server** _\[http\[s\]://\]address\[:port\]\[/path\]_

    The IP address or DNS hostname and optionally port
    of the CMP server to connect to using HTTP(S) transport.
    The port defaults to 80 or 443 if the scheme is `https`.
    If a path is included it provides the default value for the **-path** option.

- **-path** _remote\_path_

    HTTP path at the CMP server (aka CMP alias) to use for POST requests.
    Defaults to any path given with **-server**, else `"/"`.

- **-proxy** _\[http\[s\]://\]address\[:port\]\[/path\]_

    The HTTP(S) proxy server to use for reaching the CMP server unless **-no\_proxy**
    applies, see below.
    The proxy port defaults to 80 or 443 if the scheme is `https`; apart from that
    the optional `http://` or `https://`prefix and any trailing path are ignored.
    Defaults to the environment variable `http_proxy` if set, else `HTTP_PROXY`
    in case no TLS is used, otherwise `https_proxy` if set, else `HTTPS_PROXY`.

- **-no\_proxy** _addresses_
List of IP addresses and/or DNS names of servers
not to use an HTTP(S) proxy for, separated by commas and/or whitespace
(where in the latter case the whole argument must be enclosed in "...").
Default is from the environment variable `no_proxy` if set, else `NO_PROXY`.
- **-recipient** _name_

    Distinguished Name (DN) to use in the recipient field of CMP request messages,
    i.e., the CMP server (usually the addressed CA).

    The recipient field in the header of a CMP message is mandatory.
    If not given explicitly the recipient is determined in the following order:
    the subject of the CMP server certificate given with the **-srvcert** option,
    the **-issuer** option,
    the issuer of the certificate given with the **-oldcert** option,
    the issuer of the CMP client certificate (**-cert** option),
    the subject of the first certificate given with the **-untrusted** option,
    as far as any of those is present, else the NULL-DN as last resort.

    The argument must be formatted as _/type0=value0/type1=value1/type2=..._.
    For details see the description of the **-subject** option.

- **-keep\_alive** _value_

    If the given value is 0 then HTTP connections are not kept open
    after receiving a response, which is the default behavior for HTTP 1.0.
    If the value is 1 or 2 then persistent connections are requested.
    If the value is 2 then persistent connections are required,
    i.e., in case the server does not grant them an error occurs.
    The default value is 1, which means preferring to keep the connection open.

- **-msg\_timeout** _seconds_

    Number of seconds (or 0 for infinite) a CMP message round trip is
    allowed to take before a timeout error is returned.
    Default is 120.

- **-total\_timeout** _seconds_

    Maximum number seconds an enrollment may take, including attempts polling for
    certificates on `waiting` PKIStatus.
    Default is 0 (infinite).

## Server authentication options

- **-trusted** _filenames_

    When verifying signature-based protection of CMP response messages,
    these are the CA certificate(s) to trust while checking certificate chains
    during CMP server authentication.
    This option gives more flexibility than the **-srvcert** option because the
    protection certificate is not pinned but may be any certificate
    for which a chain to one of the given trusted certificates can be constructed.

    Multiple filenames may be given, separated by commas and/or whitespace
    (where in the latter case the whole argument must be enclosed in "...").
    Each source may contain multiple certificates.

- **-untrusted** _sources_

    Non-trusted intermediate certificate(s).
    Any extra certificates given with the **-cert** option are appended to it.
    All these certificates may be useful for cert path construction
    for the CMP client certificate (to include in the extraCerts field of outgoing
    messages) and for the TLS client certificate (if TLS is enabled)
    as well as for chain building
    when validating the CMP server certificate (checking signature-based
    CMP message protection),
    when verifying stapled OCSP responses (while establishing TLS connections), and
    when validating newly enrolled certificates.

    Multiple filenames or URLs may be given, separated by commas and/or whitespace
    (where in the latter case the whole argument must be enclosed in "...").
    Each file may contain multiple certificates.

- **-srvcert** _filename_

    The specific CMP server certificate to expect and directly trust (even if it is
    expired) when verifying signature-based protection of CMP response messages.
    May be set alternatively to the **-trusted** option to pin the accepted server.

    If set, the subject of the certificate is also used
    as default value for the recipient of CMP requests
    and as default value for the expected sender of CMP responses.

- **-expect\_sender** _name_

    Distinguished Name (DN) expected in the sender field of response messages.
    Defaults to the subject DN of the pinned **-srvcert**, if any.

    This can be used to make sure that only a particular entity is accepted as
    CMP message signer, and attackers are not able to use arbitrary certificates
    of a trusted PKI hieararchy to fraudulently pose as CMP server.
    Note that this option gives slightly more freedom than setting the **-srvcert**,
    which pins the server to the holder of a particular certificate, while the
    expected sender name will continue to match after updates of the server cert.

    The argument must be formatted as _/type0=value0/type1=value1/type2=..._.
    For details see the description of the **-recipient** option.

- **-ignore\_keyusage**

    Ignore key usage restrictions in CMP signer certificates when verifying
    signature-based protection of incoming CMP messages,
    else `digitalSignature` must be allowed for signer certificate.

- **-unprotected\_errors**

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

- **-extracerts\_dir** _dirname_

    Path to save extra certificates received in the extraCerts field.

- **-extracerts\_dir\_format** <_PEM|DER|P12_

    Format to save extra certificates received in the extraCerts field-

- **-cacertsout** _filename_

    The file where to save any CA certificates received in the caPubs field of
    initializiation response (ip) messages.

- **-cacerts\_dir** _dirname_

    Path to save CA certificates received in the caPubss field.

- **-cacerts\_dir\_format** <_PEM|DER|P12_

    Format to save CA certificates received in the caPubs field.

## Client authentication options

- **-ref** _value_

    Reference number/string/value to use as fallback senderKID; this is required
    if no sender name can be determined from the **-cert** or <-subject> options and
    is typically used when authenticating with pre-shared key (password-based MAC).

- **-secret** _arg_

    Prefer PBM-based message protection with given source of a secret value.
    The secret is used for creating PBM-based protection of outgoing messages
    and (as far as needed) for verifying PBM-based protection of incoming messages.
    PBM stands for Password-Based Message Authentication Code.
    This takes precedence over the **-cert** and **-key** options.

    Supports plain passwords preceded by "pass:" and others, see **-newkeypass**.

- **-cert** _filename_

    The client's current CMP signer certificate.
    Requires for the corresponding key to be given with **-key**.
    The subject of this certificate will be used as sender of outgoing CMP messages,
    while the subject of **-oldcert** or **-subjectName** may provide fallback values.
    The issuer of this certificate is used as one of the recipient fallback values
    and as fallback issuer entry in the cerificate template of IR, CR, and KUR.
    When using signature-based message protection, this "protection certificate"
    will be included first in the extraCerts field of outgoing messages
    and the signature is done with the corresponding key.
    In Initialization Request (IR) messages this can be used for authenticating
    using an external entity certificate as defined in appendix E.7 of RFC 4210.
    For Key Update Request (KUR) messages this is also used as
    the certificate to be updated if the **-oldcert** option is not given.
    If the file includes further certs, they are appended to the untrusted certs
    because they typically constitute the chain of the client certificate, which
    is included in the extraCerts field in signature-protected request messages.

- **-own\_trusted** _filenames_

    If this list of certificates are provided they are used as trust anchors
    to verify the chain building for the own CMP signer certificate.

    Multiple filenames may be given, separated by commas and/or whitespace
    (where in the latter case the whole argument must be enclosed in "...").
    Each source may contain multiple certificates.

    The certificate verification options
    **-verify\_hostname**, **-verify\_ip**, and **-verify\_email**
    have no effect on the certificate verification enabled via this option.

- **-key** _filename_

    The corresponding private key file for the client's current certificate given in
    the **-cert** option.
    This will be used for signature-based message protection
    unless the **-secret** option indicating PBM or **-unprotected\_requests** is given.

- **-keypass** _arg_

    Pass phrase source for the private key given with the **-key** option.
    Also used for **-cert** and **-oldcert** in case it is an encrypted PKCS#12 file.
    If not given here, the password will be prompted for if needed.

    Supports plain passwords preceded by "pass:" and others, see **-newkeypass**.

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
    They can be used as the default CMP signer certificate chain to include.

    Multiple filenames or URLs may be given, separated by commas and/or whitespace
    (where in the latter case the whole argument must be enclosed in "...").
    Each source may contain multiple certificates.

- **-unprotected\_requests**

    Send messages without CMP-level protection.

## TLS connection options

- **-tls\_used**

    Enable using TLS (even when other TLS\_related options are not set)
    when connecting to CMP server.
    The following TLS-related options are ignored if **-tls\_used** is not given.

- **-tls\_cert** _filename_

    Client's TLS certificate.
    If the file includes further certificates,
    they are used for constructing the client cert chain provided to the TLS server.

- **-tls\_key** _filename_

    Private key for the client's TLS certificate.

- **-tls\_keypass** _arg_

    Pass phrase source for client's private TLS key **-tls\_key**.
    Also used for **-tls\_cert** in case it is an encrypted PKCS#12 file.
    If not given here, the password will be prompted for if needed.

    Supports plain passwords preceded by "pass:" and others, see **-newkeypass**.

- **-tls\_extra** _filenames_

    Extra certificates to provide to TLS server during TLS handshake

- **-tls\_trusted** _filenames_

    Trusted certificate(s) to use for verifying the TLS server certificate.
    This implies hostname validation.

    Multiple filenames may be given, separated by commas and/or whitespace
    (where in the latter case the whole argument must be enclosed in "...").
    Each source may contain multiple certificates.

    The certificate verification options
    **-verify\_hostname**, **-verify\_ip**, and **-verify\_email**
    have no effect on the certificate verification enabled via this option.

- **-tls\_host** _name_

    Address to be checked (rather than **-server** address)
    during TLS hostname validation.
    This may be a Common Name, a DNS name, or an IP address.

## Debugging options

- **-reqin** _filenames_

    Take sequence of CMP requests from file(s).

    Multiple filenames may be given, separated by commas and/or whitespace
    (where in the latter case the whole argument must be enclosed in "...").
    As many files are read as needed for a complete transaction.

- **-reqin\_new\_tid**

    Use a fresh transactionID for CMP request messages read using **-reqin**,
    which requires re-protecting them as far as they were protected before.
    This may be needed in case the sequence of requests is reused
    and the CMP server complains that the transaction ID has already been used.

- **-reqout** _filenames_

    Save sequence of CMP requests to file(s).

    Multiple filenames may be given, separated by commas and/or whitespace.
    As many files are written as needed to store the complete transaction.

- **-rspin** _filenames_

    Process sequence of CMP responses provided in file(s), skipping server.

    Multiple filenames may be given, separated by commas and/or whitespace.
    As many files are read as needed for the complete transaction.

- **-rspout** _filenames_

    Save sequence of CMP responses to file(s).

    Multiple filenames may be given, separated by commas and/or whitespace.
    As many files are written as needed to store the complete transaction.

## Certificate status checking options, for both CMP and TLS

The following set of options determine various parameters of
certificate revocation status checking to be performed by the client
on setting up any TLS connection and on checking any signature-based protection
of CMP messages received, but not when verifying newly enrolled certificates.

By default no certificate status checks are performed.
Status checking is demanded if any of the below status checking options are set,
but only as far as a trust store is provided for TLS or at CMP level.
Then by default only the leaf certificates of a chain are checked, i.e.,
the certificates of CMP servers and of TLS servers (as far as TLS is used).
The options **-check\_all** and **-check\_any** may be used to change the extent
of the checks to futher elements in the CA chain of these certificates.

For each certificate for which the status check is demanded the
certification verification procedure will try to obtain the revocation status
first via OCSP stapling if enabled,
then from any locally available CRLs,
then from any Online Certificate Status Protocol (OCSP) responders if enabled,
and finally from CRLs downloaded from certificate distribution points (CDPs)
if enabled.
With the **-ocsp\_last** option CDPs are tried before trying OCSP.
Verification fails if no valid and current revocation status can be found
or the status indicates that the certificate has been revoked.

- **-check\_all**

    Check certificate status not only for leaf certificates of a chain
    but for all certificates (except root, i.e., self-issued certificates).

- **-check\_any**

    Check certificate status for those certificates (except root certificates)
    that contain a CDP or AIA entry (or for which OCSP stapling for TLS is enabled).
    This option is overridden by **-check\_all** if set.

- **-crls** _URLs_

    Enable CRL-based status checking and
    use given CRL(s) as primary source of certificate revocation information.
    The URLs argument may contain a single element or
    a comma- or whitespace-separated list,
    each element starting with `http:` or `file:` or being a filename or pathname.

- **-use\_cdp**

    Enable CRL-based status checking and
    enable using CRL Distribution Points (CDP) extension entries in certificates.

- **-cdps** _URLs_

    Enable CRL-based status checking and
    use the given URL(s) as fallback certificate distribution points (CDP).

- **-cdp\_proxy** _address_

    Address of the proxy server to use for getting CRLs.
    Default from environment variable `cdp_proxy`, else `CDP_PROXY`, else none.

- **-crl\_cache\_dir** _dirname_

    Directory of the CRL cache when downloaded during verification.

- **-crls\_timeout** _seconds_

    Number of seconds fetching a CRL may take, or 0 for infinite.
    A negative value implies the default: 10 seconds.

- **-use\_aia**

    Enable OCSP-based status checking and
    enable using Authority Information Access (AIA) OCSP responder entries
    in certificates.

- **-ocsp** _URLs_

    Enable OCSP-based status checking and
    use given OCSP responder URL(s) as fallback.

- **-ocsp\_timeout** _seconds_

    Number of seconds getting an OCSP response may take, or 0 for infinite.
    A negative value implies the default: 10 seconds.

- **-ocsp\_last**

    This option can be used only when OCSP-based checks are enabled using **-ocsp**
    or **-use\_aia**. If checks downloading CRLs from CDPs are also enabled
    then do OCSP-based checks last (else before using CRLs downloaded from CDPs).

- **-stapling**

    Enable the TLS certificate status request extension ("OCSP stapling"),
    which is tried first before any other methods of certificate status checking.
    This makes sense only if **-tls\_used** is given.
    So far OCSP multi-stapling is not supported,
    so status information can be obtained in this way only for the leaf certificate
    (i.e., the TLS server certificate).

## Certificate verification options, for both CMP and TLS

- **-policy**, **-purpose**, **-verify\_name**, **-verify\_depth**,
**-auth\_level**,
**-attime**,
**-ignore\_critical**,
**-issuer\_checks**\],
**-policy\_check**,
**-explicit\_policy**, **-inhibit\_any**, **-inhibit\_map**,
**-x509\_strict**, **-extended\_crl**, **-use\_deltas**,
**-policy\_print**, **-check\_ss\_sig**,
**-trusted\_first**,
**-suiteB\_128\_only**, **-suiteB\_128**, **-suiteB\_192**,
**-partial\_chain**,
**-no\_check\_time**,
**-allow\_proxy\_certs**

    Set various options of certificate chain verification.
    See the [openssl-verify(1)](http://man.he.net/man1/openssl-verify) manual page
    or ["Verification Options" in openssl(1)](http://man.he.net/man1/openssl) for details.

# COPYRIGHT

Copyright (c) 2020 Siemens AG.

Licensed under the Apache License, Version 2.0
SPDX-License-Identifier: Apache-2.0

# POD ERRORS

Hey! **The above document had some coding errors, which are explained below:**

- Around line 1:

    &#x3d;pod directives shouldn't be over one line long!  Ignoring all 5 lines of content
