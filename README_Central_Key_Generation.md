# Central Key Generation Implementation Details

This file describes the things to do for implementing the client side part of central key generation (CKG) according to the 
[Lightweight Certificate Management Protocol (CMP) Profile](https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/) (LWCP), section 4.1.6. 
The required changes are implemented as PoC in branch `AK_ckg`.

## Configuration Changes
- The `-newkeytype` configuration option needs to be extended to a keytype `central:`
- The `central:` keytype may have optional sub parameters specifiying the preferred key type

## Design Changes
- The ASN.1 CRMF definitions have to be aligned to the LWCP
    - The `EncryptedKey` definitions and implementations must be introduced
       - The `EnvelopedData` definitions must be included from CMS and some
          related functions must be implemented
       - The `SignedData` definitions must be included from CMS and some
           related functions must be implemented
- The handling of the certificates private key must be changed
    - A request without having a private key must be supported
    - Extracting the private key from the response must be supported
- The handling of the certificates public key must be changed
    - A missing or incomplete public key in the template must be supported
    - OSSL_CRMF_POPO_NONE must be used
- new CMP error codes must be defined

## Affected files

| file name | reason |
|-----------|--------|
| config/ckg.cnf|add configuration file for CKG |
| creds/CMP_EE_Chain_RSA.pem, creds/CMP_EE_Key_RSA.pem, creds/CMP_LRA_DOWNSTREAM_EE.pem | trust chain, private key and LRA certificate for key transport example|
| src/cmpClient.c | extension of `-newkeytype` configuration option |
| crypto/cmp/cmp_asn.c | introduce  `EncryptedKey` definitions|
| crypto/cmp/cmp_client.c | extend handling of the certificates private and public key |
| crypto/cmp/cmp_err.c | definition of new CMP error codes |
| crypto/cmp/cmp_local.h | implement `EncryptedKey` |
| crypto/cmp/cmp_msg.c | support request without private key, call extraction of private key from response |
| crypto/crmf/crmf_asn.c | include "../cms/cms_asn1.c" (ugly hack!) to implement `EnvelopedData` and `SignedData` and declare missing  ASN.1 functions |
| crypto/crmf/crmf_lib.c | support missing or incople public key, implement extraction of private key from envelopedData in encryptedKey |



| 





