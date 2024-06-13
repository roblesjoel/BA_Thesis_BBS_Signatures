Originally from: https://github.com/Wind4Greg/BBS-VC-Library

# BBS for VC Library

Sign, selectively disclose, and verify credentials/presentations with BBS signatures and JavaScript!

This library is an independent implementation of the `bbs-2023` cryptosuite for verifiable credentials. The algorithms and functions are from sections 3 of [BBS Cryptosuite v2023: Securing Verifiable Credentials with Selective Disclosure using BBS Signatures](https://w3c.github.io/vc-di-bbs/#algorithms) where they are specified and described.

## High Level API Design

* **Add Base**: unsigned document, key pair, mandatory pointers, generators; optional: proof configuration options, hmac key, stuff for JSON-LD document loading. Returns signed base document.
* **Verify Base**: signed base document, public key (rather than extracting it from document or web), generators; optional: stuff for JSON-LD document loading. Returns true/false.
* **Derive Proof**: signed base document, selective pointers, generators; optional: stuff for JSON-LD document loading. Returns signed derived document.
* **Verify Derived**: signed derived document, public key, generators; optional: stuff for JSON-LD document loading. Returns true/false.

Note: For verification functions the issuers public key as a `Uint8Array` without any multibase prefixes must be furnished. This library does not perform any external requests to obtain key material for verification.

## Examples

See the `examples` directory for usage examples including JSON-LD document (context) loading and BBS generator creation. Example inputs are in the `examples/input` directory.

# Generated API from JSDoc

<!-- Generated with the command
    npx jsdoc2md lib/BBSsignBase.js lib/BBSverifyBase.js lib/BBSderive.js lib/BBSverifyDerived.js > documentation/apiDoc.md
    and then copy and paste below.

    For the primitive documentation use:
     npx jsdoc2md lib/primitives.js  > documentation/primitivesDoc.md
-->

## Functions

<dl>
<dt><a href="#signBase">signBase(document, keyPair, mandatoryPointers, options, gens)</a></dt>
<dd><p>sign a base document (credential) with <code>bbs-2023</code> procedures. This is done by an
issuer and permits the recipient, the holder, the freedom to selectively disclose
&quot;statements&quot; extracted from the document to a verifier within the constraints
of the mandatory disclosure requirements imposed by the issuer.</p>
</dd>
<dt><a href="#verifyBase">verifyBase(document, pubKey, options, gens)</a></dt>
<dd><p>verify a signed selective disclosure base document (credential) with <code>bbs-2023</code>
procedures. This is can be done by an holder on receipt of the credential.</p>
</dd>
<dt><a href="#derive">derive(document, selectivePointers, options, gens, ph)</a></dt>
<dd><p>derive a selectively disclosed document (presentation) with ECDSA-SD procedures.
This is done by a holder, who has the option to selectively disclose non-mandatory
statements to a verifier.</p>
</dd>
<dt><a href="#verifyDerived">verifyDerived(document, pubKey, options, gens, ph)</a></dt>
<dd><p>verify a signed selective disclosure derived document (credential) with ECDSA-SD
procedures. This is done by a verifier on receipt of the credential.</p>
</dd>
</dl>

<a name="signBase"></a>

## signBase(document, keyPair, mandatoryPointers, options, gens)
sign a base document (credential) with `bbs-2023` procedures. This is done by an
issuer and permits the recipient, the holder, the freedom to selectively disclose
"statements" extracted from the document to a verifier within the constraints
of the mandatory disclosure requirements imposed by the issuer.

**Kind**: global function

| Param | Type | Description |
| --- | --- | --- |
| document | <code>Object</code> | The unsigned credential |
| keyPair | <code>Object</code> | The issuers private/public key pair |
| keyPair.priv | <code>Uint8Array</code> | Byte array for the BLS12-381 G1 private key without multikey prefixes |
| keyPair.pub | <code>Uint8Array</code> | Byte array for the BLS12-381 G2 public key without multikey prefixes |
| mandatoryPointers | <code>Array</code> | An array of mandatory pointers in JSON pointer format |
| options | <code>Object</code> | A variety of options to control signing and processing |
| options.proofConfig | <code>Object</code> | proof configuration options without `@context`  field. Optional. This will be generated with current date information and  did:key verification method otherwise. |
| options.hmacKey | <code>Uint8Array</code> | A byte array for the HMAC key. Optional. A   cryptographically secure random value will be generated if not specified. |
| options.proofKeyPair | <code>Object</code> | A proof specific P256 key pair. Must   be unique for each call to signBase. Optional. A unique key pair will be   generated if not specified. |
| options.documentLoader | <code>function</code> | A JSON-LD document loader to be   passed on to JSON-LD processing functions. Optional. |
| gens | <code>Object</code> | generators object from BBS prepareGenerators of sufficient size to cover the number of statements (messages) in the document. |

<a name="verifyBase"></a>

## verifyBase(document, pubKey, options, gens)
verify a signed selective disclosure base document (credential) with `bbs-2023`
procedures. This is can be done by an holder on receipt of the credential.

**Kind**: global function

| Param | Type | Description |
| --- | --- | --- |
| document | <code>Object</code> | The signed `bbs-2023` base credential |
| pubKey | <code>Uint8Array</code> | Byte array for the issuers BLS12-381 G2 public key without multikey prefixes |
| options | <code>Object</code> | A variety of options to control signing and processing |
| options.documentLoader | <code>function</code> | A JSON-LD document loader to be   passed on to JSON-LD processing functions. Optional. |
| gens | <code>Object</code> | generators object from BBS prepareGenerators of sufficient size to cover the number of statements (messages) in the document. |

<a name="derive"></a>

## derive(document, selectivePointers, options, gens, ph)
derive a selectively disclosed document (presentation) with ECDSA-SD procedures.
This is done by a holder, who has the option to selectively disclose non-mandatory
statements to a verifier.

**Kind**: global function

| Param | Type | Description |
| --- | --- | --- |
| document | <code>Object</code> | The signed base credential |
| selectivePointers | <code>Array</code> | An array of selective pointers in JSON pointer format |
| options | <code>Object</code> | A variety of options to control signing and processing |
| options.documentLoader | <code>function</code> | A JSON-LD document loader to be   passed on to JSON-LD processing functions. Optional. |
| gens | <code>Object</code> | generators object from BBS prepareGenerators of sufficient size to cover the number of statements (messages) in the document. |
| ph | <code>Uint8Array</code> | BBS presentation header |

<a name="verifyDerived"></a>

## verifyDerived(document, pubKey, options, gens, ph)
verify a signed selective disclosure derived document (credential) with ECDSA-SD
procedures. This is done by a verifier on receipt of the credential.

**Kind**: global function

| Param | Type | Description |
| --- | --- | --- |
| document | <code>Object</code> | The signed SD derived credential |
| pubKey | <code>Uint8Array</code> | Byte array for the issuers P256 public key without multikey prefixes |
| options | <code>Object</code> | A variety of options to control signing and processing |
| options.documentLoader | <code>function</code> | A JSON-LD document loader to be   passed on to JSON-LD processing functions. Optional. |
| gens | <code>Object</code> | generators object from BBS prepareGenerators of sufficient size to cover the number of statements (messages) in the document. |
| ph | <code>Uint8Array</code> | BBS presentation header |


