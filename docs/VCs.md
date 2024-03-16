## This notes will be part of the documentation as paragraphs

Presentations is not part?
The Id in the VC is used to match the subject, that can be done with ZKP or same stuff

Vocabulary:
https://w3c.github.io/vc-specs-dir/

can issuer be something else?
Like public Key?

DIDs?

ID
Signer Sends VC to holder (also the signature)

Maybe like this:

{
    sig:
    msgs: {}
}

holder then sends data to verifier
but it was a new VC

4.11.2 doest say much :(

5.8 Verifier needs to say what he wants
"t is also possible for the verifier to provide a schema to the holder as part of a request for the holder's data"

https://w3c.github.io/vc-di-bbs/#selective-disclosure-and-data-leakage

How to proof that I want to get my ID?
Like when switching from physical to digital -> QR Code

binding vcs to keys?

there is a spec anonymity set done with a bit string
bit string status list
zkp solution

Privacy considerations:

Looks like any data in the vc can be removed, so how would a validUntil in the VC work????
Data can not be changes but it doesnt describe how the proof is generated?
Sinature (proof) is to be used in the whole document

IDs for the subject. Solution: Dont use ids for the subject. If they are needed, they would need to be masked. It why subject ids would be needed are out of scope for this thesis.

IDs for the credential. They are needed to revoke long living credentials. If the credentials are short lived (like monthly subscription) validUntil should be used. Each month a new credential would be 
issued. (can also be solved with pseudonyms instead of creating a new presentation each time).
Long Lived credential have a bit of a problem. The Id could be put into a revocation list with a big enough anonymity pool (eg. 100k). That list could be passed from the verifier to the holder. The holder then generates a ZKP showing that his id is not in that pool. 

Asking for information that is not needed.
Solution: The Holder does not accept the request and thus does not used the service.
Or hold the services accountable and restrict what they can request.

Data theft: There is no solution but to revoke the VC.


OID4VP:
Data is sent over HTTPS.
ver requests data with the presentation_definition or the (presentation_definition_uri). Other extensions are optional and out of scope for this project.

Response contains a VP (vp_token) as json string (encoded as base 64) or a json object. If only 1 VP is returned do not use array syntax (even with Link secrets only 1 VP is needed)

(presentation_submission) contains mapping between the requested attributes and the attributes in the VP

{
    "@context": [
        "https://www.w3.org/2018/credentials/v1"
    ],
    "type": [
        "VerifiablePresentation"
    ],
    "verifiableCredential": [
        {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "https://example.com/credentials/1872",
            "type": [
                "VerifiableCredential",
                "IDCardCredential"
            ],
            "issuer": {
                "id": "did:example:issuer"
            },
            "issuanceDate": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "given_name": "Fredrik",
                "family_name": "Strömberg",
                "birthdate": "1949-01-22"
            },
            "proof": {
                "type": "Ed25519Signature2018",
                "created": "2021-03-19T15:30:15Z",
                "jws": "eyJhb...JQdBw",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:example:issuer#keys-1"
            }
        }
    ],
    "id": "ebc6f1c2",
    "holder": "did:example:holder",
    "proof": {
        "type": "Ed25519Signature2018",
        "created": "2021-03-19T15:30:15Z",
        "challenge": "n-0S6_WzA2Mj",
        "domain": "https://client.example.org/cb",
        "jws": "eyJhbG...IAoDA",
        "proofPurpose": "authentication",
        "verificationMethod": "did:example:holder#key-1"
    }
},
{
    "id": "Presentation example 1",
    "definition_id": "Example with selective disclosure",
    "descriptor_map": [
        {
            "id": "ID card with constraints",
            "format": "ldp_vp",
            "path": "$",
            "path_nested": {
                "format": "ldp_vc",
                "path": "$.verifiableCredential[0]"
            }
        }
    ]
}

when different devices then use the response mode "direct_post"

Replay attack: use nonces? and use client id to bind client?



Device Trackign is out of scope for this project