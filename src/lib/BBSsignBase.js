import { concatBytes } from '@noble/hashes/utils' // bytesToHex is in here too
import { API_ID_BBS_SHA, messages_to_scalars as msgsToScalars, sign } from '@grottonetworking/bbs-signatures'
import { base58btc } from 'multiformats/bases/base58'
import jsonld from 'jsonld'
import { randomBytes } from './randomBytes.js'
import { sha256 } from '@noble/hashes/sha256'
import { createHmac, createShuffledIdLabelMapFunction, canonicalizeAndGroup } from
  './primitives.js'
import { klona } from 'klona'
import cbor from 'cbor'
import { base64url } from 'multiformats/bases/base64'

// BLS12-381 G2 public key prefix 0xeb01
const PRE_MKEY_BLS12_381 = new Uint8Array([0xeb, 0x01])

/**
 * sign a base document (credential) with `bbs-2023` procedures. This is done by an
 * issuer and permits the recipient, the holder, the freedom to selectively disclose
 * "statements" extracted from the document to a verifier within the constraints
 * of the mandatory disclosure requirements imposed by the issuer.
 *
 * @param {Object} document - The unsigned credential
 * @param {Object} keyPair - The issuers private/public key pair
 * @param {Uint8Array} keyPair.priv - Byte array for the BLS12-381 G1 private key without multikey prefixes
 * @param {Uint8Array} keyPair.pub - Byte array for the BLS12-381 G2 public key without multikey prefixes
 * @param {Array} mandatoryPointers - An array of mandatory pointers in JSON pointer format
 * @param {Object} options - A variety of options to control signing and processing
 * @param {Object} options.proofConfig - proof configuration options without `@context`
 *  field. Optional. This will be generated with current date information and
 *  did:key verification method otherwise.
 * @param {Uint8Array} options.hmacKey - A byte array for the HMAC key. Optional. A
 *   cryptographically secure random value will be generated if not specified.
 * @param {Object} options.proofKeyPair - A proof specific P256 key pair. Must
 *   be unique for each call to signBase. Optional. A unique key pair will be
 *   generated if not specified.
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 * @param {Object} gens - generators object from BBS prepareGenerators of
 * sufficient size to cover the number of statements (messages) in the document.
 */
export async function signBase (document, keyPair, mandatoryPointers, options, gens) {
  // Set up proof configuration and canonize
  let proofConfig = {}
  if (options.proofConfig !== undefined) {
    proofConfig = Object.assign({}, options.proofConfig)
  } else { // Create the proofConfig
    proofConfig.type = 'DataIntegrityProof'
    proofConfig.cryptosuite = 'bbs-2023'
    const nd = new Date()
    proofConfig.created = nd.toISOString()
    const publicKeyMultibase = base58btc.encode(concatBytes(PRE_MKEY_BLS12_381, keyPair.pub))
    proofConfig.verificationMethod = 'https://example.com/publicKey'
    //proofConfig.verificationMethod = "www.example.com/keys"
    proofConfig.proofPurpose = 'assertionMethod'
  }
  proofConfig['@context'] = document['@context']
  const proofCanon = await jsonld.canonize(proofConfig, { documentLoader: options.documentLoader })

  // Check for HMAC key and generate if not present
  let hmacKey
  if (options.hmacKey !== undefined) {
    hmacKey = options.hmacKey
  } else {
    hmacKey = randomBytes(32)
  }
  // **Transformation Step**
  const hmacFunc = createHmac(hmacKey)
  const labelMapFactoryFunction = createShuffledIdLabelMapFunction(hmacFunc)
  const groups = { mandatory: mandatoryPointers }
  const stuff = await canonicalizeAndGroup(document, labelMapFactoryFunction, groups, { documentLoader: options.documentLoader })
  const mandatory = stuff.groups.mandatory.matching
  const nonMandatory = stuff.groups.mandatory.nonMatching
  let transformed = {"mandatory": mandatory, "nonMandatory": nonMandatory};
  // **Hashing Step**
  const proofHash = sha256(proofCanon) // @noble/hash will convert string to bytes via UTF-8
  // console.log(`Proof hash: ${bytesToHex(proofHash)}`)
  const mandatoryHash = sha256([...mandatory.values()].join(''))
  // console.log(`Mandatory hash: ${bytesToHex(mandatoryHash)}`)
  /* Create BBS signature */
  const bbsHeader = concatBytes(proofHash, mandatoryHash)
  const te = new TextEncoder()
  const bbsMessages = [...nonMandatory.values()].map(txt => te.encode(txt)) // must be byte arrays
  const msgScalars = await msgsToScalars(bbsMessages, API_ID_BBS_SHA)
  // const gens = await prepareGenerators(bbsMessages.length, API_ID_BBS_SHA)
  const bbsSignature = await sign(keyPair.priv, keyPair.pub, bbsHeader, msgScalars, gens, API_ID_BBS_SHA)
  // console.log(`BBS signature: ${bytesToHex(bbsSignature)}`)

  // CBOR-encode components and append it to proofValue.
  // bbsSignature, bbsHeader, publicKey, hmacKey, and mandatoryPointers
  let proofValue = new Uint8Array([0xd9, 0x5d, 0x02])
  const components = [bbsSignature, bbsHeader, keyPair.pub, hmacKey, mandatoryPointers]
  const cborThing = await cbor.encodeAsync(components)
  proofValue = concatBytes(proofValue, cborThing)
  const baseProof = base64url.encode(proofValue)
  // console.log(baseProof)
  // console.log(`Length of baseProof is ${baseProof.length} characters`)

  // Construct and Write Signed Document
  const signedDocument = klona(document)
  delete proofConfig['@context']
  signedDocument.proof = proofConfig
  signedDocument.proof.proofValue = baseProof
  return signedDocument
}
