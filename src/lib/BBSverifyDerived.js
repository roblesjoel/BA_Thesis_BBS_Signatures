import { API_ID_BBS_SHA, messages_to_scalars as msgsToScalars, proofVerify } from '@grottonetworking/bbs-signatures'
import { concatBytes } from '@noble/hashes/utils' // bytesToHex lives here too
import jsonld from 'jsonld'
import { sha256 } from '@noble/hashes/sha256'
import { createLabelMapFunction, labelReplacementCanonicalizeJsonLd } from './primitives.js'
import { klona } from 'klona'
import cbor from 'cbor'
import { base64url } from 'multiformats/bases/base64'

/**
 * verify a signed selective disclosure derived document (credential) with ECDSA-SD
 * procedures. This is done by a verifier on receipt of the credential.
 *
 * @param {Object} document - The signed SD derived credential
 * @param {Uint8Array} pubKey - Byte array for the issuers P256 public key without multikey prefixes
 * @param {Object} options - A variety of options to control signing and processing
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 * @param {Object} gens - generators object from BBS prepareGenerators of
 * sufficient size to cover the number of statements (messages) in the document.
 * @param {Uint8Array} ph - BBS presentation header
 */
export async function verifyDerived (doc, pubKey, options, gens, ph = new Uint8Array()) {
  const document = klona(doc)
  const proof = document.proof
  const proofValue = proof.proofValue
  const proofConfig = klona(document.proof)
  delete proofConfig.proofValue
  proofConfig['@context'] = document['@context']
  delete document.proof // **IMPORTANT** from now on we work with the document without proof!!!!!!!
  const proofCanon = await jsonld.canonize(proofConfig, { documentLoader: options.documentLoader })
  const proofHash = sha256(proofCanon) // @noble/hash will convert string to bytes via UTF-8
  // console.log(`Proof hash: ${bytesToHex(proofHash)}`)
  // Parse Derived ProofValue
  if (!proofValue.startsWith('u')) {
    throw new Error('proofValue not a valid multibase-64-url encoding')
  }
  const decodedProofValue = base64url.decode(proofValue)
  if (decodedProofValue[0] !== 0xd9 || decodedProofValue[1] !== 0x5d || decodedProofValue[2] !== 0x03) {
    throw new Error('Invalid proofValue header')
  }
  const decodeThing = cbor.decode(decodedProofValue.slice(3))
  if (decodeThing.length !== 5) {
    throw new Error('Bad length of CBOR decoded proofValue data')
  }
  let [bbsProof, labelMapCompressed, mandatoryIndexes, adjSelectedIndexes, presentationHeader] = decodeThing
  // Here
  // cbor library workaround for issue https://github.com/hildjj/node-cbor/issues/186
  if (!(labelMapCompressed instanceof Map) && (Object.keys(labelMapCompressed).length === 0) ) {
    labelMapCompressed = new Map();
  }
  if (!(labelMapCompressed instanceof Map)) {
    throw new Error('Bad label map in proofValue')
  }
  // Modified for **BBS** labeling, just an integer
  labelMapCompressed.forEach(function (value, key) {
    if (!Number.isInteger(key) || !Number.isInteger(value)) {
      throw new Error('Bad key or value in compress label map in proofValue')
    }
  })
  if (!Array.isArray(mandatoryIndexes)) {
    throw new Error('mandatory indexes is not an array in proofValue')
  }
  mandatoryIndexes.forEach(value => {
    if (!Number.isInteger(value)) {
      throw new Error('Value in mandatory indexes  is not an integer')
    }
  })
  const labelMap = new Map()
  labelMapCompressed.forEach(function (v, k) {
    const key = 'c14n' + k
    const value = 'b' + v
    labelMap.set(key, value)
  })

  // Initialize labelMapFactoryFunction to the result of calling the "createLabelMapFunction" algorithm.
  const labelMapFactoryFunction = createLabelMapFunction(labelMap)
  /* Initialize nquads to the result of calling the "labelReplacementCanonicalize" algorithm, passing
    document, labelMapFactoryFunction, and any custom JSON-LD API options. Note: This step transforms
    the document into an array of canonical N-Quads with pseudorandom blank node identifiers based on
    labelMap.
  */
  const nquads = await labelReplacementCanonicalizeJsonLd(document,
    labelMapFactoryFunction, options)
  const mandatory = []
  const nonMandatory = []
  nquads.forEach(function (value, index) {
    if (mandatoryIndexes.includes(index)) {
      mandatory.push(value)
    } else {
      nonMandatory.push(value)
    }
  })
  const mandatoryHash = sha256(mandatory.join(''))
  /* Verify BBS Proof */
  const bbsHeader = concatBytes(proofHash, mandatoryHash)
  const te = new TextEncoder()
  const bbsMessages = [...nonMandatory.values()].map(txt => te.encode(txt)) // must be byte arrays
  const msgScalars = await msgsToScalars(bbsMessages, API_ID_BBS_SHA)
  const verified = await proofVerify(pubKey, bbsProof, bbsHeader, ph, msgScalars,
    adjSelectedIndexes, gens, API_ID_BBS_SHA)
  return verified
}
