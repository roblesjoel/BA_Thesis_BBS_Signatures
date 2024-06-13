import { API_ID_BBS_SHA, messages_to_scalars as msgsToScalars, verify } from '@grottonetworking/bbs-signatures'
import { bytesToHex, concatBytes } from '@noble/hashes/utils' // bytesToHex lives here too
import jsonld from 'jsonld'
import { sha256 } from '@noble/hashes/sha256'
import { createHmac, createShuffledIdLabelMapFunction, canonicalizeAndGroup } from
  './primitives.js'
import { klona } from 'klona'
import cbor from 'cbor'
import { base64url } from 'multiformats/bases/base64'

/**
 * verify a signed selective disclosure base document (credential) with `bbs-2023`
 * procedures. This is can be done by an holder on receipt of the credential.
 *
 * @param {Object} document - The signed `bbs-2023` base credential
 * @param {Uint8Array} pubKey - Byte array for the issuers BLS12-381 G2 public key without multikey prefixes
 * @param {Object} options - A variety of options to control signing and processing
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 * @param {Object} gens - generators object from BBS prepareGenerators of
 * sufficient size to cover the number of statements (messages) in the document.
 */
export async function verifyBase (doc, pubKey, options, gens) {
  // parseBaseProofValue:
  const document = klona(doc)
  const proof = klona(document.proof)
  delete document.proof // IMPORTANT: all work uses document without proof
  const proofValue = proof.proofValue // base64url encoded
  const proofValueBytes = base64url.decode(proofValue)
  // console.log(proofValueBytes.length);
  // check header bytes are: 0xd9, 0x5d, and 0x02
  if (proofValueBytes[0] !== 0xd9 || proofValueBytes[1] !== 0x5d || proofValueBytes[2] !== 0x02) {
    throw new Error('Invalid proofValue header')
  }
  const decodeThing = cbor.decode(proofValueBytes.slice(3))
  if (decodeThing.length !== 5) {
    throw new Error('Bad length of CBOR decoded proofValue data')
  }
  const [bbsSignature, bbsHeaderBase, publicKeyBase, hmacKey, mandatoryPointers] = decodeThing
  // setup HMAC stuff
  const hmac = createHmac(hmacKey)
  const labelMapFactoryFunction = createShuffledIdLabelMapFunction(hmac)

  const groups = {
    mandatory: mandatoryPointers
  }
  const stuff = await canonicalizeAndGroup(document, labelMapFactoryFunction, groups,
    { documentLoader: options.documentLoader })
  const mandatoryMatch = stuff.groups.mandatory.matching
  const mandatoryNonMatch = stuff.groups.mandatory.nonMatching
  // canonize proof configuration and hash it
  const proofConfig = proof
  proofConfig['@context'] = document['@context']
  delete proofConfig.proofValue // Don't forget to remove this
  const proofCanon = await jsonld.canonize(proofConfig, { documentLoader: options.documentLoader })
  const proofHash = sha256(proofCanon)
  // console.log(`proofHash: ${bytesToHex(proofHash)}`)
  const mandatoryCanon = [...mandatoryMatch.values()].join('')
  const mandatoryHash = sha256(mandatoryCanon)

  // **Verify BBS signature**
  const bbsHeader = concatBytes(proofHash, mandatoryHash)
  if (bytesToHex(bbsHeader) !== bytesToHex(bbsHeaderBase)) {
    // console.log('computed bbsHeader and bbsHeader from base DO NOT match!')
    return false
  }
  const te = new TextEncoder()
  const bbsMessages = [...mandatoryNonMatch.values()].map(txt => te.encode(txt)) // must be byte arrays
  const msgScalars = await msgsToScalars(bbsMessages, API_ID_BBS_SHA)
  const verified = await verify(publicKeyBase, bbsSignature, bbsHeader, msgScalars, gens, API_ID_BBS_SHA)
  return verified
}
