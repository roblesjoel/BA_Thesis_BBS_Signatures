import { API_ID_BBS_SHA, messages_to_scalars as msgsToScalars, proofGen } from '@grottonetworking/bbs-signatures'
import { concatBytes } from '@noble/hashes/utils'
import { klona } from 'klona'
import cbor from 'cbor'
import { base64url } from 'multiformats/bases/base64'
import {
  createHmac, createShuffledIdLabelMapFunction, canonicalizeAndGroup, selectJsonLd,
  stripBlankNodePrefixes
} from './primitives.js'
import jsonld from 'jsonld'

/**
 * derive a selectively disclosed document (presentation) with ECDSA-SD procedures.
 * This is done by a holder, who has the option to selectively disclose non-mandatory
 * statements to a verifier.
 *
 * @param {Object} document - The signed base credential
 * @param {Array} selectivePointers - An array of selective pointers in JSON pointer format
 * @param {Object} options - A variety of options to control signing and processing
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 * @param {Object} gens - generators object from BBS prepareGenerators of
 * sufficient size to cover the number of statements (messages) in the document.
 * @param {Uint8Array} ph - BBS presentation header
 */
export async function derive (document, selectivePointers, options, gens, ph = new Uint8Array()) {
  const doc = klona(document)
  // parseBaseProofValue:
  const proof = doc.proof
  delete doc.proof // IMPORTANT: all work uses document without proof
  const proofValue = proof.proofValue // base64url encoded
  const proofValueBytes = base64url.decode(proofValue)
  // console.log(proofValueBytes.length);
  // check header bytes are: 0xd9, 0x5d, and 0x00
  if (proofValueBytes[0] !== 0xd9 || proofValueBytes[1] !== 0x5d || proofValueBytes[2] !== 0x02) {
    throw new Error('Invalid proofValue header')
  }
  const decodeThing = cbor.decode(proofValueBytes.slice(3))

  if (decodeThing.length !== 5) {
    throw new Error('Bad length of CBOR decoded proofValue data')
  }
  const [bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers] = decodeThing
  // Combine pointers and create reveal document
  const combinedPointers = mandatoryPointers.concat(selectivePointers)
  const revealDocument = selectJsonLd(doc, combinedPointers)

  const hmac = await createHmac(hmacKey)
  const labelMapFactoryFunction = createShuffledIdLabelMapFunction(hmac)

  const groups = {
    mandatory: mandatoryPointers,
    selective: selectivePointers,
    combined: combinedPointers
  }
  const stuff = await canonicalizeAndGroup(doc, labelMapFactoryFunction, groups,
    { documentLoader: options.documentLoader })
  const combinedMatch = stuff.groups.combined.matching
  console.log(combinedMatch);
  const mandatoryMatch = stuff.groups.mandatory.matching
  const mandatoryNonMatch = stuff.groups.mandatory.nonMatching // For reverse engineering
  const selectiveMatch = stuff.groups.selective.matching
  const combinedIndexes = [...combinedMatch.keys()]
  const nonMandatoryIndexes = [...mandatoryNonMatch.keys()]

  // Compute the "adjusted mandatory indexes" relative to their position in combined list
  const adjMandatoryIndexes = []
  mandatoryMatch.forEach((value, index) => {
    adjMandatoryIndexes.push(combinedIndexes.indexOf(index))
  })

  /* Determine which non-mandatory nquad match a selectively disclosed nquad and
    get its index relative to place in the non-mandatory list.
    The non-mandatory nquads are the BBS messages and we need the selective indexes
    relative to this list.
  */
  const adjSelectiveIndexes = []
  selectiveMatch.forEach((value, index) => {
    const adjIndex = nonMandatoryIndexes.indexOf(index)
    if (adjIndex !== -1) {
      adjSelectiveIndexes.push(adjIndex)
    }
  })

  // **Create Verifier Label Map**
  const deskolemizedNQuads = stuff.groups.combined.deskolemizedNQuads
  let canonicalIdMap = new Map()
  // The goal of the below is to get the canonicalIdMap and not the canonical document
  await jsonld.canonize(deskolemizedNQuads.join(''), {
    documentLoader: options.documentLoader,
    inputFormat: 'application/n-quads',
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    safe: true,
    canonicalIdMap
  })
  canonicalIdMap = stripBlankNodePrefixes(canonicalIdMap)
  const verifierLabelMap = new Map()
  const labelMap = stuff.labelMap
  canonicalIdMap.forEach(function (value, key) {
    verifierLabelMap.set(value, labelMap.get(key))
  })

  // Recreate BBS messages
  const te = new TextEncoder()
  const bbsMessages = [...mandatoryNonMatch.values()].map(txt => te.encode(txt)) // must be byte arrays
  const msgScalars = await msgsToScalars(bbsMessages, API_ID_BBS_SHA)

  const bbsProof = await proofGen(publicKey, bbsSignature, bbsHeader, ph, msgScalars,
    adjSelectiveIndexes, gens, API_ID_BBS_SHA)

  // 7. serialize via CBOR: BBSProofValue, compressedLabelMap, mandatoryIndexes, selectiveIndexes, ph
  // Initialize newProof to a shallow copy of proof.
  const newProof = Object.assign({}, proof)
  // Modified for **BBS** unlinkable labeling
  const compressLabelMap = new Map()
  verifierLabelMap.forEach(function (v, k) {
    const key = parseInt(k.split('c14n')[1])
    const value = parseInt(v.split('b')[1])
    compressLabelMap.set(key, value)
  })

  let derivedProofValue = new Uint8Array([0xd9, 0x5d, 0x03])
  const components = [bbsProof, compressLabelMap, adjMandatoryIndexes, adjSelectiveIndexes, ph]
  const cborThing = await cbor.encodeAsync(components)
  derivedProofValue = concatBytes(derivedProofValue, cborThing)
  const derivedProofValueString = base64url.encode(derivedProofValue)
  // console.log(derivedProofValueString)
  // console.log(`Length of derivedProofValue is ${derivedProofValueString.length} characters`)
  newProof.proofValue = derivedProofValueString
  revealDocument.proof = newProof
  return revealDocument
}
