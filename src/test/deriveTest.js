/* global describe, it, before */
import { assert } from 'chai'
/* Test derive (derived document creation) against test vector. Note that CBOR
  encoding is not unique so we need to CBOR parse the proof values and compare them.
*/

import { readFile } from 'fs/promises'
import { localLoader } from './documentLoader.js'
import { derive } from '../lib/BBSderive.js'
import { base64url } from 'multiformats/bases/base64'
import cbor from 'cbor'
import { API_ID_BBS_SHA, prepareGenerators } from '@grottonetworking/bbs-signatures'

const gens = await prepareGenerators(30, API_ID_BBS_SHA)

// Read signed base doc and selective pointers from files
const selective = JSON.parse(await readFile(new URL('./specTestVectors/windSelective.json',
  import.meta.url)))
const signedBase = JSON.parse(await readFile(new URL('./specTestVectors/addSignedSDBase.json',
  import.meta.url)))
// Get output test vector
const derivedVector = JSON.parse(await readFile(new URL('./specTestVectors/derivedRevealDocument.json',
  import.meta.url)))

const options = { documentLoader: localLoader }
// derive (document, selectivePointers, options, gens, ph = new Uint8Array())
const derivedDoc = await derive(signedBase, selective, options, gens)
// console.log(signedDoc)

function parseDerivedProofValue (proofValue) {
  const decodedProofValue = base64url.decode(proofValue)
  // check header bytes are: 0xd9, 0x5d, and 0x03
  if (decodedProofValue[0] !== 0xd9 || decodedProofValue[1] !== 0x5d || decodedProofValue[2] !== 0x03) {
    throw new Error('Invalid proofValue header')
  }
  const decodeThing = cbor.decode(decodedProofValue.slice(3))
  if (decodeThing.length !== 5) {
    throw new Error('Bad length of CBOR decoded proofValue data')
  }
  return decodeThing
}

// let bbsProofL, labelMapCompressedL, mandatoryIndexesL, adjSelectedIndexesL, presentationHeaderL
// let bbsProofV, labelMapCompressedV, mandatoryIndexesV, adjSelectedIndexesV, presentationHeaderV

const decodeThingLocal = parseDerivedProofValue(derivedDoc.proof.proofValue)
const decodeThingVector = parseDerivedProofValue(derivedVector.proof.proofValue)

const [bbsProofL, labelMapCompressedL, mandatoryIndexesL, adjSelectedIndexesL, presentationHeaderL] = decodeThingLocal;
const [bbsProofV, labelMapCompressedV, mandatoryIndexesV, adjSelectedIndexesV, presentationHeaderV] = decodeThingVector;
// console.log('Created Derived Proof parsed:')
// console.log(parseDerivedProofValue(derivedDoc.proof.proofValue))
// console.log('Test vector Proof parsed:')
// console.log(parseDerivedProofValue(derivedVector.proof.proofValue))
describe('derive (from signed base)', async function () {
  it('Check mandatory indexes local compute vs test vector', async function () {
    assert.deepEqual(mandatoryIndexesL, mandatoryIndexesV)
  })
  it('Check label map compressed local compute vs test vector', async function () {
    assert.deepEqual(labelMapCompressedL, labelMapCompressedV)
  })
  it('Check selected indexes local compute vs test vector', async function () {
    assert.deepEqual(adjSelectedIndexesL, adjSelectedIndexesV)
  })
})
