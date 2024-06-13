/* global describe, it */
import { assert } from 'chai'
/* Test the verifyDerived against test vectors in valid and invalid cases.
*/

import { readFile } from 'fs/promises'
import { localLoader } from './documentLoader.js'
import { verifyDerived } from '../lib/BBSverifyDerived.js'
import { API_ID_BBS_SHA, prepareGenerators } from '@grottonetworking/bbs-signatures'
import { hexToBytes } from '@noble/hashes/utils'

const gens = await prepareGenerators(30, API_ID_BBS_SHA)

// Read input doc, keys, mandatory pointers from files
const signedDerived = JSON.parse(await readFile(new URL('./specTestVectors/derivedRevealDocument.json',
  import.meta.url)))
const ph = hexToBytes("113377aa") // From the spec.
// const signedDerived = JSON.parse(await readFile(new URL('../examples/output/derivedDocument.json',
//   import.meta.url)))
// const ph = new Uint8Array()
const keyMaterial = JSON.parse(await readFile(new URL('./specTestVectors/BBSKeyMaterial.json',
  import.meta.url)))
const pubKey = hexToBytes(keyMaterial.publicKeyHex)
const options = { documentLoader: localLoader }
describe('verifyDerived', async function () {
  it('valid derived document', async function () {
    // verifyDerived (doc, pubKey, options, gens, ph)
    const result = await verifyDerived(signedDerived, pubKey, options, gens, ph)
    // const result = await verifyDerived(signedDerived, pubKey, , gens)
    assert.isTrue(result)
  })
  it('invalid derived document changed sail number', async function () {
    const oldSailNo = signedDerived.credentialSubject.sailNumber
    signedDerived.credentialSubject.sailNumber = 'CA101'
    const result = await verifyDerived(signedDerived, pubKey, options, gens)
    assert.isFalse(result)
    signedDerived.credentialSubject.sailNumber = oldSailNo
  })
})
