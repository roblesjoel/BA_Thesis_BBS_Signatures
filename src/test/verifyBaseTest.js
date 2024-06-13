/* global describe, it */
import { assert } from 'chai'
/* Test the verifyBase against test vectors in valid and invalid cases.
*/

import { readFile } from 'fs/promises'
import { localLoader } from './documentLoader.js'
import { verifyBase } from '../lib/BBSverifyBase.js'
import { hexToBytes } from '@noble/hashes/utils'
import { API_ID_BBS_SHA, prepareGenerators } from '@grottonetworking/bbs-signatures'

const gens = await prepareGenerators(30, API_ID_BBS_SHA)

// Read input doc, keys, mandatory pointers from files
const signedBase = JSON.parse(await readFile(new URL('./specTestVectors/addSignedSDBase.json',
  import.meta.url)))
const keyMaterial = JSON.parse(await readFile(new URL('./specTestVectors/BBSKeyMaterial.json',
  import.meta.url)))
const pubKey = hexToBytes(keyMaterial.publicKeyHex)

describe('verifyBase', async function () {
  it('valid base document', async function () {
    const result = await verifyBase(signedBase, pubKey, { documentLoader: localLoader }, gens)
    assert.isTrue(result)
  })
  it('invalid base document changed sail number', async function () {
    const oldSailNo = signedBase.credentialSubject.sailNumber
    signedBase.credentialSubject.sailNumber = 'CA101'
    const result = await verifyBase(signedBase, pubKey, { documentLoader: localLoader }, gens)
    assert.isFalse(result)
    signedBase.credentialSubject.sailNumber = oldSailNo
  })
})
