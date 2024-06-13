/* global describe, it */
import { assert } from 'chai'
import { readFile } from 'fs/promises'
import { localLoader } from './documentLoader.js'
import { signBase } from '../lib/BBSsignBase.js'
import { hexToBytes } from '@noble/hashes/utils'
import { base64url } from 'multiformats/bases/base64'
import cbor from 'cbor'
import { API_ID_BBS_SHA, prepareGenerators } from '@grottonetworking/bbs-signatures'

const gens = await prepareGenerators(30, API_ID_BBS_SHA)

// Read input doc and mandatory pointers from files
const document = JSON.parse(await readFile(new URL('./specTestVectors/windDoc.json',
  import.meta.url)))
const mandatory = JSON.parse(await readFile(new URL('./specTestVectors/windMandatory.json',
  import.meta.url)))
// Get (output) Test Vector
const signedBase = JSON.parse(await readFile(new URL('./specTestVectors/addSignedSDBase.json',
  import.meta.url)))
// Get and process key material
const keyMaterial = JSON.parse(await readFile(new URL('./specTestVectors/BBSKeyMaterial.json',
  import.meta.url)))
// console.log(keyMaterial)
const keyPair = {}
keyPair.priv = hexToBytes(keyMaterial.privateKeyHex)
keyPair.pub = hexToBytes(keyMaterial.publicKeyHex)
// HMAC/PRF key material -- Shared between issuer and holder
const hmacKeyString = keyMaterial.hmacKeyString
const hmacKey = hexToBytes(hmacKeyString)

const options = {
  hmacKey,
  documentLoader: localLoader
}

// This has to match what was used to generate the test vector
const proofConfig = {}
proofConfig.cryptosuite = 'bbs-2023'
proofConfig.type = 'DataIntegrityProof'
proofConfig.created = signedBase.proof.created
proofConfig.verificationMethod = signedBase.proof.verificationMethod
proofConfig.proofPurpose = signedBase.proof.proofPurpose
proofConfig['@context'] = signedBase['@context']
options.proofConfig = proofConfig
const signedDoc = await signBase(document, keyPair, mandatory, options, gens)
// console.log(signedDoc)

function parseProofValue (proofValue) {
  const proofValueBytes = base64url.decode(proofValue)
  if (proofValueBytes[0] !== 0xd9 || proofValueBytes[1] !== 0x5d || proofValueBytes[2] !== 0x02) {
    throw new Error('Invalid proofValue header')
  }
  const decodeThing = cbor.decode(proofValueBytes.slice(3))
  if (decodeThing.length !== 5) {
    throw new Error('Bad length of CBOR decoded proofValue data')
  }
  return decodeThing
}

const decodeThingLocal = parseProofValue(signedDoc.proof.proofValue)
const decodeThingVector = parseProofValue(signedBase.proof.proofValue)
// [bbsSignature, bbsHeaderBase, publicKeyBase, hmacKey, mandatoryPointers]
const [bbsSigL, bbsHeadL, pubKeyL, hmacKeyL, mandPointL] = decodeThingLocal
const [bbsSigV, bbsHeadV, pubkeyV, hmacKeyV, mandPointv] = decodeThingVector

describe('signBase', function () {
  it('BBS sig local vs test vector', function () {
    assert.deepEqual(bbsSigL, bbsSigV)
  })
  it('BBS header local vs test vector', function () {
    assert.deepEqual(bbsHeadL, bbsHeadV)
  })
  it('BBS pubKey local vs test vector', function () {
    assert.deepEqual(pubKeyL, pubkeyV)
  })
  it('BBS hmac key local vs test vector', function () {
    assert.deepEqual(hmacKeyL, hmacKeyV)
  })
  it('BBS mandatory pointers local vs test vector', function () {
    assert.deepEqual(mandPointL, mandPointv)
  })
})
