import { mkdir, readFile, writeFile } from 'fs/promises'
import { localLoader } from './documentLoader.js'
import { base58btc } from 'multiformats/bases/base58'
import { signBase } from '../lib/BBSsignBase.js'
import { concatBytes, hexToBytes } from '@noble/hashes/utils'
import { API_ID_BBS_SHA, prepareGenerators } from '@grottonetworking/bbs-signatures'

const gens = await prepareGenerators(30, API_ID_BBS_SHA)
// Read input document from a file
const document = JSON.parse(
  await readFile(new URL('./input/example.json', import.meta.url)))
const mandatoryPointers = JSON.parse(
  await readFile(new URL('./input/mandatory.json', import.meta.url)))
// Obtain key material and process into byte array format
// Obtain key material and process into byte array format
const keyMaterial = JSON.parse(
  await readFile(new URL('./input/BBSKeyMaterial.json', import.meta.url)))
// HMAC/PRF key material -- Shared between issuer and holder
const hmacKeyString = keyMaterial.hmacKeyString
const hmacKey = hexToBytes(hmacKeyString)
// Sample long term issuer signing key
const keyPair = {}
keyPair.priv = hexToBytes(keyMaterial.privateKeyHex)
keyPair.pub = hexToBytes(keyMaterial.publicKeyHex)

const options = {
  hmacKey,
  documentLoader: localLoader
}

const proofConfig = {}
proofConfig.type = 'DataIntegrityProof'
proofConfig.cryptosuite = 'bbs-2023'
proofConfig.created = '2023-08-15T23:36:38Z'
// BLS12-381 G2 public key prefix 0xeb01
const publicKeyMultibase = base58btc.encode(concatBytes(new Uint8Array([0xeb, 0x01]), keyPair.pub))
proofConfig.verificationMethod = 'https://example.com/publicKey' //'did:key:' + publicKeyMultibase + '#' + publicKeyMultibase
proofConfig.proofPurpose = 'assertionMethod'
proofConfig['@context'] = document['@context']
console.log(document)
options.proofConfig = proofConfig
const signedDoc = await signBase(document, keyPair, mandatoryPointers, options, gens)

console.log(signedDoc)
// Create output directory and write file if you want
const baseDir = './output/'
await mkdir(baseDir, { recursive: true })
writeFile(baseDir + 'signedBase.json', JSON.stringify(signedDoc, null, 2))
