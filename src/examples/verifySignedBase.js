import { API_ID_BBS_SHA, prepareGenerators } from '@grottonetworking/bbs-signatures'
import { readFile } from 'fs/promises'
import { localLoader } from './documentLoader.js'
import { verifyBase } from '../lib/BBSverifyBase.js'
import { hexToBytes } from '@noble/hashes/utils'

// Read input document from a file
const document = JSON.parse(
  await readFile(new URL('./output/signedBase.json', import.meta.url)))
// Obtain key material and process into byte array format
const keyMaterial = JSON.parse(
  await readFile(new URL('./input/BBSKeyMaterial.json', import.meta.url)))
// Sample long term issuer signing key
const pubKey = hexToBytes(keyMaterial.publicKeyHex)

const options = { documentLoader: localLoader }
const gens = await prepareGenerators(30, API_ID_BBS_SHA)
const verified = await verifyBase(document, pubKey, options, gens)
console.log(`Signed base document verified: ${verified}`)
