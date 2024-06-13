import { readFile } from 'fs/promises'
import { localLoader } from './documentLoader.js'
import { hexToBytes } from '@noble/hashes/utils'
import { verifyDerived } from '../lib/BBSverifyDerived.js'
import { API_ID_BBS_SHA, prepareGenerators } from '@grottonetworking/bbs-signatures'

const gens = await prepareGenerators(30, API_ID_BBS_SHA)

// Read input document from a file
const document = JSON.parse(
  await readFile(new URL('./output/derivedDocument.json', import.meta.url)))
// Obtain key material and process into byte array format

const keyMaterial = JSON.parse(
  await readFile(new URL('./input/BBSKeyMaterial.json', import.meta.url)))
// Sample long term issuer signing key
const pubKey = hexToBytes(keyMaterial.publicKeyHex)

const options = { documentLoader: localLoader }
// verifyDerived (doc, pubKey, options, gens, ph)
const verified = await verifyDerived(document, pubKey, options, gens, new Uint8Array())
console.log(`Signed derived document verified: ${verified}`)
