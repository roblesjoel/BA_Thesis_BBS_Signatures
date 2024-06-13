import { mkdir, readFile, writeFile } from 'fs/promises'
import { localLoader } from './documentLoader.js'
import { derive } from '../lib/BBSderive.js'
import { API_ID_BBS_SHA, prepareGenerators } from '@grottonetworking/bbs-signatures'

const gens = await prepareGenerators(30, API_ID_BBS_SHA)
// Read input document from a file
const document = JSON.parse(
  await readFile(new URL('./output/signedBase.json', import.meta.url)))
const selectivePointers = JSON.parse(
  await readFile(new URL('./input/selective.json', import.meta.url))
)

const options = { documentLoader: localLoader }

const derived = await derive(document, selectivePointers, options, gens)
console.log(derived)
// Create output directory and write file if you want
const baseDir = './output/'
await mkdir(baseDir, { recursive: true })
writeFile(baseDir + 'derivedDocument.json', JSON.stringify(derived, null, 2))
