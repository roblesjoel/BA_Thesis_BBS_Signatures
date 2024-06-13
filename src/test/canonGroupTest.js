/* global describe, it */
import { assert } from 'chai'
/* Test the canonicalizeAndGroup function against two of the published test vectors
   from the specification.
*/

import { readFile } from 'fs/promises'
import { localLoader } from './documentLoader.js'
import { canonicalizeAndGroup, createShuffledIdLabelMapFunction, createHmac } from '../lib/primitives.js'
import { hexToBytes } from '@noble/hashes/utils'

// For serialization of JavaScript Map via JSON
// function replacerMap (key, value) { // See https://stackoverflow.com/questions/29085197/how-do-you-json-stringify-an-es6-map
//   if (value instanceof Map) {
//     return {
//       dataType: 'Map',
//       value: Array.from(value.entries()) // or with spread: value: [...value]
//     }
//   } else {
//     return value
//   }
// }

// Recreates the JSONified Map
function reviverMap (key, value) {
  if (typeof value === 'object' && value !== null) {
    if (value.dataType === 'Map') {
      return new Map(value.value)
    }
  }
  return value
}

// Read input doc, keys, mandatory pointers from files
const document = JSON.parse(await readFile(new URL('./specTestVectors/windDoc.json',
  import.meta.url)))
const keyMaterial = JSON.parse(await readFile(new URL('./specTestVectors/BBSKeyMaterial.json',
  import.meta.url)))
const mandatory = JSON.parse(await readFile(new URL('./specTestVectors/windMandatory.json',
  import.meta.url)))
const hmacKey = hexToBytes(keyMaterial.hmacKeyString)
// Read Test Vectors from files
const nquads = JSON.parse(await readFile(new URL('./specTestVectors/addBaseDocHMACCanon.json',
  import.meta.url)))
const transformed = JSON.parse(await readFile(new URL('./specTestVectors/addBaseTransform.json',
  import.meta.url)), reviverMap)

const labelMapFactoryFunction = createShuffledIdLabelMapFunction(createHmac(hmacKey))
const groupDefinitions = { mandatory }
const groupOutput = await canonicalizeAndGroup(document, labelMapFactoryFunction,
  groupDefinitions, { documentLoader: localLoader })
// console.log(JSON.stringify(groupOutput, replacerMap, 2))
// await writeFile('canonGroupOut.json', JSON.stringify(groupOutput, replacerMap, 2))

describe('canonicalizeAndGroup', async function () {
  it('HMACd NQuads', function () {
    assert.deepEqual(groupOutput.nquads, nquads)
  })
  it('mandatory matching nquad map', function () {
    assert.deepEqual(groupOutput.groups.mandatory.matching, transformed.mandatory)
  })
  it('mandatory non-matching nquad map', function () {
    assert.deepEqual(groupOutput.groups.mandatory.nonMatching, transformed.nonMandatory)
  })
})
