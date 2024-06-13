/* global describe, it */
import { assert } from 'chai'
/* Test for JSON pointer based selection using spec test vector */

import { readFile } from 'fs/promises'
import { selectJsonLd } from '../lib/primitives.js'

// Read input document from a file
const document = JSON.parse(
  await readFile(new URL('./specTestVectors/windDoc.json', import.meta.url)))
const mandatoryPointers = JSON.parse(
  await readFile(new URL('./specTestVectors/windMandatory.json', import.meta.url)))
const selectivePointers = JSON.parse(
  await readFile(new URL('./specTestVectors/windSelective.json', import.meta.url)))
const revealDoc = JSON.parse(
  await readFile(new URL('./specTestVectors/derivedRevealDocument.json', import.meta.url)))
delete revealDoc.proof // Don't include proof!
const selDoc = selectJsonLd(document, mandatoryPointers.concat(selectivePointers))

describe('Pointer Selection Test', function () {
  it('selectJsonLd', function () {
    assert.deepEqual(selDoc, revealDoc)
  })
})
