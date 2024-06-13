/* global describe, it */
import { assert } from 'chai'
/*
    Test pointer to paths using cases from RFC6901.
*/
import { jsonPointerToPaths } from '../lib/primitives.js'

const testCases = ['', '/foo', '/foo/0', '/', '/a~1b', '/c%d', '/e^f', '/g|h', '/i\\j',
  '/k\'l', '/ ', '/m~0n']
const output = [[], ['foo'], ['foo', 0], [''], ['a/b'], ['c%d'], ['e^f'], ['g|h'],
  ['i\\j'], ["k'l"], [' '], ['m~n']]

describe('jsonPointerToPaths', function () {
  for (let i = 0; i < testCases.length; i++) {
    it(`test string ${testCases[i]}`, function () {
      assert.deepEqual(output[i], jsonPointerToPaths(testCases[i]))
    })
  }
})
