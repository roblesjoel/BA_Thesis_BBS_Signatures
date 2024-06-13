/**
 * Primitives to enable selective disclosure processing of JSON-LD
 * based verifiable credentials. Algorithms from the draft W3C specification. See
 * https://w3c.github.io/vc-di-ecdsa/ for more descriptions and context.
 */

import { klona } from 'klona'
import { v4 as uuidv4 } from 'uuid'
import jsonld from 'jsonld'
import { base64url } from 'multiformats/bases/base64'
import { sha256 } from '@noble/hashes/sha256'
import { hmac } from '@noble/hashes/hmac'
import { randomBytes } from './randomBytes.js'
// Debugging
// import { writeFile } from 'fs/promises'

/**
 * Replaces all blank node identifiers in an expanded JSON-LD document with custom-scheme
 * URNs. Nodes without and id or blank node identifier will be assigned one.
 * @param {Array} expanded - an expanded JSON-LD array/object
 * @param {Object} options - options to control the blank node labels assigned
 * @param {Object} options.bnPrefix - a custom blank node prefix
 * @param {Object} options.randString - a UUID string or other comparably random string
 * @param {Object} options.count - blank node id counter
 */
export function skolemizeExpandedJsonLd (expanded, options = {}) {
  // Set up options
  if (options.bnPrefix === undefined) {
    options.bnPrefix = 'urn:bnid:'
  }
  if (options.randString === undefined) {
    options.randString = uuidv4()
  }
  if (options.count === undefined) {
    options.count = 0
  }
  const skolemizedExpandedDocument = []
  expanded.forEach(element => {
    // If either element is not an object or it contains the key @value, append a copy of element
    // to skolemizedExpandedDocument and continue to the next element.
    if (typeof element !== 'object' || element['@value'] !== undefined) {
      skolemizedExpandedDocument.push(klona(element))
    } else {
    // Otherwise, initialize skolemizedNode to an object, and for each property and
    // value in element:
    //   If value is an array, set the value of property in skolemizedNode to the
    //   result of calling this algorithm recursively passing value for expanded and
    //   keeping the other parameters the same.
    //   Otherwise, set the value of property in skolemizedNode to the first element
    //   in the array result of calling this algorithm recursively passing an array with
    //   value as its only element for expanded and keeping the other parameters the same.
      const skolemizedNode = {}
      for (const prop in element) {
        const value = element[prop]
        if (Array.isArray(value)) {
          skolemizedNode[prop] = skolemizeExpandedJsonLd(value, options)
        } else {
          skolemizedNode[prop] = skolemizeExpandedJsonLd([value], options)[0]
        }
      }
      // If skolemizedNode has no @id property, set the value of the @id property in skolemizedNode
      // to the concatenation of bnPrefix, "_", random, "_" and the value of count, incrementing
      // the value of count afterwards.
      if (skolemizedNode['@id'] === undefined) {
        skolemizedNode['@id'] = options.bnPrefix + '_' + options.randString + '_' + options.count
        options.count++
      } else if (skolemizedNode['@id'].startsWith('_:')) {
        // Otherwise, if the value of the @id property in skolemizedNode starts with "_:",
        // preserve the existing blank node identifier when skolemizing by setting the value
        // of the @id property in skolemizedNode to the concatenation of bnPrefix,
        // and the existing value of the @id property.
        skolemizedNode['@id'] = options.bnPrefix + '_' + skolemizedNode['@id']
      }
      // Append skolemizedNode to skolemizedExpandedDocument.
      skolemizedExpandedDocument.push(skolemizedNode)
    }
  })
  return skolemizedExpandedDocument
}

/**
 * Helper function for selectJsonLd
 * @param {Object} source - a JSON-LD object
 */
function createInitialSelection (source) {
  const selection = {}
  if (source.id && !source.id.startsWith('_:')) {
    selection.id = source.id
  }
  if (source.type !== undefined) {
    selection.type = source.type
  }
  return selection
}

/**
 * Helper function for selectionJsonLd.  Converts a JSON Pointer into an array
 * of paths in a JSON tree.
 * @param {String} pointer - a JSON pointer string per RFC6901
 * @returns {Array} paths
 */
export function jsonPointerToPaths (pointer) { // Exported for testing
  const validEscapes = ['~0', '~1']
  const paths = []
  const splitPath = pointer.split('/').slice(1)
  splitPath.forEach(path => {
    if (!path.includes('~')) {
      const num = parseInt(path) // check for integer
      if (isNaN(num)) {
        paths.push(path)
      } else {
        paths.push(num)
      }
    } else {
      // valid escape check
      const escapes = path.match(/~./g) // should produce array with '~0' and '~1' only otherwise error
      escapes.forEach(seq => {
        if (!validEscapes.includes(seq)) {
          throw new Error(`Invalid JSON Pointer escape sequence: ${seq}`)
        }
      })
      let unescaped = path
      if (unescaped.includes('~0')) { // '~0' unescapes to '~'
        unescaped = unescaped.replace(/~0/g, '~')
      }
      if (unescaped.includes('~1')) { // '~1' unescapes to '/'
        unescaped = unescaped.replace(/~1/g, '/')
      }
      paths.push(unescaped)
    }
  })
  return paths
}

/**
 * Selects a portion of a compact JSON-LD document using paths parsed from a parsed JSON
 * Pointer. This is a helper function used within the algorithm selectJsonLd.
 * @param {Array} paths - array of paths parsed from a JSON pointer
 * @param {Object} document - a compact JSON-LD document
 * @param {Object} selectionDocument - a selection document to be populated
 * @param {Array} arrays - an array of arrays for tracking selected arrays
 */
function selectPaths (paths, document, selectionDocument, arrays) {
  // 1. Initialize parentValue to document.
  let parentValue = document
  // 2. Initialize value to parentValue.
  let value = parentValue
  // 3. Initialize selectedParent to selectionDocument.
  let selectedParent = selectionDocument
  // 4. Initialize selectedValue to selectedParent.
  let selectedValue = selectedParent
  // 5. For each path in paths:
  for (const path of paths) {
    // 1. Set selectedParent to selectedValue.
    selectedParent = selectedValue
    // 2. Set parentValue to value.
    parentValue = value
    // 3. Set value to parentValue[path]. If value is now undefined, throw an error indicating
    //    that the JSON pointer does not match the given document.
    value = parentValue[path]
    if (value === undefined) {
      throw new Error('JSON pointer does not match the given document')
    }
    // 4. Set selectedValue to selectedParent[path].
    selectedValue = selectedParent[path]
    // 5. If selectedValue is now undefined:
    if (selectedValue === undefined) {
      // 1. If value is an array, set selectedValue to an empty array and append
      //    selectedValue to arrays.
      if (Array.isArray(value)) {
        selectedValue = []
        arrays.push(selectedValue)
      } else {
      // 2. Otherwise, set selectedValue to an initial selection passing value as
      // source to the algorithm in createInitialSelection.
        selectedValue = createInitialSelection(value)
      }
      // 3. Set selectedParent[path] to selectedValue.
      selectedParent[path] = selectedValue
    }
  }
  // 6. Note: With path traversal complete at the target value, the selected value will now be computed.
  // 7. If value is a literal, set selectedValue to value.
  if (typeof value !== 'object') { // literal
    selectedValue = value
  } else {
    // 8. If value is an array, Set selectedValue to a copy of value.
    if (Array.isArray(value)) {
      selectedValue = klona(value)
    } else {
    // 9. In all other cases, set selectedValue to an object that merges a shallow copy
    //  of selectedValue with a deep copy of value, e.g., {...selectedValue, …deepCopy(value)}.
      selectedValue = { ...selectedValue, ...klona(value) }
    }
  }
  // 10. Get the last path, lastPath, from paths.
  const lastPath = paths.at(-1)
  // 11. Set selectedParent[lastPath] to selectedValue.
  selectedParent[lastPath] = selectedValue
}

/**
 * The following algorithm selects a portion of a compact JSON-LD document using an array
 * of JSON Pointers. The required inputs are an array of JSON Pointers (pointers) and a
 * compact JSON-LD document (document). The document is assumed to use a JSON-LD context
 * that aliases '@id' and '@type' to id and type, respectively, and to use only one '@context'
 * property at the top level of the document.
 * @param {Object} document
 * @param {Array} pointers
 * @returns A new JSON-LD document that represents a selection (selectionDocument) of the
 * original JSON-LD document is produced as output.
 */
export function selectJsonLd (document, pointers) {
  if (pointers.length === 0) { // Nothing selected
    return null
  }
  const arrays = []
  const selectionDocument = createInitialSelection(document)
  selectionDocument['@context'] = klona(document['@context'])
  pointers.forEach(pointer => {
    const paths = jsonPointerToPaths(pointer)
    // Use the algorithm selectPaths, passing document, paths, selectionDocument, and arrays.
    selectPaths(paths, document, selectionDocument, arrays)
  })
  // For each array in arrays: Make array dense by removing any undefined elements
  // between elements that are defined.
  for (const array of arrays) {
    let i = 0
    while (i < array.length) {
      if (array[i] === undefined) {
        array.splice(i, 1) // Removes 1 element at position i
        continue // Don't increment i yet, array length has changed
      }
      i++
    }
  }
  return selectionDocument
}

export function createHmac (key) {
  if (key === undefined) {
    key = randomBytes(32)
  }
  return function hmacFunc (input) {
    return hmac(sha256, key, input)
  }
}

/**
 * The following algorithm creates a label map factory function that uses an HMAC to replace
 * canonical blank node identifiers with their encoded HMAC digests. The required input is an
 * HMAC (previously initialized with a secret key), HMAC. A function, labelMapFactoryFunction,
 * is produced as output.
 * @param {Function} hmacFunc - an initialized (with key) function to compute HMACs
 * @returns a labelMapFactoryFunction
 */
export function createHmacIdLabelMapFunction (hmacFunc) {
  // Create a function, labelMapFactoryFunction, with one required input (a canonical node
  // identifier map, canonicalIdMap), that will return a blank node identifier map, bnodeIdMap, as output
  return function labelMapFactoryFunction (canonicalIdMap) {
    //  Generate a new empty bnode identifier map, bnodeIdMap.
    const bnodeIdMap = new Map()
    // For each map entry, entry, in canonicalIdMap:
    canonicalIdMap.forEach((value, key) => {
      // HMAC the canonical identifier from the value in entry to get an HMAC digest, digest.
      const hmacBytes = hmacFunc(value)
      // Generate a new string value, b64urlDigest, and initialize it to "u" followed by appending a base64url-no-pad encoded version of the digest value.
      const newId = base64url.encode(hmacBytes)
      // Add a new entry, newEntry, to bnodeIdMap using the key from entry and b64urlDigest as the value.
      bnodeIdMap.set(key, newId)
    })
    return bnodeIdMap
  }
}

/**
 * The following algorithm creates a label map factory function that uses an HMAC to shuffle
 * blank node ids. The required input is an
 * HMAC (previously initialized with a secret key), HMAC. A function, labelMapFactoryFunction,
 * is produced as output.
 * @param {Function} hmacFunc - an initialized (with key) function to compute HMACs
 * @returns a labelMapFactoryFunction
 */
export function createShuffledIdLabelMapFunction (hmac) {
  return function labelMapFactoryFunction (canonicalIdMap) {
    const te = new TextEncoder()
    const bnodeIdMap = new Map()
    for (const [input, c14nLabel] of canonicalIdMap) {
      const utf8Bytes = te.encode(c14nLabel)
      // console.log(`c14nLabel: ${c14nLabel}`)
      const hashed = hmac(utf8Bytes)
      // multibase prefix of `u` is important to make bnode ID syntax-legal
      // see: https://www.w3.org/TR/n-quads/#BNodes
      //let test = base64url.encode(hashed)
      bnodeIdMap.set(input, base64url.encode(hashed))
      //bnodeIdMap.set(input, `u${base64url.encode(hashed)}`)
    }
    const hmacIds = [...bnodeIdMap.values()].sort()
    const bnodeKeys = [...bnodeIdMap.keys()]
    bnodeKeys.forEach(bkey => {
      bnodeIdMap.set(bkey, 'b' + hmacIds.indexOf(bnodeIdMap.get(bkey)))
    })
    return bnodeIdMap
  }
}

// helper function
async function toDeskolemizedNQuads (skolemized, options) {
  // Convert skolemized doc to RDF to produce skolemized N-Quads.
  const rdfOptions = { safe: true, ...options, format: 'application/n-quads' }
  const rdf = await jsonld.toRDF(skolemized, rdfOptions)
  // Split N-Quads into arrays for deskolemization.
  const skolemizedNQuadArray = rdf.split('\n').slice(0, -1).map(nq => nq + '\n')
  // deskolemize
  const deskolemizedNQuads = []
  for (const nq of skolemizedNQuadArray) {
    if (!nq.includes('<urn:bnid:')) {
      deskolemizedNQuads.push(nq)
    } else {
      deskolemizedNQuads.push(nq.replace(/(<urn:bnid:([^>]+)>)/g, '_:$2'))
    }
  }
  return deskolemizedNQuads
}

// Helper function for relabeling
export function relabelBlankNodes (nquads, labelMap) {
  const replacer = (m, s1, label) => '_:' + labelMap.get(label)
  return nquads.map(e => e.replace(/(_:([^\s]+))/g, replacer))
}

// Helper function for use with implementations do not do strip `_:` prefixes
export function stripBlankNodePrefixes (map) {
  let checked = false
  const stripped = new Map()
  for (const [key, value] of map) {
    if (!checked) {
      checked = true
      if (!key.startsWith('_:')) {
        return map
      }
    }
    stripped.set(key.slice(2), value.slice(2))
  }
  return stripped
}

/**
 * The following algorithm selects a portion of a skolemized compact JSON-LD document
 * using an array of JSON Pointers, and outputs the resulting canonical N-Quads with any
 * blank node labels replaced using the given label map
 * @param {Array} pointers - an array of JSON Pointers
 * @param {Object} skolemizedCompactDocument - a skolemized compact JSON-LD document
 * @param {Map} labelMap - a blank node label map
 * @param {*} options
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 * @returns  An object containing the new JSON-LD document that represents a selection of
 * the original JSON-LD document (selectionDocument), an array of deskolemized N-Quad strings
 * (deskolemizedNQuads), and an array of canonical N-Quads with replacement blank node
 * labels (nquads).
 */
async function selectCanonicalNQuads (pointers, skolemizedCompactDocument, labelMap, options) {
  // Initialize selectionDocument to the result of the algorithm in Section 3.3.13 selectJsonLd,
  // passing pointers, and skolemizedCompactDocument as document.
  const selectionDocument = selectJsonLd(skolemizedCompactDocument, pointers)
  // Initialize deskolemizedNQuads to the result of the algorithm in Section 3.3.9 toDeskolemizedNQuads,
  // passing selectionDocument as skolemizedCompactDocument, and any custom options.
  const deskolemizedNQuads = await toDeskolemizedNQuads(selectionDocument, options)
  // Initialize nquads to the result of the algorithm in Section 3.3.14 relabelBlankNodes,
  // passing labelMap, and deskolemizedNQuads as nquads.
  const nquads = relabelBlankNodes(deskolemizedNQuads, labelMap)
  // Return an object containing selectionDocument, deskolemizedNQuads, and nquads.
  return { selectionDocument, deskolemizedNQuads, nquads }
}

/**
 * The following algorithm is used to output canonical N-Quad strings that match custom
 * selections of a compact JSON-LD document. It does this by canonicalizing a compact
 * JSON-LD document (replacing any blank node identifiers using a label map) and grouping
 * the resulting canonical N-Quad strings according to the selection associated with each
 * group. Each group will be defined using an assigned name and array of JSON pointers.
 * The JSON pointers will be used to select portions of the skolemized document, such
 * that the output can be converted to canonical N-Quads to perform group matching.
 * @param {Object} document - a compact JSON-LD document. The document is assumed to
 * use a JSON-LD context that aliases "@id" and "@type" to id and type, respectively,
 * and to use only one "@context" property at the top level of the document.
 * @param {Function} labelMapFactoryFunction - a function that maps blank node ids to a "urn:" scheme
 * @param {Object} groupDefinitions - a map of group names to corresponding arrays of JSON pointers
 * @param {Object} options
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 * @returns An object containing the created groups (groups), the skolemized compact
 * JSON-LD document (skolemizedCompactDocument), the skolemized expanded JSON-LD document
 * (skolemizedExpandedDocument), the deskolemized N-Quad strings (deskolemizedNQuads),
 * the blank node label map (labelMap), and the canonical N-Quad strings nquads.
 */
export async function canonicalizeAndGroup (document, labelMapFactoryFunction,
  groupDefinitions, options) {
  const expanded = await jsonld.expand(document, { safe: true, documentLoader: options.documentLoader })
  const skolemized = {}
  skolemized.expanded = skolemizeExpandedJsonLd(expanded, { bnPrefix: 'urn:bnid:' })
  skolemized.compact = await jsonld.compact(skolemized.expanded, document['@context'],
    { safe: true, documentLoader: options.documentLoader })
  /*
  Initialize deskolemizedNQuads to the result of the algorithm in Section 3.3.9 toDeskolemizedNQuads,
  passing skolemizedExpandedDocument and any custom options.
  */
  // Convert skolemized doc to RDF to produce skolemized N-Quads.
  const deskolemizedNQuads = await toDeskolemizedNQuads(skolemized.expanded, options)
  /*
  Initialize nquads and labelMap to their associated values in the result of the algorithm in
  Section 3.3.1 labelReplacementCanonicalizeNQuads, passing labelMapFactoryFunction, deskolemizedNQuads
  as nquads, and any custom options.

  Run the RDF Dataset Canonicalization Algorithm [RDF-CANON] on the joined nquads, passing any custom
  options, and as output, get the canonicalized dataset, which includes a canonical bnode
  identifier map, canonicalIdMap.
  */
  const canonicalIdMap = new Map()
  const canonicalNQuads = await jsonld.canonize(deskolemizedNQuads.join(''), {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    safe: true,
    inputFormat: 'application/n-quads',
    documentLoader: options.documentLoader,
    canonicalIdMap
  })
  // --Start Debugging--
  // const documentCanon = canonicalNQuads.split('\n').slice(0, -1).map(q => q + '\n') // array
  // await writeFile('../examples/output/addBaseDocCanon.json', JSON.stringify(documentCanon, null, 2))
  // --End Debugging--
  // **Missing step from  specification**? No, issue with current JSON-LD library...
  // ensure labels in map do not include `_:` prefix
  const canonicalIdMapStripped = stripBlankNodePrefixes(canonicalIdMap)
  // Pass canonicalIdMap to labelMapFactoryFunction to produce a new bnode identifier map, labelMap.
  const labelMap = labelMapFactoryFunction(canonicalIdMapStripped)
  // Use the canonicalized dataset and labelMap to produce the canonical N-Quads representation as
  // an array of N-Quad strings, canonicalNQuads.
  /* Notes: The above canonicalNQuads use blank node ids like "_:c14n0", the canonicalIdMap maps from
    the skolemized ids to these canonical ids, e.g., "_:_88c1eab3-9bfe-49e8-b5c5-7417311ef33a_0" ->  "_:c14n0"
    The labelMap computed with HMAC maps from the skolemized ids to the HMAC ids, e.g.,
    "_88c1eab3-9bfe-49e8-b5c5-7417311ef33a_0" -> "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38"
    The test vectors show replacing "_:c14n0" with "_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38
  */
  // Create map from "_:c14nX" to replacement labels
  const c14nMap = new Map()
  canonicalIdMap.forEach((c14Value, key) => {
    const skolId = key.slice(2) // remove the "_:"
    c14nMap.set(c14Value, labelMap.get(skolId))
  })
  // --Start Debugging--
  // console.log('canonAndGroup c14n map:')
  // await writeFile('../examples/output/c14nMap.json', JSON.stringify(c14nMap, replacerMap, 2))
  // --End Debugging--
  // Replace all "_:c14nX" labels with mapped stuff
  let nquads = canonicalNQuads
  c14nMap.forEach((value, key) => {
    const searchStr = new RegExp(key + ' ', 'g')
    nquads = nquads.replace(searchStr, '_:' + value + ' ')
  })
  // break into array, sort, and add back the CR
  nquads = nquads.split('\n').slice(0, -1).sort().map(s => s + '\n')
  // --Start Debugging--
  // await writeFile('../examples/output/processedQuads.json', JSON.stringify(nquads, null, 2))
  // --End Debugging--
  // Initialize selections to a new map.
  const selections = new Map()
  /* For each key (name) and value (pointers) entry in groupDefinitions:
    Add an entry with a key of name and a value that is the result of the algorithm in Section 3.3.15
    selectCanonicalNQuads, passing pointers, labelMap, skolemizedCompactDocument as document,
    and any custom options.
  */
  // console.log(groupDefinitions)
  for (const name in groupDefinitions) {
    const pointers = groupDefinitions[name]
    const selectTemp = await selectCanonicalNQuads(pointers, skolemized.compact, labelMap, options)
    selections.set(name, selectTemp)
  }
  const groups = {}
  /* For each key (name) and value (selectionResult) entry in selections:
      Initialize matching to an empty map.
      Initialize nonMatching to an empty map.
      Initialize selectedNQuads to nquads from selectionResult.
      Initialize selectedDeskolemizedNQuads from deskolemizedNQuads from selectionResult.
      For each element (nq) and index (index) in nquads:
          Create a map entry, entry, with a key of index and a value of nq.
          If selectedNQuads includes nq then add entry to matching; otherwise, add entry to nonMatching.
      Set name in groups to an object containing matching, nonMatching, and selectedDeskolemizedNQuads as deskolemizedNQuads.
  */
  selections.forEach((selectionResult, name) => {
    const matching = new Map()
    const nonMatching = new Map()
    const selectedNQuads = selectionResult.nquads
    const selectedDeskolemizedNQuads = selectionResult.deskolemizedNQuads
    nquads.forEach((nq, index) => {
      if (selectedNQuads.includes(nq)) {
        matching.set(index, nq)
      } else {
        nonMatching.set(index, nq)
      }
      groups[name] = { matching, nonMatching, deskolemizedNQuads: selectedDeskolemizedNQuads }
    })
  })
  // Temporary
  return { skolemized, deskolemizedNQuads, nquads, labelMap, groups }
}

/**
 * The following algorithm creates a label map factory function that uses an input label map
 * to replace canonical blank node identifiers with another value.
 * @param {Map} labelMap
 * @returns A function, labelMapFactoryFunction
 */
export function createLabelMapFunction (labelMap) {
  return function labelMapFactoryFunction (canonicalIdMap) {
    const bnodeIdMap = new Map()
    /* For each map entry, entry, in canonicalIdMap:
      Use the canonical identifier from the value in entry as a key in labelMap to get the new label, newLabel.
      Add a new entry, newEntry, to bnodeIdMap using the key from entry and newLabel as the value.
    */
    canonicalIdMap.forEach((value, key) => {
      const newLabel = labelMap.get(value)
      bnodeIdMap.set(key, newLabel)
    })
    return bnodeIdMap
  }
}

/**
 * The following algorithm canonicalizes a JSON-LD document and replaces any blank node
 * identifiers in the canonicalized result using a label map factory function,
 * labelMapFactoryFunction.
 * @param {Object} document - a JSON-LD document
 * @param {Function} labelMapFactoryFunction - a label map factory function
 * @param {Object} options
 * @param {function} options.documentLoader - A JSON-LD document loader to be
 *   passed on to JSON-LD processing functions. Optional.
 * @returns An N-Quads representation of the canonicalNQuads as an array of N-Quad strings,
 * with the replaced blank node labels, and a map from the old blank node IDs to the new blank
 * node IDs, labelMap.
 */
export async function labelReplacementCanonicalizeJsonLd (document, labelMapFactoryFunction, options) {
  /*
    Deserialize the JSON-LD document to RDF, rdf, using the Deserialize JSON-LD to RDF algorithm, passing
    any custom options (such as a document loader).
    Serialize rdf to an array of N-Quad strings, nquads.
    Return the result of calling the algorithm in Section 3.3.1 labelReplacementCanonicalizeNQuads,
    passing nquads, labelMapFactoryFunction, and any custom options.
  */
  const canonicalIdMap = new Map()
  const canonicalNQuads = await jsonld.canonize(document, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    safe: true,
    documentLoader: options.documentLoader,
    canonicalIdMap
  })
  const canonicalIdMapStripped = stripBlankNodePrefixes(canonicalIdMap)
  // Pass canonicalIdMap to labelMapFactoryFunction to produce a new bnode identifier map, labelMap.
  const labelMap = labelMapFactoryFunction(canonicalIdMapStripped)
  // Use the canonicalized dataset and labelMap to produce the canonical N-Quads representation as
  // an array of N-Quad strings, canonicalNQuads.
  // Create map from "_:c14nX" to replacement labels
  const c14nMap = new Map()
  canonicalIdMap.forEach((c14Value, key) => {
    const skolId = key.slice(2) // remove the "_:"
    c14nMap.set(c14Value, labelMap.get(skolId))
  })
  // Replace all "_:c14nX" labels with mapped stuff
  let nquads = canonicalNQuads
  c14nMap.forEach((value, key) => {
    const searchStr = new RegExp(key + ' ', 'g')
    nquads = nquads.replace(searchStr, '_:' + value + ' ')
  })
  // break into array, sort, and add back the CR
  nquads = nquads.split('\n').slice(0, -1).sort().map(s => s + '\n')
  return nquads
}

// For Debugging
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
