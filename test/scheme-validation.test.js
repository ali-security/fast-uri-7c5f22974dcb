'use strict'

const test = require('tape')
const fastURI = require('..')

const MALFORMED_SCHEME_ERROR = 'URI scheme is malformed.'

const malformedSchemes = [
  '%2f%2fevil.example:/pwn',
  '%u002f%u002fevil.example:/pwn',
  '%0d%0aSet-Cookie:%20sid=attacker:/p',
  'foo%3Abar:value',
  'foo%2Fbar:value',
  '1http://example.com/',
  'foo_bar:value',
  'éxample:value',
  // U+212A KELVIN SIGN and U+017F LATIN SMALL LETTER LONG S case-fold to "k"
  // and "s" under Unicode rules, so a case-insensitive /iu scheme check would
  // accept them as "kttp" and "scheme".
  'Kttp://example.com/',
  'ſcheme:value'
]

test('parse validates the decoded scheme against RFC 3986', (t) => {
  const validSchemes = [
    ['a:value', 'a'],
    ['HTTP://example.com/', 'http'],
    ['a1+.-:value', 'a1+.-'],
    ['%4Aavascript:alert(1)', 'javascript'],
    ['foo%2Bbar:value', 'foo+bar'],
    ['%u006Aavascript:1', 'javascript'],
    ['ht%74ps://example.com/', 'https']
  ]

  for (const [uri, scheme] of validSchemes) {
    const parsed = fastURI.parse(uri)
    t.equal(parsed.error, undefined, uri)
    t.equal(parsed.scheme, scheme, uri + ' scheme')
  }

  for (const uri of malformedSchemes) {
    const parsed = fastURI.parse(uri)
    t.equal(parsed.error, MALFORMED_SCHEME_ERROR, uri)
  }
  t.end()
})

test('decoded schemes select their scheme handlers', (t) => {
  t.equal(
    fastURI.normalize('ht%74ps://example.com:443'),
    'https://example.com/',
    'HTTP normalization runs after decoding the scheme'
  )

  // The scheme handler must be picked from the decoded scheme, not the raw
  // percent-encoded one, otherwise scheme-specific parsing is skipped for any
  // URI whose scheme is encoded.
  const ws = fastURI.parse('w%73://example.com/chat')
  t.equal(ws.scheme, 'ws', 'encoded ws scheme decodes')
  t.equal(ws.resourceName, '/chat', 'ws parsing runs after decoding the scheme')
  t.equal(ws.secure, false, 'ws handler set the secure flag')
  t.end()
})

test('normalize preserves schemes that decode to invalid identifiers', (t) => {
  for (const uri of malformedSchemes) {
    t.equal(fastURI.normalize(uri), uri, uri)
  }
  t.end()
})

test('scheme normalization cannot introduce authority or control delimiters', (t) => {
  const authority = '%2f%2fevil.example:/pwn'
  const crlf = '%0d%0aSet-Cookie:%20sid=attacker:/p'

  t.equal(fastURI.parse(authority).host, undefined, 'original input has no authority')
  t.equal(fastURI.normalize(authority), authority, 'normalization does not create an authority')
  t.equal(
    fastURI.parse(fastURI.normalize(authority)).host,
    undefined,
    'the normalized output still has no authority'
  )
  t.equal(fastURI.normalize(crlf), crlf, 'normalization does not emit raw CRLF')
  t.equal(fastURI.normalize(crlf).includes('\r\n'), false, 'normalized output contains no raw CRLF')
  t.end()
})

test('equal returns false for malformed decoded schemes', (t) => {
  for (const uri of malformedSchemes) {
    t.equal(fastURI.equal(uri, uri, {}), false, uri)
  }
  t.end()
})

test('resolve rejects malformed decoded schemes in either input', (t) => {
  t.throws(
    () => fastURI.resolve('%2f%2fevil.example:/base', 'child'),
    /URI scheme is malformed\./,
    'malformed base'
  )
  t.throws(
    () => fastURI.resolve('https://allowed.example/app/', '%2f%2fevil.example:/pwn'),
    /URI scheme is malformed\./,
    'malformed relative reference'
  )
  t.end()
})

test('serialize validates decoded component schemes', (t) => {
  t.equal(
    fastURI.serialize({ scheme: 'foo%2Bbar', path: 'value' }),
    'foo+bar:value',
    'valid decoded scheme is serialized'
  )
  t.throws(
    () => fastURI.serialize({ scheme: '//evil.example', path: '/pwn' }),
    /URI scheme is malformed\./,
    'raw invalid scheme'
  )
  t.throws(
    () => fastURI.serialize({ scheme: '%2f%2fevil.example', path: '/pwn' }),
    /URI scheme is malformed\./,
    'encoded invalid scheme'
  )
  t.equal(
    fastURI.equal(
      { scheme: '%2f%2fevil.example', path: '/pwn' },
      { scheme: '%2f%2fevil.example', path: '/pwn' },
      {}
    ),
    false,
    'equality fails closed for malformed component objects'
  )
  t.end()
})
