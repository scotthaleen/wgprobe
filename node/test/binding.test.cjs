const assert = require('node:assert/strict')
const { mkdtemp, writeFile } = require('node:fs/promises')
const { tmpdir } = require('node:os')
const path = require('node:path')
const test = require('node:test')

const wgprobe = require('../index.js')

const FAKE_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='

test('exports the typed asynchronous API', () => {
  assert.equal(typeof wgprobe.probeFile, 'function')
  assert.equal(typeof wgprobe.probeKeyFile, 'function')
  assert.equal(wgprobe.version(), '0.1.2')
})

test('rejects invalid local configuration with a stable code', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'wgprobe-node-'))
  const config = path.join(directory, 'invalid.conf')
  await writeFile(config, '[Interface]\nPrivateKey = invalid\n')

  await assert.rejects(wgprobe.probeFile(config), (error) => {
    assert.equal(error.code, 'InvalidArg')
    assert.match(error.message, /private ?key/i)
    return true
  })
})

test('returns operational endpoint errors as reports', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'wgprobe-node-'))
  const config = path.join(directory, 'local-error.conf')
  await writeFile(
    config,
    `[Interface]\nPrivateKey = ${FAKE_KEY}\n[Peer]\nPublicKey = ${FAKE_KEY}\nEndpoint = 127.0.0.1\n`,
  )

  const report = await wgprobe.probeFile(config)
  assert.equal(report.schemaVersion, 1)
  assert.equal(report.verdict, 'local_error')
  assert.equal(report.endpoint, '127.0.0.1')
  assert.equal(report.resolvedEndpoint, undefined)
  assert.ok(Array.isArray(report.phases))
  assert.equal(report.phases[0].status, 'error')
  assert.doesNotMatch(JSON.stringify(report), new RegExp(FAKE_KEY))
})

test('validates raw-key data options before probing', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'wgprobe-node-'))
  const key = path.join(directory, 'private-key')
  await writeFile(key, FAKE_KEY)

  await assert.rejects(
    wgprobe.probeKeyFile(key, FAKE_KEY, '127.0.0.1:1', {
      ping: ['127.0.0.1'],
    }),
    /data checks require address/,
  )
})

test('rejects fractional timeout values', async () => {
  await assert.rejects(
    wgprobe.probeFile('unused', { deadlineMs: 1.5 }),
    /deadlineMs must be an integer/,
  )
})
