import {
  type ProbeKeyFileOptions,
  type ProbeOptions,
  type ProbeReport,
  probeFile,
  probeKeyFile,
  version,
} from '../index.js'

const options: ProbeOptions = {
  ping: ['10.0.0.1'],
  resolve: ['example.com'],
  dnsServer: '10.0.0.53',
  deadlineMs: 9_000,
}

const keyOptions: ProbeKeyFileOptions = {
  ...options,
  address: '10.0.0.2/32',
  allowedIps: ['0.0.0.0/0'],
}

const report: Promise<ProbeReport> = probeFile('test.conf', options)
const keyReport: Promise<ProbeReport> = probeKeyFile(
  'private-key',
  'peer-key',
  'example.test:51820',
  keyOptions,
)

void report
void keyReport
void version()
