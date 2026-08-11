# wgprobe for Node.js

The `wgprobe` npm package provides typed asynchronous Node.js bindings to the
provider-neutral Rust probe engine. It supports Node.js 22.13 and newer on
glibc-based 64-bit Linux and macOS. Alpine Linux, other musl systems, and Windows
are not currently supported. Windows support is implemented but temporarily
disabled while npm reviews the native package name.

Install the package:

```sh
npm install wgprobe
```

Probe a one-peer WireGuard configuration:

```ts
import { probeFile } from "wgprobe";

const report = await probeFile("path/to/test.conf", {
  ping: ["10.5.0.1"],
  resolve: ["example.com"],
});

console.log(report.verdict);
for (const phase of report.phases) {
  console.log(phase.phase, phase.status, phase.detail);
}
```

The functions return promises because file access, name resolution, and UDP
probing run outside the JavaScript thread. At most eight probes run concurrently
in one process. Cancelling a promise does not cancel an operating-system resolver
call or a probe that has already started.

Configuration and private-key files contain secrets. Restrict their permissions,
keep them out of version control, and never put key values in source, logs,
command-line arguments, or environment variables.
