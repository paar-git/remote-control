// Exercise the release metadata pipeline end to end, without building the app.
//
// The generators only ran when a tag was pushed, so a defect in them surfaced
// as a failed release rather than a failed check: a missing bundle path, an
// unset environment variable read with `??`, or a signature that did not
// verify each cost a full release cycle to discover. This runs the same three
// scripts over a stand-in artifact with a throwaway key and checks the output,
// in a couple of seconds, on every pull request.
//
// Usage: node scripts/smoke-release-pipeline.mjs

import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync, verify } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const REPOSITORY = 'example/remote-control';
const TAG = 'v9.9.9';
const VERSION = '9.9.9';

function fail(message) {
  console.error(`smoke-release-pipeline: ${message}`);
  process.exit(1);
}

function check(condition, message) {
  if (!condition) fail(message);
}

const workspace = mkdtempSync(join(tmpdir(), 'rc-release-smoke-'));

try {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const publicKeyB64 = spki.subarray(spki.length - 32).toString('base64');
  const privateKeyB64 = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');

  // A stand-in installer. Only its bytes, size and hash matter here.
  const artifact = join(workspace, 'remote-control-9.9.9-x64.msi');
  const bytes = Buffer.alloc(4096, 7);
  writeFileSync(artifact, bytes);

  const metadataDir = join(workspace, 'metadata');
  mkdirSync(metadataDir, { recursive: true });
  writeFileSync(
    join(metadataDir, 'windows-x64-msi.json'),
    `${JSON.stringify(
      {
        platform: 'windows-x64',
        filename: 'remote-control-9.9.9-x64.msi',
        packageFormat: 'msi',
        url: `https://github.com/${REPOSITORY}/releases/download/${TAG}/remote-control-9.9.9-x64.msi`,
        sha256: createHash('sha256').update(bytes).digest('hex'),
        size: bytes.length,
        signatureRequired: false,
        path: artifact,
      },
      null,
      2,
    )}\n`,
  );

  const notes = join(workspace, 'release-notes.md');
  const manifest = join(workspace, 'release-manifest.json');
  const index = join(workspace, 'release-index.json');

  // The shape a workflow actually produces: secrets that do not exist arrive as
  // empty strings rather than being absent, which is what broke index signing.
  const env = {
    ...process.env,
    CI: 'true',
    GITHUB_REPOSITORY: REPOSITORY,
    GITHUB_REF_NAME: TAG,
    RELEASE_INDEX_PRIVATE_KEY_PEM: '',
    RELEASE_INDEX_PRIVATE_KEY_B64: '',
    RELEASE_INDEX_PUBLIC_KEY_B64: '',
    RELEASE_MANIFEST_PRIVATE_KEY_PEM: '',
    RELEASE_MANIFEST_PRIVATE_KEY_B64: privateKeyB64,
    RELEASE_MANIFEST_PUBLIC_KEY_B64: publicKeyB64,
  };

  const run = (script, args) =>
    execFileSync(process.execPath, [script, ...args], { env, encoding: 'utf8', stdio: 'pipe' });

  run('scripts/generate-release-notes.mjs', ['--tag', 'HEAD', '--output', notes]);
  check(readFileSync(notes, 'utf8').trim() !== '', 'release notes must not be empty');

  run('scripts/generate-release-manifest.mjs', [
    '--version',
    VERSION,
    '--artifacts-dir',
    metadataDir,
    '--notes-file',
    notes,
    '--output',
    manifest,
  ]);

  run('scripts/generate-release-index.mjs', [
    '--manifest',
    manifest,
    '--manifest-url',
    `https://github.com/${REPOSITORY}/releases/download/${TAG}/release-manifest.json`,
    '--output',
    index,
  ]);

  for (const [name, path] of [
    ['manifest', manifest],
    ['index', index],
  ]) {
    const content = readFileSync(path);
    const signature = Buffer.from(readFileSync(`${path}.sig`, 'utf8').trim(), 'base64');
    check(signature.length === 64, `${name} signature must be 64 bytes, got ${signature.length}`);

    const spkiKey = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(publicKeyB64, 'base64'),
    ]);
    const key = { key: spkiKey, format: 'der', type: 'spki' };
    check(verify(null, content, key, signature), `${name} signature must verify`);

    const tampered = Buffer.from(content);
    tampered[tampered.length - 3] ^= 0x01;
    check(!verify(null, tampered, key, signature), `a modified ${name} must not verify`);
  }

  const parsedManifest = JSON.parse(readFileSync(manifest, 'utf8'));
  check(parsedManifest.version === VERSION, 'manifest must carry the requested version');
  check(
    parsedManifest.releaseNotes.trim() !== '',
    'generated notes must reach the manifest, or users see no changelog',
  );
  check(
    parsedManifest.platforms['windows-x64'].artifacts[0].sha256.length === 64,
    'artifact must carry a full SHA-256',
  );

  const parsedIndex = JSON.parse(readFileSync(index, 'utf8'));
  check(parsedIndex.releases.length === 1, 'index must list the release');
  check(
    parsedIndex.releases[0].manifestUrl.startsWith('https://'),
    'metadata must only be fetched over https',
  );
  check(
    parsedIndex.releases[0].manifestSha256 ===
      createHash('sha256').update(readFileSync(manifest)).digest('hex'),
    'the index must pin the exact manifest bytes it points at',
  );

  console.log('smoke-release-pipeline: signed manifest and index generated and verified.');
} finally {
  rmSync(workspace, { recursive: true, force: true });
}
