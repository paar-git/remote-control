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
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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

  // A stand-in bundle tree. The product name contains a space on purpose: that
  // is what GitHub rewrites on upload, and a URL built from the unrewritten
  // name 404s for every platform.
  const bundleRoot = join(workspace, 'bundle');
  mkdirSync(join(bundleRoot, 'msi'), { recursive: true });
  const builtName = 'Remote Control_9.9.9_x64_en-US.msi';
  const bytes = Buffer.alloc(4096, 7);
  writeFileSync(join(bundleRoot, 'msi', builtName), bytes);

  const metadataDir = join(workspace, 'metadata');
  const assetsDir = join(workspace, 'assets');
  const collected = join(metadataDir, 'windows-x64-msi.json');

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
    // Optional release policy inputs, unset in the workflow and therefore
    // delivered as empty strings. An empty minimumSupportedVersion is not "no
    // minimum": the client parses it and rejects the manifest outright.
    RELEASE_MINIMUM_SUPPORTED_VERSION: '',
    RELEASE_MINIMUM_UPDATER_VERSION: '',
    RELEASE_MINIMUM_OS_VERSION: '',
    RELEASE_MANDATORY_UPDATE: '',
  };

  // Any blank value that survives into the metadata is a bug: the schema treats
  // these fields as absent-or-meaningful, never as empty.
  const assertNoBlankValues = (label, value, path = '') => {
    if (typeof value === 'string') {
      check(value.trim() !== '', `${label} must not contain a blank value at ${path || '(root)'}`);
    } else if (Array.isArray(value)) {
      value.forEach((entry, position) => assertNoBlankValues(label, entry, `${path}[${position}]`));
    } else if (value !== null && typeof value === 'object') {
      for (const [key, entry] of Object.entries(value)) {
        assertNoBlankValues(label, entry, path === '' ? key : `${path}.${key}`);
      }
    }
  };

  const run = (script, args) => {
    try {
      return execFileSync(process.execPath, [script, ...args], {
        env,
        encoding: 'utf8',
        stdio: 'pipe',
      });
    } catch (error) {
      // Without this the script's own diagnostic is swallowed and the failure
      // reads as an unrelated ENOENT further down.
      fail(`${script} failed:\n${error.stderr || error.message}`);
      return '';
    }
  };

  run('scripts/collect-release-artifact.mjs', [
    '--bundle-root',
    bundleRoot,
    '--extension',
    '.msi',
    '--platform',
    'windows-x64',
    '--package-format',
    'msi',
    '--assets-dir',
    assetsDir,
    '--output',
    collected,
  ]);

  const artifactMetadata = JSON.parse(readFileSync(collected, 'utf8'));
  check(
    !artifactMetadata.filename.includes(' '),
    'the recorded asset name must match what GitHub serves, which has no spaces',
  );
  check(
    !artifactMetadata.url.includes('%20'),
    `a URL encoding a space cannot resolve to the uploaded asset: ${artifactMetadata.url}`,
  );
  check(
    existsSync(join(assetsDir, artifactMetadata.filename)),
    'the uploaded file must be named exactly as the metadata records it',
  );
  check(
    artifactMetadata.sha256 === createHash('sha256').update(bytes).digest('hex'),
    'the recorded checksum must be the checksum of the copied installer',
  );
  // The publish job resolves each asset by its recorded filename.
  artifactMetadata.path = join(assetsDir, artifactMetadata.filename);
  writeFileSync(collected, `${JSON.stringify(artifactMetadata, null, 2)}\n`);

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
  assertNoBlankValues('manifest', parsedManifest);
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
  assertNoBlankValues('index', parsedIndex);
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
