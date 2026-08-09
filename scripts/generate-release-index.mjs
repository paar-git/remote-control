import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function firstConfiguredKey(value) {
  return value
    ?.split(',')
    .map((key) => key.trim())
    .find(Boolean);
}

function publicKeyFromBase64(value) {
  const bytes = Buffer.from(value, 'base64');
  const spki =
    bytes.length === 32
      ? Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), bytes])
      : bytes;
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

function privateKey() {
  const pem =
    process.env.RELEASE_INDEX_PRIVATE_KEY_PEM ?? process.env.RELEASE_MANIFEST_PRIVATE_KEY_PEM;
  const b64 =
    process.env.RELEASE_INDEX_PRIVATE_KEY_B64 ?? process.env.RELEASE_MANIFEST_PRIVATE_KEY_B64;
  if (pem) return createPrivateKey(pem);
  if (b64)
    return createPrivateKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'pkcs8' });
  if (process.env.CI === 'true')
    fail(
      'CI release indexes require RELEASE_INDEX_PRIVATE_KEY_* or RELEASE_MANIFEST_PRIVATE_KEY_*.',
    );
  return null;
}

function summarizeManifest(manifest, manifestUrl, manifestPath) {
  const platforms = {};
  for (const platform of Object.keys(manifest.platforms ?? {}).sort()) {
    const entry = manifest.platforms[platform];
    platforms[platform] = {
      formats: [...new Set((entry.artifacts ?? []).map((artifact) => artifact.format))].sort(),
    };
  }
  return {
    version: manifest.version,
    releaseDate: manifest.releaseDate,
    manifestUrl,
    manifestSha256: sha256(manifestPath),
    ...(manifest.minimumVersion === undefined ? {} : { minimumVersion: manifest.minimumVersion }),
    ...(manifest.minimumSupportedVersion === undefined
      ? {}
      : { minimumSupportedVersion: manifest.minimumSupportedVersion }),
    ...(manifest.minimumUpdaterVersion === undefined
      ? {}
      : { minimumUpdaterVersion: manifest.minimumUpdaterVersion }),
    ...(manifest.minimumOSVersion === undefined
      ? {}
      : { minimumOSVersion: manifest.minimumOSVersion }),
    platforms,
  };
}

const SEMVER = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function parseVersion(value) {
  const match = SEMVER.exec(value);
  if (!match) fail(`Not a semantic version: ${value}`);
  return {
    numbers: [Number(match[1]), Number(match[2]), Number(match[3])],
    prerelease: match[4] === undefined ? [] : match[4].split('.'),
  };
}

// Semantic-version precedence, including pre-release ordering. Parsing each dot
// segment with parseInt produced NaN for a version such as `0.1.1-rc.1`, and a
// NaN comparator silently corrupts the sort that decides which release the
// index presents as newest.
function comparePrerelease(left, right) {
  // A version with a pre-release ranks below the same version without one.
  if (left.length === 0 && right.length === 0) return 0;
  if (left.length === 0) return 1;
  if (right.length === 0) return -1;
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const l = left[index];
    const r = right[index];
    if (l === undefined) return -1;
    if (r === undefined) return 1;
    const lNumeric = /^\d+$/.test(l);
    const rNumeric = /^\d+$/.test(r);
    if (lNumeric && rNumeric) {
      const delta = Number(l) - Number(r);
      if (delta !== 0) return delta;
    } else if (lNumeric !== rNumeric) {
      return lNumeric ? -1 : 1;
    } else if (l !== r) {
      return l < r ? -1 : 1;
    }
  }
  return 0;
}

function compareVersions(left, right) {
  const l = parseVersion(left);
  const r = parseVersion(right);
  for (let index = 0; index < 3; index += 1) {
    const delta = l.numbers[index] - r.numbers[index];
    if (delta !== 0) return delta;
  }
  return comparePrerelease(l.prerelease, r.prerelease);
}

const manifestPath = resolve(arg('manifest', 'release-manifest.json'));
const output = resolve(arg('output', 'release-index.json'));
const previousIndexPath = arg('previous-index');
const manifestUrl = arg('manifest-url') ?? process.env.RELEASE_MANIFEST_URL;
if (!manifestUrl?.startsWith('https://'))
  fail('Missing HTTPS --manifest-url or RELEASE_MANIFEST_URL.');
if (!existsSync(manifestPath)) fail(`Manifest not found: ${manifestPath}`);

const manifest = readJson(manifestPath);
const releasesByVersion = new Map();
if (previousIndexPath && existsSync(previousIndexPath)) {
  const previous = readJson(previousIndexPath);
  for (const entry of previous.releases ?? []) releasesByVersion.set(entry.version, entry);
}
releasesByVersion.set(manifest.version, summarizeManifest(manifest, manifestUrl, manifestPath));
const releases = [...releasesByVersion.values()].sort(
  (left, right) => -compareVersions(left.version, right.version),
);
const index = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  releases,
};
const bytes = Buffer.from(`${JSON.stringify(index, null, 2)}\n`);
writeFileSync(output, bytes);

const key = privateKey();
if (key) {
  const signature = sign(null, bytes, key);
  writeFileSync(`${output}.sig`, signature.toString('base64'));
  const publicKeyB64 = firstConfiguredKey(
    process.env.RELEASE_INDEX_PUBLIC_KEY_B64 ?? process.env.RELEASE_MANIFEST_PUBLIC_KEY_B64,
  );
  if (publicKeyB64) {
    if (!verify(null, bytes, publicKeyFromBase64(publicKeyB64), signature)) {
      fail('Generated release-index signature did not verify.');
    }
  }
}

console.log(`Wrote ${output} with ${releases.length} release(s).`);
