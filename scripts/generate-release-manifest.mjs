import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

const ALLOWED_PLATFORMS = new Set([
  'windows-x64',
  'windows-arm64',
  'macos-x64',
  'macos-arm64',
  'linux-x64',
  'linux-arm64',
]);

const ALLOWED_FORMATS = new Set(['exe', 'msi', 'dmg', 'pkg', 'appimage', 'deb', 'rpm', 'tar.gz']);
const FORMAT_ALIASES = new Map([
  ['app-image', 'appimage'],
  ['tar-gz', 'tar.gz'],
  ['tgz', 'tar.gz'],
]);

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function normalizeFormat(format) {
  return FORMAT_ALIASES.get(format) ?? format;
}

function optionalJsonEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) return undefined;
  if (value.startsWith('{') || value.startsWith('[')) return JSON.parse(value);
  return value;
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

function readJson(path) {
  const text = readFileSync(path, 'utf8').replace(/^\uFEFF/, '');
  return JSON.parse(text);
}

async function main() {
  const version = arg('version') ?? process.env.RELEASE_VERSION;
  if (!version) fail('Missing --version or RELEASE_VERSION.');
  const releaseDate = arg('release-date', new Date().toISOString().slice(0, 10));
  const artifactsDir = resolve(arg('artifacts-dir', 'release-artifacts'));
  const output = resolve(arg('output', 'release-manifest.json'));
  const notesFile = arg('notes-file');
  const releaseNotes = notesFile && existsSync(notesFile) ? readFileSync(notesFile, 'utf8') : '';
  const repository = process.env.GITHUB_REPOSITORY;
  const tag = process.env.GITHUB_REF_NAME ?? `v${version}`;

  if (!existsSync(artifactsDir)) fail(`Artifacts directory not found: ${artifactsDir}`);

  const generatedMetadataNames = new Set(['release-manifest.json', 'release-index.json']);
  const metadataFiles = readdirSync(artifactsDir)
    .filter((name) => name.endsWith('.json') && !generatedMetadataNames.has(name))
    .sort()
    .map((name) => join(artifactsDir, name))
    .filter((path) => resolve(path) !== output);
  if (metadataFiles.length === 0) fail(`No artifact metadata JSON files found in ${artifactsDir}.`);

  const platforms = {};
  for (const file of metadataFiles) {
    const metadata = readJson(file);
    const entries = Array.isArray(metadata) ? metadata : [metadata];
    for (const entry of entries) {
      if (!ALLOWED_PLATFORMS.has(entry.platform))
        fail(`Unsupported platform ${entry.platform} in ${file}.`);
      const packageFormat = normalizeFormat(entry.packageFormat ?? entry.format);
      if (!ALLOWED_FORMATS.has(packageFormat))
        fail(`Unsupported package format ${entry.packageFormat ?? entry.format} in ${file}.`);
      const artifactPath = entry.path ? resolve(entry.path) : null;
      const filename = entry.filename ?? (artifactPath ? basename(artifactPath) : null);
      if (
        !filename ||
        filename.includes('/') ||
        filename.includes('\\') ||
        filename.includes('..')
      ) {
        fail(`Unsafe or missing filename for ${entry.platform}.`);
      }
      platforms[entry.platform] ??= { artifacts: [] };
      if (
        platforms[entry.platform].artifacts.some((artifact) => artifact.format === packageFormat)
      ) {
        fail(`Duplicate ${entry.platform} ${packageFormat} artifact metadata.`);
      }
      const size = entry.size ?? (artifactPath ? statSync(artifactPath).size : null);
      const digest = entry.sha256 ?? (artifactPath ? sha256(artifactPath) : null);
      const url =
        entry.url ??
        (repository
          ? `https://github.com/${repository}/releases/download/${tag}/${encodeURIComponent(filename)}`
          : null);
      if (!url?.startsWith('https://')) fail(`Missing HTTPS URL for ${entry.platform}.`);
      if (!Number.isSafeInteger(size) || size <= 0) fail(`Invalid size for ${entry.platform}.`);
      if (!/^[a-fA-F0-9]{64}$/.test(digest)) fail(`Invalid SHA-256 for ${entry.platform}.`);
      platforms[entry.platform].artifacts.push({
        format: packageFormat,
        url,
        sha256: digest.toLowerCase(),
        size,
        ...(entry.installSize === undefined ? {} : { installSize: entry.installSize }),
        filename,
        signatureRequired: Boolean(entry.signatureRequired),
      });
    }
  }

  const sortedPlatforms = {};
  for (const platform of Object.keys(platforms).sort()) {
    sortedPlatforms[platform] = {
      artifacts: platforms[platform].artifacts.sort((left, right) =>
        left.format.localeCompare(right.format),
      ),
    };
  }

  const manifest = {
    version,
    releaseDate,
    minimumSupportedVersion: process.env.RELEASE_MINIMUM_SUPPORTED_VERSION ?? undefined,
    minimumUpdaterVersion: process.env.RELEASE_MINIMUM_UPDATER_VERSION ?? undefined,
    minimumOSVersion: optionalJsonEnv('RELEASE_MINIMUM_OS_VERSION'),
    mandatoryUpdate: process.env.RELEASE_MANDATORY_UPDATE === 'true',
    releaseNotes,
    platforms: sortedPlatforms,
  };
  for (const key of Object.keys(manifest)) if (manifest[key] === undefined) delete manifest[key];

  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(output, bytes);

  const privateKeyPem = process.env.RELEASE_MANIFEST_PRIVATE_KEY_PEM;
  const privateKeyB64 = process.env.RELEASE_MANIFEST_PRIVATE_KEY_B64;
  if (privateKeyPem || privateKeyB64) {
    const key = privateKeyPem
      ? createPrivateKey(privateKeyPem)
      : createPrivateKey({
          key: Buffer.from(privateKeyB64, 'base64'),
          format: 'der',
          type: 'pkcs8',
        });
    const signature = sign(null, bytes, key);
    writeFileSync(`${output}.sig`, signature.toString('base64'));
    const publicKeyB64 = firstConfiguredKey(process.env.RELEASE_MANIFEST_PUBLIC_KEY_B64);
    if (publicKeyB64 && !verify(null, bytes, publicKeyFromBase64(publicKeyB64), signature)) {
      fail('Generated release-manifest signature did not verify.');
    }
  } else if (process.env.CI === 'true') {
    fail(
      'CI releases must set RELEASE_MANIFEST_PRIVATE_KEY_PEM or RELEASE_MANIFEST_PRIVATE_KEY_B64.',
    );
  }

  console.log(`Wrote ${output} with ${Object.keys(sortedPlatforms).length} platform artifact(s).`);
}

main().catch((error) => fail(error instanceof Error ? error.message : String(error)));
