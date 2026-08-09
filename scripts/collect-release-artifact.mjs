// Locate the installer a Tauri build produced and record what the release
// metadata needs to know about it.
//
// Usage:
//   node scripts/collect-release-artifact.mjs \
//     --extension .msi --platform windows-x64 --package-format msi \
//     --assets-dir release-assets --output release-metadata/windows-x64-msi.json
//
// Lives here rather than inline in the workflow so it can be exercised by
// scripts/smoke-release-pipeline.mjs on every pull request. Inline, it produced
// two defects that were only discoverable by pushing a tag: a bundle path that
// never existed, and an asset name that did not survive upload.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

/**
 * The name GitHub will actually serve for an uploaded asset.
 *
 * GitHub rewrites whitespace in a release asset's name to `.`, so a product
 * name containing a space means the file is stored under a different name than
 * it was built with. A URL built from the built name then 404s for every
 * platform. Normalising here keeps one name across the copied file, the
 * manifest's `filename`, and the download URL.
 */
function assetName(filename) {
  return filename.replace(/\s+/g, '.');
}

/** Where Cargo puts build output, honouring a `--target` cross build. */
function bundleRoot(rustTarget) {
  const targetDirectory = JSON.parse(
    execFileSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    }),
  ).target_directory;
  const segments = rustTarget ? [rustTarget] : [];
  return join(targetDirectory, ...segments, 'release', 'bundle');
}

function findArtifacts(root, extension) {
  const found = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.name.endsWith(extension)) found.push(path);
    }
  };
  walk(root);
  return found.sort();
}

function main() {
  const extension = arg('extension') ?? process.env.EXTENSION;
  const platform = arg('platform') ?? process.env.PLATFORM;
  const packageFormat = arg('package-format') ?? process.env.PACKAGE_FORMAT;
  const assetsDir = arg('assets-dir', 'release-assets');
  const output = arg('output');
  const rustTarget = (arg('rust-target') ?? process.env.RUST_TARGET ?? '').trim();
  const root = arg('bundle-root') ?? bundleRoot(rustTarget);

  if (!extension || !platform || !packageFormat || !output) {
    fail('Missing --extension, --platform, --package-format or --output.');
  }
  if (!existsSync(root)) fail(`Bundle directory not found: ${root}`);

  const files = findArtifacts(root, extension);
  if (files.length !== 1) {
    fail(
      `Expected one ${extension} artifact under ${root}, found ${files.length}: ${files.join(', ')}`,
    );
  }

  const source = files[0];
  const filename = assetName(basename(source));
  mkdirSync(assetsDir, { recursive: true });
  const target = join(assetsDir, filename);
  copyFileSync(source, target);

  const bytes = readFileSync(target);
  const repository = process.env.GITHUB_REPOSITORY;
  const tag = process.env.GITHUB_REF_NAME;
  if (!repository || !tag) fail('GITHUB_REPOSITORY and GITHUB_REF_NAME must be set.');

  const metadata = {
    platform,
    filename,
    packageFormat,
    url: `https://github.com/${repository}/releases/download/${tag}/${encodeURIComponent(filename)}`,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    size: statSync(target).size,
    signatureRequired: process.env.SIGNATURE_REQUIRED === 'true',
  };

  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(metadata, null, 2)}\n`);
  console.log(`Collected ${filename} (${metadata.size} bytes) for ${platform}/${packageFormat}.`);
}

main();
