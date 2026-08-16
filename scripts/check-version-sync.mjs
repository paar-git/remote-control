import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function readJson(path) {
  return JSON.parse(readFileSync(resolve(path), 'utf8').replace(/^\uFEFF/, ''));
}

function readWorkspaceCargoVersion() {
  const cargo = readFileSync(resolve('Cargo.toml'), 'utf8');
  const workspacePackage = cargo.match(/\[workspace\.package\]([\s\S]*?)(?:\n\[|$)/);
  if (!workspacePackage) throw new Error('Cargo.toml is missing [workspace.package]');
  const version = workspacePackage[1].match(/\nversion\s*=\s*"([^"]+)"/);
  if (!version) throw new Error('Cargo.toml [workspace.package] is missing version');
  return version[1];
}

const versions = new Map([
  ['Cargo workspace', readWorkspaceCargoVersion()],
  ['root package.json', readJson('package.json').version],
  ['desktop package.json', readJson('apps/desktop-client/package.json').version],
  ['shared-types package.json', readJson('packages/shared-types/package.json').version],
  ['Tauri config', readJson('apps/desktop-client/src-tauri/tauri.conf.json').version],
]);

const expected = versions.get('Cargo workspace');
const mismatches = [...versions].filter(([, version]) => version !== expected);
if (mismatches.length > 0) {
  console.error('Version drift detected:');
  for (const [name, version] of versions) console.error(`- ${name}: ${version}`);
  process.exit(1);
}

const refName = process.env.GITHUB_REF_NAME;
if (refName?.startsWith('v')) {
  const tagVersion = refName.slice(1);
  if (tagVersion !== expected) {
    console.error(`Git tag ${refName} does not match project version ${expected}.`);
    process.exit(1);
  }
}

console.log(`Version sync OK: ${expected}`);
