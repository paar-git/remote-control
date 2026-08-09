// Build the release notes shown inside the app's update screen from the commits
// between the previous release tag and this one.
//
// Usage: node scripts/generate-release-notes.mjs --tag v0.1.1 --output notes.md
//
// The notes are embedded verbatim into `release-manifest.json`, so this runs in
// the release workflow before the manifest is generated.

import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function git(args, { quiet = false } = {}) {
  return execFileSync('git', args, {
    encoding: 'utf8',
    // `git describe` writes "No tags can describe" to stderr when a repository
    // has no tags yet. That is an expected answer for a first release, not a
    // problem worth printing into the release log.
    stdio: quiet ? ['ignore', 'pipe', 'ignore'] : ['ignore', 'pipe', 'inherit'],
  }).trim();
}

// Conventional-commit prefixes, mapped to the headings users actually read.
// Anything unrecognised still appears, under "Other changes", so a real fix is
// never silently dropped from the notes because its prefix was unusual.
const SECTIONS = [
  { heading: 'Features', types: ['feat'] },
  { heading: 'Fixes', types: ['fix'] },
  { heading: 'Performance', types: ['perf'] },
  { heading: 'Security', types: ['security'] },
  { heading: 'Other changes', types: [] },
];

const IGNORED_TYPES = new Set(['chore', 'ci', 'build', 'test', 'style', 'docs', 'refactor']);

const HEADER = /^(?<type>[a-z]+)(?<scope>\([^)]*\))?(?<breaking>!)?:\s*(?<summary>.+)$/;

function parseCommit(line) {
  const separator = line.indexOf(' ');
  const subject = separator === -1 ? line : line.slice(separator + 1);
  const match = HEADER.exec(subject);
  if (!match?.groups) return { type: null, breaking: false, summary: subject };
  return {
    type: match.groups.type,
    breaking: match.groups.breaking === '!',
    summary: match.groups.summary,
  };
}

function previousTag(tag) {
  try {
    return git(['describe', '--tags', '--abbrev=0', `${tag}^`], { quiet: true });
  } catch {
    return null;
  }
}

function capitalise(text) {
  return text.length === 0 ? text : text[0].toUpperCase() + text.slice(1);
}

const tag = arg('tag') ?? process.env.GITHUB_REF_NAME;
if (!tag) fail('Missing --tag or GITHUB_REF_NAME.');
const output = resolve(arg('output', 'release-notes.md'));

const previous = arg('previous') ?? previousTag(tag);
const range = previous === null ? tag : `${previous}..${tag}`;

let log;
try {
  log = git(['log', '--no-merges', '--format=%H %s', range]);
} catch (error) {
  fail(`Could not read the commit range ${range}: ${error.message}`);
}

const commits = log
  .split('\n')
  .filter((line) => line.trim() !== '')
  .map(parseCommit);

const breaking = commits.filter((commit) => commit.breaking);
const grouped = new Map(SECTIONS.map((section) => [section.heading, []]));
for (const commit of commits) {
  if (commit.type !== null && IGNORED_TYPES.has(commit.type)) continue;
  const section =
    SECTIONS.find((candidate) => commit.type !== null && candidate.types.includes(commit.type)) ??
    SECTIONS.at(-1);
  grouped.get(section.heading).push(commit.summary);
}

const lines = [];
if (breaking.length > 0) {
  lines.push('Breaking changes');
  for (const commit of breaking) lines.push(`- ${capitalise(commit.summary)}`);
  lines.push('');
}
for (const { heading } of SECTIONS) {
  const entries = grouped.get(heading);
  if (entries.length === 0) continue;
  lines.push(heading);
  for (const entry of entries) lines.push(`- ${capitalise(entry)}`);
  lines.push('');
}
if (lines.length === 0) {
  lines.push(`Maintenance release ${tag.replace(/^v/, '')}.`, '');
}

writeFileSync(output, `${lines.join('\n').trimEnd()}\n`);
console.log(`Wrote ${output} from ${commits.length} commit(s) in ${range}.`);
