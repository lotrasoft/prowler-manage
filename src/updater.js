// Self-update from GitHub.
//
//   git mode      Running from a git clone (development, Windows). Check with `git fetch`, update
//                 with `git pull --ff-only` + dependency install, then restart this process.
//   service mode  Installed by deploy/install.sh (VERSION.json next to src/). The service user can't
//                 write /opt, so it only drops a request file; the root-owned systemd path unit
//                 prowler-manage-update.path runs deploy/update.sh, which installs the current head
//                 of the configured branch and restarts the service.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { run } from './exec.js';
import { DATA_DIR } from './store.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VERSION_FILE = path.join(ROOT, 'VERSION.json');
const STATE_DIR = process.env.PROWLER_MANAGE_STATE || path.dirname(DATA_DIR); // /var/lib/prowler-manage for the service
const UPDATE_DIR = path.join(STATE_DIR, 'update');
const TOKEN_FILE = process.env.PROWLER_MANAGE_GITHUB_TOKEN_FILE || '/etc/prowler-manage/github-token';
const INSTALL_CONF = '/etc/prowler-manage/install.conf';

/** GitHub API base: api.github.com, or GITHUB_API from install.conf (GitHub Enterprise). */
function githubApi() {
  try {
    const m = fs.readFileSync(INSTALL_CONF, 'utf8').match(/^GITHUB_API=(https:\/\/\S+|http:\/\/127\.0\.0\.1:\d+\S*)$/m);
    if (m) return m[1].replace(/\/$/, '');
  } catch {}
  return 'https://api.github.com';
}
const SHA_RE = /^[0-9a-f]{40}$/;

export function mode() {
  if (fs.existsSync(path.join(ROOT, '.git'))) return 'git';
  if (fs.existsSync(VERSION_FILE)) return 'service';
  return 'none';
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

const git = async (...args) => (await run('git', ['-C', ROOT, ...args])).stdout.trim();

function parseRepo(url) {
  const m = String(url || '').match(/github\.com[:/]([^/]+\/[^/.]+?)(?:\.git)?\/?$/);
  return m ? m[1] : null;
}

function githubToken() {
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN.trim();
  try {
    return fs.readFileSync(TOKEN_FILE, 'utf8').trim();
  } catch {
    return '';
  }
}

async function github(apiPath) {
  const token = githubToken();
  const res = await fetch(`${githubApi()}${apiPath}`, {
    headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'prowler-manage', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
  if (!res.ok) {
    const hint = res.status === 404 || res.status === 401 ? (token ? ' (check the GitHub token\'s access to this repository)' : ' (private repository: install a GitHub token, see README)') : '';
    throw new Error(`GitHub API ${apiPath.split('?')[0]} → ${res.status}${hint}`);
  }
  return res.json();
}

const commitInfo = (c) => ({ sha: c.sha, short: c.sha.slice(0, 7), message: c.commit.message.split('\n')[0], author: c.commit.author?.name, date: c.commit.author?.date });

/**
 * Where this installation came from, without touching the network: the clone's origin remote
 * (git mode) or the repository recorded by deploy/install.sh (service mode).
 */
export async function source() {
  const m = mode();
  let repo = null;
  let branch = null;
  let remoteUrl = null;
  if (m === 'git') {
    remoteUrl = await git('remote', 'get-url', 'origin').catch(() => null);
    repo = parseRepo(remoteUrl);
    branch = await git('rev-parse', '--abbrev-ref', 'HEAD').catch(() => null);
  } else if (m === 'service') {
    const v = readJson(VERSION_FILE) || {};
    repo = v.repo || null;
    branch = v.branch || 'main';
  }
  const url = repo ? `https://github.com/${repo}` : remoteUrl ? remoteUrl.replace(/\/\/[^@/]+@/, '//') : null; // never show embedded credentials
  return { mode: m, repo, branch, url, branchUrl: repo && branch ? `https://github.com/${repo}/tree/${branch}` : null };
}

/** Current version, latest version on GitHub, and the commits in between. */
export async function check() {
  const m = mode();
  if (m === 'none') return { mode: m, canUpdate: false, reason: 'Not a git clone and not installed with deploy/install.sh; update manually' };

  if (m === 'git') {
    const branch = await git('rev-parse', '--abbrev-ref', 'HEAD');
    const repo = parseRepo(await git('remote', 'get-url', 'origin').catch(() => ''));
    await git('fetch', '--quiet', 'origin', branch);
    const current = await git('rev-parse', 'HEAD');
    const latest = await git('rev-parse', `origin/${branch}`);
    const log = await git('log', '--format=%H%x09%an%x09%aI%x09%s', `HEAD..origin/${branch}`);
    const commits = log ? log.split('\n').map((l) => {
      const [sha, author, date, message] = l.split('\t');
      return { sha, short: sha.slice(0, 7), author, date, message };
    }) : [];
    const ahead = Number(await git('rev-list', '--count', `origin/${branch}..HEAD`));
    const dirty = (await git('status', '--porcelain', '--untracked-files=no')).length > 0;
    let reason = null;
    if (dirty) reason = 'This clone has uncommitted changes; commit or stash them first';
    else if (ahead) reason = `This clone has ${ahead} commit(s) not on GitHub; push them first`;
    return { mode: m, repo, branch, url: repo ? `https://github.com/${repo}` : null, current: current.slice(0, 7), currentSha: current, latest: latest.slice(0, 7), latestSha: latest, commits, updateAvailable: commits.length > 0, canUpdate: commits.length > 0 && !reason, reason, lastResult: null };
  }

  const v = readJson(VERSION_FILE) || {};
  if (!v.repo) return { mode: m, canUpdate: false, reason: 'VERSION.json has no repository (installed from a copy without a GitHub remote)' };
  const head = await github(`/repos/${v.repo}/commits/${encodeURIComponent(v.branch || 'main')}`);
  // Compare installed → latest: "ahead" = newer commits on GitHub; "behind" = the installed version
  // is newer (don't downgrade); unknown = installed from a commit GitHub doesn't have.
  let commits = [];
  let relation = v.sha === head.sha ? 'identical' : 'unknown';
  if (SHA_RE.test(v.sha || '') && v.sha !== head.sha) {
    try {
      const cmp = await github(`/repos/${v.repo}/compare/${v.sha}...${head.sha}`);
      relation = cmp.status;
      commits = cmp.commits.map(commitInfo).reverse();
    } catch {
      relation = 'unknown';
    }
  }
  const updateAvailable = ['ahead', 'diverged', 'unknown'].includes(relation);
  const pending = fs.existsSync(path.join(UPDATE_DIR, 'request.json'));
  const warning =
    relation === 'unknown' ? `The installed version (${(v.sha || '?').slice(0, 7)}) is not on GitHub; updating replaces it with ${head.sha.slice(0, 7)}`
    : relation === 'diverged' ? 'The installed version has commits that are not on GitHub; updating replaces it with the GitHub version'
    : null;
  return {
    mode: m,
    repo: v.repo,
    url: `https://github.com/${v.repo}`,
    branch: v.branch || 'main',
    current: (v.sha || '').slice(0, 7) || 'unknown',
    currentSha: v.sha,
    installedAt: v.installedAt,
    latest: head.sha.slice(0, 7),
    latestSha: head.sha,
    commits,
    relation,
    warning,
    updateAvailable,
    canUpdate: updateAvailable && !pending,
    reason: pending ? 'An update is already queued' : relation === 'behind' ? 'The installed version is newer than GitHub' : null,
    lastResult: readJson(path.join(UPDATE_DIR, 'status.json')),
  };
}

/** The running version (for the UI to notice a restart onto a new version). */
export async function currentVersion() {
  const m = mode();
  if (m === 'git') return { mode: m, sha: await git('rev-parse', 'HEAD').catch(() => null) };
  if (m === 'service') return { mode: m, sha: readJson(VERSION_FILE)?.sha || null };
  return { mode: m, sha: null };
}

/** Apply the update. Resolves once the update is underway; the process restarts afterwards. */
export async function update(log, { shutdown }) {
  const m = mode();
  if (m === 'service') {
    // Only a trigger: the root updater ignores any content and installs the branch head itself.
    fs.mkdirSync(UPDATE_DIR, { recursive: true });
    fs.writeFileSync(path.join(UPDATE_DIR, 'request.json'), JSON.stringify({ requestedAt: new Date().toISOString() }));
    log('Update requested; the system updater installs it and restarts the manager (about a minute)');
    return { restarting: true };
  }
  if (m !== 'git') throw new Error('Self-update is not available for this installation');

  const branch = await git('rev-parse', '--abbrev-ref', 'HEAD');
  log(`git pull --ff-only origin ${branch}`);
  await run('git', ['-C', ROOT, 'pull', '--ff-only', 'origin', branch], { log });
  log('Installing dependencies');
  const pnpm = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm';
  try {
    await run(pnpm, ['install', '--frozen-lockfile'], { cwd: ROOT, log, shell: process.platform === 'win32' });
  } catch (e) {
    log(`pnpm not usable (${e.message.split('\n')[0]}); trying npx`);
    await run(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['--yes', 'pnpm', 'install', '--frozen-lockfile'], { cwd: ROOT, log, shell: process.platform === 'win32' });
  }

  if (process.execArgv.some((a) => a.startsWith('--watch'))) {
    log('Running under node --watch: it restarts on the changed files by itself');
    return { restarting: true };
  }
  // Start a fresh copy of this process (it waits for the port), then exit.
  const logFile = path.join(DATA_DIR, 'manager.log');
  const out = fs.openSync(logFile, 'a');
  const child = spawn(process.execPath, [...process.execArgv, ...process.argv.slice(1)], {
    cwd: process.cwd(),
    env: process.env,
    detached: true,
    stdio: ['ignore', out, out],
    windowsHide: true,
  });
  child.unref();
  log(`Restarting (new process ${child.pid}; its output goes to ${logFile})`);
  setTimeout(shutdown, 1500);
  return { restarting: true };
}
