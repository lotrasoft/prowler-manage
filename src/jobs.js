// In-memory background jobs with captured log output, polled by the UI.
import crypto from 'node:crypto';
import { patchInstance } from './store.js';

const jobs = new Map();
const busy = new Set();

export function getJob(id) {
  return jobs.get(id);
}

export function isBusy(instanceId) {
  return busy.has(instanceId);
}

/**
 * Run `fn(log, job)` in the background for an instance. Only one job per instance at a time.
 * `busyState` is written to instance.state while running; on failure state becomes "error".
 */
export function startJob(instanceId, title, busyState, fn) {
  if (busy.has(instanceId)) throw new Error('Another operation is already running for this instance');
  const job = {
    id: crypto.randomUUID(),
    instanceId,
    title,
    status: 'running',
    log: [],
    notice: null, // instructions the UI shows above the log (e.g. certificate upload steps)
    links: [], // [{label, href}] shown as buttons in the progress dialog
    startedAt: new Date().toISOString(),
  };
  const log = (line) => {
    const text = String(line).replace(/\r/g, '');
    for (const l of text.split('\n')) if (l.trim()) job.log.push(`[${new Date().toLocaleTimeString()}] ${l}`);
    if (job.log.length > 5000) job.log.splice(0, job.log.length - 5000);
  };
  jobs.set(job.id, job);
  busy.add(instanceId);
  if (busyState) {
    try {
      patchInstance(instanceId, { state: busyState, lastJobId: job.id });
    } catch {}
  }

  (async () => {
    try {
      await fn(log, job);
      job.status = 'succeeded';
      job.notice = null;
      job.links = [];
      log('Done.');
    } catch (err) {
      job.status = 'failed';
      job.error = err.message;
      log(`ERROR: ${err.message}`);
      if (busyState) {
        try {
          patchInstance(instanceId, { state: 'error', lastError: err.message });
        } catch {}
      }
    } finally {
      job.finishedAt = new Date().toISOString();
      busy.delete(instanceId);
    }
  })();

  return job;
}
