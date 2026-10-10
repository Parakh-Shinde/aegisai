import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const runId = process.env.RUN_ID;
const apiBaseUrl = (process.env.AEGISAI_TOOL_RUNNER_API_URL || 'http://api:8000').replace(/\/$/, '');
const token = process.env.AEGISAI_TOOL_RUNNER_TOKEN;

if (!runId || !token) {
  console.error('RUN_ID and AEGISAI_TOOL_RUNNER_TOKEN are required.');
  process.exit(2);
}

const headers = {
  'Content-Type': 'application/json',
  'X-AEGISAI-Tool-Runner-Token': token,
};

async function api(path, options = {}) {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    ...options,
    headers: { ...headers, ...(options.headers || {}) },
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`AEGISAI runner API ${response.status}: ${text.slice(0, 600)}`);
  }
  return text ? JSON.parse(text) : {};
}

function toolVersion() {
  const result = spawnSync('promptfoo', ['--version'], { encoding: 'utf8' });
  return (result.stdout || result.stderr || process.env.AEGISAI_PROMPTFOO_VERSION || 'unknown')
    .trim()
    .slice(0, 80);
}

async function markFailed(message) {
  try {
    await api(`/tool-evaluations/runner/runs/${encodeURIComponent(runId)}/fail`, {
      method: 'POST',
      body: JSON.stringify({ error_summary: String(message).slice(0, 1000) }),
    });
  } catch (error) {
    console.error(`Could not report runner failure: ${error.message}`);
  }
}

try {
  const claim = await api(`/tool-evaluations/runner/runs/${encodeURIComponent(runId)}/claim`, {
    method: 'POST',
  });
  const configPath = '/tmp/promptfoo.json';
  const reportPath = '/tmp/promptfoo-report.json';
  writeFileSync(configPath, JSON.stringify(claim.config, null, 2));

  const result = spawnSync(
    'promptfoo',
    [
      'eval',
      '--config', configPath,
      '--output', reportPath,
      '--no-share',
      '--no-progress-bar',
      '--no-cache',
    ],
    {
      encoding: 'utf8',
      timeout: Number.parseInt(process.env.AEGISAI_TOOL_RUNNER_TIMEOUT_MS || '180000', 10),
      env: {
        ...process.env,
        OLLAMA_BASE_URL: claim.ollama_base_url,
        PROMPTFOO_DISABLE_TELEMETRY: 'true',
        PROMPTFOO_DISABLE_UPDATE_CHECK: 'true',
      },
    },
  );

  if (!existsSync(reportPath)) {
    const detail = [result.error?.message, result.stderr, result.stdout]
      .filter(Boolean)
      .join(' ')
      .trim();
    throw new Error(`Promptfoo did not produce a report. ${detail}`.slice(0, 1000));
  }
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  const completed = await api(`/tool-evaluations/runner/runs/${encodeURIComponent(runId)}/complete`, {
    method: 'POST',
    body: JSON.stringify({ tool_version: toolVersion(), report }),
  });
  console.log(JSON.stringify(completed));
  if (result.status && result.status !== 0) {
    console.warn(`Promptfoo returned ${result.status}; AEGISAI imported its completed findings.`);
  }
  process.exit(0);
} catch (error) {
  await markFailed(error.message || error);
  console.error(error.stack || error.message || error);
  process.exit(1);
}
