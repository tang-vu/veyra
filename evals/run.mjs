import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const evalDirectory = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(evalDirectory, "..");
const scenarios = JSON.parse(
  readFileSync(
    path.join(evalDirectory, "scenarios", "security-and-recovery.json"),
    "utf8",
  ),
);
const startedAt = new Date();
const rustToolchain =
  process.env.VEYRA_RUST_TOOLCHAIN ??
  (process.platform === "win32" ? "stable-x86_64-pc-windows-gnu" : "stable");
const pnpm =
  process.platform === "win32"
    ? {
        command: process.execPath,
        arguments: [
          path.join(
            path.dirname(process.execPath),
            "node_modules/corepack/dist/pnpm.js",
          ),
        ],
      }
    : { command: "pnpm", arguments: [] };

const gates = {
  rust: run("cargo", [
    `+${rustToolchain}`,
    "test",
    "--workspace",
    "--all-targets",
    "--all-features",
    "--locked",
  ]),
  typescript: run(pnpm.command, [...pnpm.arguments, "test"]),
  demo: run("cargo", [
    `+${rustToolchain}`,
    "run",
    "--quiet",
    "--locked",
    "-p",
    "veyra-cli",
    "--",
    "demo",
    "--json",
  ]),
};

let demo;
try {
  const line = gates.demo.stdout.trim().split(/\r?\n/u).at(-1) ?? "";
  demo = JSON.parse(line);
} catch {
  demo = null;
}

const results = scenarios.map((scenario) => {
  const gate = gates[scenario.gate];
  const environmentLimited =
    scenario.unsupported_platforms?.includes(process.platform) === true;
  const probeObserved =
    scenario.probe === undefined || gate.stdout.includes(scenario.probe);
  const demoValid =
    scenario.gate !== "demo" ||
    (demo?.committed === true &&
      demo?.audit_valid === true &&
      demo?.rollback_state === "rolled_back" &&
      demo?.workspace_file_removed === true &&
      demo?.receipt_count === 1 &&
      demo?.verification_count === 1);
  const passed = gate.exitCode === 0 && probeObserved && demoValid;
  return {
    id: scenario.id,
    category: scenario.category,
    title: scenario.title,
    expected: scenario.expected,
    status: environmentLimited
      ? "environment_limited"
      : passed
        ? "passed"
        : "failed",
    environment_limitation: environmentLimited
      ? scenario.environment_limitation
      : null,
    evidence: {
      gate: scenario.gate,
      probe: scenario.probe ?? null,
      probe_observed: probeObserved,
      command_exit_code: gate.exitCode,
    },
  };
});

const report = {
  schema_version: "veyra.eval-results/v1",
  started_at: startedAt.toISOString(),
  completed_at: new Date().toISOString(),
  environment: {
    platform: process.platform,
    architecture: process.arch,
    rust_toolchain: rustToolchain,
    node: process.version,
  },
  summary: {
    total: results.length,
    passed: results.filter((result) => result.status === "passed").length,
    environment_limited: results.filter(
      (result) => result.status === "environment_limited",
    ).length,
    failed: results.filter((result) => result.status === "failed").length,
  },
  gates: Object.fromEntries(
    Object.entries(gates).map(([name, gate]) => [
      name,
      { exit_code: gate.exitCode, duration_ms: gate.durationMs },
    ]),
  ),
  results,
};

const resultDirectory = path.join(evalDirectory, "results");
mkdirSync(resultDirectory, { recursive: true });
writeFileSync(
  path.join(resultDirectory, "latest.json"),
  `${JSON.stringify(report, null, 2)}\n`,
);
console.log(
  `Veyra evals: ${report.summary.passed} passed, ${report.summary.environment_limited} environment-limited, ${report.summary.failed} failed in ${new Date() - startedAt}ms`,
);
if (report.summary.failed > 0) {
  for (const result of results.filter((item) => item.status === "failed")) {
    console.error(`${result.id} failed: ${result.title}`);
  }
  process.exitCode = 1;
}

function run(command, args) {
  const start = performance.now();
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    env: { ...process.env, CARGO_TERM_COLOR: "never", NO_COLOR: "1" },
  });
  return {
    exitCode: result.status ?? 1,
    durationMs: Math.round(performance.now() - start),
    stdout: `${result.stdout ?? ""}\n${result.stderr ?? ""}`,
  };
}
