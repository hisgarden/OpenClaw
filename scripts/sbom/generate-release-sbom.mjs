#!/usr/bin/env node
// Orchestrates SBOM generation for OpenClaw release artifacts.
//
// Phase 1 surface: argv parsing, target resolution, output-path layout, and
// the verify-mode hash-comparison logic that gates `pnpm sbom:generate:check`.
// The actual cdxgen invocation is `pnpm dlx @cyclonedx/cdxgen` so we do not
// take cdxgen on as a devDependency until Phase 2.
//
// See docs/security/audit-2026-04.md and
// docs/plans/2026-04-25-001-feat-sbom-zero-trust-solo-audit-plan.md.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

export const CDXGEN_VERSION = "11.6.0";
export const CDXGEN_PACKAGE = `@cyclonedx/cdxgen@${CDXGEN_VERSION}`;
export const SBOM_OUTPUT_DIR = "bom";
export const HASH_RECORD_DIR = path.join("docs", ".generated");
export const SUPPORTED_TARGETS = ["root", "extension", "all-extensions"];
export const SUPPORTED_FORMATS = ["cyclonedx", "spdx"];

export class SbomCliError extends Error {
  constructor(message, { exitCode = 1 } = {}) {
    super(message);
    this.name = "SbomCliError";
    this.exitCode = exitCode;
  }
}

/**
 * Parse argv (without node + script path) into a structured options object.
 * Pure function — used directly by tests.
 */
export function parseArgs(argv) {
  const options = {
    target: "root",
    extensionId: undefined,
    outDir: SBOM_OUTPUT_DIR,
    check: false,
    formats: ["cyclonedx", "spdx"],
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--check") {
      options.check = true;
    } else if (arg === "--target") {
      options.target = argv[++i];
    } else if (arg === "--extension") {
      options.target = "extension";
      options.extensionId = argv[++i];
    } else if (arg === "--out-dir") {
      options.outDir = argv[++i];
    } else if (arg === "--format") {
      options.formats = String(argv[++i] ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else {
      throw new SbomCliError(`unknown argument: ${arg}`);
    }
  }
  if (!SUPPORTED_TARGETS.includes(options.target)) {
    throw new SbomCliError(
      `unknown --target: ${options.target} (must be one of ${SUPPORTED_TARGETS.join(", ")})`,
    );
  }
  if (options.target === "extension" && !options.extensionId) {
    throw new SbomCliError("--extension requires an extension id");
  }
  for (const format of options.formats) {
    if (!SUPPORTED_FORMATS.includes(format)) {
      throw new SbomCliError(
        `unknown --format: ${format} (must be one of ${SUPPORTED_FORMATS.join(", ")})`,
      );
    }
  }
  return options;
}

/**
 * Compute the on-disk output paths for the SBOM artifacts of a single target.
 * Pure function — used directly by tests.
 */
export function resolveOutputPaths(options) {
  const { target, extensionId, outDir, formats } = options;
  const slug =
    target === "root"
      ? "openclaw"
      : target === "extension"
        ? `extensions/${extensionId}`
        : "all-extensions";
  const baseName = target === "extension" ? `${path.basename(extensionId)}.sbom` : "sbom";
  const subdir = target === "extension" ? path.join(outDir, "extensions") : outDir;
  const result = { slug, subdir, files: {} };
  for (const format of formats) {
    const ext = format === "cyclonedx" ? "cdx.json" : "spdx.json";
    result.files[format] = path.join(subdir, `${baseName}.${ext}`);
  }
  return result;
}

/**
 * Compute SHA-256 of a file's content. Throws if the file is missing.
 */
export function computeArtifactSha256(filePath) {
  const content = readFileSync(filePath);
  return createHash("sha256").update(content).digest("hex");
}

/**
 * Determine the hash-record file for a given SBOM artifact path. Mirrors the
 * docs/.generated/<basename>.sha256 convention used by config:docs:gen/check
 * and plugin-sdk:api:gen/check.
 */
export function hashRecordPath(artifactPath, hashRecordDir = HASH_RECORD_DIR) {
  const basename = path.basename(artifactPath);
  return path.join(hashRecordDir, `${basename}.sha256`);
}

/**
 * Compare a freshly computed hash against a recorded one. Returns null when
 * they match, or a structured drift object describing what changed.
 */
export function compareWithRecordedHash({ artifactPath, recordPath }) {
  const computed = computeArtifactSha256(artifactPath);
  if (!existsSync(recordPath)) {
    return {
      kind: "missing-record",
      artifactPath,
      recordPath,
      computed,
    };
  }
  const recorded = readFileSync(recordPath, "utf8").trim().split(/\s+/, 1)[0];
  if (recorded !== computed) {
    return {
      kind: "drift",
      artifactPath,
      recordPath,
      computed,
      recorded,
    };
  }
  return null;
}

/**
 * Write the hash record in the conventional `<sha256>  <basename>\n` form.
 */
export function writeHashRecord({ artifactPath, recordPath }) {
  mkdirSync(path.dirname(recordPath), { recursive: true });
  const hash = computeArtifactSha256(artifactPath);
  writeFileSync(recordPath, `${hash}  ${path.basename(artifactPath)}\n`, "utf8");
  return hash;
}

/**
 * Build the cdxgen argv for a single output. Pure function — does not invoke
 * cdxgen. The runner wraps `pnpm dlx ${CDXGEN_PACKAGE}` around this.
 */
export function buildCdxgenArgs({
  target,
  extensionId,
  outputFile,
  format,
  configPath = "scripts/sbom/cdxgen-config.json",
}) {
  const args = ["-o", outputFile, "--spec-version", "1.6", "--config", configPath];
  if (format === "spdx") {
    args.push("--output-format", "spdx");
  }
  if (target === "extension") {
    args.push(path.join("extensions", extensionId));
  } else if (target === "all-extensions") {
    args.push("--include-subprojects");
    args.push("extensions");
  }
  // root target uses the current working directory as the project root.
  return args;
}

/**
 * Spawn cdxgen via pnpm dlx. Returns { ok, stdout, stderr, code }.
 * Network-bound on first run (downloads cdxgen).
 */
function runCdxgen({ args, cwd = process.cwd() }) {
  const result = spawnSync("pnpm", ["dlx", CDXGEN_PACKAGE, ...args], {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  });
  return {
    ok: result.status === 0,
    code: result.status ?? -1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

/**
 * @typedef {Object} GenerateResult
 * @property {string} format
 * @property {string} outputFile
 * @property {string} [hash]
 * @property {{ kind: "drift" | "missing-record", artifactPath: string, recordPath: string, computed: string, recorded?: string } | null} [drift]
 */

/**
 * Generate SBOMs for the configured target. In `--check` mode, regenerates
 * to a temporary location and verifies the recorded hashes match instead of
 * overwriting. The `cwd` option roots all relative paths (subdir, output
 * files, hash records) — defaults to process.cwd() so production callers
 * keep working unchanged. Tests pass a temp dir to avoid process.chdir.
 *
 * @returns {Promise<GenerateResult[]>}
 */
export async function generateSboms(options, { runner = runCdxgen, cwd = process.cwd() } = {}) {
  const { subdir, files } = resolveOutputPaths(options);
  const absSubdir = path.resolve(cwd, subdir);
  mkdirSync(absSubdir, { recursive: true });
  const results = [];
  for (const [format, outputFile] of Object.entries(files)) {
    const absOutput = path.resolve(cwd, outputFile);
    const absTarget = options.check ? `${absOutput}.tmp.${process.pid}` : absOutput;
    const args = buildCdxgenArgs({
      target: options.target,
      extensionId: options.extensionId,
      outputFile: absTarget,
      format,
    });
    const run = runner({ args, cwd });
    if (!run.ok) {
      throw new SbomCliError(
        `cdxgen failed for ${format} (exit ${run.code}): ${run.stderr.trim() || run.stdout.trim()}`,
      );
    }
    const recordPath = path.resolve(cwd, hashRecordPath(outputFile));
    if (options.check) {
      const drift = compareWithRecordedHash({
        artifactPath: absTarget,
        recordPath,
      });
      results.push({ format, outputFile, drift });
    } else {
      const hash = writeHashRecord({ artifactPath: absOutput, recordPath });
      results.push({ format, outputFile, hash });
    }
  }
  return results;
}

const HELP_TEXT = `Usage: node scripts/sbom/generate-release-sbom.mjs [options]

Options:
  --target <root|extension|all-extensions>   What to generate for (default: root)
  --extension <id>                            Extension id (implies --target extension)
  --out-dir <path>                            Output directory (default: bom)
  --format <cyclonedx,spdx>                   Comma-separated formats (default: both)
  --check                                     Verify mode: compare against docs/.generated hashes
  -h, --help                                  Show this message

Examples:
  node scripts/sbom/generate-release-sbom.mjs
  node scripts/sbom/generate-release-sbom.mjs --target extension --extension anthropic
  node scripts/sbom/generate-release-sbom.mjs --check

Phase 1 of the SBOM/zero-trust audit. See docs/security/audit-2026-04.md.
`;

async function main(argv) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    if (error instanceof SbomCliError) {
      console.error(`[sbom] ${error.message}`);
      console.error(HELP_TEXT);
      process.exit(error.exitCode);
    }
    throw error;
  }
  if (options.help) {
    console.log(HELP_TEXT);
    return;
  }
  try {
    const results = await generateSboms(options);
    if (options.check) {
      const drifts = results.filter((r) => r.drift);
      if (drifts.length > 0) {
        for (const r of drifts) {
          const drift = r.drift;
          if (!drift) {
            continue;
          }
          if (drift.kind === "missing-record") {
            console.error(
              `[sbom] missing recorded hash for ${r.outputFile} (expected ${drift.recordPath})`,
            );
          } else {
            console.error(
              `[sbom] drift detected for ${r.outputFile}: recorded=${drift.recorded ?? ""} computed=${drift.computed}`,
            );
          }
        }
        process.exit(1);
      }
      console.log("[sbom] check ok");
    } else {
      for (const r of results) {
        console.log(`[sbom] wrote ${r.outputFile} (sha256=${r.hash ?? ""})`);
      }
    }
  } catch (error) {
    if (error instanceof SbomCliError) {
      console.error(`[sbom] ${error.message}`);
      process.exit(error.exitCode);
    }
    throw error;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
