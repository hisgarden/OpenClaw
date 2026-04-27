import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildCdxgenArgs,
  CDXGEN_PACKAGE,
  compareWithRecordedHash,
  computeArtifactSha256,
  generateSboms,
  hashRecordPath,
  parseArgs,
  resolveOutputPaths,
  SbomCliError,
  writeHashRecord,
} from "../../scripts/sbom/generate-release-sbom.mjs";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { force: true, recursive: true });
  }
});

function makeTempDir() {
  const dir = mkdtempSync(path.join(tmpdir(), "openclaw-sbom-gen-"));
  tempDirs.push(dir);
  return dir;
}

describe("parseArgs", () => {
  it("returns defaults when called with no args", () => {
    const options = parseArgs([]);
    expect(options.target).toBe("root");
    expect(options.outDir).toBe("bom");
    expect(options.check).toBe(false);
    expect(options.formats).toEqual(["cyclonedx", "spdx"]);
  });

  it("parses --target and --extension together", () => {
    const options = parseArgs(["--extension", "anthropic"]);
    expect(options.target).toBe("extension");
    expect(options.extensionId).toBe("anthropic");
  });

  it("parses --check", () => {
    expect(parseArgs(["--check"]).check).toBe(true);
  });

  it("parses --format with multiple comma-separated values", () => {
    expect(parseArgs(["--format", "cyclonedx,spdx"]).formats).toEqual(["cyclonedx", "spdx"]);
    expect(parseArgs(["--format", "cyclonedx"]).formats).toEqual(["cyclonedx"]);
  });

  it("rejects an unknown target", () => {
    expect(() => parseArgs(["--target", "weird"])).toThrow(SbomCliError);
  });

  it("rejects an unknown format", () => {
    expect(() => parseArgs(["--format", "swid"])).toThrow(SbomCliError);
  });

  it("rejects --target extension without --extension id", () => {
    expect(() => parseArgs(["--target", "extension"])).toThrow(/extension id/);
  });

  it("rejects unknown flags", () => {
    expect(() => parseArgs(["--bogus"])).toThrow(/unknown argument/);
  });
});

describe("resolveOutputPaths", () => {
  it("places root SBOMs at bom/sbom.{cdx,spdx}.json", () => {
    const paths = resolveOutputPaths({
      target: "root",
      outDir: "bom",
      formats: ["cyclonedx", "spdx"],
    });
    expect(paths.files.cyclonedx).toBe(path.join("bom", "sbom.cdx.json"));
    expect(paths.files.spdx).toBe(path.join("bom", "sbom.spdx.json"));
  });

  it("places extension SBOMs under bom/extensions/<name>.sbom.*.json", () => {
    const paths = resolveOutputPaths({
      target: "extension",
      extensionId: "anthropic",
      outDir: "bom",
      formats: ["cyclonedx"],
    });
    expect(paths.files.cyclonedx).toBe(path.join("bom", "extensions", "anthropic.sbom.cdx.json"));
  });

  it("respects a non-default outDir", () => {
    const paths = resolveOutputPaths({
      target: "root",
      outDir: "out/sbom",
      formats: ["cyclonedx"],
    });
    expect(paths.files.cyclonedx).toBe(path.join("out", "sbom", "sbom.cdx.json"));
  });
});

describe("buildCdxgenArgs", () => {
  it("includes spec-version 1.6 and the config path", () => {
    const args = buildCdxgenArgs({
      target: "root",
      outputFile: "bom/sbom.cdx.json",
      format: "cyclonedx",
    });
    expect(args).toContain("--spec-version");
    expect(args).toContain("1.6");
    expect(args).toContain("--config");
    expect(args).toContain("scripts/sbom/cdxgen-config.json");
  });

  it("adds --output-format spdx for the spdx format", () => {
    const args = buildCdxgenArgs({
      target: "root",
      outputFile: "bom/sbom.spdx.json",
      format: "spdx",
    });
    expect(args).toContain("--output-format");
    expect(args).toContain("spdx");
  });

  it("targets the extension subdirectory when --target extension", () => {
    const args = buildCdxgenArgs({
      target: "extension",
      extensionId: "anthropic",
      outputFile: "bom/extensions/anthropic.sbom.cdx.json",
      format: "cyclonedx",
    });
    expect(args).toContain(path.join("extensions", "anthropic"));
  });

  it("includes --include-subprojects for all-extensions", () => {
    const args = buildCdxgenArgs({
      target: "all-extensions",
      outputFile: "bom/all-extensions.sbom.cdx.json",
      format: "cyclonedx",
    });
    expect(args).toContain("--include-subprojects");
    expect(args).toContain("extensions");
  });
});

describe("computeArtifactSha256 / hash record helpers", () => {
  it("computes a stable sha256 over file content", () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, "artifact.json");
    writeFileSync(filePath, "hello\n", "utf8");
    expect(computeArtifactSha256(filePath)).toBe(
      // sha256("hello\n")
      "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
    );
  });

  it("hashRecordPath returns docs/.generated/<basename>.sha256", () => {
    const recordPath = hashRecordPath("bom/sbom.cdx.json");
    expect(recordPath).toBe(path.join("docs", ".generated", "sbom.cdx.json.sha256"));
  });

  it("compareWithRecordedHash returns null when hashes match", () => {
    const dir = makeTempDir();
    const artifact = path.join(dir, "a.json");
    writeFileSync(artifact, "x", "utf8");
    const record = path.join(dir, "a.json.sha256");
    writeHashRecord({ artifactPath: artifact, recordPath: record });
    expect(compareWithRecordedHash({ artifactPath: artifact, recordPath: record })).toBeNull();
  });

  it("compareWithRecordedHash flags drift when content changes", () => {
    const dir = makeTempDir();
    const artifact = path.join(dir, "a.json");
    writeFileSync(artifact, "old", "utf8");
    const record = path.join(dir, "a.json.sha256");
    writeHashRecord({ artifactPath: artifact, recordPath: record });
    writeFileSync(artifact, "new", "utf8");
    const drift = compareWithRecordedHash({ artifactPath: artifact, recordPath: record });
    expect(drift?.kind).toBe("drift");
    expect(drift?.recorded).not.toEqual(drift?.computed);
  });

  it("compareWithRecordedHash flags missing record", () => {
    const dir = makeTempDir();
    const artifact = path.join(dir, "a.json");
    writeFileSync(artifact, "x", "utf8");
    const result = compareWithRecordedHash({
      artifactPath: artifact,
      recordPath: path.join(dir, "missing.sha256"),
    });
    expect(result?.kind).toBe("missing-record");
  });

  it("writeHashRecord creates parent directories", () => {
    const dir = makeTempDir();
    const artifact = path.join(dir, "a.json");
    writeFileSync(artifact, "x", "utf8");
    const record = path.join(dir, "deep", "nested", "a.sha256");
    writeHashRecord({ artifactPath: artifact, recordPath: record });
    const recorded = readFileSync(record, "utf8");
    expect(recorded).toMatch(/^[0-9a-f]{64} {2}a\.json\n$/);
  });
});

describe("generateSboms with a stubbed cdxgen runner", () => {
  it("invokes the runner once per format and writes hash records on success", async () => {
    const dir = makeTempDir();
    const calls: Array<{ args: string[] }> = [];
    const runner = ({ args }: { args: string[] }) => {
      calls.push({ args });
      // The runner is responsible for cdxgen creating the output file. Stub it.
      const outIdx = args.indexOf("-o");
      writeFileSync(args[outIdx + 1], `{"format":"${args.at(-1)}"}`, "utf8");
      return { ok: true, code: 0, stdout: "", stderr: "" };
    };
    const results = await generateSboms(
      { target: "root", outDir: "bom", formats: ["cyclonedx", "spdx"], check: false },
      { runner, cwd: dir },
    );
    expect(calls).toHaveLength(2);
    expect(results).toHaveLength(2);
    for (const r of results) {
      expect(r.hash).toMatch(/^[0-9a-f]{64}$/);
      const recordContent = readFileSync(path.join(dir, hashRecordPath(r.outputFile)), "utf8");
      expect(recordContent).toContain(r.hash);
    }
  });

  it("throws SbomCliError when the runner fails", async () => {
    const dir = makeTempDir();
    const runner = () => ({ ok: false, code: 2, stdout: "", stderr: "boom" });
    await expect(
      generateSboms(
        { target: "root", outDir: "bom", formats: ["cyclonedx"], check: false },
        { runner, cwd: dir },
      ),
    ).rejects.toThrow(/cdxgen failed/);
  });

  it("in --check mode, returns drift details instead of overwriting records", async () => {
    const dir = makeTempDir();
    let runCount = 0;
    const runner = ({ args }: { args: string[] }) => {
      runCount += 1;
      const outIdx = args.indexOf("-o");
      // First write produces the recorded version; subsequent writes drift.
      writeFileSync(args[outIdx + 1], runCount === 1 ? "v1" : "v2", "utf8");
      return { ok: true, code: 0, stdout: "", stderr: "" };
    };
    // Seed the hash record with v1.
    await generateSboms(
      { target: "root", outDir: "bom", formats: ["cyclonedx"], check: false },
      { runner, cwd: dir },
    );
    // Now run in check mode; the stub will produce v2 → drift expected.
    const checked = await generateSboms(
      { target: "root", outDir: "bom", formats: ["cyclonedx"], check: true },
      { runner, cwd: dir },
    );
    expect(checked).toHaveLength(1);
    expect(checked[0].drift?.kind).toBe("drift");
  });
});

describe("CDXGEN_PACKAGE pin", () => {
  it("is pinned to a specific version (no floating tag)", () => {
    expect(CDXGEN_PACKAGE).toMatch(/^@cyclonedx\/cdxgen@\d+\.\d+\.\d+$/);
  });
});
