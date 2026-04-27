# Generated Docs Artifacts

SHA-256 hash files are the tracked drift-detection artifacts. The full JSON
baselines are generated locally (gitignored) for inspection only.

**Tracked (committed to git):**

- `config-baseline.sha256` — hashes of config baseline JSON artifacts.
- `plugin-sdk-api-baseline.sha256` — hashes of Plugin SDK API baseline artifacts.
- `sbom.cdx.json.sha256` — hash of the root CycloneDX SBOM (created on first `pnpm sbom:generate` run).
- `sbom.spdx.json.sha256` — hash of the root SPDX SBOM (created on first `pnpm sbom:generate` run).

**Local only (gitignored):**

- `config-baseline.json`, `config-baseline.core.json`, `config-baseline.channel.json`, `config-baseline.plugin.json`
- `plugin-sdk-api-baseline.json`, `plugin-sdk-api-baseline.jsonl`
- `bom/sbom.cdx.json`, `bom/sbom.spdx.json` (live in `bom/`, not here)

Do not edit any of these files by hand.

- Regenerate config baseline: `pnpm config:docs:gen`
- Validate config baseline: `pnpm config:docs:check`
- Regenerate Plugin SDK API baseline: `pnpm plugin-sdk:api:gen`
- Validate Plugin SDK API baseline: `pnpm plugin-sdk:api:check`
- Regenerate SBOMs: `pnpm sbom:generate`
- Validate SBOMs: `pnpm sbom:generate:check`
