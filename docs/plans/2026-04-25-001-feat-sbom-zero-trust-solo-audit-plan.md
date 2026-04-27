---
title: "feat: SBOM, Zero Trust, and Solo-Maintainer Audit + Remediation"
type: feat
status: active
date: 2026-04-25
---

# feat: SBOM, Zero Trust, and Solo-Maintainer Audit + Remediation

## Overview

OpenClaw has accumulated substantial security infrastructure (CodeQL, Dependabot across 6 ecosystems, `detect-secrets` with a 13k-line baseline, OIDC trusted-publishing for npm, strict ws/wss policy, CODEOWNERS to `@openclaw/secops`, a bespoke `scripts/sbom-risk-report.mjs`) — and equally substantial complexity (~443k LOC across 7,025 `src/` TS files, 109 extensions, 28 workflows, 314 root npm scripts, 8 release pipelines, 5 app platforms).

This plan does two things:

1. **Audit** — produce a single durable findings document at `docs/security/audit-2026-04.md` that captures the current SBOM, zero-trust, and solo-maintainability posture with cited evidence. This is the deliverable.
2. **Remediate** — a prioritized roadmap of independent, mergeable units that close the highest-leverage gaps: CycloneDX SBOM in CI, GitHub artifact attestations + Docker provenance, VEX scaffold for EU CRA, plugin-capability declarations, ghcr OIDC, and a solo-maintainer "what we said no to" register.

Each remediation unit is independently shippable. The user picks which to actually pursue based on the audit's risk ranking. Nothing here is a one-shot rewrite.

---

## Problem Frame

Three lenses, three pressures:

- **SBOM.** Current `scripts/sbom-risk-report.mjs` produces a bespoke `schemaVersion:1` JSON over the pnpm lockfile — useful internally for ownership tracking, but not consumable by any external scanner, regulator, or downstream user. Zero SPDX/CycloneDX output anywhere in the repo or release artifacts. Docker `provenance: false` is set explicitly four times across `docker-release.yml`, `install-smoke.yml`, `npm-telegram-beta-e2e.yml`, `openclaw-live-and-e2e-checks-reusable.yml`. EU CRA vulnerability-reporting obligations bind on **2026-09-11** (≈4.5 months from today) and full SBOM-in-technical-documentation obligations on **2027-12-11**. OpenClaw is in the EU's Important-Product-Class-II discussion frame as a network-connected developer tool; assume in scope.

- **Zero Trust.** The gateway is **explicitly single-operator-trusted** by design (`SECURITY.md` lines 98-122). Shared-bearer auth grants full operator + owner-sender; per-request `x-openclaw-scopes` is ignored under shared-secret. This is a documented product decision, not a gap. The actual gaps are downstream of that: ghcr publish uses static `secrets.GITHUB_TOKEN` rather than registry-OIDC; Docker images carry no provenance attestation; plugin install gives full host trust with only a 1-entry hardcoded denylist + `plugins.allow` allowlist as mitigations; secret rotation policy is not codified; outbound network destinations are not allowlisted/observed.

- **Solo-maintainer suitability.** The artifact set indicates a project built for a small team (CODEOWNERS, `@openclaw/secops`, named maintainer agents `$openclaw-{pr,release,ghsa}-maintainer`, owner-only Carbon pin governed by `@thewilloftheshadow`) but with one primary developer carrying it. Industry data places this firmly in the "Large surface" tier where 80-100% of a 40h week goes to maintenance toil without aggressive automation. The agent-driven workflows already in place are the right mitigation; the missing piece is a written register of what has been deliberately frozen, deferred, or said-no-to so that triage is mechanical rather than re-deliberated.

Source: research synthesized from `ce-repo-research-analyst` (full repo scan, 2026-04-25) and `ce-best-practices-researcher` (2026 SBOM/zero-trust/solo-maintainer industry survey) — see Sources section.

---

## Requirements Trace

- R1. Audit document captures, with cited evidence, the current SBOM tooling, signing posture, dependency-pinning posture, secret-handling posture, plugin trust model, network posture, CI/CD trust posture, and solo-maintainer surface metrics. Lives at `docs/security/audit-2026-04.md`. Re-runnable annually.
- R2. CycloneDX 1.6 (primary) and SPDX 3.0.1 (secondary) SBOMs are generated in CI for every release and attached to GitHub Releases, the npm tarball metadata, and the GHCR container image as OCI referrers.
- R3. Every released artifact (npm tarball, Docker image, macOS DMG) carries a GitHub Artifact Attestation (`actions/attest-build-provenance`) bound to its digest, plus an SBOM attestation (`actions/attest-sbom`) — reaching SLSA Build Level 3 via GitHub-native primitives.
- R4. Docker images stop opting out of buildx provenance (`provenance: false` removed where it is currently set just to silence noise) and a VEX (`bom.vex.json`, CycloneDX VEX) document is published per release stating `not_affected` for known transitive CVEs that don't affect OpenClaw, with justifications.
- R5. Plugin loader gains a manifest-declared capability layer (network/fs/process/secrets) that the loader can enforce or warn on, and `src/plugins/dependency-denylist.ts` is extended to consume an externally-maintained list (file or remote registry) rather than a hardcoded one-entry array. Trust model itself is not changed.
- R6. ghcr.io publish in `docker-release.yml` switches to OIDC where viable (or the rationale for staying on `GITHUB_TOKEN` is documented in SECURITY.md); `npm audit signatures` runs in CI on every PR.
- R7. A "what we said no to" register lives at `docs/maintenance/scope-guardrails.md` enumerating frozen contracts, deferred features, owner-only decisions, and platforms/integrations explicitly out of scope — so triage is mechanical.
- R8. The existing bespoke `scripts/sbom-risk-report.mjs` is wired into a CI workflow (currently the script and its `deps:sbom-risk:check` lane exist but no workflow invokes them) so ownership-gap regressions block merges.

---

## Scope Boundaries

- **Not changing** the single-operator gateway trust model. That is a product decision in `SECURITY.md` and out of scope for this plan. Per-request scope splitting on the shared-secret HTTP path is a separate product proposal (route to `ce-brainstorm` if pursued).
- **Not changing** the in-process plugin loading model. Capability declarations (R5) are a _layer_ on top, not a replacement. Process-isolated/`worker_threads`-isolated plugin execution is a follow-up topic, not this plan.
- **Not building** a custom signing infrastructure. All signing uses GitHub-native + sigstore + npm provenance; no key custody added.
- **Not consolidating** the 28 CI workflows or the 314 npm scripts. That is a separate refactor and would compete with release stability during the EU CRA runway.
- **Not addressing** mobile-platform-specific signing (iOS/Android) — Sparkle EdDSA for macOS auto-update is already in place; iOS goes through App Store, Android through Play, both with their own attestation chains.

### Deferred to Follow-Up Work

- Per-request scope enforcement on shared-secret bearer auth: separate `ce-brainstorm` (product-shape question, not technical).
- Process-isolated plugin runtime (`worker_threads` + Node `--permission`): separate plan after R5 lands and we have a year of capability-declaration data.
- CI-workflow consolidation (target <15 from current 28): separate refactor plan.
- Sibling `../openclaw.ai` installer-repo audit: out of scope here; needs its own pass.

---

## Context & Research

### Relevant Code and Patterns

- `scripts/sbom-risk-report.mjs` — existing bespoke risk reporter; ownership ledger at `scripts/lib/dependency-ownership.json`. Wired into `deps:sbom-risk` and `deps:sbom-risk:check` package.json scripts. **Not** invoked from any workflow yet.
- `scripts/root-dependency-ownership-audit.mjs` — companion ownership audit.
- `scripts/stage-bundled-plugin-runtime-deps.mjs` + `scripts/runtime-postbuild.mjs` + `scripts/copy-bundled-plugin-metadata.mjs` + `scripts/test-built-bundled-runtime-deps.mjs` — already track per-extension bundled runtime deps with content-hashed stamps. The natural seam to emit per-extension SBOMs from.
- `src/plugins/install.ts` — references `NpmIntegrityDrift` type; loader already has internal awareness of npm tarball integrity hashes.
- `src/plugins/dependency-denylist.ts` — current 1-entry hardcoded denylist (`plain-crypto-js`); the seam for R5's externalized list.
- `.github/workflows/openclaw-npm-release.yml:281,286-289,366` — the existing OIDC + provenance + verify-tarball pattern. Mirror this for Docker and DMG.
- `.github/workflows/codeql.yml` — established daily scan pattern; SBOM-generation workflow can mirror its `Blacksmith 16vcpu` scheduling and concurrency posture.
- `.github/dependabot.yml` — already has `cooldown: default-days: 2` (good supply-chain posture); npm `minimumReleaseAge: 2880` (48h) in `pnpm-workspace.yaml` reinforces this.
- `docs/.generated/*.sha256` — established pattern for tracking generated-artifact hashes in-repo without committing the full JSON. SBOMs should follow this convention.
- `SECURITY.md` — already documents trust boundaries clearly; audit document and remediations should cite specific line ranges and link back rather than re-derive.

### Institutional Learnings

- `docs/solutions/` — searched; no prior SBOM, attestation, or VEX learnings exist. This plan is greenfield in that area. (Once R2-R4 land, an `ce-compound` writeup of the chosen SBOM toolchain and per-release publish flow will be valuable for future maintainers.)
- The architecture rule "manifest-first control plane; targeted runtime loaders; no hidden contract bypasses" (root `AGENTS.md`) is the existing precedent that R5 (manifest-declared capabilities) should align with.

### External References

- CycloneDX 1.6 spec — chosen as primary SBOM format for npm-ecosystem fit, native VEX support, and EU CRA TR-03183-2 endorsement. SPDX 3.0.1 emitted secondarily for federal-procurement consumers.
- `@cyclonedx/cdxgen` — primary generator for source SBOMs (understands pnpm workspaces).
- `syft` — secondary generator for built artifacts (Docker layers, macOS `.app` bundles).
- `actions/attest-build-provenance@v2`, `actions/attest-sbom@v2` — GitHub-native sigstore-backed attestation actions; reach SLSA Build L3 without custom key custody.
- `npm audit signatures` — registry-signature verification on every install.
- EU CRA timeline: in force 2024-12-10; vuln-reporting obligations bind 2026-09-11; full SBOM/technical-documentation obligations bind 2027-12-11.
- Supply-chain attack pattern (2026): Shai-Hulud npm worm; Axios-namespace Sapphire-Sleet compromise (2026-03-31); Trivy reportedly compromised twice March 2026 (audit before relying on it).

### Slack Context

Not gathered — Slack tooling not detected as configured in this session and not requested by user. If organizational context exists for the security-officer (`Jamieson O'Reilly`), the `@openclaw/secops` group, or prior CRA-readiness discussions, ask for a Slack search before R1 ships.

---

## Key Technical Decisions

- **CycloneDX 1.6 primary, SPDX 3.0.1 secondary.** Rationale: CycloneDX is the npm-ecosystem default consumer format and natively carries VEX. SPDX is added for federal-procurement consumers and EU CRA breadth. Dual-publish has near-zero marginal cost from cdxgen.
- **`@cyclonedx/cdxgen` for source SBOMs, `syft` for built-artifact SBOMs.** Rationale: cdxgen understands pnpm workspaces; syft understands Docker layers and `.app` bundles. Use the right tool per surface.
- **GitHub Artifact Attestations + npm provenance + sigstore (keyless via OIDC) — no self-managed signing keys.** Rationale: The only signing key OpenClaw should custody is the existing Sparkle EdDSA key. Adding more single-owner keys increases bus-factor risk; keyless OIDC eliminates rotation entirely.
- **Per-extension SBOMs are CI artifacts only, not release-bundled.** Rationale: 109 extensions × per-release would bloat the release page. Generate on extension-touched lanes via `pnpm changed:lanes`; aggregate root SBOM ships with releases.
- **Plugin capability declarations are advisory in v1 (warn, don't block).** Rationale: 109 first-party extensions need a soak period to declare capabilities accurately before the loader enforces. Flip to enforced in a follow-up after one release cycle.
- **External denylist source is a JSON file under `src/plugins/`, not a remote registry, for v1.** Rationale: keeps the loader hermetic; remote-registry pull adds a new trust dependency. Revisit once Socket.dev integration is considered.
- **Audit document is markdown in-repo, not a PDF or external doc.** Rationale: lives next to the code it describes; diff-able year over year; CODEOWNERS-gated.
- **Wire existing `deps:sbom-risk:check` into CI before adding new SBOM tooling.** Rationale: cheap quick win; the script already exists and is tested. Validates the in-CI plumbing before adding cdxgen.

---

## Open Questions

### Resolved During Planning

- _Which SBOM format?_ → CycloneDX 1.6 primary, SPDX 3.0.1 secondary (above).
- _Is the trust-model change in scope?_ → No, explicitly out (Scope Boundaries).
- _Should the 1-entry hardcoded denylist be replaced by Socket.dev or similar?_ → Not in v1; externalize to a JSON file under repo control first.

### Deferred to Implementation

- _Exact Blacksmith vs ubuntu-latest split for the SBOM generation job_ — depends on cdxgen runtime on the actual lockfile size. Decide during U2.
- _Whether `actions/attest-sbom` accepts both CycloneDX and SPDX in one call or requires two attestations per artifact_ — verify against current action docs during U3.
- _Per-extension SBOM regeneration trigger_ — `pnpm changed:lanes` integration may need a new lane; defer to U2 implementation.
- _Whether ghcr OIDC requires repository-level config changes that affect other workflows_ — investigate during U6; if it does, scope creep risk → document and stay on `GITHUB_TOKEN` for v1.
- _Capability vocabulary for plugin manifests (R5)_ — the exact set of capability strings (`net.outbound`, `fs.read`, etc.) emerges from surveying what existing extensions actually do. Defer to U5.

---

## High-Level Technical Design

> _This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce._

### Release-time SBOM + attestation pipeline

```
                           +-----------------------------+
                           |  release tag pushed (npm,   |
                           |  docker, macos)             |
                           +--------------+--------------+
                                          |
        +---------------------------------+----------------------------------+
        |                                 |                                  |
        v                                 v                                  v
+-------+--------+              +---------+---------+               +--------+--------+
| openclaw-npm-  |              | docker-release.yml|               | macos-release.yml|
| release.yml    |              | (multi-arch)      |               | (Sparkle DMG)    |
| (already OIDC) |              |                   |               |                  |
+-------+--------+              +---------+---------+               +--------+--------+
        |                                 |                                  |
        v                                 v                                  v
   cdxgen --> SBOM      syft scan image --> SBOM       syft scan .app --> SBOM
        |                                 |                                  |
        v                                 v                                  v
 attest-build-provenance  attest-build-provenance        attest-build-provenance
 attest-sbom              attest-sbom + cosign sign     attest-sbom
        |                                 |                                  |
        v                                 v                                  v
 npm publish --provenance  push to ghcr (provenance: true,    upload DMG + sbom +
   (existing)              attestation OCI referrer)          attestations to GH Release
```

Key shape: each release workflow grows two steps (generate SBOM, attest), reuses GitHub-native actions, no external service dependencies beyond sigstore (already used implicitly via npm provenance).

### Plugin capability layer (R5)

```
plugin manifest (extension package.json)
   "openclawCapabilities": {
       "net.outbound": ["api.anthropic.com", "*.openai.com"],
       "fs.read": ["~/.openclaw/credentials/anthropic"],
       "process.spawn": false,
       "secrets.read": ["anthropic.api_key"]
   }
                 |
                 v
   +----------- loader (src/plugins/install.ts) -----------+
   | v1: PARSE + LOG; mismatch with observed runtime calls |
   |     emits a warning to the structured log.            |
   | v2 (future plan): ENFORCE — refuse undeclared call.   |
   +-------------------------------------------------------+
```

Advisory-mode v1 keeps blast radius near zero (no extension breaks) while building the capability data needed to design the v2 enforcement model.

---

## Output Structure

New files this plan creates:

    docs/
      security/
        audit-2026-04.md           (R1 — the audit deliverable)
      maintenance/
        scope-guardrails.md        (R7 — the say-no register)
    .github/
      workflows/
        sbom-and-attest.yml        (R2/R3 — central SBOM workflow, may be invoked from release workflows)
    scripts/
      sbom/
        cdxgen-config.json         (cdxgen config: include workspaces, exclude qa-*)
        generate-release-sbom.mjs  (orchestrates cdxgen + syft per release surface)
    src/plugins/
      capabilities.ts              (manifest schema + parse + warn)
      capabilities.test.ts
      dependency-denylist.json     (externalized list, replaces hardcoded array)
    bom/
      vex/
        README.md                  (how the VEX file is curated per release)

Existing files modified (not exhaustive — see per-unit Files lists):

    .github/workflows/ci.yml                       (wire deps:sbom-risk:check)
    .github/workflows/docker-release.yml           (remove provenance: false; add attest)
    .github/workflows/openclaw-npm-release.yml     (add SBOM generation + attest-sbom)
    .github/workflows/macos-release.yml            (add syft + attest)
    src/plugins/install.ts                         (consume capabilities.ts)
    src/plugins/dependency-denylist.ts             (load from JSON file)
    SECURITY.md                                    (link audit doc; document any ghcr OIDC decision)
    package.json                                   (add sbom:* scripts)

This is a scope declaration. The implementer may adjust layout if implementation reveals a better structure; per-unit Files sections remain authoritative.

---

## Implementation Units

- U1. **Audit findings document**

**Goal:** Produce `docs/security/audit-2026-04.md` codifying the current SBOM, zero-trust, and solo-maintainability state with cited evidence — the deliverable the user asked for.

**Requirements:** R1

**Dependencies:** None (research already done in this planning phase; reuses ce-repo-research-analyst output)

**Files:**

- Create: `docs/security/audit-2026-04.md`
- Modify: `SECURITY.md` (add link to audit doc under a new "Audit history" section near the top)
- Modify: `.github/CODEOWNERS` (gate `docs/security/` to `@openclaw/secops`)

**Approach:**

- Three top-level sections (SBOM, Zero Trust, Solo-Maintainer Surface), each with: "What exists" (with file/line citations), "What is missing" (concrete, observational, not prescriptive), "Risk classification" (high/med/low with one-line rationale).
- A summary table at the top: dimension × current state × target state × this-plan-unit-that-addresses-it (cross-link to U2-U8 IDs).
- An appendix listing every cited file with its observed responsibility — serves as a reading map for the next auditor.
- Do **not** restate trust-model design decisions as gaps; cite SECURITY.md and move on.
- Date-stamp the doc and explicitly mark it re-runnable annually (next due 2027-04).

**Patterns to follow:**

- `SECURITY.md` voice: telegraph-style, concrete, no marketing.
- Citation style: `path/to/file.ts:LINE` per repo convention.

**Test scenarios:**

- _Test expectation: none — pure documentation unit. Verification is reviewer signoff that every claim has a cited file/line and that no claim contradicts current main._

**Verification:**

- `@openclaw/secops` reviews and signs off.
- `pnpm check:docs` (markdown-lint) passes against the new file.
- A spot-check finds at least one citation per top-level claim.

---

- U2. **CycloneDX + SPDX SBOM generation in CI**

**Goal:** Generate a root CycloneDX 1.6 + SPDX 3.0.1 SBOM on every release; per-extension SBOMs on extension-touched changed lanes. Wire the existing `deps:sbom-risk:check` into the same workflow so ownership-gap regressions also block.

**Requirements:** R2, R8

**Dependencies:** U1 (audit doc establishes the rationale and is linked from the workflow)

**Files:**

- Create: `.github/workflows/sbom-and-attest.yml` (callable workflow; release workflows invoke it)
- Create: `scripts/sbom/cdxgen-config.json`
- Create: `scripts/sbom/generate-release-sbom.mjs`
- Create: `test/scripts/generate-release-sbom.test.ts`
- Modify: `package.json` — add `sbom:generate`, `sbom:generate:check`, `sbom:per-extension` scripts; ensure `deps:sbom-risk:check` is reachable by name from the workflow
- Modify: `.github/workflows/ci.yml` — add a `sbom-risk-check` job that runs `pnpm deps:sbom-risk:check` on PRs (cheap, ~seconds)
- Modify: `docs/.generated/` — register `sbom.cdx.json.sha256` and `sbom.spdx.json.sha256` (do not commit the full JSON, per existing convention)

**Approach:**

- `sbom-and-attest.yml` is a `workflow_call` reusable workflow with inputs `{artifact-type: npm|docker|macos, artifact-path, artifact-digest}`. Generates SBOM(s) with cdxgen (source) or syft (built artifact) based on `artifact-type`. Outputs SBOM file paths for the calling workflow to attest in U3.
- `generate-release-sbom.mjs` orchestrates: `cdxgen -t npm -o bom.cdx.json --spec-version 1.6 --include-formulation --required-only`, then converts to SPDX via cdxgen's built-in converter, then validates schema.
- Per-extension SBOMs are generated only when `pnpm changed:lanes --json` indicates the extension lane is dirty; uploaded as workflow artifacts (not release assets). A new lane `sbom` may be needed in `scripts/changed-lanes.mjs`.
- The existing `scripts/sbom-risk-report.mjs` ownership check runs in parallel; failure of either job fails the parent release workflow.
- Cap workflow runtime: cdxgen on a 1497-package lockfile typically completes in 60-180s on Blacksmith 16vcpu; if it exceeds 5 minutes, switch to ubuntu-latest large.

**Execution note:** Add the unit test for `generate-release-sbom.mjs` first against a fixture pnpm workspace; then wire the workflow. The orchestrator script is the regression-prone surface, not the generated SBOM itself.

**Patterns to follow:**

- Reusable workflow shape: `.github/workflows/openclaw-cross-os-release-checks-reusable.yml`, `openclaw-live-and-e2e-checks-reusable.yml`.
- Generated-artifact hashing: see how existing `pnpm config:docs:gen/check`, `pnpm plugin-sdk:api:gen/check`, and the `docs/.generated/*.sha256` pattern work.
- Workflow permissions: minimal at workflow level (`contents: read`), elevate per job; mirror `.github/workflows/codeql.yml`.

**Test scenarios:**

- _Happy path:_ `generate-release-sbom.mjs` against a fixture pnpm workspace produces a valid CycloneDX 1.6 JSON that passes cdxgen's schema validator; component count matches the lockfile's `packages` count within ±1.
- _Happy path:_ SPDX conversion produces a valid SPDX 3.0.1 document; same component count.
- _Edge case:_ a workspace with zero `dependencies` (a `packages/*` package that is type-only) emits a valid SBOM with `components: []` rather than failing.
- _Edge case:_ `pnpm.overrides` substitutions (e.g., `request -> @cypress/request`) appear in the SBOM under their _resolved_ name, not the manifest name — verify this matches CycloneDX 1.6 expectations.
- _Error path:_ cdxgen exit code != 0 propagates as a failed CI job; stderr is captured in the workflow log.
- _Error path:_ schema-validation failure on the generated SBOM blocks the release workflow with a clear error.
- _Integration:_ `sbom-and-attest.yml` invoked from a synthetic test workflow with `artifact-type: npm` produces an artifact upload; downstream attest job in U3 can consume it without path mangling.
- _Integration:_ `pnpm deps:sbom-risk:check` failing (synthetic ownership gap) blocks the parent CI workflow.

**Verification:**

- A dry-run release produces both `bom.cdx.json` and `bom.spdx.json` as workflow artifacts.
- Component counts within ±2 between CycloneDX and SPDX outputs (both derive from the same lockfile).
- `pnpm sbom:generate:check` is added to the `pnpm check` aggregate.

---

- U3. **Build provenance and SBOM attestations (SLSA L3)**

**Goal:** Every released artifact (npm tarball, GHCR Docker image, macOS DMG) carries a sigstore-backed `actions/attest-build-provenance` attestation bound to its digest, plus an `actions/attest-sbom` attestation pointing at the U2 SBOMs.

**Requirements:** R3

**Dependencies:** U2

**Files:**

- Modify: `.github/workflows/openclaw-npm-release.yml` (add attest steps after publish)
- Modify: `.github/workflows/docker-release.yml` (add attest steps; coordinated with U4)
- Modify: `.github/workflows/macos-release.yml` (add syft scan + attest after notarization)
- Modify: `.github/workflows/sbom-and-attest.yml` from U2 (add `attest-sbom` step optionally invokable per artifact)
- Modify: `SECURITY.md` (add "Verifying release artifacts" section with `gh attestation verify` and `cosign verify-attestation` examples)

**Approach:**

- npm path: existing `id-token: write` + `npm publish --provenance` already gives us npm-side provenance (verifiable via `npm audit signatures`). Add `actions/attest-sbom@v2` post-publish referencing the published tarball SHA512 and the U2 SBOM. Add `actions/attest-build-provenance@v2` for the build itself.
- Docker path: enable `provenance: true` on `docker/build-push-action` (coordinated with U4 — currently set to `false` in 4 places); add `actions/attest-build-provenance@v2` with `subject-name: ghcr.io/openclaw/openclaw` and `push-to-registry: true`.
- macOS path: after `scripts/codesign-mac-app.sh` and notarization complete, run `syft <app-bundle> -o cyclonedx-json > bom.macos.cdx.json`, then attest. DMG is the subject; the `.app` is part of the SBOM.
- All attestations are sigstore-backed via OIDC — no key custody added.
- Document verification commands in SECURITY.md so downstream consumers can check.

**Patterns to follow:**

- Existing OIDC + `id-token: write` block in `.github/workflows/openclaw-npm-release.yml:281-289`.
- Trusted-publishing environment guard `environment: npm-release` — replicate as `docker-release` and `macos-release` environments with the same dispatch-ref allowlist (`refs/heads/main` or `refs/heads/release/YYYY.M.D`).

**Test scenarios:**

- _Happy path:_ npm release dry-run produces both a `provenance` claim (verifiable via `npm audit signatures @openclaw/openclaw@<version>`) and a sigstore-backed SBOM attestation (verifiable via `gh attestation verify --owner openclaw <tarball>`).
- _Happy path:_ Docker release pushes an image to GHCR with both provenance and SBOM as OCI referrers; `cosign tree ghcr.io/openclaw/openclaw@<digest>` lists them.
- _Happy path:_ macOS DMG release uploads the DMG, the SBOM, and the attestation bundle as GitHub Release assets.
- _Edge case:_ a re-run of a release (idempotency) does not double-publish attestations or fail on duplicate-subject detection — sigstore tolerates this but the workflow should not error.
- _Error path:_ attestation step failure does **not** unpublish the artifact (npm/Docker push happened first), but **does** mark the workflow as failed and block the release-checks gate. Manual recovery procedure documented in SECURITY.md.
- _Integration:_ `gh attestation verify --owner openclaw dist/openclaw-<v>.tgz` returns 0 against an actual published tarball from a test release.
- _Integration:_ `cosign verify-attestation --type cyclonedx --certificate-identity-regexp ".+/openclaw/.+" ghcr.io/openclaw/openclaw@<digest>` returns 0 against an actual pushed image.

**Verification:**

- All three release workflows produce verifiable attestations on a dry-run release tag.
- `SECURITY.md` "Verifying release artifacts" section includes copy-pasteable commands that work against the dry-run.
- The next real release publishes attestations end-to-end.

---

- U4. **Enable Docker buildx provenance + remove blanket `provenance: false`**

**Goal:** Audit each of the 4 `provenance: false` settings, remove the ones added only to silence noise, and document why any remaining ones are intentional.

**Requirements:** R4 (partial — pairs with U3 for the attestation side)

**Dependencies:** U3 (so provenance enablement coincides with attestation generation; otherwise we'd briefly publish provenance-tagged images with no attestation chain)

**Files:**

- Modify: `.github/workflows/docker-release.yml` (lines 164, 180, 281, 297)
- Modify: `.github/workflows/install-smoke.yml` (4 places per audit findings)
- Modify: `.github/workflows/npm-telegram-beta-e2e.yml`
- Modify: `.github/workflows/openclaw-live-and-e2e-checks-reusable.yml`
- Modify: `SECURITY.md` (note any intentional `provenance: false` retentions and rationale — e.g., E2E test images that are never published)

**Approach:**

- For each `provenance: false`, classify: **(a) published image** → flip to `provenance: true`, **(b) ephemeral test image never pushed** → keep `provenance: false` and add a comment explaining why.
- Expectation: `docker-release.yml` flips to `true` (published); `install-smoke.yml`, `npm-telegram-beta-e2e.yml`, and the live/e2e reusable likely stay `false` since those images are pulled into smoke tests and discarded.
- Comment format: `# provenance: false intentional — see SECURITY.md "Test-image provenance policy"`.

**Patterns to follow:**

- `docker/build-push-action` v6+ supports `provenance: mode=max` for full SLSA provenance; `mode=min` is also valid. Default to `mode=max` for published images.

**Test scenarios:**

- _Happy path:_ `docker-release.yml` dry-run produces an image whose `docker buildx imagetools inspect <digest> --format '{{json .Provenance}}'` returns non-empty SLSA provenance.
- _Edge case:_ `install-smoke.yml` continues to pass with its `provenance: false` retained (smoke time should not regress).
- _Integration:_ the U3 `attest-build-provenance` step succeeds against the U4-enabled provenance-bearing image (they don't conflict — they layer).

**Verification:**

- All 4 `provenance: false` occurrences are either flipped or accompanied by a comment + SECURITY.md entry.
- `docker-release.yml` produces SLSA-provenance-bearing images on the next release.

---

- U5. **Plugin manifest capability declarations (advisory v1) + externalized denylist**

**Goal:** Extensions declare what they need (`net.outbound`, `fs.read`, `process.spawn`, `secrets.read`); loader parses, logs declared capabilities, and warns on observed-but-undeclared calls. Externalize `dependency-denylist.ts`'s 1-entry hardcoded array to `dependency-denylist.json`.

**Requirements:** R5

**Dependencies:** U1 (audit doc has stated the trust model and called this out as the layer being added)

**Files:**

- Create: `src/plugins/capabilities.ts` (schema, parser, warn-emitter)
- Create: `src/plugins/capabilities.test.ts`
- Create: `src/plugins/dependency-denylist.json` (with the existing `plain-crypto-js` entry plus a structured schema for additions)
- Create: `src/plugins/dependency-denylist.test.ts` (if not already covered)
- Modify: `src/plugins/install.ts` (parse `openclawCapabilities` from each extension's `package.json`; pass to runtime; emit advisory log)
- Modify: `src/plugins/dependency-denylist.ts` (load from JSON file; same exported API)
- Modify: `docs/concepts/plugin-trust.md` if it exists, else create it; document the capability vocabulary
- Modify: `extensions/AGENTS.md` (note the new optional `openclawCapabilities` block in extension `package.json` files)
- _Optionally_ modify: 5-10 first-party extensions' `package.json` to declare their actual capabilities, as exemplars (do **not** modify all 109 in this plan; that's a follow-up sweep)

**Approach:**

- Capability schema (initial vocabulary, refined during implementation by surveying actual extension behavior):
  - `net.outbound: string[]` — host patterns the plugin will dial
  - `fs.read: string[]` — path patterns the plugin will read (supports `~/.openclaw/...` expansion)
  - `fs.write: string[]` — path patterns the plugin will write
  - `process.spawn: boolean | string[]` — false | true | allowlist of binary names
  - `secrets.read: string[]` — secret IDs the plugin will request
- v1 parser is **lenient**: missing `openclawCapabilities` → log INFO `"plugin <id> has not declared capabilities"`; mismatch → log WARN. Never blocks the plugin.
- Externalized denylist: same structural shape (`{ name: string, reason: string, addedDate: string }[]`), loaded once at startup; loader API unchanged.
- The advisory log lands in the existing structured-log path so `./scripts/clawlog.sh` surfaces it.

**Execution note:** This unit is the highest-risk for breakage of the 109 in-tree extensions. Land it behind a feature flag (`OPENCLAW_PLUGIN_CAPABILITIES=advisory|off`) defaulted to `advisory` in dev builds and `off` in releases for the first version. Flip release default to `advisory` after one release cycle has shipped clean.

**Patterns to follow:**

- Manifest parsing: existing extension `package.json` parsing in `src/plugins/install.ts`.
- Structured logging: existing log pattern in `src/plugins/`.
- Discriminated unions for capability values, per the root `AGENTS.md` Code rules.

**Test scenarios:**

- _Happy path:_ an extension declaring `net.outbound: ["api.anthropic.com"]` parses without error and the loader logs the declaration at INFO.
- _Happy path:_ the externalized JSON denylist loads at startup; an extension whose `package.json` `dependencies` includes a denylisted name is rejected with the same error message as today.
- _Edge case:_ extension with no `openclawCapabilities` block loads with an INFO log and no warning — undeclared is not yet warned-on at the loader level (warning happens at the runtime-call seam in a future plan).
- _Edge case:_ malformed `openclawCapabilities` (e.g., `net.outbound: "string"` instead of `string[]`) emits a clear validation error pointing at the offending extension and the offending field; loader still loads the plugin (lenient v1).
- _Edge case:_ denylist JSON file missing or malformed at startup falls back to the previous hardcoded behavior with a WARN log (don't fail-closed on loader bug).
- _Error path:_ an extension declaring a capability for an unknown key (e.g., `openclawCapabilities.gpu.cuda`) emits a WARN naming the unknown key but does not fail load; this lets us evolve vocabulary without breaking older extensions.
- _Integration:_ loading 5-10 real first-party extensions whose `package.json` has been updated with declarations succeeds end-to-end; declarations appear in the structured log.
- _Integration:_ `pnpm test extensions` is unaffected (no behavioral change for extensions that don't opt in).

**Verification:**

- New `src/plugins/capabilities.ts` and `src/plugins/dependency-denylist.json` exist and are loaded.
- Unit tests cover the schema, parser, and denylist loader.
- 5-10 first-party extensions ship example `openclawCapabilities` blocks in their `package.json`.
- A WARN appears in the structured log when an extension declares a capability whose vocabulary key is unknown.
- No existing extension regresses (`pnpm test extensions` remains green).

---

- U6. **GHCR publish via OIDC + `npm audit signatures` in CI**

**Goal:** Reduce static-token surface area: `docker-release.yml` ghcr publish moves to OIDC where viable; `npm audit signatures` runs in CI on every PR to catch registry-signature regressions early.

**Requirements:** R6

**Dependencies:** U3 (so the new attestation chain is in place before we change the auth path; reduces blast radius if OIDC needs reverting)

**Files:**

- Modify: `.github/workflows/docker-release.yml` (lines 93, 210, 321 — the three `docker/login-action@v3` blocks currently using `password: ${{ secrets.GITHUB_TOKEN }}`)
- Modify: `.github/workflows/ci.yml` (add `pnpm install --frozen-lockfile && pnpm dlx --yes npm audit signatures` step or equivalent; cache-friendly)
- Modify: `SECURITY.md` (document the choice — OIDC vs token, and why)

**Approach:**

- ghcr.io now supports OIDC via the GHCR registry's GitHub Actions trust policy. Concrete change: the `docker/login-action` block uses `username: ${{ github.actor }}` + `password: ${{ secrets.GITHUB_TOKEN }}` today; the OIDC variant requires no static password but does require `id-token: write` permission and a registry-side trust policy configured at the org level.
- **Investigation gate:** if org-level config changes affect other workflows or repositories, **do not push through**; document the static-token retention rationale in SECURITY.md and skip the OIDC half. The signatures-check half remains worth doing regardless.
- `npm audit signatures` runs after `pnpm install` in CI; expected runtime ~10s for 1497 packages; if a package fails signature verification, fail the job with a clear message naming the offending package.

**Patterns to follow:**

- The npm OIDC pattern in `.github/workflows/openclaw-npm-release.yml:281-289`.
- Existing CI lane gating in `scripts/check-changed.mjs` — the audit-signatures step should run on every PR, not just on changed lanes (signature regressions can affect any package).

**Test scenarios:**

- _Happy path (signatures):_ `npm audit signatures` against current `pnpm-lock.yaml` returns 0; CI step passes.
- _Happy path (OIDC, if pursued):_ `docker-release.yml` dry-run pushes to ghcr without `secrets.GITHUB_TOKEN` referenced for the registry login.
- _Error path:_ a synthetic unsigned package (test fixture) fails the signatures check with a clear message naming the package.
- _Integration:_ the existing `docker-release.yml` continues to push images and pass downstream smoke tests after the OIDC swap.

**Verification:**

- `npm audit signatures` runs in `ci.yml` on every PR.
- Either ghcr publish uses OIDC (and SECURITY.md notes it), or static-token retention is documented in SECURITY.md with rationale.

---

- U7. **VEX scaffold + EU CRA readiness note**

**Goal:** Establish the `bom/vex/` directory and the per-release VEX maintenance workflow so SBOM publication doesn't generate downstream support load from non-applicable CVEs. Document EU CRA timeline alignment.

**Requirements:** R4 (the VEX half), R1 (audit doc references this readiness)

**Dependencies:** U2 (SBOM exists before VEX makes sense)

**Files:**

- Create: `bom/vex/README.md` (curation workflow: how to add a `not_affected` claim, what justifications are valid per CycloneDX VEX spec)
- Create: `bom/vex/template.cdx.vex.json` (empty CycloneDX VEX skeleton)
- Modify: `.github/workflows/sbom-and-attest.yml` (optionally include the latest VEX file as a release asset alongside the SBOM)
- Modify: `docs/security/audit-2026-04.md` (U1 doc) — add a section "EU CRA readiness checklist" with concrete deadlines: vuln-reporting 2026-09-11, full SBOM 2027-12-11
- Modify: `SECURITY.md` — link to VEX file from "Reporting security issues" section so downstream consumers know to check before filing

**Approach:**

- VEX is owner-curated, not auto-generated. The README codifies: when a `pnpm audit` or scanner alert lands, the security agent (`$openclaw-ghsa-maintainer`) decides whether to add a `not_affected` claim with a justification (`vulnerable_code_not_in_execute_path`, `vulnerable_code_not_present`, etc.) per CycloneDX VEX 1.6 spec.
- Initial VEX file populated with currently-known not-affected CVEs from the existing `pnpm.overrides` block — each override is essentially an unstated VEX claim today; this surfaces them.
- The CRA readiness section in the audit doc is a concrete checklist (machine-readable SBOM in technical documentation: ✅ via U2; vulnerability disclosure process: ✅ via existing SECURITY.md; CVD coordination: needs a channel; etc.).

**Patterns to follow:**

- `INCIDENT_RESPONSE.md` voice for the VEX README — concrete, action-oriented.

**Test scenarios:**

- _Happy path:_ the VEX template validates against the CycloneDX VEX 1.6 schema.
- _Happy path:_ adding a single `not_affected` claim with a valid justification produces a VEX file that scanner X (e.g., `grype` with VEX support) honors — the previously-flagged CVE no longer appears in scan output.
- _Edge case:_ missing or invalid justification field is caught by schema validation before the file is committed (add a pre-commit hook or `pnpm vex:check` script).

**Verification:**

- `bom/vex/README.md` exists and is reviewed by `@openclaw/secops`.
- The audit doc's CRA section is reviewed by the named security officer (Jamieson O'Reilly per SECURITY.md).
- A scan of the latest released image with VEX applied shows reduced false-positive count vs. without.

---

- U8. **"What we said no to" register**

**Goal:** Externalize the bus-factor-reducing decisions implicit in `AGENTS.md`/`SECURITY.md`/`CLAUDE.md` into a single browseable register at `docs/maintenance/scope-guardrails.md` so triage is mechanical.

**Requirements:** R7

**Dependencies:** U1 (audit doc identifies the solo-maintainer surface; this doc is the actionable response)

**Files:**

- Create: `docs/maintenance/scope-guardrails.md`
- Modify: `AGENTS.md` (root) — add a one-line pointer to the register near "Architecture" section
- Modify: `.github/CODEOWNERS` (gate `docs/maintenance/` to maintainer)

**Approach:**

- Sections: **Frozen contracts** (e.g., plugin SDK barrels listed in `src/plugin-sdk/`, gateway protocol additive-only), **Owner-only changes** (Carbon `@buape/carbon` pin, Sparkle key custody, releases), **Deferred features** (per-request scope splitting on shared-secret bearer auth, process-isolated plugin runtime, CI-workflow consolidation), **Out of scope** (sibling `../openclaw.ai` repo, mobile-platform internals beyond Sparkle).
- Each entry: one-line statement, who decided, when, link to canonical source (PR, issue, AGENTS.md line).
- The doc is the **first** stop for a new contributor (or future-self) asking "should we do X" — if X is in the register, the answer is mechanical.
- Re-reviewed annually alongside the audit doc (U1).

**Patterns to follow:**

- The "Footguns" section style in root `AGENTS.md` — telegraph, no marketing.

**Test scenarios:**

- _Test expectation: none — pure documentation unit. Verification is reviewer signoff._

**Verification:**

- Reviewed by primary maintainer.
- A spot-check of 3 random AGENTS.md/SECURITY.md "owner-only" or "out of scope" statements finds them mirrored in the register.
- `pnpm check:docs` passes.

---

## System-Wide Impact

- **Interaction graph:** Release workflows (`openclaw-npm-release.yml`, `docker-release.yml`, `macos-release.yml`) gain SBOM + attestation steps. CI workflow (`ci.yml`) gains `deps:sbom-risk:check` and `npm audit signatures`. Plugin loader (`src/plugins/install.ts`) gains capability parsing. Structured log gets new INFO/WARN entries.
- **Error propagation:** SBOM generation failures fail the release; attestation failures fail the release post-publish (manual recovery documented). Capability parse warnings do not block plugin load (advisory v1). Denylist load failure falls back to the prior hardcoded behavior with WARN.
- **State lifecycle risks:** Attestation re-runs against the same artifact digest are idempotent on sigstore's side but the workflow should not error — verify in U3 tests. SBOM regeneration on identical lockfile state should produce byte-identical output (cdxgen has a `--required-only` mode; verify determinism).
- **API surface parity:** No public TS API changes. `package.json` extension manifest gains an optional `openclawCapabilities` block — this is _additive_, ignored by older OpenClaw versions, and does not break downstream extension authors.
- **Integration coverage:** End-to-end attestation verification (`gh attestation verify`, `cosign verify-attestation`, `npm audit signatures`) requires actual published artifacts — covered by dry-run release tags during U3 implementation.
- **Unchanged invariants:** The single-operator gateway trust model. The in-process plugin runtime. The Sparkle EdDSA key custody. The 28-workflow CI structure. The 109-extension surface. CODEOWNERS rules (U1 and U8 add new paths, do not modify existing rules).

---

## Risks & Dependencies

| Risk                                                                                         | Likelihood | Impact | Mitigation                                                                                                                                                                                                             |
| -------------------------------------------------------------------------------------------- | ---------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| cdxgen runtime exceeds CI budget on the 1497-package lockfile                                | Med        | Med    | Benchmark on Blacksmith 16vcpu first; switch to `ubuntu-latest-large` if >5min; cache `cdxgen` install.                                                                                                                |
| CycloneDX↔SPDX conversion drift (component counts diverge)                                   | Med        | Low    | Test scenario in U2 asserts ±2 component count tolerance; treat divergence as a generator bug to file upstream, not a release-blocker.                                                                                 |
| Enabling Docker buildx provenance breaks downstream image consumers (rare but documented)    | Low        | Med    | Coordinate U3 + U4; dry-run the next non-production release first; document rollback (`provenance: false` revert) in SECURITY.md.                                                                                      |
| ghcr OIDC migration requires org-level config changes affecting unrelated workflows          | Med        | High   | Investigation gate in U6 — if blocked, document static-token retention with rationale and skip; do not force the change.                                                                                               |
| Plugin capability v1 advisory logs become noisy enough to mask real warnings                 | Med        | Low    | Default to `OPENCLAW_PLUGIN_CAPABILITIES=off` in releases for one cycle; flip to `advisory` after soak.                                                                                                                |
| VEX maintenance becomes a recurring solo-maintainer toil burden                              | High       | Med    | Curate VEX only against CVEs that actually generate downstream noise; don't pre-emptively VEX every transitive CVE. Owner-only sign-off per entry.                                                                     |
| EU CRA scope interpretation is wrong (we may not be in scope)                                | Med        | Low    | Audit doc states the assumption explicitly; if legal review confirms out-of-scope, downgrade U7's CRA section without rolling back the SBOM/attestation work — those are valuable regardless.                          |
| Wiring `deps:sbom-risk:check` into CI surfaces existing ownership-ledger gaps and blocks PRs | High       | Low    | Land U2 in two phases: (a) advisory-only for one week, (b) hard-block. Use the advisory week to backfill `scripts/lib/dependency-ownership.json`.                                                                      |
| One of the 8 release pipelines is missed during U3 attestation rollout                       | Med        | Med    | Audit doc (U1) enumerates all 8; U3 explicitly addresses npm/docker/macos (the externally-published 3); plugin-npm-release and plugin-clawhub-release are similar to npm and follow as a U3 follow-up if scope allows. |

---

## Phased Delivery

### Phase 1 — Quick wins (week 1-2)

- U1 (audit doc) — establishes shared understanding.
- U2 (SBOM generation, advisory mode for `sbom-risk:check`) — gets the SBOM tooling in place without blocking PRs yet.

### Phase 2 — SLSA L3 (week 3-4)

- U3 (attestations across npm/docker/macos).
- U4 (Docker provenance enable, removing `provenance: false` where unintentional).
- Flip `sbom-risk:check` from advisory to hard-block once ownership-ledger gaps are backfilled.

### Phase 3 — Hardening + readiness (week 5-7)

- U5 (plugin capabilities advisory + externalized denylist).
- U6 (ghcr OIDC + `npm audit signatures`).
- U7 (VEX scaffold + CRA readiness note in audit doc).

### Phase 4 — Bus-factor (week 8)

- U8 (scope-guardrails register).
- Re-review audit doc (U1) against landed changes; update for accuracy.

Total ≈ 8 weeks with one solo developer at ~15h/week of focused security work, assuming agent-assisted PRs and no major firefighting.

---

## Alternative Approaches Considered

- **Use only the existing `scripts/sbom-risk-report.mjs`, no CycloneDX/SPDX.** Rejected: the bespoke format is not consumable by external scanners, regulators, or downstream users; EU CRA explicitly requires machine-readable SBOM in a recognized format. Keeping it as the _internal_ ownership tool is correct (U2 wires it into CI); replacing it is wrong.
- **Self-managed signing keys (PGP, raw cosign keys).** Rejected: adds a single-owner key custody burden; sigstore keyless OIDC eliminates rotation entirely and mirrors the existing npm trusted-publishing pattern. The only signing key OpenClaw should custody is Sparkle's — and that's already in place because Sparkle requires it.
- **Process-isolated plugin runtime now (R5 enforced from day 1).** Rejected: 109 in-tree extensions need a soak period to declare capabilities accurately; advisory v1 collects the data needed to design the v2 enforcement model. Doing both at once would require renegotiating contracts with 109 extensions and likely break first-party releases.
- **Consolidate 28 workflows to <15 in this plan.** Rejected: scope creep; competes with EU CRA runway. Worth doing later as a dedicated refactor.
- **Adopt Trivy as the SBOM/scanner.** Rejected: Trivy reportedly compromised twice in March 2026; cdxgen + syft + GitHub-native attestations is a more diversified toolchain and avoids re-introducing a single-tool dependency.
- **Push for product-level scope reduction (drop iOS or Android to reduce solo surface).** Rejected: out of scope for a security/SBOM audit. If the maintainer wants to revisit platform commitments, that's a separate `ce-brainstorm`.

---

## Success Metrics

- **SBOM coverage:** every GitHub Release after Phase 2 has a CycloneDX 1.6 + SPDX 3.0.1 SBOM as an asset, plus npm-package and GHCR-image SBOM attestations.
- **Attestation verifiability:** `npm audit signatures @openclaw/openclaw@<v>`, `gh attestation verify`, and `cosign verify-attestation` all return 0 against the latest release without manual setup.
- **Provenance coverage:** 0 unintentional `provenance: false` settings remaining in `.github/workflows/`; any retained ones have a code comment + SECURITY.md justification.
- **Plugin capability coverage:** ≥10 first-party extensions ship example `openclawCapabilities` declarations within Phase 3; this number is reported in the Phase 4 audit re-review.
- **Solo-maintainer signal:** the scope-guardrails register (U8) is referenced in at least one PR triage decision in the first month after landing — the signal that it's actually load-bearing rather than ornamental.
- **CRA readiness:** if/when EU CRA scope is confirmed, the audit doc's CRA checklist shows ≥80% green by 2026-09-11 (vuln-reporting deadline).

---

## Documentation Plan

- `docs/security/audit-2026-04.md` — new (U1).
- `docs/maintenance/scope-guardrails.md` — new (U8).
- `docs/concepts/plugin-trust.md` — new or updated (U5).
- `bom/vex/README.md` — new (U7).
- `SECURITY.md` — updated in U1 (audit-history link), U3 (verification commands), U4 (test-image provenance policy), U6 (auth-path rationale), U7 (VEX link).
- `extensions/AGENTS.md` — updated in U5 (capability declaration vocabulary).
- `AGENTS.md` (root) — updated in U8 (pointer to scope-guardrails register).
- Changelog entries: U2, U3, U4, U6 are user-facing (security improvement) — entries under `### Changes`. U1, U5, U7, U8 are internal/docs — likely no changelog entry per repo convention.

---

## Operational / Rollout Notes

- **No feature flag for U2/U3/U4** — these only run on release tag pushes; rollout is per-release.
- **Feature flag `OPENCLAW_PLUGIN_CAPABILITIES=off|advisory`** for U5; defaults to `off` in releases for one cycle, then `advisory`.
- **No runtime data migration** — additive throughout.
- **Monitoring:** the structured log (`./scripts/clawlog.sh`) is the primary signal for U5 capability mismatches and U6 audit-signatures failures.
- **Rollback procedures:**
  - SBOM step failure: revert the workflow modification; release continues without SBOM (file an incident, don't block on it).
  - Attestation step failure post-publish: the artifact is published; document on the release page that attestations are missing for this version; investigate before the next release.
  - Docker provenance enable causes downstream breakage: revert to `provenance: false` and re-tag.
  - Plugin capability advisory log noise: flip the env var to `off` in releases.
- **Sequencing critical path:** U1 → U2 → (U3 || U7 partial) → U4 → U5 || U6 || U7 (rest) → U8. Phase boundaries enforce this.

---

## Sources & References

- Research: `ce-repo-research-analyst` agent run (2026-04-25), full repo scan covering `scripts/sbom-risk-report.mjs`, `.github/workflows/`, `SECURITY.md`, `src/plugins/`, `src/secrets/`, `src/security/`, `src/gateway/`.
- Research: `ce-best-practices-researcher` agent run (2026-04-25), 2026-current SBOM/zero-trust/solo-maintainer landscape.
- `SECURITY.md` lines 60-65, 75, 87, 98-122, 117-121, 132-153, 223-229, 261-267, 273, 279-285 — operator trust model, plugin trust model, sandbox defaults, scope.
- `AGENTS.md` (root) lines 22, 133, 137-143, 153-156, 159 — security/release policy.
- `.github/workflows/openclaw-npm-release.yml:281-289, 366` — existing OIDC + npm provenance + verify-tarball pattern (the pattern U3 generalizes).
- `.github/workflows/docker-release.yml:93, 164, 180, 210, 281, 297, 321` — current `provenance: false` and `GITHUB_TOKEN` ghcr login (the surfaces U4/U6 modify).
- `.github/workflows/codeql.yml` — workflow shape pattern for U2's `sbom-and-attest.yml`.
- `.github/dependabot.yml` — current 6-ecosystem cooldown-2-day grouped-update posture.
- `pnpm-workspace.yaml` — `minimumReleaseAge: 2880` (48h) supply-chain soak; preserve.
- `scripts/sbom-risk-report.mjs` (315 lines) + `test/scripts/sbom-risk-report.test.ts` + `scripts/lib/dependency-ownership.json` (172 records) — existing SBOM-adjacent tooling.
- `src/plugins/install.ts`, `src/plugins/dependency-denylist.ts` — plugin loader seams modified by U5.
- `src/gateway/connection-details.ts:66-80`, `src/gateway/net.ts:508-542`, `src/pairing/setup-code.ts:75-79, 287` — current network-trust posture (referenced by U1 audit doc).
- EU CRA: in force 2024-12-10; vuln-reporting 2026-09-11; full obligations 2027-12-11; technical guideline BSI TR-03183-2.
- CycloneDX 1.6 spec; SPDX 3.0.1 spec.
- `actions/attest-build-provenance@v2`, `actions/attest-sbom@v2` — GitHub Artifact Attestations docs.
- Supply-chain attack landscape (2026): Shai-Hulud npm worm; Axios-namespace Sapphire-Sleet compromise (2026-03-31); Trivy reported compromises (March 2026 — audit before re-introducing).
