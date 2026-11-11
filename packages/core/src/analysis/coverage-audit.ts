import path from "node:path";
import type { Finding, PermissionManifest, ScanCoverage } from "../types/index.js";
import { extractPermissions } from "./permission-extractor.js";

/**
 * Coverage/permission consistency audit.
 *
 * Pure, read-only audit over the output of a single analyzeStaticCoverage run.
 * It never mutates the coverage, findings, or contents it receives, and its
 * result is plain JSON-serializable data (paths, counts, booleans, enums) —
 * no Maps, RegExps, functions, or file contents.
 */

export interface CoverageAuditInput {
  findings: Finding[];
  coverage: ScanCoverage;
  contents: ReadonlyMap<string, string>;
}

export const PERMISSION_BOOLEAN_NAMES = [
  "shell",
  "canDeleteFiles",
  "canAccessDB",
  "canSendEmail",
  "canMakeHTTPRequests"
] as const;

export type PermissionBooleanName = (typeof PERMISSION_BOOLEAN_NAMES)[number];

export interface PermissionBooleanAudit {
  /** Boolean value as produced by extractPermissions on the same contents. */
  value: boolean;
  /** Relative paths of the files that triggered this boolean. */
  triggeredBy: string[];
  /** True when every triggering file is present in coverage.analyzedFiles. */
  allTriggersAnalyzed: boolean;
}

export interface NamedSources {
  name: string;
  sources: string[];
}

export interface CoverageAuditCheck {
  name: string;
  passed: boolean;
  /** Human-readable explanation, present only when the check failed. */
  reason?: string;
}

export interface CoverageAudit {
  /** Files that actually participated in rule matching, grouped by scope. */
  analyzedFiles: {
    total: number;
    code: string[];
    data: string[];
  };
  /** Excluded files classified by their existing reason, counted as-is. */
  excludedFiles: {
    total: number;
    byReason: Record<string, number>;
  };
  truncationCount: number;
  readErrorCount: number;
  findingsTotal: number;
  permissions: {
    booleans: Record<PermissionBooleanName, PermissionBooleanAudit>;
    secrets: NamedSources[];
    envVars: NamedSources[];
    /** True when per-file attribution recomposes the extractPermissions result exactly. */
    consistentWithExtractor: boolean;
  };
  suspicious: {
    /** Booleans that are true while none of their triggering files were rule-analyzed. */
    permissionsFromUncoveredFiles: PermissionBooleanName[];
    /** coverage.status is "sufficient" yet no non-empty code file was analyzed. */
    sufficientWithoutCode: boolean;
  };
  checks: CoverageAuditCheck[];
}

function sameStringSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every(item => set.has(item));
}

function sortStrings(values: Iterable<string>): string[] {
  return [...values].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
}

/**
 * Audit one analyzeStaticCoverage result for coverage/permission consistency.
 *
 * @param scan    The exact { findings, coverage, contents } returned by analyzeStaticCoverage.
 * @param dirPath The directory that was scanned (used to relativize contents keys
 *                the same way the analyzer produced coverage paths).
 */
export async function auditScanCoverage(scan: CoverageAuditInput, dirPath: string): Promise<CoverageAudit> {
  const { findings, coverage, contents } = scan;

  const analyzedPaths = coverage.analyzedFiles.map(f => f.path);
  const analyzedSet = new Set(analyzedPaths);
  const codeFiles = sortStrings(coverage.analyzedFiles.filter(f => f.scope === "code").map(f => f.path));
  const dataFiles = sortStrings(coverage.analyzedFiles.filter(f => f.scope === "data").map(f => f.path));

  const byReason: Record<string, number> = {};
  for (const excluded of coverage.excludedFiles) {
    byReason[excluded.reason] = (byReason[excluded.reason] ?? 0) + 1;
  }

  // Relativize contents keys exactly like the analyzer relativizes inventory paths.
  const relOf = (file: string) => path.relative(dirPath, file) || path.basename(file);
  const contentRelPaths = new Map<string, string>();
  for (const key of contents.keys()) {
    contentRelPaths.set(key, relOf(key));
  }

  // Authoritative manifest over the same contents, plus per-file manifests for attribution.
  const manifest = await extractPermissions(dirPath, contents);
  const perFile = new Map<string, PermissionManifest>();
  for (const [key, content] of contents) {
    perFile.set(relOf(key), await extractPermissions(dirPath, new Map([[key, content]])));
  }

  const booleans = {} as Record<PermissionBooleanName, PermissionBooleanAudit>;
  for (const name of PERMISSION_BOOLEAN_NAMES) {
    const triggeredBy = sortStrings(
      [...perFile.entries()].filter(([, m]) => m[name]).map(([rel]) => rel)
    );
    booleans[name] = {
      value: manifest[name],
      triggeredBy,
      allTriggersAnalyzed: triggeredBy.every(p => analyzedSet.has(p))
    };
  }

  const collectSources = (pick: (m: PermissionManifest) => string[]): NamedSources[] => {
    const sources = new Map<string, Set<string>>();
    for (const [rel, m] of perFile) {
      for (const name of pick(m)) {
        let bucket = sources.get(name);
        if (!bucket) sources.set(name, (bucket = new Set()));
        bucket.add(rel);
      }
    }
    return [...sources.entries()]
      .map(([name, srcs]) => ({ name, sources: sortStrings(srcs) }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  };
  const secrets = collectSources(m => m.secrets);
  const envVars = collectSources(m => m.envVars);

  const booleansConsistent = PERMISSION_BOOLEAN_NAMES.every(
    name => manifest[name] === (booleans[name].triggeredBy.length > 0)
  );
  const consistentWithExtractor =
    booleansConsistent &&
    sameStringSet(manifest.secrets, secrets.map(s => s.name)) &&
    sameStringSet(manifest.envVars, envVars.map(e => e.name));

  const permissionsFromUncoveredFiles = PERMISSION_BOOLEAN_NAMES.filter(name => {
    const b = booleans[name];
    return b.value && b.triggeredBy.every(p => !analyzedSet.has(p));
  });

  const hasNonEmptyCode = coverage.analyzedFiles.some(f => f.scope === "code" && f.nonEmpty);
  const sufficientWithoutCode = coverage.status === "sufficient" && !hasNonEmptyCode;

  const checks: CoverageAuditCheck[] = [];

  const onlyInContents = sortStrings([...contentRelPaths.values()].filter(p => !analyzedSet.has(p)));
  const onlyInCoverage = sortStrings(analyzedPaths.filter(p => !new Set(contentRelPaths.values()).has(p)));
  const analyzedSetMatches = onlyInContents.length === 0 && onlyInCoverage.length === 0;
  checks.push({
    name: "analyzed-set-matches-coverage",
    passed: analyzedSetMatches,
    ...(analyzedSetMatches
      ? {}
      : {
          reason: `Rule-matched file set differs from coverage.analyzedFiles: only in contents: [${onlyInContents.join(", ")}]; only in coverage: [${onlyInCoverage.join(", ")}]`
        })
  });

  checks.push({
    name: "permission-booleans-match-extractor",
    passed: consistentWithExtractor,
    ...(consistentWithExtractor
      ? {}
      : { reason: "Per-file permission attribution does not recompose the extractPermissions result for the same contents" })
  });

  const noUncoveredPermissions = permissionsFromUncoveredFiles.length === 0;
  checks.push({
    name: "permission-triggers-covered-by-analysis",
    passed: noUncoveredPermissions,
    ...(noUncoveredPermissions
      ? {}
      : {
          reason: `Permission(s) ${permissionsFromUncoveredFiles.join(", ")} are true but none of their triggering files appear in coverage.analyzedFiles`
        })
  });

  checks.push({
    name: "sufficient-status-implies-non-empty-code",
    passed: !sufficientWithoutCode,
    ...(sufficientWithoutCode
      ? {}
      : { reason: "coverage.status is 'sufficient' but no non-empty code-scope file participated in rule matching" })
  });

  checks.push({
    name: "non-empty-code-analyzed",
    passed: hasNonEmptyCode,
    ...(hasNonEmptyCode
      ? {}
      : { reason: "No analyzable code: no non-empty code-scope file participated in rule matching" })
  });

  return {
    analyzedFiles: {
      total: analyzedPaths.length,
      code: codeFiles,
      data: dataFiles
    },
    excludedFiles: {
      total: coverage.excludedFiles.length,
      byReason
    },
    truncationCount: coverage.truncation.length,
    readErrorCount: coverage.readErrors.length,
    findingsTotal: findings.length,
    permissions: {
      booleans,
      secrets,
      envVars,
      consistentWithExtractor
    },
    suspicious: {
      permissionsFromUncoveredFiles,
      sufficientWithoutCode
    },
    checks
  };
}
