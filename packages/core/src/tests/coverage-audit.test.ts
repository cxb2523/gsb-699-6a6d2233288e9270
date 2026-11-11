import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  analyzeStaticCoverage,
  auditScanCoverage,
  extractPermissions,
  PERMISSION_BOOLEAN_NAMES
} from "../index.js";

function tmpDir(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "otb-audit-test-"));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content, "utf8");
  }
  return dir;
}

function withDir(files: Record<string, string>, fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = tmpDir(files);
  return fn(dir).finally(() => fs.rmSync(dir, { recursive: true, force: true }));
}

function checkByName(audit: Awaited<ReturnType<typeof auditScanCoverage>>, name: string) {
  const check = audit.checks.find(c => c.name === name);
  assert.ok(check, `expected audit to contain check '${name}'`);
  return check;
}

test("coverage audit: analyzed set and permission booleans match analyzer/extractor on code+data dir", async () => {
  await withDir(
    {
      "agent.ts": [
        'import { exec } from "child_process";',
        'import fs from "node:fs";',
        'const key = process.env.MY_API_KEY;',
        'exec("ls");',
        'fs.unlinkSync(target);'
      ].join("\n"),
      "config.json": '{ "name": "demo", "retries": 3 }'
    },
    async dir => {
      const scan = await analyzeStaticCoverage(dir);
      const audit = await auditScanCoverage(scan, dir);

      // Analyzed file set equals coverage.analyzedFiles exactly.
      const coveragePaths = scan.coverage.analyzedFiles.map(f => f.path).sort();
      assert.equal(audit.analyzedFiles.total, scan.coverage.analyzedFiles.length);
      assert.deepEqual([...audit.analyzedFiles.code, ...audit.analyzedFiles.data].sort(), coveragePaths);
      assert.deepEqual(audit.analyzedFiles.code, ["agent.ts"]);
      assert.deepEqual(audit.analyzedFiles.data, ["config.json"]);

      // Permission booleans equal extractPermissions on the same directory.
      const manifest = await extractPermissions(dir);
      for (const name of PERMISSION_BOOLEAN_NAMES) {
        assert.equal(audit.permissions.booleans[name].value, manifest[name], `boolean ${name} must match extractPermissions`);
      }
      assert.equal(audit.permissions.booleans.shell.value, true);
      assert.equal(audit.permissions.booleans.canDeleteFiles.value, true);
      assert.deepEqual(audit.permissions.booleans.shell.triggeredBy, ["agent.ts"]);
      assert.ok(audit.permissions.booleans.shell.allTriggersAnalyzed);

      // Secret/envVar sources are attributed to the code file.
      assert.deepEqual(audit.permissions.envVars, [{ name: "MY_API_KEY", sources: ["agent.ts"] }]);
      assert.deepEqual(audit.permissions.secrets, [{ name: "MY_API_KEY", sources: ["agent.ts"] }]);

      // All consistency checks pass on a healthy scan.
      for (const check of audit.checks) {
        assert.ok(check.passed, `check '${check.name}' should pass: ${check.reason ?? ""}`);
      }
      assert.equal(audit.suspicious.permissionsFromUncoveredFiles.length, 0);
      assert.equal(audit.suspicious.sufficientWithoutCode, false);
      assert.equal(scan.coverage.status, "sufficient");
    }
  );
});

test("coverage audit: docs+data-only directory reports no analyzable code and non-sufficient coverage", async () => {
  await withDir(
    {
      "README.md": "# Demo\n\nSome prose docs, no code.\n",
      "data.json": '{ "key": "value" }'
    },
    async dir => {
      const scan = await analyzeStaticCoverage(dir);
      const audit = await auditScanCoverage(scan, dir);

      assert.notEqual(scan.coverage.status, "sufficient");
      assert.deepEqual(audit.analyzedFiles.code, []);
      assert.deepEqual(audit.analyzedFiles.data, ["data.json"]);

      const codeCheck = checkByName(audit, "non-empty-code-analyzed");
      assert.equal(codeCheck.passed, false);
      assert.match(codeCheck.reason ?? "", /No analyzable code/);

      // README.md is excluded and classified by its existing reason.
      assert.equal(audit.excludedFiles.total, 1);
      assert.equal(audit.excludedFiles.byReason["outside-rule-scope"], 1);

      // No permission boolean may be true without any analyzed trigger file.
      assert.equal(audit.suspicious.permissionsFromUncoveredFiles.length, 0);
      assert.ok(checkByName(audit, "permission-triggers-covered-by-analysis").passed);
    }
  );
});

test("coverage audit: empty directory does not throw and all counts are zero", async () => {
  await withDir({}, async dir => {
    const scan = await analyzeStaticCoverage(dir);
    const audit = await auditScanCoverage(scan, dir);

    assert.equal(audit.analyzedFiles.total, 0);
    assert.deepEqual(audit.analyzedFiles.code, []);
    assert.deepEqual(audit.analyzedFiles.data, []);
    assert.equal(audit.excludedFiles.total, 0);
    assert.deepEqual(audit.excludedFiles.byReason, {});
    assert.equal(audit.truncationCount, 0);
    assert.equal(audit.readErrorCount, 0);
    assert.equal(audit.findingsTotal, 0);
    for (const name of PERMISSION_BOOLEAN_NAMES) {
      assert.equal(audit.permissions.booleans[name].value, false);
      assert.deepEqual(audit.permissions.booleans[name].triggeredBy, []);
    }
    assert.ok(checkByName(audit, "analyzed-set-matches-coverage").passed);
  });
});

test("coverage audit: result is JSON-serializable plain data", async () => {
  await withDir(
    {
      "agent.ts": 'const key = process.env.MY_TOKEN;\nfetch(url);\n',
      "notes.md": "# notes\n"
    },
    async dir => {
      const scan = await analyzeStaticCoverage(dir);
      const audit = await auditScanCoverage(scan, dir);

      const roundTripped = JSON.parse(JSON.stringify(audit));
      assert.deepEqual(roundTripped, audit);
    }
  );
});
