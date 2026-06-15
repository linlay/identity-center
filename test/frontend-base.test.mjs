import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { normalizeViteBasePath } from "../frontend/vite-base.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("frontend base path stays rooted at the admin route", () => {
  assert.equal(normalizeViteBasePath(undefined), "/admin/");
  assert.equal(normalizeViteBasePath(""), "/admin/");
  assert.equal(normalizeViteBasePath("/admin"), "/admin/");
  assert.equal(normalizeViteBasePath("/admin/"), "/admin/");
});

test("frontend base path rejects Git Bash path-converted Windows paths", () => {
  assert.throws(
    () => normalizeViteBasePath("C:/Program Files/Git/admin/"),
    /VITE_BASE_PATH was converted to a Windows filesystem path/u
  );
  assert.throws(
    () => normalizeViteBasePath("C:\\Program Files\\Git\\admin\\"),
    /VITE_BASE_PATH was converted to a Windows filesystem path/u
  );
});

test("release frontend build protects VITE_BASE_PATH from MSYS path conversion", () => {
  const releaseCommon = fs.readFileSync(path.join(repoRoot, "scripts", "release-common.sh"), "utf8");

  assert.match(releaseCommon, /MSYS_NO_PATHCONV=1/u);
  assert.match(releaseCommon, /MSYS2_ENV_CONV_EXCL=.*VITE_BASE_PATH/u);
  assert.match(releaseCommon, /VITE_BASE_PATH="\$VITE_BASE_PATH" npm run build/u);
});
