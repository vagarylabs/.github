"""F14 (root, 2026-10-29): a judge must not read its config, ignore list or exception register from the tree it judges
unless a change to that file is a ci-judge change. This file declares every judge the org runs and the tree files each
reads. The tests fail when any of those files is unprotected in any repository profile of the trusted manifest, or when
release-assets.lock gains a tool nobody classified. So a new judge config cannot land unprotected. Stdlib only. Run:
  python3 -m unittest discover -s trusted/tests -p 'test_*.py' -v
"""
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "trusted"))
import classify  # noqa: E402

# tool -> the tree files it reads as its own configuration, ignore list or exception register.
JUDGES = {
    "gitleaks": [".gitleaks.toml", ".gitleaksignore"],
    "trivy": [".trivyignore", ".trivyignore.yaml", "trivy.yaml", "trivy.yml"],
    "semgrep": [".semgrepignore", ".semgrep.yml", ".semgrep.yaml", ".semgrep/rules.yml"],
    "zizmor": ["zizmor.yml", "zizmor.yaml", ".github/zizmor.yml", ".github/zizmor.yaml"],
    "actionlint": [".github/actionlint.yaml", ".github/actionlint.yml"],
    "ast-grep": ["sgconfig.yml", ".ast-grep/rules/x.yml"],
    "shellcheck": [".shellcheckrc", "scripts/ci/.shellcheckrc"],
    "lychee": ["lychee.toml", ".lycheeignore"],
    "syft": [".syft.yaml", ".syft.yml"],
    # the release scan's VEX (vagaris server-image*.yml TRIVY_VEX) and its reviewed evidence and scoping fixtures
    "vex": ["security/vex/vagaris-server.openvex.json", "security/vex/evidence/esbuild.json",
            "security/vex/fixtures/scope.cdx.json"],
    "exception-register": ["docs/exception-register.json"],
    "secret-scan-registry": [".github/secret-scan-registry.json", "scripts/ci/secret-scan-registry.json"],
}
# A tool in release-assets.lock that reads no configuration from the tree it runs over, and why.
NOT_JUDGES = {
    "cosign": "signs and verifies by flags and key references; reads no file of the tree it signs",
    "prometheus": "promtool checks the rule files it is pointed at, which are the subject, not its configuration",
    "restic": "backup, not a judge",
    "trufflehog": "every exclusion is a flag in the trusted workflow; it reads no ignore file from the tree",
}
# Judges that exist in one repository only.
REPO_JUDGES = {
    "vagarylabs/vagaris": ["scripts/check-vex-binary-evidence.mjs", "scripts/check-vex-scoping.mjs"],
}


def manifest():
    return classify.validate_manifest(json.loads((ROOT / "trusted" / "manifest.json").read_text()))


def profiles(m):
    return [("default", m["default"])] + sorted(m["repos"].items())


class JudgeConfigsAreProtected(unittest.TestCase):
    def test_every_judge_config_is_ci_judge_in_every_profile(self):
        for name, entry in profiles(manifest()):
            for tool, paths in JUDGES.items():
                for path in paths:
                    with self.subTest(profile=name, tool=tool, path=path):
                        self.assertIn("ci-judge", classify.classes_for(entry, path),
                                      "%s reads %s from the tree it judges; protect it in %s" % (tool, path, name))

    def test_a_repository_s_own_judges_are_ci_judge_in_its_profile(self):
        m = manifest()
        for repo, paths in REPO_JUDGES.items():
            for path in paths:
                with self.subTest(repo=repo, path=path):
                    self.assertIn("ci-judge", classify.classes_for(classify.repo_entry(m, repo), path))

    def test_every_locked_tool_is_classified_as_a_judge_or_not(self):
        locked = {line.split()[0] for line in (ROOT / "release-assets.lock").read_text().splitlines()
                  if line.strip() and not line.startswith("#")}
        unclassified = sorted(locked - set(JUDGES) - set(NOT_JUDGES))
        self.assertEqual(unclassified, [], "classify each new release-assets.lock tool in JUDGES (with the tree files it "
                                           "reads) or NOT_JUDGES (with why it reads none)")
        self.assertEqual(sorted(set(JUDGES) & set(NOT_JUDGES)), [])

    def test_the_declared_lists_have_teeth(self):
        # Control: a path no judge reads is not ci-judge, so the protection above is not everything-matches.
        entry = manifest()["default"]
        self.assertNotIn("ci-judge", classify.classes_for(entry, "src/app.ts"))
        self.assertNotIn("ci-judge", classify.classes_for(entry, "docs/readme.md"))


if __name__ == "__main__":
    unittest.main()
