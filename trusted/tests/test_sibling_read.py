"""Tests for classify.py's sibling-read mode: a raw create-github-app-token mint followed by a sibling read is refused;
the shared vagarylabs/.github/actions/sibling-repo-read is the one way (root, 2026-10-27). Planted reds use the three
real shapes found on 2026-10-28 (vagaris pr.yml's bare clone, vagary-core invariants.yml's ls-remote + fetch,
vagary-voice vendor-drift.yml's actions/checkout). Stdlib only. Run:
  python3 -m unittest discover -s trusted/tests -p 'test_*.py' -v
"""
import contextlib
import io
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "trusted"))
import classify  # noqa: E402

MINT = """      - name: Read-only token
        id: t
        uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.SOURCE_READ_APP_ID }}
          private-key: ${{ secrets.SOURCE_READ_APP_PRIVATE_KEY }}
          repositories: vagary-core
"""


def wf(*jobs):
    return "name: w\non: pull_request\njobs:\n" + "".join(jobs)


def job(name, steps):
    return f"  {name}:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n" + steps


BARE_CLONE = """      - name: Supply vagary-core objects
        env:
          GH_TOKEN: ${{ steps.t.outputs.token }}
        run: |
          git -c 'http.https://github.com/.extraheader=' -c credential.helper="$helper" \\
            clone --quiet --bare --single-branch --branch main https://github.com/vagarylabs/vagary-core.git "$store"
"""
CHECKOUT_SIBLING = """      - name: Checkout vagary-core canonical (main)
        uses: actions/checkout@v4
        with:
          repository: vagarylabs/vagary-core
          token: ${{ steps.t.outputs.token }}
"""
LS_REMOTE = """      - name: Check out the siblings
        run: |
          url="https://github.com/vagarylabs/${repo}.git"
          sha=$(git -c "$nohdr" -c credential.helper="$helper" ls-remote "$url" refs/heads/main | cut -f1)
"""


class SiblingReadFindings(unittest.TestCase):
    def findings(self, text):
        return classify.sibling_read_findings(text)

    def test_the_three_real_shapes_are_refused(self):
        for name, steps in (("bare clone across a continued line", BARE_CLONE), ("checkout of a sibling", CHECKOUT_SIBLING),
                            ("ls-remote of a named url", LS_REMOTE)):
            with self.subTest(name):
                found = self.findings(wf(job("verify", MINT + steps)))
                self.assertEqual(len(found), 1, found)
                self.assertEqual(found[0][0], "verify")

    def test_the_checkout_line_and_the_finding_line_are_reported(self):
        found = self.findings(wf(job("drift", MINT + CHECKOUT_SIBLING)))
        self.assertIn("actions/checkout of vagarylabs/vagary-core", found[0][2])

    def test_a_composite_action_is_one_unit(self):
        action = "name: a\nruns:\n  using: composite\n  steps:\n" + MINT.replace("      ", "    ") + BARE_CLONE.replace("      ", "    ")
        self.assertEqual(len(self.findings(action)), 1)

    def test_what_is_not_a_sibling_read_with_a_fresh_token(self):
        own_fetch = "      - run: git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main\n" \
                    "      - run: echo https://github.com/vagarylabs/vagaris\n"
        own_checkout = "      - uses: actions/checkout@v4\n        with:\n          repository: ${{ github.repository }}\n"
        shared = "      - uses: vagarylabs/.github/actions/sibling-repo-read@" + "0" * 40 + "\n" \
                 "        with:\n          repositories: vagary-core\n          bare: vagary-core:/tmp/c.git\n"
        renovate = MINT + "      - uses: renovatebot/github-action@v40\n        with:\n          token: ${{ steps.t.outputs.token }}\n"
        for name, text in (("own remote", wf(job("p", MINT + own_fetch))), ("own checkout", wf(job("p", MINT + own_checkout))),
                           ("the shared action", wf(job("p", shared + BARE_CLONE))), ("a mint alone", wf(job("r", renovate))),
                           ("a clone before the mint", wf(job("p", BARE_CLONE + MINT))),
                           ("mint and clone in different jobs", wf(job("a", MINT), job("b", BARE_CLONE)))):
            with self.subTest(name):
                self.assertEqual(self.findings(text), [])

    def test_a_commented_read_is_not_a_read(self):
        commented = MINT + "      - run: |\n          # git clone https://github.com/vagarylabs/vagary-core.git\n"
        self.assertEqual(self.findings(wf(job("p", commented))), [])


class Manifest(unittest.TestCase):
    def manifest(self, **sibling):
        m = {"version": 1, "default": {"protected": [{"class": "c", "patterns": ["x"]}], "ratchet_files": []},
             "timeout_floor": {"minutes": 6, "mode": "report", "exemptions": []}}
        m.update(sibling)
        return m

    def test_sibling_read_mode_is_required_and_closed(self):
        self.assertEqual(classify.validate_manifest(self.manifest(sibling_read={"mode": "report"}))["sibling_read"]["mode"], "report")
        for bad in ({}, {"sibling_read": {}}, {"sibling_read": {"mode": "warn"}}, {"sibling_read": "report"}):
            with self.subTest(bad=bad):
                with self.assertRaises(classify.IntegrityError):
                    classify.validate_manifest(self.manifest(**bad))

    def test_the_committed_manifest_carries_it(self):
        import json
        m = classify.validate_manifest(json.loads((ROOT / "trusted" / "manifest.json").read_text()))
        self.assertIn(m["sibling_read"]["mode"], ("report", "enforce"))


class Mode(unittest.TestCase):
    def run_mode(self, mode, files):
        m = {"sibling_read": {"mode": mode}}
        out = io.StringIO()
        with mock.patch.object(classify, "resolve_head"), \
                mock.patch.object(classify, "git", return_value="\n".join(files)), \
                mock.patch.object(classify, "blob", side_effect=lambda sha, path: files[path]), \
                mock.patch.object(classify, "summary"), contextlib.redirect_stdout(out):
            code = classify.run_sibling_read(m, "vagarylabs/x", None, "a" * 40)
        return code, out.getvalue()

    def test_report_lists_and_enforce_refuses(self):
        files = {".github/workflows/w.yml": wf(job("v", MINT + BARE_CLONE)), "README.md": "x"}
        code, out = self.run_mode("report", files)
        self.assertEqual(code, 0)
        self.assertIn("::warning file=.github/workflows/w.yml", out)
        code, out = self.run_mode("enforce", files)
        self.assertEqual(code, 1)
        self.assertIn("::error file=.github/workflows/w.yml", out)
        clean = {".github/workflows/w.yml": wf(job("v", MINT))}
        self.assertEqual(self.run_mode("enforce", clean)[0], 0)


if __name__ == "__main__":
    unittest.main()
