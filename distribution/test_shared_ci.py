import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import time

import shared_ci as s

OLD, NEW, TAGOBJ = "a"*40, "b"*40, "c"*40


def qualified():
    raw = json.dumps({"schema_version": 1, "repository": s.REPOSITORY, "candidate_sha": NEW,
                      "qualification_ref": "evidence://fixture/qualification", "review_ref": "review://fixture/exact-source"}).encode()
    return raw, hashlib.sha256(raw).hexdigest()


class QualificationTests(unittest.TestCase):
    def test_exact_reviewed_input_required(self):
        raw, digest = qualified()
        self.assertEqual(s.qualification(raw, digest, NEW)["candidate_sha"], NEW)
        for changed, expected, sha in [(raw+b" ", digest, NEW), (raw, digest, OLD), (b"{}", "0"*64, NEW)]:
            with self.assertRaises(s.Refusal): s.qualification(changed, expected, sha)

    def test_malformed_unknown_duplicate_and_wrong_repository_refused(self):
        raw, _ = qualified(); value=json.loads(raw)
        bad = [b"{", b"[]", b"x"*65537,
               json.dumps({**value, "schema_version": True}).encode(),
               json.dumps({**value, "repository": "other/repo"}).encode(),
               json.dumps({**value, "review_ref": ""}).encode(),
               json.dumps({**value, "authorized": True}).encode(),
               raw[:-1]+b',"candidate_sha":"'+NEW.encode()+b'"}']
        for payload in bad:
            with self.subTest(payload=payload[:40]), self.assertRaises(s.Refusal):
                s.qualification(payload, hashlib.sha256(payload).hexdigest(), NEW)


class TagTests(unittest.TestCase):
    def test_real_lightweight_and_annotated_remote_tag(self):
        ref={"ref":"refs/tags/v1.2.3","object":{"type":"commit","sha":NEW}}
        self.assertEqual(s.verify_tag("v1.2.3",NEW,lambda _:ref)["commit"],NEW)
        ref["object"]={"type":"tag","sha":TAGOBJ}
        def read(path):
            return ref if "/ref/" in path else {"sha":TAGOBJ,"object":{"type":"commit","sha":NEW}}
        self.assertEqual(s.verify_tag("v1.2.3",NEW,read)["tag_object_chain"],[TAGOBJ,NEW])

    def test_missing_moved_malformed_cyclic_tag_never_verified(self):
        for ref in [{}, {"ref":"refs/tags/v1.2.3","object":{"type":"commit","sha":OLD}},
                    {"ref":"refs/tags/v1.2.3","object":{"type":"tree","sha":NEW}},
                    {"ref":"refs/tags/v1.2.3","object":{"type":"commit","sha":1}}]:
            with self.assertRaises(s.Refusal): s.verify_tag("v1.2.3",NEW,lambda _:ref)
        def cycle(path):
            return {"ref":"refs/tags/v1.2.3","sha":TAGOBJ,"object":{"type":"tag","sha":TAGOBJ}}
        with self.assertRaises(s.Refusal): s.verify_tag("v1.2.3",NEW,cycle)

    def test_floating_invalid_or_unselected_version_refused_without_read(self):
        def forbidden(_): self.fail("invalid tag reached provider")
        for tag in ["main","v1","1.2.3","v01.2.3","v1.2.3\n","v1.2.3/other",None]:
            with self.assertRaises(s.Refusal): s.verify_tag(tag,NEW,forbidden)


class BoundedGithubReadTests(unittest.TestCase):
    def test_stdout_limit_refuses_before_retaining_unbounded_payload(self):
        reader=s.GithubRead();real=subprocess.Popen
        def child(*args,**kwargs):
            return real([sys.executable,"-c","import sys;sys.stdout.write('x'*1000000)"],**kwargs)
        with mock.patch.object(s.subprocess,"Popen",side_effect=child),self.assertRaises(s.Refusal):
            reader("fixture")

    def test_one_deadline_stops_a_silent_child(self):
        reader=s.GithubRead();reader.deadline=time.monotonic()+0.1;real=subprocess.Popen
        def child(*args,**kwargs):return real([sys.executable,"-c","import time;time.sleep(5)"],**kwargs)
        start=time.monotonic()
        with mock.patch.object(s.subprocess,"Popen",side_effect=child),self.assertRaises(s.Refusal):reader("fixture")
        self.assertLess(time.monotonic()-start,2)

    def test_provider_error_does_not_leak_stderr(self):
        reader=s.GithubRead();real=subprocess.Popen
        def child(*args,**kwargs):return real([sys.executable,"-c","import sys;sys.stderr.write('fixture-private-token');sys.exit(1)"],**kwargs)
        with mock.patch.object(s.subprocess,"Popen",side_effect=child),self.assertRaises(s.Refusal) as caught:reader("fixture")
        self.assertNotIn("fixture-private-token",str(caught.exception))


def workflow(line):
    return "jobs:\n  validate:\n    steps:\n      - name: Check\n" + "        " + line


class BumpTests(unittest.TestCase):
    def test_exact_pin_kept_with_verified_label(self):
        line=workflow(f'uses: "vagarylabs/.github/actions/change-impact-plan@{OLD}" # main\n')
        updated,count=s.rewrite(line,'actions/change-impact-plan',OLD,NEW,'v1.2.3')
        self.assertEqual(count,1)
        self.assertIn('@'+NEW+'" # v1.2.3',updated)
        self.assertNotIn('@v1.2.3',updated)
        self.assertEqual(s.rewrite(line,'actions/change-impact-plan',OLD,NEW,'main')[1],1)

    def test_moved_pin_floating_ref_nonstandard_comment_and_zero_hits_refused(self):
        for line in [f'uses: vagarylabs/.github/actions/change-impact-plan@{NEW}\n',
                     'uses: vagarylabs/.github/actions/change-impact-plan@main\n',
                     f'uses: vagarylabs/.github/actions/change-impact-plan@{OLD} # important owner rationale\n',
                     'uses: other/repo@main\n']:
            with self.assertRaises(s.Refusal):s.rewrite(workflow(line),'actions/change-impact-plan',OLD,NEW,'main')

    def test_cli_outputs_plan_and_never_changes_consumer(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);file=root/'workflow.yml';before=workflow(f'uses: vagarylabs/.github/actions/change-impact-plan@{OLD} # main\n');file.write_text(before)
            raw,digest=qualified();q=root/'qualification.json';q.write_bytes(raw)
            args=[sys.executable,str(Path(s.__file__).resolve()),'--qualification',str(q),'--qualification-sha256',digest,
                  '--sha',NEW,'--consumer',d,'--path','workflow.yml','--component','actions/change-impact-plan','--from-sha',OLD]
            result=subprocess.run(args,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            plan=json.loads(result.stdout);self.assertIs(plan['writes'],False);self.assertIs(plan['authorization_evaluated'],False)
            self.assertIs(plan['qualification_verified_by_this_tool'],False)
            self.assertEqual(file.read_text(),before)
            result=subprocess.run(args+['--path','../escape.yml'],text=True,capture_output=True)
            self.assertEqual(result.returncode,2);self.assertEqual(file.read_text(),before)


class ContextRegressionTests(unittest.TestCase):
    ref = f"vagarylabs/.github/actions/change-impact-plan@{OLD}"

    def rewrite(self, text):
        return s.rewrite(text, 'actions/change-impact-plan', OLD, NEW, 'main')

    def test_literal_folded_and_heredoc_bodies_unchanged(self):
        for marker in ["|", "|-", ">", ">+", "|2-"]:
            body = (f"jobs:\n  validate:\n    steps:\n      - run: {marker}\n"
                    f"          cat <<'EOF'\n          uses: {self.ref}\n          EOF\n"
                    f"      - uses: {self.ref} # main\n")
            updated, count = self.rewrite(body)
            self.assertEqual(count, 1)
            self.assertIn(f"          uses: {self.ref}\n", updated)
            self.assertIn('@'+NEW, updated)

    def test_multiline_quoted_and_plain_scalars_are_data(self):
        for scalar in [f'"echo\n          uses: {self.ref}\n          end"',
                       f"'echo\n          uses: {self.ref}\n          end'",
                       f"echo\n          uses: {self.ref}"]:
            body = f"jobs:\n  validate:\n    steps:\n      - run: {scalar}\n      - uses: {self.ref}\n"
            updated, count = self.rewrite(body)
            self.assertEqual(count, 1)
            self.assertIn(f'uses: {self.ref}', updated)

    def test_actual_workflow_and_composite_paths(self):
        for body in [f"jobs:\n  validate:\n    uses: {self.ref}\n",
                     f"runs:\n  using: composite\n  steps:\n    - name: Test\n      uses: {self.ref}\n",
                     f"on: [push, pull_request]\njobs:\n  validate:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Test\n        uses: '{self.ref}'\n        with:\n          example: [one, two]\n"]:
            self.assertEqual(self.rewrite(body)[1], 1)

    def test_unsupported_flow_alias_quoted_key_and_multiline_uses_refuse(self):
        for body in [f'jobs: {{validate: {{uses: {self.ref}}}}}\n',
                     f'jobs:\n  "validate":\n    uses: {self.ref}\n',
                     f'jobs:\n  validate: &anchor\n    uses: {self.ref}\n',
                     f'jobs:\n  validate:\n    uses: >\n      {self.ref}\n',
                     f'jobs:\n  validate:\n    steps:\n      - uses: "{self.ref}\n          "\n']:
            with self.subTest(body=body), self.assertRaises(s.Refusal):
                self.rewrite(body)

    def test_script_only_reference_never_qualifies(self):
        with self.assertRaises(s.Refusal):
            self.rewrite(f'jobs:\n  validate:\n    steps:\n      - run: |\n          uses: {self.ref}\n')


class FileReadRegressionTests(unittest.TestCase):
    def test_regular_nested_and_byte_limit(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root/'nested').mkdir(); (root/'nested'/'a').write_bytes(b'ok')
            self.assertEqual(s.read_regular(root, 'nested/a', 2), b'ok')
            with self.assertRaises(s.Refusal): s.read_regular(root, 'nested/a', 1)
            with self.assertRaises(s.Refusal): s.read_regular(root, '../a', 2)

    def test_fifo_and_directory_refused_without_read(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); os.mkfifo(root/'fifo'); (root/'dir').mkdir()
            for name in ['fifo', 'dir']:
                with mock.patch.object(s.os, 'read', side_effect=AssertionError('nonregular read')):
                    with self.assertRaises(s.Refusal): s.read_regular(root, name, 128)

    def test_leaf_and_intermediate_symlinks_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root/'target').mkdir(); (root/'target'/'a').write_bytes(b'ok')
            (root/'leaf').symlink_to(root/'target'/'a'); (root/'link').symlink_to(root/'target')
            for name in ['leaf', 'link/a']:
                with self.assertRaises(OSError): s.read_regular(root, name, 128)

    def test_leaf_replacement_with_fifo_or_symlink_before_open_refuses(self):
        for replacement in ['fifo', 'symlink']:
            with tempfile.TemporaryDirectory() as d:
                root=Path(d); leaf=root/'a'; leaf.write_bytes(b'ok'); real=os.open
                def replacing(path, flags, *args, **kwargs):
                    if path == 'a':
                        leaf.unlink()
                        if replacement == 'fifo': os.mkfifo(leaf)
                        else: leaf.symlink_to(root/'missing')
                    return real(path, flags, *args, **kwargs)
                with mock.patch.object(s.os, 'open', side_effect=replacing):
                    with self.assertRaises((s.Refusal, OSError)): s.read_regular(root, 'a', 128)

    def test_canonical_root_ancestor_swap_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d).resolve(); root=parent/'selected'; root.mkdir(); (root/'a').write_bytes(b'ok')
            other=parent/'other'; other.mkdir(); (other/'a').write_bytes(b'wrong')
            real=os.open
            def swapping(path, flags, *args, **kwargs):
                if path == 'selected':
                    root.rename(parent/'original'); root.symlink_to(other)
                return real(path, flags, *args, **kwargs)
            with mock.patch.object(s.os,'open',side_effect=swapping):
                with self.assertRaises(OSError): s.read_regular(root,'a',128)

    def test_post_open_replacement_and_during_read_mutation_refuse(self):
        for change in ['replace', 'append']:
            with tempfile.TemporaryDirectory() as d:
                root=Path(d); leaf=root/'a'; leaf.write_bytes(b'ok'); real=os.read; called=False
                def changing(fd, length):
                    nonlocal called
                    data=real(fd,length)
                    if not called:
                        called=True
                        if change == 'replace':
                            leaf.unlink(); leaf.write_bytes(b'ok')
                        else:
                            with leaf.open('ab') as stream: stream.write(b'new')
                    return data
                with mock.patch.object(s.os,'read',side_effect=changing):
                    with self.assertRaises(s.Refusal): s.read_regular(root,'a',128)

    def test_cli_fifo_qualification_and_consumer_refuse(self):
        for which in ['qualification', 'consumer']:
            with tempfile.TemporaryDirectory() as d:
                root=Path(d); q=root/'q'; file=root/'workflow.yml'
                raw,digest=qualified();q.write_bytes(raw)
                file.write_text(workflow(f'uses: vagarylabs/.github/actions/change-impact-plan@{OLD}\n'))
                fifo=q if which=='qualification' else file; fifo.unlink();os.mkfifo(fifo)
                result=subprocess.run([sys.executable,str(Path(s.__file__).resolve()),'--qualification',str(q),
                    '--qualification-sha256',digest,'--sha',NEW,'--consumer',d,'--path','workflow.yml',
                    '--component','actions/change-impact-plan','--from-sha',OLD],capture_output=True,text=True,timeout=3)
                self.assertEqual(result.returncode,2,result.stderr)


if __name__=='__main__':unittest.main()
