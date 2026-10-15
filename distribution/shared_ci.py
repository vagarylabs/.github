#!/usr/bin/env python3
"""Read-only shared-CI distribution planning. Never tags, writes consumers, publishes or authorizes."""
import argparse
import difflib
import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
import re
import selectors
import subprocess
import time

REPOSITORY = "vagarylabs/.github"
SHA = re.compile(r"[0-9a-f]{40}\Z")
TAG = re.compile(r"v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
COMPONENT = re.compile(r"(?:actions/[a-z0-9][a-z0-9-]*|\.github/workflows/[a-z0-9][a-z0-9-]*\.ya?ml)\Z")
USES = re.compile(r'^(?P<prefix>\s*(?:-\s*)?uses:\s*)(?P<quote>[\"\']?)(?P<repo>vagarylabs/\.github/[^@\s\"\']+)@(?P<sha>[0-9a-f]{40})(?P=quote)(?P<comment>\s*(?:#.*)?)$')


class Refusal(ValueError):
    pass


def exact_sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise Refusal("an exact lowercase 40-hex SHA is required")
    return value


def qualification(raw, expected_digest, sha):
    """Bind a previously reviewed input. This does not authenticate or requalify its assertions."""
    if len(raw) > 65536 or not re.fullmatch(r"[0-9a-f]{64}", expected_digest or ""):
        raise Refusal("bounded qualification input and its reviewed SHA256 are required")
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise Refusal("qualification input changed since review")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Refusal("duplicate qualification key")
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise Refusal("qualification input is not JSON") from None
    keys = {"schema_version", "repository", "candidate_sha", "qualification_ref", "review_ref"}
    if not isinstance(value, dict) or set(value) != keys or type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise Refusal("unsupported qualification input shape")
    if value["repository"] != REPOSITORY or value["candidate_sha"] != exact_sha(sha):
        raise Refusal("qualification repository/revision mismatch")
    for key in ("qualification_ref", "review_ref"):
        text = value[key]
        if not isinstance(text, str) or not 1 <= len(text) <= 1024 or any(ord(c) < 32 for c in text):
            raise Refusal("qualification and review references are required")
    return value


class GithubRead:
    """Use existing gh authentication, GET only; one finite deadline and output budget."""
    def __init__(self):
        self.deadline = time.monotonic() + 20
        self.remaining = 262144

    def __call__(self, endpoint):
        if time.monotonic() >= self.deadline:
            raise Refusal("GitHub read deadline exhausted")
        proc = subprocess.Popen(["gh", "api", "--method", "GET", endpoint],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = bytearray()
        select = selectors.DefaultSelector()
        try:
            for stream in (proc.stdout, proc.stderr):
                select.register(stream, selectors.EVENT_READ)
            while select.get_map():
                left = self.deadline - time.monotonic()
                if left <= 0:
                    raise Refusal("GitHub read deadline exhausted")
                for key, _ in select.select(left):
                    import os
                    data = os.read(key.fileobj.fileno(), min(16384, self.remaining + 1))
                    if not data:
                        select.unregister(key.fileobj)
                        continue
                    self.remaining -= len(data)
                    if self.remaining < 0 or len(output) + len(data) > 65536:
                        raise Refusal("GitHub metadata response exceeded its bound")
                    if key.fileobj is proc.stdout:
                        output.extend(data)
            if proc.wait(timeout=max(0.01, self.deadline-time.monotonic())):
                raise Refusal("GitHub metadata read unavailable; no tag or qualification inferred")
            return json.loads(output)
        except Refusal:
            raise
        except (ValueError, subprocess.TimeoutExpired):
            raise Refusal("GitHub metadata was unavailable, malformed or incomplete") from None
        finally:
            select.close()
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            proc.stdout.close()
            proc.stderr.close()


def verify_tag(tag, sha, read):
    if not TAG.fullmatch(tag or ""):
        raise Refusal("an explicitly selected stable vMAJOR.MINOR.PATCH tag is required")
    exact_sha(sha)
    ref = read(f"repos/{REPOSITORY}/git/ref/tags/{tag}")
    if not isinstance(ref, dict) or ref.get("ref") != f"refs/tags/{tag}":
        raise Refusal("remote tag is missing or mismatched")
    obj, seen, chain = ref.get("object"), set(), []
    for _ in range(5):
        if not isinstance(obj, dict) or not isinstance(obj.get("sha"), str) or not SHA.fullmatch(obj["sha"]):
            raise Refusal("tag object is incomplete")
        oid = obj["sha"]
        if oid in seen:
            raise Refusal("cyclic tag chain")
        seen.add(oid)
        chain.append(oid)
        if obj.get("type") == "commit":
            if oid != sha:
                raise Refusal("published tag resolves to another commit")
            return {"tag": tag, "commit": sha, "tag_object_chain": chain}
        if obj.get("type") != "tag":
            raise Refusal("tag does not resolve to a commit")
        node = read(f"repos/{REPOSITORY}/git/tags/{oid}")
        if not isinstance(node, dict) or node.get("sha") != oid:
            raise Refusal("annotated tag response mismatch")
        obj = node.get("object")
    raise Refusal("tag chain exceeds bound")


def read_regular(root, relative, limit):
    """Read a bounded regular descriptor under the selected root; never follow child links.

    The root itself is a caller-selected directory, canonicalized once. Descendant
    lookup uses directory descriptors, so replacement cannot redirect traversal.
    The deadline bounds the loop, not an OS stall on a remote filesystem.
    """
    parts = PurePosixPath(relative).parts
    if not parts or PurePosixPath(relative).is_absolute() or ".." in parts:
        raise Refusal("input path must be relative and contained")
    if not all(hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_NONBLOCK", "O_DIRECTORY")):
        raise Refusal("safe descriptor reads are unavailable on this platform")
    canonical = Path(root).resolve(strict=True)
    directory = os.open(canonical.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        for part in (*canonical.parts[1:], *parts[:-1]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise Refusal("input must be a bounded regular file")
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        deadline, chunks, size = time.monotonic() + 5, [], 0
        while True:
            if time.monotonic() >= deadline:
                raise Refusal("local read deadline exhausted")
            block = os.read(descriptor, min(65536, limit + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            if size > limit:
                raise Refusal("input exceeds its byte bound")
        after = os.fstat(descriptor)
        current = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or signature(before) != signature(after) or signature(after) != signature(current):
            raise Refusal("input changed during the read")
        return b"".join(chunks)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def quote_end(value, quote, start=0):
    index = start
    while index < len(value):
        if quote == '"' and value[index] == "\\":
            index += 2
        elif value[index] == quote:
            if quote == "'" and index + 1 < len(value) and value[index + 1] == quote:
                index += 2
            else:
                return index
        else:
            index += 1
    return None


def workflow_uses_lines(text, target):
    """Recognize block-style job/step references, never scalar contents.

    This deliberately is not a general YAML parser. Unsupported reference-bearing
    flow/anchor/quoted-key constructs refuse; ordinary run bodies are preserved.
    """
    stack, selected, pending_quote = [], set(), None
    for number, line in enumerate(text.splitlines()):
        if pending_quote:
            end = quote_end(line, pending_quote)
            if end is not None:
                if line[end + 1:].strip() and not line[end + 1:].lstrip().startswith("#"):
                    raise Refusal("ambiguous multiline scalar termination")
                pending_quote = None
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "\t" in line[:len(line)-len(line.lstrip())]:
            raise Refusal("tab-indented YAML is unsupported")
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if stack and stack[-1][2] != "mapping":
            if stack[-1][2] == "ambiguous" and target in line:
                raise Refusal("reference inside unsupported YAML context")
            continue
        body = line[indent:]
        if body.startswith("- "):
            stack.append((indent, "-", "mapping"))
            indent += 2
            body = body[2:]
        mapping = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_-]*):(?:[ ]+(.*)|[ ]*)", body)
        if not mapping:
            if target in body:
                raise Refusal("reference uses unsupported YAML syntax")
            stack.append((indent, "?", "ambiguous"))
            continue
        key, value = mapping.group(1), mapping.group(2) or ""
        value = value.strip()
        path = [frame[1] for frame in stack]
        supported = (len(path) == 2 and path[0] == "jobs" or
                     len(path) == 4 and path[0] == "jobs" and path[2:] == ["steps", "-"] or
                     path == ["runs", "steps", "-"])
        if key == "uses":
            if target in value:
                if not supported:
                    raise Refusal("reference is outside a supported job or step")
                selected.add(number)
            elif value.startswith(("|", ">", "&", "*", "[", "{")) or not value:
                # An opaque uses value could hide a second requested reference.
                raise Refusal("multiline or indirect uses values need an owner edit")
        kind = "mapping" if not value or value.startswith("#") else "scalar"
        if value.startswith(("&", "*", "!", "[", "{")):
            kind = "ambiguous"
            if target in value:
                raise Refusal("reference uses unsupported flow or alias syntax")
        if value.startswith(('"', "'")):
            end = quote_end(value, value[0], 1)
            if end is None:
                if key == "uses":
                    raise Refusal("multiline uses values need an owner edit")
                pending_quote = value[0]
        stack.append((indent, key, kind))
    if pending_quote:
        raise Refusal("unterminated quoted scalar")
    return selected


def rewrite(text, component, before, after, label):
    exact_sha(before); exact_sha(after)
    if label != "main" and not TAG.fullmatch(label or ""):
        raise Refusal("only main or a verified stable tag annotation is supported")
    if before == after or not COMPONENT.fullmatch(component):
        raise Refusal("distinct exact revisions and a supported component are required")
    output, count = [], 0
    target = REPOSITORY + "/" + component
    selected = workflow_uses_lines(text, target)
    for number, line in enumerate(text.splitlines(keepends=True)):
        if number not in selected:
            output.append(line); continue
        stripped = line.rstrip("\r\n")
        match = USES.fullmatch(stripped)
        if not match or match["repo"] != target or match["sha"] != before:
            raise Refusal("consumer reference moved or uses unsupported syntax; inspect manually")
        comment = match["comment"].strip()
        if comment and comment != "# main" and not (comment.startswith("# ") and TAG.fullmatch(comment[2:])):
            raise Refusal("consumer annotation needs an owner-preserving manual edit")
        end = line[len(stripped):]
        output.append(f'{match["prefix"]}{match["quote"]}{target}@{after}{match["quote"]} # {label}{end}')
        count += 1
    if not count:
        raise Refusal("requested exact consumer reference was not found")
    return "".join(output), count


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qualification", required=True)
    ap.add_argument("--qualification-sha256", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--tag", help="Existing published stable tag; omitted keeps the approved # main annotation")
    ap.add_argument("--consumer", required=True)
    ap.add_argument("--path", action="append", required=True, help="Explicit relative YAML path; at most32")
    ap.add_argument("--component", required=True)
    ap.add_argument("--from-sha", required=True)
    args = ap.parse_args()
    try:
        qpath = Path(args.qualification).absolute()
        q = qualification(read_regular(qpath.parent, qpath.name, 65536), args.qualification_sha256, args.sha)
        tag = verify_tag(args.tag, args.sha, GithubRead()) if args.tag else None
        root = Path(args.consumer).resolve()
        if not 1 <= len(args.path) <= 32 or len(set(args.path)) != len(args.path):
            raise Refusal("one to32 unique explicit consumer paths required")
        rows, total = [], 0
        for name in args.path:
            rel = PurePosixPath(name)
            path = root / name
            if not re.fullmatch(r"[A-Za-z0-9_./-]{1,240}", name) or rel.is_absolute() or ".." in rel.parts or rel.suffix not in (".yml", ".yaml"):
                raise Refusal("consumer path must be a contained ordinary YAML file")
            raw = read_regular(root, name, 2097152)
            total += len(raw)
            if len(raw) > 2097152 or total > 8388608:
                raise Refusal("consumer source exceeds the planning bound")
            text = raw.decode("utf-8")
            updated, count = rewrite(text, args.component, args.from_sha, args.sha, args.tag or "main")
            rows.append({"path": name, "original_sha256": hashlib.sha256(raw).hexdigest(), "references": count,
                         "patch": "".join(difflib.unified_diff(text.splitlines(True), updated.splitlines(True),
                                                              fromfile="a/"+name, tofile="b/"+name))})
        print(json.dumps({"operation": "plan-only", "writes": False, "authorization_evaluated": False,
                          "qualification_input": q, "qualification_input_sha256": args.qualification_sha256,
                          "qualification_verified_by_this_tool": False, "published_tag_binding": tag,
                          "files": rows, "owner_next_steps": ["review compatibility and companion policy pins",
                          "apply through normal owning-lane PR and hooks", "run existing RU-02 ratchet and consumer checks",
                          "root controls trusted-ruleset re-pins separately"]}, indent=2))
    except Refusal as exc:
        ap.exit(2, f"shared-ci plan refused: {exc}\n")
    except (OSError, UnicodeError):
        ap.exit(2, "shared-ci plan refused: required source/input could not be read safely\n")


if __name__ == "__main__":
    main()
