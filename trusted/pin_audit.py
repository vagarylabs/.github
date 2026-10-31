#!/usr/bin/env python3
"""U1 pin audit (root's GO, 2026-10-29): is every exact pin C1 admits still current? Weekly, report-only, for the
calling repository.

This file is the single source. .github/workflows/pin-audit.yml carries it, trusted/classify.py and
trusted/manifest.json as byte-identical inline copies (a reusable workflow cannot read a script from its own
repository), and trusted/tests/test_pin_audit.py fails on drift.

C1 (classify.py `pins`) makes every Dockerfile FROM name its image by digest and every setup-node node-version an
exact X.Y.Z. A pin is only as current as its last refresh: the tag moves on (a rebuilt base image), the Node line ships
a patch, a major reaches end of life. Updaters (Renovate, Dependabot) refresh pins; this audit checks them
independently, and a lagging pin in a repository whose caller declares an updater is reported as that updater's miss.

It reads the head tree as data with the readers C1 uses (classify.from_images, classify.node_versions):
  - each FROM image pinned as <name>:<tag>@sha256:<digest> (a global ARG default is resolved): ONE registry HEAD per
    distinct <registry>/<name>:<tag>, anonymous (a Bearer challenge is answered with an anonymous token from the
    challenge's https realm, one per repository). A digest that is no longer the tag's is `tag_moved`; a tag the
    registry no longer has is `tag_gone`.
  - each exact Node version: a setup-node node-version (a value, a list or a node-version-file) and a FROM
    node:X.Y.Z[-variant] tag. Behind the newest release of its major in nodejs.org/dist/index.json is `node_behind`;
    past its major's end date in the nodejs/Release schedule is `node_eol`. One GET of each. A node:X[-variant] or
    node:<codename>[-variant] tag is judged for end of life by its line (its patch moves with the tag: tag_moved).
Not audited, and listed with why (never a silent pass): a FROM without a digest, or built from an ARG without a usable
default (C1's findings); a digest without a tag (nothing to compare); a node-version that is not exact (C1's finding);
a node alias tag (lts, current, latest), whose movement is judged but which names no version.

INCOMPLETE is a finding, never a clean week. Every fetch that fails, times out, is refused, is over its byte cap or is
not attempted inside the deadline is listed; the headline says INCOMPLETE; an `audit_incomplete` finding names the
failed fetches; the result records complete: false. The job stays green (report-only). The weekly reader (`record`)
carries each repository's last COMPLETE run date, so a missing or failing week is visible.

Bounds: one deadline for the audit, a timeout per request, a byte cap on every body read, a cap on distinct tags.
No credential is sent anywhere: the registries see anonymous requests and anonymous tokens only.

  audit  --manifest FILE --repo OWNER/NAME --head SHA --owner LANE [--docker-updater U] [--node-updater U]
         [--json-out FILE] [--summary FILE]      in the repository's checkout; git reads only, nothing executed
  record --runs FILE --now ISO8601 [--summary FILE]
                                                 the weekly board line from scripts/pin_audit_runs.py's runs file
Exit codes: 0 (findings and INCOMPLETE included), 2 a usage, manifest or head error.
"""
import argparse
import datetime
import http.client
import ipaddress
import json
import pathlib
import re
import sys
import time
import types
import urllib.error
import urllib.parse
import urllib.request


def _load_classify():
    # `python3 -I` leaves the script's own directory off sys.path, so the classifier written next to this file is
    # loaded by its path, never by import name; and compiled from its source, never through the import system, which
    # would write a __pycache__ beside it and read one back in place of the source.
    path = pathlib.Path(__file__).resolve().with_name("classify.py")
    module = types.ModuleType("classify")
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


classify = _load_classify()

DEADLINE_SECONDS = 240      # the whole audit, every fetch included; the step's own timeout is 8 minutes
REQUEST_TIMEOUT = 20        # one request: connect, and each read
MAX_BODY_BYTES = 4000000    # one GET body (nodejs.org/dist/index.json is about 0.3 MB)
MAX_TOKEN_BYTES = 65536     # one anonymous token response
MAX_TAGS = 300              # distinct registry tags HEADed; the rest are not attempted: INCOMPLETE
MAX_LISTED = 200            # summary lines per section; the JSON result carries every row
MISSING_DAYS = 8            # `record`: a repository whose newest run is older than this is MISSING
RETENTION_DAYS = 35         # the workflow's artifact retention: older results cannot be read back
NODE_DIST = "https://nodejs.org/dist/index.json"
NODE_SCHEDULE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
DOCKER_HUB = "https://registry-1.docker.io"
# A multi-arch tag's digest is its index's: without both index types in Accept, a registry answers with one platform's
# manifest and every multi-arch pin would read as moved.
ACCEPT = ", ".join(("application/vnd.oci.image.index.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json"))
UPDATERS = ("none", "renovate", "dependabot")
CLASSES = ("tag_moved", "tag_gone", "node_behind", "node_eol", "audit_incomplete")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/@-]{0,63}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NAME = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_EXACT = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
# A node image tag's version part: X.Y.Z, X or X.Y (the patch moves with the tag), or a word (an alias, a codename).
_NODE_TAG = re.compile(r"^(?P<spec>\d+(?:\.\d+){0,2}|[A-Za-z]+)(?:-[A-Za-z0-9_.-]+)?$")
_NODE_ALIASES = ("lts", "current", "latest")
_ARG = re.compile(r"^\s*ARG\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:=(?P<value>\S*))?\s*$", re.I)
_SUBST = re.compile(r"\$\{(?P<a>[A-Za-z_][A-Za-z0-9_]*)\}|\$(?P<b>[A-Za-z_][A-Za-z0-9_]*)")
_CHALLENGE = re.compile(r'(\w+)="([^"]*)"')


class Failed(Exception):
    """A fetch that did not produce a usable answer: the audit is INCOMPLETE."""


# ---------- the head tree (data only, through classify's git readers) ----------

def global_args(text):
    """{name: default} for the ARGs declared before the first FROM, the only ones a FROM line can use."""
    out = {}
    for line in text.splitlines():
        if re.match(r"^\s*FROM\s", line, re.I):
            break
        m = _ARG.match(line)
        if m and m.group("value") is not None:
            out[m.group("name")] = m.group("value").strip("'\"")
    return out


def resolve_args(image, args):
    """The image with each $NAME / ${NAME} replaced by its global default, or None when one has no usable default."""
    missing = []

    def sub(m):
        name = m.group("a") or m.group("b")
        if not args.get(name):
            missing.append(name)
            return ""
        return args[name]
    out = _SUBST.sub(sub, image)
    return None if missing or "$" in out else out


def parse_image(image):
    """(registry, repository, tag, digest) of an image reference, None when it is not one this audit reads. Docker Hub
    is `docker.io`, and a one-part Docker Hub name is under `library/`."""
    ref, at, digest = image.partition("@")
    if at and not _DIGEST.match(digest):
        return None
    first, slash, rest = ref.partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        registry, path = first.lower(), rest
    else:
        registry, path = "docker.io", ref
    name, tag = path, ""
    if ":" in path.rsplit("/", 1)[-1]:
        name, tag = path.rsplit(":", 1)
    if registry == "docker.io" and "/" not in name:
        name = "library/" + name
    if not _NAME.match(name) or (tag and not _TAG.match(tag)):
        return None
    return registry, name, tag, digest or None


def collect(head):
    """The pins the head tree declares: (images, nodes, not_audited, files read).
    images: [(path, line, image, registry, name, tag, digest)]; nodes: [(path, line, version, source)];
    not_audited: [(path, line, what, why)]."""
    images, nodes, skipped = [], [], []
    dockerfiles, workflows = classify.dockerfiles(head), classify.workflow_files(head)
    for path in dockerfiles:
        text = classify.blob(head, path) or ""
        args = global_args(text)
        for line, written in classify.from_images(text):
            image = resolve_args(written, args) if "$" in written else written
            if image is None:
                skipped.append((path, line, written, "built from an ARG without a usable default (C1 image_arg)"))
                continue
            ref = parse_image(image)
            if ref is None:
                skipped.append((path, line, image, "not an image reference this audit reads"))
            elif ref[3] is None:
                skipped.append((path, line, image, "not pinned by digest (C1 image_tag)"))
            elif not ref[2]:
                skipped.append((path, line, image, "pinned by digest alone: no tag to compare it with"))
            else:
                images.append((path, line, image) + ref)
                node = _NODE_TAG.match(ref[2])
                if ref[0] == "docker.io" and ref[1] == "library/node":
                    if node:
                        nodes.append((path, line, node.group("spec").lower(), "FROM " + image))
                    else:
                        skipped.append((path, line, image, "a node image tag with no version this audit reads"))
    for path in workflows:
        text = classify.blob(head, path) or ""
        for line, kind, value, items in classify.node_versions(text, head):
            source = ("node-version-file " + value) if kind == "file" else "node-version"
            if kind == "expr":
                skipped.append((path, line, value, "an expression (C1 node_version_expr)"))
            elif not items or not all(_EXACT.match(x) for x in items):
                skipped.append((path, line, value or ", ".join(items), "not an exact X.Y.Z (C1 node_version_loose)"))
            else:
                nodes += [(path, line, x.lstrip("v"), source) for x in items]
    return images, nodes, skipped, (len(dockerfiles), len(workflows))


# ---------- fetches (bounded, anonymous) ----------

def _loopback(url):
    host = urllib.parse.urlsplit(url).hostname or ""
    try:
        return host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def allowed(url, loopback=False):
    """https; plain http only to a loopback address, and only when the audit runs against the tests' stub."""
    scheme = urllib.parse.urlsplit(url).scheme
    return scheme == "https" or (loopback and scheme == "http" and _loopback(url))


class _Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, loopback):
        super().__init__()
        self.loopback = loopback

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed(newurl, self.loopback):
            return None  # not followed: the 3xx is the answer, and a failed fetch
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(req.full_url).netloc:
            new.remove_header("Authorization")  # an anonymous token stays with the host that issued the challenge
        return new


class Fetcher:
    """Every request of one audit: one deadline, a timeout per request, a byte cap per body, and a log of each call."""

    def __init__(self, deadline=DEADLINE_SECONDS, timeout=REQUEST_TIMEOUT, loopback=False):
        self.end = time.monotonic() + deadline
        self.deadline = deadline
        self.timeout = timeout
        self.loopback = loopback
        self.calls = []
        self.opener = urllib.request.build_opener(_Redirects(loopback))

    def request(self, method, url, headers=None, cap=None):
        """(status, headers, body) for any HTTP answer; Failed for no answer, a refused URL or an over-cap body. `cap`
        is the body's byte cap (MAX_BODY_BYTES when None); 0 reads no body (a HEAD)."""
        cap = MAX_BODY_BYTES if cap is None else cap
        left = self.end - time.monotonic()
        if left <= 0:
            raise Failed("not attempted: the %g s audit deadline had passed" % self.deadline)
        if not allowed(url, self.loopback):
            raise Failed("refused: %s is not https" % url)
        self.calls.append((method, url))
        req = urllib.request.Request(url, method=method, headers=dict(headers or {}, **{"User-Agent": "vagarylabs-pin-audit"}))
        try:
            resp = self.opener.open(req, timeout=min(self.timeout, left))
        except urllib.error.HTTPError as e:
            resp = e
        except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
            raise Failed("no answer: %s" % (getattr(e, "reason", None) or e))
        try:
            body = b""
            if cap:
                while len(body) <= cap:
                    if time.monotonic() > self.end:
                        raise Failed("the body did not arrive inside the audit deadline")
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    body += chunk
                if len(body) > cap:
                    raise Failed("the body is over its %d-byte cap" % cap)
            return resp.getcode(), resp.headers, body
        except (http.client.HTTPException, OSError) as e:
            raise Failed("the body did not arrive: %s" % e)
        finally:
            try:
                resp.close()
            except OSError:
                pass

    def json(self, url, cap=None, headers=None):
        status, _, body = self.request("GET", url, headers, cap)
        if status != 200:
            raise Failed("HTTP %d" % status)
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise Failed("the body is not JSON")


def anonymous_token(fetch, challenge, name):
    """An anonymous pull token from a `Bearer realm=...,service=...` challenge; Failed when it cannot be had."""
    if not challenge.lower().startswith("bearer "):
        raise Failed("401 without a Bearer challenge")
    params = dict(_CHALLENGE.findall(challenge))
    realm = params.get("realm", "")
    if not allowed(realm, fetch.loopback):
        raise Failed("refused token realm %r: not https" % realm)
    query = {"scope": params.get("scope") or "repository:%s:pull" % name}
    if params.get("service"):
        query["service"] = params["service"]
    doc = fetch.json(realm + ("&" if "?" in realm else "?") + urllib.parse.urlencode(query), cap=MAX_TOKEN_BYTES)
    token = doc.get("token") or doc.get("access_token") if isinstance(doc, dict) else None
    if not isinstance(token, str) or not token:
        raise Failed("the token response holds no token")
    return token


def tag_digest(fetch, base, registry, name, tag, tokens):
    """The tag's current digest (its index's, for a multi-arch tag), None when the registry has no such tag."""
    url = "%s/v2/%s/manifests/%s" % (base, name, tag)
    headers = {"Accept": ACCEPT}
    if (registry, name) in tokens:
        headers["Authorization"] = "Bearer " + tokens[(registry, name)]
    status, answer, _ = fetch.request("HEAD", url, headers, cap=0)
    if status == 401 and "Authorization" not in headers:
        tokens[(registry, name)] = anonymous_token(fetch, answer.get("WWW-Authenticate", ""), name)
        headers["Authorization"] = "Bearer " + tokens[(registry, name)]
        status, answer, _ = fetch.request("HEAD", url, headers, cap=0)
    if status == 404:
        return None
    if status != 200:
        raise Failed("HTTP %d" % status)
    digest = answer.get("Docker-Content-Digest", "")
    if not _DIGEST.match(digest):
        raise Failed("the 200 answer carries no sha256 Docker-Content-Digest")
    return digest


def node_releases(fetch, dist_url, schedule_url):
    """({major: (version, date)} newest release per major, {major: {"end", "lts", "codename"}}) from the two Node
    documents. `lts` and `codename` are "" when the schedule has none for that line."""
    dist = fetch.json(dist_url)
    if not isinstance(dist, list) or not dist:
        raise Failed("the dist index is not a non-empty list")
    newest = {}
    for row in dist:
        m = _EXACT.match(row.get("version", "")) if isinstance(row, dict) else None
        if not m:
            continue
        key = tuple(int(x) for x in m.groups())
        if key > newest.get(key[0], ((-1,), None, None))[0]:
            newest[key[0]] = (key, "%d.%d.%d" % key, row.get("date") or "?")
    if not newest:
        raise Failed("the dist index names no X.Y.Z release")
    schedule = fetch.json(schedule_url)
    if not isinstance(schedule, dict):
        raise Failed("the release schedule is not an object")
    lines = {}
    for line, row in schedule.items():
        m = re.match(r"^v(\d+)$", line)
        if m and isinstance(row, dict) and re.match(r"^\d{4}-\d{2}-\d{2}$", str(row.get("end", ""))):
            lines[int(m.group(1))] = {"end": row["end"], "lts": str(row.get("lts") or ""),
                                      "codename": str(row.get("codename") or "").lower()}
    if not lines:
        raise Failed("the release schedule names no vN line with an end date")
    return {k: (v, d) for k, (_, v, d) in newest.items()}, lines


# ---------- the audit ----------

def validate_pin_audit(m):
    """The manifest's `pin_audit` section: {"exemptions": [...]}, each exactly classify's pin-exemption fields. Its
    `uses` is the audited pin as the result prints it: a FROM image reference, or a Node version."""
    p = m.get("pin_audit")
    if not isinstance(p, dict) or set(p) != {"exemptions"} or not isinstance(p["exemptions"], list):
        raise classify.IntegrityError("manifest: pin_audit must be {\"exemptions\": [...]}")
    for i, e in enumerate(p["exemptions"]):
        if not isinstance(e, dict) or set(e) != set(classify.PIN_EXEMPTION_FIELDS) or not all(
                isinstance(e[f], str) and e[f].strip() for f in classify.PIN_EXEMPTION_FIELDS):
            raise classify.IntegrityError("manifest: pin_audit exemption %d needs exactly the non-empty strings %s"
                                          % (i, ", ".join(classify.PIN_EXEMPTION_FIELDS)))
    return p["exemptions"]


def _ver(v):
    return tuple(int(x) for x in _EXACT.match(v).groups())


def audit(repo, head, owner, exemptions, docker_updater="none", node_updater="none", endpoints=None, fetch=None,
          today=None):
    """The result document (see the module docstring). `endpoints` replaces registry and Node URLs (the tests' stub):
    {"docker.io": base, "<registry>": base, "node-dist": url, "node-schedule": url}."""
    endpoints = endpoints or {}
    fetch = fetch or Fetcher(loopback=bool(endpoints))
    today = today or datetime.date.today().isoformat()
    classify.resolve_head(None, head)
    images, nodes, skipped, (n_docker, n_workflows) = collect(head)
    findings, incomplete = [], []

    def finding(cls, path, line, pin, current, newest, updater, detail):
        findings.append({"class": cls, "owner": owner, "file": path, "line": line, "pin": pin, "current": current,
                         "newest": newest, "updater": updater, "detail": detail})

    def miss(updater):
        return "; %s did not refresh it (the updater's miss)" % updater if updater != "none" else ""

    by_tag = {}
    for row in images:
        by_tag.setdefault(row[3:6], []).append(row)
    tokens = {}
    for n, (key, rows) in enumerate(sorted(by_tag.items())):
        registry, name, tag = key
        what = "registry HEAD %s/%s:%s" % key
        if n >= MAX_TAGS:
            incomplete.append({"fetch": what, "why": "not attempted: over the %d-tag bound" % MAX_TAGS,
                               "pins": ["%s:%d" % (r[0], r[1]) for r in rows]})
            continue
        base = endpoints.get(registry) or (DOCKER_HUB if registry == "docker.io" else "https://" + registry)
        try:
            now = tag_digest(fetch, base, registry, name, tag, tokens)
        except Failed as e:
            incomplete.append({"fetch": what, "why": str(e), "pins": ["%s:%d" % (r[0], r[1]) for r in rows]})
            continue
        for path, line, image, _, _, _, pinned in rows:
            if now is None:
                finding("tag_gone", path, line, image, pinned, "-", docker_updater,
                        "the registry has no tag %s any more (HEAD 404)%s" % (tag, miss(docker_updater)))
            elif now != pinned:
                finding("tag_moved", path, line, image, pinned, now, docker_updater,
                        "the tag's digest is no longer the pinned one%s" % miss(docker_updater))
    if nodes:
        try:
            newest, lines = node_releases(fetch, endpoints.get("node-dist", NODE_DIST),
                                          endpoints.get("node-schedule", NODE_SCHEDULE))
        except Failed as e:
            incomplete.append({"fetch": "Node releases (dist index and schedule)", "why": str(e),
                               "pins": sorted({"%s:%d" % (r[0], r[1]) for r in nodes})})
            newest = lines = None
        codenames = {v["codename"]: k for k, v in (lines or {}).items() if v["codename"]}
        for path, line, spec, source in nodes if newest is not None else ():
            updater = docker_updater if source.startswith("FROM ") else node_updater
            if _EXACT.match(spec):
                major = _ver(spec)[0]
            elif spec[0].isdigit():
                major = int(spec.split(".")[0])  # X or X.Y: the patch moves with the tag, judged as tag_moved
            elif spec in codenames:
                major = codenames[spec]
            else:
                why = "a moving Node alias" if spec in _NODE_ALIASES else "not a Node version, line or codename"
                skipped.append((path, line, source, "%s (%s): the tag's movement is judged, no version is" % (why, spec)))
                continue
            if major not in lines or (_EXACT.match(spec) and major not in newest):
                skipped.append((path, line, spec, "Node %d is not in the dist index and the release schedule" % major))
                continue
            if _EXACT.match(spec) and _ver(newest[major][0]) > _ver(spec):
                top, date = newest[major]
                finding("node_behind", path, line, spec, spec, "%s (released %s)" % (top, date), updater,
                        "%s is behind the newest Node %d%s" % (source, major, miss(updater)))
            if lines[major]["end"] < today:
                lts = max((k for k, v in lines.items() if v["lts"] and v["lts"] <= today <= v["end"] and k in newest),
                          default=None)
                finding("node_eol", path, line, spec, "Node %d (end of life %s)" % (major, lines[major]["end"]),
                        "Node %s (LTS)" % newest[lts][0] if lts is not None else "-", updater,
                        "%s is on a major past its end of life%s" % (source, miss(updater)))
    if incomplete:
        findings.append({"class": "audit_incomplete", "owner": owner, "file": "-", "line": 0, "pin": "-",
                         "current": "%d fetches failed" % len(incomplete), "newest": "-", "updater": "none",
                         "detail": "; ".join("%s: %s" % (x["fetch"], x["why"]) for x in incomplete)})
    exempt, used = [], set()
    for f in list(findings):
        hit = next((i for i, e in enumerate(exemptions) if e["uses"] == f["pin"] and e["repo"] in ("*", repo)
                    and e["file"] in ("*", f["file"]) and f["class"] != "audit_incomplete"), None)
        if hit is not None:
            used.add(hit)
            findings.remove(f)
            exempt.append(dict(f, record=exemptions[hit]["record"], reason=exemptions[hit]["reason"]))
    stale = [e for i, e in enumerate(exemptions) if i not in used and e["repo"] == repo]
    return {"schema": 1, "repo": repo, "head": head, "ran_at": datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ"), "owner": owner, "complete": not incomplete,
            "updaters": {"docker": docker_updater, "node": node_updater},
            "read": {"dockerfiles": n_docker, "workflow_files": n_workflows, "image_pins": len(images),
                     "distinct_tags": len(by_tag), "node_pins": len(nodes)},
            "findings": findings, "incomplete": incomplete, "exempt": exempt, "stale_exemptions": stale,
            "not_audited": [{"file": p, "line": n, "pin": w, "why": y} for p, n, w, y in skipped],
            "requests": len(fetch.calls)}


def _short(text):
    return re.sub(r"(sha256:[0-9a-f]{12})[0-9a-f]{52}", r"\1...", str(text))


def render(doc):
    """The job summary: the headline first, then every finding, what was not audited, and every failed fetch."""
    n = len(doc["findings"])
    if doc["complete"]:
        head = "## Pin audit: %s: COMPLETE, %d finding%s" % (doc["repo"], n, "" if n == 1 else "s")
    else:
        head = ("## Pin audit: %s: INCOMPLETE (%d fetches failed), %d findings. Not a clean week: what the failed fetches "
                "cover was not judged." % (doc["repo"], len(doc["incomplete"]), n))
    r = doc["read"]
    out = [head, "Head %s; owner %s; updaters: docker %s, node %s. Read %d Dockerfiles and %d workflow/action files: "
           "%d image pins on %d distinct tags, %d exact Node pins; %d requests. Report-only."
           % (classify.md_code(doc["head"]), classify.md_code(doc["owner"]), classify.md_code(doc["updaters"]["docker"]),
              classify.md_code(doc["updaters"]["node"]), r["dockerfiles"], r["workflow_files"], r["image_pins"],
              r["distinct_tags"], r["node_pins"], doc["requests"]), ""]
    for f in doc["findings"][:MAX_LISTED]:
        where = "-" if f["file"] == "-" else classify.md_code("%s:%d" % (f["file"], f["line"]))
        out.append("- %s %s %s current %s newest %s owner %s updater %s: %s"
                   % (f["class"].upper(), where, classify.md_code(_short(f["pin"])), classify.md_code(_short(f["current"])),
                      classify.md_code(_short(f["newest"])), classify.md_code(f["owner"]), classify.md_code(f["updater"]),
                      f["detail"]))
    if n > MAX_LISTED:
        out.append("- ... and %d more (the pin-audit artifact lists every finding)" % (n - MAX_LISTED))
    if doc["incomplete"]:
        out += ["", "### Failed fetches (%d)" % len(doc["incomplete"])]
        out += ["- %s: %s (covers %s)" % (x["fetch"], x["why"], ", ".join(x["pins"][:5]) + (" ..." if len(x["pins"]) > 5 else ""))
                for x in doc["incomplete"][:MAX_LISTED]]
    if doc["not_audited"]:
        out += ["", "### Not audited (%d)" % len(doc["not_audited"])]
        out += ["- %s %s: %s" % (classify.md_code("%s:%d" % (x["file"], x["line"])), classify.md_code(_short(x["pin"])),
                                 x["why"]) for x in doc["not_audited"][:MAX_LISTED]]
    for e in doc["exempt"]:
        out.append("- EXEMPT %s %s %s (record %s: %s)" % (e["class"], classify.md_code("%s:%d" % (e["file"], e["line"])),
                                                        classify.md_code(e["pin"]), classify.md_code(e["record"]),
                                                        classify.md_code(e["reason"])))
    for e in doc["stale_exemptions"]:
        out.append("- STALE EXEMPTION %s in %s (record %s): nothing it names is behind"
                   % (classify.md_code(e["uses"]), classify.md_code(e["file"]), classify.md_code(e["record"])))
    return "\n".join(out) + "\n"


# ---------- record: the weekly board line ----------

def _when(text):
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def record(runs, now):
    """One board line per repository, from the runs file scripts/pin_audit_runs.py writes:
    {"repos": {"OWNER/NAME": [{"id", "created_at", "conclusion", "result": <pin-audit.json> | null, "error": str}]},
     "errors": {"OWNER/NAME": "why its runs could not be listed"}}.
    The newest run's state, its finding count, and the last run whose result says complete: true. A repository with no
    run newer than MISSING_DAYS is MISSING; a result that cannot be read back is said so, never counted complete."""
    now = _when(now)
    lines, totals = [], {"complete": 0, "incomplete": 0, "missing": 0, "unread": 0, "findings": 0}
    errors = runs.get("errors") or {}
    repos = sorted(set(runs["repos"]) | set(errors))
    for repo in repos:
        if repo in errors:
            totals["unread"] += 1
            lines.append("- %s NO RESULT (%s)" % (repo, errors[repo]))
            continue
        rows = sorted(runs["repos"][repo], key=lambda r: r["created_at"], reverse=True)
        last = next((r for r in rows if (r.get("result") or {}).get("complete") is True), None)
        since = ("last COMPLETE %s" % last["created_at"][:10]) if last else (
            "no COMPLETE run among the %d read (artifacts are kept %d days)" % (len(rows), RETENTION_DAYS))
        if not rows or (now - _when(rows[0]["created_at"])).days >= MISSING_DAYS:
            totals["missing"] += 1
            newest = ("newest run %s" % rows[0]["created_at"][:10]) if rows else "no run read"
            lines.append("- %s MISSING: no run in the last %d days (%s); %s" % (repo, MISSING_DAYS, newest, since))
            continue
        top, result = rows[0], rows[0].get("result")
        if result is None:
            totals["unread"] += 1
            lines.append("- %s run %s %s: NO RESULT (%s); %s" % (repo, top["id"], top["created_at"][:10],
                                                                top.get("error") or "no pin-audit artifact", since))
            continue
        found = [f for f in result.get("findings", []) if f.get("class") != "audit_incomplete"]
        misses = sum(1 for f in found if f.get("updater", "none") != "none")
        state = "COMPLETE" if result.get("complete") is True else "INCOMPLETE (%d fetches failed)" % len(result.get("incomplete", []))
        totals["complete" if result.get("complete") is True else "incomplete"] += 1
        totals["findings"] += len(found)
        lines.append("- %s run %s %s: %s, %d findings (%d an updater's miss), owner %s; %s"
                     % (repo, top["id"], top["created_at"][:10], state, len(found), misses, result.get("owner"), since))
    head = ("pin-audit week of %s: %d repositories, %d COMPLETE, %d INCOMPLETE, %d NO RESULT, %d MISSING; %d findings"
            % (now.strftime("%Y-%m-%d"), len(repos), totals["complete"], totals["incomplete"], totals["unread"],
               totals["missing"], totals["findings"]))
    return head + "\n" + "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit")
    a.add_argument("--manifest", required=True)
    a.add_argument("--repo", required=True)
    a.add_argument("--head", required=True)
    a.add_argument("--owner", required=True, help="the lane that owns this repository's findings")
    a.add_argument("--docker-updater", default="none", choices=UPDATERS)
    a.add_argument("--node-updater", default="none", choices=UPDATERS)
    a.add_argument("--json-out")
    a.add_argument("--summary", help="append the Markdown here (GITHUB_STEP_SUMMARY)")
    a.add_argument("--endpoint", action="append", default=[], metavar="KEY=URL",
                   help="tests only: a loopback URL for a registry host, node-dist or node-schedule")
    a.add_argument("--request-timeout", type=float, default=REQUEST_TIMEOUT)
    r = sub.add_parser("record")
    r.add_argument("--runs", required=True)
    r.add_argument("--now", required=True, help="UTC, YYYY-MM-DDTHH:MM:SSZ")
    r.add_argument("--summary")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "record":
            with open(args.runs, encoding="utf-8") as fh:
                text = record(json.load(fh), args.now)
        else:
            if not _REPO.match(args.repo) or not _OWNER.match(args.owner):
                raise classify.IntegrityError("--repo must be OWNER/NAME and --owner a lane name")
            endpoints = {}
            for item in args.endpoint:
                key, eq, url = item.partition("=")
                if not eq or not _loopback(url):
                    raise classify.IntegrityError("--endpoint is KEY=URL with a loopback URL (tests only): %r" % item)
                endpoints[key] = url.rstrip("/")
            with open(args.manifest, encoding="utf-8") as fh:
                m = classify.validate_manifest(json.load(fh))
            doc = audit(args.repo, args.head, args.owner, validate_pin_audit(m), args.docker_updater,
                        args.node_updater, endpoints, Fetcher(timeout=args.request_timeout, loopback=bool(endpoints)))
            text = render(doc)
            if args.json_out:
                with open(args.json_out, "w", encoding="utf-8") as fh:
                    json.dump(doc, fh, indent=1, sort_keys=True)
    except (classify.IntegrityError, OSError, ValueError, KeyError) as exc:
        print("::error title=pin audit::%s" % exc)
        return 2
    sys.stdout.write(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
