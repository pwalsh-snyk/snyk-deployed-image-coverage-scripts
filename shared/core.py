"""Shared Snyk reconcile logic: Kubernetes pod image collection helpers, image matching, Snyk API."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests
from urllib3.exceptions import MaxRetryError, ProtocolError

try:
    from kubernetes import client as k8s_client
    from kubernetes.client.rest import ApiException
except ImportError:
    print("Install dependencies: pip install -r requirements.txt", file=sys.stderr)
    raise

log = logging.getLogger("reconcile.shared")


def configure_logging(*, debug: bool) -> None:
    """Attach a handler to ``reconcile.shared`` for optional DEBUG during cleanup matching."""
    log.setLevel(logging.DEBUG if debug else logging.WARNING)
    if log.handlers:
        return
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    log.addHandler(h)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_REST_VERSION = "2024-10-15"
# Snyk REST GET /orgs/{{org_id}}/projects rejects limit < 10.
SNYK_REST_PROJECTS_PAGE_MIN_LIMIT = 10
V1_IMPORT_PATH = "/api/v1/org/{org_id}/integrations/{integration_id}/import"
V1_PROJECT_TAGS_PATH = "/api/v1/org/{org_id}/project/{project_id}/tags"
V1_PROJECT_DELETE_PATH = "/api/v1/org/{org_id}/project/{project_id}"
DEFAULT_IMPORT_TAG_KEY = "image"
DEFAULT_IMPORT_TAG_VALUE = "deployed"
KUBE_SYSTEM_NAMESPACE = "kube-system"
# ---------------------------------------------------------------------------
# Integration routing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IntegrationRouting:
    """Map image refs to Snyk registry integration IDs."""

    default: str
    acr: str | None = None
    gcp: str | None = None
    mcr: str | None = None
    docker_hub: str | None = None
    ecr: str | None = None


def _env_optional(key: str) -> str | None:
    v = os.environ.get(key, "").strip()
    return v or None


def _env_truthy(key: str, *, default: bool = True) -> bool:
    """Parse env var as boolean; unknown non-empty strings keep `default`."""
    raw = os.environ.get(key)
    if raw is None:
        return default
    s = raw.strip().lower()
    if s in ("0", "false", "no", "off", ""):
        return False
    if s in ("1", "true", "yes", "on"):
        return True
    return default


def load_integration_routing() -> IntegrationRouting | None:
    default = _env_optional("SNYK_INTEGRATION_ID")
    if not default:
        return None
    return IntegrationRouting(
        default=default,
        acr=_env_optional("SNYK_INTEGRATION_ID_ACR"),
        gcp=_env_optional("SNYK_INTEGRATION_ID_GCP"),
        mcr=_env_optional("SNYK_INTEGRATION_ID_MCR"),
        docker_hub=_env_optional("SNYK_INTEGRATION_ID_DOCKER_HUB"),
        ecr=_env_optional("SNYK_INTEGRATION_ID_ECR"),
    )


def integration_id_for_image(ref: str, routing: IntegrationRouting) -> str:
    """Choose integration UUID from registry hostname in the image reference."""
    n = normalize_image_ref(ref)
    if "azurecr.io" in n:
        return routing.acr or routing.default
    if "docker.pkg.dev" in n or ".gcr.io" in n or n.startswith("gcr.io/"):
        return routing.gcp or routing.default
    if "amazonaws.com" in n or ".ecr." in n:
        return routing.ecr or routing.default
    if "mcr.microsoft.com" in n:
        return routing.mcr or routing.default
    return routing.docker_hub or routing.default

@dataclass
class _ContainerImageRefs:
    """spec.image and resolved status.image_id for one container in one pod."""

    spec_image: str | None = None
    image_id: str | None = None  # already stripped of ``docker-pullable://``


def collect_cluster_images(
    core_v1: k8s_client.CoreV1Api,
    *,
    include_kube_system: bool = False,
    only_running_pods: bool = True,
    exclude_init_containers: bool = False,
) -> tuple[set[str], set[str]]:
    """
    Walk pods and return ``(all_refs, import_targets)``.

    ``all_refs`` is every observed image string — both ``spec.image`` and
    resolved ``status.containerStatuses[].image_id`` digests — used by cleanup
    to match Snyk projects against what is actually running.

    ``import_targets`` is one ref per container: ``spec.image`` (tag form) when
    present, falling back to ``status.image_id`` when the spec ref is missing.
    Pairing is preserved by keying on ``container.name``, which appears in both
    ``pod.spec.containers`` and ``pod.status.containerStatuses``. This keeps
    multiple containers in the same registry repository (e.g. one ECR repo with
    ``juice-shop-app`` and ``nginx-alpine`` tags) from being double-imported as
    both their tag and their digest.

    When ``only_running_pods`` is True (default), only pods with
    ``status.phase == "Running"`` are considered. Otherwise completed or failed
    Job/CronJob pods (and other phases) still contribute their images — which
    often pulls in registry images that are no longer actually deployed.

    When ``exclude_init_containers`` is True, init container images are omitted
    (some demos use a minimal image like busybox only in ``initContainers``).

    By default, pods in the ``kube-system`` namespace are skipped to avoid
    continually importing cluster addon images. Set ``include_kube_system=True``
    to include them.
    """
    all_refs: set[str] = set()
    import_targets: set[str] = set()
    try:
        pods = core_v1.list_pod_for_all_namespaces(watch=False)
    except ApiException as e:
        raise RuntimeError(f"Kubernetes list pods failed: {e}") from e
    except (MaxRetryError, ProtocolError, ConnectionError, OSError) as e:
        raise RuntimeError(f"Could not reach the cluster API server: {e}") from e

    for pod in pods.items:
        ns = (pod.metadata.namespace if pod.metadata else None) or ""
        if not include_kube_system and ns == KUBE_SYSTEM_NAMESPACE:
            continue
        if only_running_pods:
            phase = (pod.status.phase if pod.status else None) or ""
            if phase != "Running":
                continue

        # Per-container map keyed by container name: container_statuses report
        # the same name, which lets us pair a spec.image tag with its digest.
        per_container: dict[str, _ContainerImageRefs] = {}

        spec = pod.spec
        if spec:
            spec_containers: list = list(spec.containers or [])
            if not exclude_init_containers:
                spec_containers += list(spec.init_containers or [])
            spec_containers += list(spec.ephemeral_containers or [])
            for container in spec_containers:
                if not container.name or not container.image:
                    continue
                img = container.image.strip()
                per_container.setdefault(container.name, _ContainerImageRefs()).spec_image = img
                all_refs.add(img)

        status = pod.status
        if status:
            statuses: list = list(status.container_statuses or [])
            if not exclude_init_containers:
                statuses += list(status.init_container_statuses or [])
            statuses += list(status.ephemeral_container_statuses or [])
            for cs in statuses:
                if not cs.name or not cs.image_id:
                    continue
                cleaned = strip_docker_pullable_prefix(cs.image_id)
                per_container.setdefault(cs.name, _ContainerImageRefs()).image_id = cleaned
                all_refs.add(cleaned)

        # Per-container pairing: emit exactly one import target per container.
        # Prefer spec.image so the Snyk project is keyed on the human-readable
        # tag (e.g. ``juice-shop-repo:nginx-alpine``); fall back to the digest
        # when spec is missing (rare — can happen for ephemeralContainers).
        for refs in per_container.values():
            if refs.spec_image:
                import_targets.add(refs.spec_image)
            elif refs.image_id:
                import_targets.add(refs.image_id)

    return all_refs, import_targets
# ---------------------------------------------------------------------------
# Image ref helpers
# ---------------------------------------------------------------------------

def normalize_image_ref(ref: str) -> str:
    s = ref.strip().lower()
    return re.sub(r"\s+", "", s)


_DOCKER_PULLABLE_PREFIX = "docker-pullable://"
_SHA256_DIGEST = re.compile(r"(?i)sha256:([a-f0-9]{64})")


def strip_docker_pullable_prefix(image_id: str) -> str:
    s = image_id.strip()
    if s.startswith(_DOCKER_PULLABLE_PREFIX):
        return s[len(_DOCKER_PULLABLE_PREFIX) :].strip()
    return s


def extract_sha256_digest(ref: str) -> str | None:
    """Return canonical ``sha256:<64-hex>`` if present, else None."""
    m = _SHA256_DIGEST.search(ref)
    if m:
        return f"sha256:{m.group(1).lower()}"
    return None


def strip_digest(ref: str) -> str:
    parts = re.split(r"@sha256:", ref, maxsplit=1, flags=re.IGNORECASE)
    return parts[0].strip()


def strip_registry_hostname(ref: str) -> str:
    """
    Remove registry hostname prefix for Snyk import API.

    The hostname is implied by the integration — passing the full reference
    causes 'Unauthorized access or resource does not exist' even with valid
    credentials. Only the repository path and tag should be sent as target.name.

    Examples:
      pwalshobaks2025.azurecr.io/microservices-demo/frontend:v0.10.5
        -> microservices-demo/frontend:v0.10.5
      us-central1-docker.pkg.dev/google-samples/microservices-demo/frontend:v0.10.5
        -> google-samples/microservices-demo/frontend:v0.10.5
      redis:alpine  (no hostname — returned unchanged)
        -> redis:alpine
    """
    parts = ref.split("/", 1)
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
        return parts[1]
    return ref


def add_matching_keys_from_string(keys: set[str], raw: str) -> None:
    """
    Add normalized ref keys for Snyk-side strings (names, imageId, target refs),
    using the same rules as cluster-side tokens: strip docker-pullable,
    normalize, repo@tag without digest, and standalone sha256 digest.
    """
    if not raw.strip():
        return
    cleaned = strip_docker_pullable_prefix(raw.strip())
    if not cleaned:
        return
    keys.add(normalize_image_ref(cleaned))
    keys.add(normalize_image_ref(strip_digest(cleaned)))
    d = extract_sha256_digest(cleaned)
    if d:
        keys.add(d)


def cluster_image_matches_snyk(img: str, known: set[str]) -> bool:
    """True if this cluster image string matches any known Snyk key (ref or digest)."""
    cleaned = strip_docker_pullable_prefix(img.strip())
    n = normalize_image_ref(cleaned)
    n_base = normalize_image_ref(strip_digest(cleaned))
    digest = extract_sha256_digest(cleaned)
    if n in known or n_base in known or (digest and digest in known):
        return True
    if n.startswith("docker.io/"):
        short = n[len("docker.io/") :]
        sn = normalize_image_ref(short)
        sb = normalize_image_ref(strip_digest(short))
        sd = extract_sha256_digest(short)
        if sn in known or sb in known or (sd and sd in known):
            return True
    # Snyk container imports use ``strip_registry_hostname`` targets — project ``name`` is
    # ``repo:tag`` or ``repo@sha256:…`` without the registry host. Cluster pod refs usually
    # include ``account.dkr.ecr….amazonaws.com/`` (or other hosts), so compare repo-path forms too.
    rp = strip_registry_hostname(cleaned)
    if rp != cleaned:
        rpn = normalize_image_ref(rp)
        rpb = normalize_image_ref(strip_digest(rp))
        rd = extract_sha256_digest(rp)
        if rpn in known or rpb in known or (rd and rd in known):
            return True
    return False


def repo_base_image_path(ref: str) -> str:
    """
    Repository path without registry host, image tag, or digest — used to relate
    a ``repo:tag`` spec string to a ``repo@sha256:…`` runtime id for the same image.

    Docker Hub official images (``library/`` namespace) are canonicalized to the
    short form so a bare ``nginx`` (typical pod ``spec.image``) matches the
    canonical ``docker.io/library/nginx@sha256:…`` form Kubernetes records in
    ``status.containerStatuses[].image_id`` after pull.
    """
    s = strip_docker_pullable_prefix(ref.strip())
    if not s:
        return ""
    if re.fullmatch(r"(?i)sha256:[a-f0-9]{64}", s):
        return normalize_image_ref(s)
    s = strip_digest(s)

    # Detect whether the source has an explicit registry host. Refs without a
    # host (or whose host is the Docker Hub host) live in the Docker Hub
    # namespace, where ``library/`` is implicit for official images.
    parts = s.split("/", 1)
    has_explicit_host = len(parts) > 1 and ("." in parts[0] or ":" in parts[0])
    on_docker_hub = (not has_explicit_host) or parts[0].lower() in (
        "docker.io",
        "index.docker.io",
    )

    s = strip_registry_hostname(s)

    if on_docker_hub and s.lower().startswith("library/"):
        s = s[len("library/") :]

    if "/" in s:
        repo, last = s.rsplit("/", 1)
        if ":" in last:
            last = last.split(":", 1)[0]
        s = f"{repo}/{last}" if repo else last
    elif ":" in s:
        s = s.split(":", 1)[0]
    return normalize_image_ref(s)


def pick_representative_for_import(refs: list[str]) -> str:
    """Prefer a ``:tag`` style ref for Snyk import so the UI groups on a tag name."""
    if len(refs) == 1:
        return refs[0]

    def sort_key(r: str) -> tuple[int, int]:
        c = strip_docker_pullable_prefix(r.strip())
        before_at, _, tail = c.partition("@")
        has_tag = ":" in before_at and not re.match(r"(?i)^sha256:", before_at)
        # 0 = has tag before @, 1 = digest-only / bare repo@sha
        tier = 0 if has_tag else (1 if tail.lower().startswith("sha256:") else 2)
        return (tier, len(c))

    return sorted(refs, key=sort_key)[0]


def dedupe_cluster_images_by_content(refs: set[str]) -> set[str]:
    """
    Collapse tag + digest variants that refer to the same image (typical when
    mixing pod ``spec.image`` with ``status.image_id``) to one import target
    per content digest.
    """
    by_digest: dict[str, list[str]] = {}
    without_digest: list[str] = []

    for r in refs:
        d = extract_sha256_digest(r)
        if d:
            by_digest.setdefault(d, []).append(r)
        else:
            without_digest.append(r)

    digest_by_repo_base: dict[str, list[str]] = {}
    for d, group in by_digest.items():
        digest_by_repo_base.setdefault(repo_base_image_path(group[0]), []).append(d)

    out: set[str] = set()
    for group in by_digest.values():
        out.add(pick_representative_for_import(group))

    for r in without_digest:
        rb = repo_base_image_path(r)
        d_for_repo = digest_by_repo_base.get(rb, [])
        if len(d_for_repo) == 1:
            continue
        out.add(r)

    return out


# ---------------------------------------------------------------------------
# Snyk helpers
# ---------------------------------------------------------------------------

def snyk_project_image_keys(project: dict) -> set[str]:
    keys: set[str] = set()
    attrs = project.get("attributes") or {}
    log.debug(
        "project %s: attrs keys=%s name=%r (n=%d)",
        project.get("id"),
        list(attrs.keys()),
        attrs.get("name"),
        len(attrs),
    )
    name = attrs.get("name")
    if isinstance(name, str) and name:
        add_matching_keys_from_string(keys, name)
    for key in ("imageId", "image_id", "targetReference", "target_reference"):
        val = attrs.get(key)
        if isinstance(val, str) and val:
            add_matching_keys_from_string(keys, val)
    return keys


def iter_snyk_projects(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    version: str,
    tags: list[str] | None = None,
    expand: list[str] | None = None,
) -> Iterable[dict]:
    """
    Paginate org projects. Optional ``tags`` REST filter uses ``key:value`` strings
    (projects must match all listed tags).

    Pass ``expand=[\"target\"]`` so each project includes ``relationships.target.data.id``
    (the list response often omits target linkage without it).
    """
    base = rest_base.rstrip("/")
    url = f"{base}/rest/orgs/{org_id}/projects"
    params_list: list[tuple[str, str | int]] = [
        ("version", version),
        ("limit", 100),
    ]
    if tags:
        for t in tags:
            params_list.append(("tags", t))
    if expand:
        for e in expand:
            params_list.append(("expand", e))
    params: list[tuple[str, str | int]] | None = params_list

    while url:
        r = session.get(url, params=params)
        r.raise_for_status()
        payload = r.json()
        for item in payload.get("data") or []:
            yield item
        links = payload.get("links") or {}
        next_href = links.get("next")
        if not next_href:
            break
        url = next_href if next_href.startswith("http") else f"{base}{next_href}" if next_href.startswith("/") else f"{base}/{next_href}"
        params = None


def is_likely_container_project(project: dict) -> bool:
    ptype = project.get("type")
    if ptype == "project":
        meta = project.get("meta") or {}
        pt = meta.get("project_type") or (project.get("attributes") or {}).get("type")
        if pt is None:
            return True
        if isinstance(pt, str):
            pl = pt.lower()
            # Snyk often uses project_type "linux" for container image scans.
            if pl == "linux" or "container" in pl:
                return True
        if pt in ("dockerfile", "helm", "kubernetes"):
            return True
        # apk/deb are OS layers inside container image scans (e.g. redis:alpine → apk).
        if pt in ("apk", "deb"):
            return True
        return "docker" in str(pt).lower() or "container" in str(pt).lower()
    return True


def import_image_v1(
    session: requests.Session,
    v1_base: str,
    org_id: str,
    integration_id: str,
    image_ref: str,
) -> tuple[bool, str | None, int]:
    """
    POST v1 import. Returns ``(ok, location_or_error_body, http_status)``.

    Snyk stores and logs the import **target** as ``strip_registry_hostname(image_ref)``
    (e.g. ``juice-shop-repo:mytag``), not the full ECR URL — match that in the Snyk UI.
    """
    url = f"{v1_base.rstrip('/')}" + V1_IMPORT_PATH.format(
        org_id=org_id, integration_id=integration_id
    )
    # Strip the registry hostname — Snyk's import API expects only the
    # repository path (e.g. "microservices-demo/frontend:v0.10.5").
    # Including the hostname causes "Unauthorized access or resource does not exist".
    target_name = strip_registry_hostname(image_ref)
    body = {"target": {"name": target_name}}
    r = session.post(url, json=body)
    if r.status_code == 201:
        loc = r.headers.get("Location")
        if loc and loc.startswith("/"):
            loc = f"{v1_base.rstrip('/')}{loc}"
        return True, loc, r.status_code
    return False, r.text, r.status_code


def project_ids_from_import_job(payload: dict) -> list[str]:
    """Collect Snyk project UUIDs from a finished import-job JSON body."""
    out: list[str] = []
    seen: set[str] = set()

    def add(pid: object) -> None:
        if isinstance(pid, str) and pid not in seen:
            seen.add(pid)
            out.append(pid)

    for list_key in ("projects", "createdProjects", "projectIds"):
        chunk = payload.get(list_key)
        if not isinstance(chunk, list):
            continue
        for item in chunk:
            if isinstance(item, str):
                add(item)
            elif isinstance(item, dict):
                if item.get("success") is False:
                    continue
                add(item.get("id") or item.get("projectId") or item.get("project_id"))

    for nest_key in ("log", "logs", "results", "projectsLog"):
        nested = payload.get(nest_key)
        if not isinstance(nested, list):
            continue
        for item in nested:
            if not isinstance(item, dict):
                continue
            sub = item.get("projects")
            if isinstance(sub, list):
                for p in sub:
                    if not isinstance(p, dict):
                        continue
                    if p.get("success") is False:
                        continue
                    add(p.get("projectId") or p.get("id") or p.get("project_id"))
            else:
                if item.get("success") is False:
                    continue
                add(item.get("projectId") or item.get("id") or item.get("project_id"))

    return out


def add_project_tags(
    session: requests.Session,
    v1_base: str,
    org_id: str,
    project_id: str,
    tags: list[tuple[str, str]],
) -> tuple[bool, str]:
    """
    POST key/value tags to one project (one tag per request).

    Snyk v1 expects each call as {"key": "...", "value": "..."}, not {"tags": [...]}.
    """
    url = f"{v1_base.rstrip('/')}" + V1_PROJECT_TAGS_PATH.format(
        org_id=org_id, project_id=project_id
    )
    for k, v in tags:
        r = session.post(url, json={"key": k, "value": v})
        if r.status_code in (200, 201, 204):
            continue
        if r.status_code == 409:
            continue
        if r.status_code == 422 and r.text and "already applied" in r.text:
            continue
        return False, r.text or r.reason
    return True, ""


def delete_project_v1(
    session: requests.Session,
    v1_base: str,
    org_id: str,
    project_id: str,
) -> tuple[bool, str]:
    url = f"{v1_base.rstrip('/')}" + V1_PROJECT_DELETE_PATH.format(
        org_id=org_id, project_id=project_id
    )
    r = session.delete(url)
    if r.status_code in (200, 204):
        return True, ""
    return False, r.text or r.reason


def get_project_target_id(project: dict) -> str | None:
    """Return ``relationships.target.data.id`` from a REST project resource (JSON:API)."""
    rel = (project.get("relationships") or {}).get("target") or {}
    data = rel.get("data")
    if not isinstance(data, dict):
        return None
    tid = data.get("id")
    return tid if isinstance(tid, str) and tid else None


def _log_resolve_target_relationships_debug(
    project_id: str | None,
    label: str,
    list_project: dict,
    full_project: dict | None,
) -> None:
    """Emit raw ``relationships`` from list and/or GET payloads when target id cannot be resolved."""
    try:
        list_rel = json.dumps(list_project.get("relationships"), sort_keys=True, default=str)
    except (TypeError, ValueError):
        list_rel = repr(list_project.get("relationships"))
    if full_project is not None:
        try:
            get_rel = json.dumps(full_project.get("relationships"), sort_keys=True, default=str)
        except (TypeError, ValueError):
            get_rel = repr(full_project.get("relationships"))
        print(
            f"  debug: resolve_project_target_id project_id={project_id!r} ({label}) "
            f"relationships[list]={list_rel} relationships[get]={get_rel}",
            flush=True,
        )
    else:
        print(
            f"  debug: resolve_project_target_id project_id={project_id!r} ({label}) "
            f"relationships[list]={list_rel}",
            flush=True,
        )


def fetch_project_rest(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    version: str,
    project_id: str,
    *,
    expand: list[str] | None = None,
) -> dict | None:
    """GET ``/rest/orgs/{{org_id}}/projects/{{project_id}}``; return the JSON:API resource object."""
    base = rest_base.rstrip("/")
    url = f"{base}/rest/orgs/{org_id}/projects/{project_id}"
    params: list[tuple[str, str]] = [("version", version)]
    if expand:
        for e in expand:
            params.append(("expand", e))
    r = session.get(url, params=params)
    r.raise_for_status()
    payload = r.json()
    data = payload.get("data")
    return data if isinstance(data, dict) else None


def resolve_project_target_id(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    version: str,
    project: dict,
) -> str | None:
    """
    Target id for orphan cleanup: prefer embedded relationship, else GET project with
    ``expand=target`` (list responses often omit ``relationships.target.data``).
    """
    pid = project.get("id")
    if not isinstance(pid, str) or not pid:
        _log_resolve_target_relationships_debug(
            None, "missing_project_id", project, None
        )
        return None

    tid = get_project_target_id(project)
    if tid:
        return tid

    try:
        full = fetch_project_rest(
            session, rest_base, org_id, version, pid, expand=["target"]
        )
    except requests.HTTPError as e:
        _log_resolve_target_relationships_debug(
            pid, f"fetch_project_http_error:{e}", project, None
        )
        return None
    except requests.RequestException as e:
        _log_resolve_target_relationships_debug(
            pid, f"fetch_project_error:{e}", project, None
        )
        return None

    tid = get_project_target_id(full) if full else None
    if tid:
        return tid

    _log_resolve_target_relationships_debug(
        pid, "no_target_id_after_embed_and_get", project, full
    )
    return None


def target_has_remaining_projects(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    version: str,
    target_id: str,
) -> bool:
    """
    ``GET /rest/orgs/{{org_id}}/projects?target_id={{targetId}}&limit={{min}}``.

    Uses ``limit >= SNYK_REST_PROJECTS_PAGE_MIN_LIMIT`` (Snyk returns 400 if lower).
    Returns True if any project remains for that target.
    """
    base = rest_base.rstrip("/")
    url = f"{base}/rest/orgs/{org_id}/projects"
    r = session.get(
        url,
        params={
            "version": version,
            "limit": SNYK_REST_PROJECTS_PAGE_MIN_LIMIT,
            "target_id": [target_id],
        },
    )
    r.raise_for_status()
    payload = r.json()
    data = payload.get("data") or []
    return len(data) > 0


def delete_target_rest(
    session: requests.Session,
    rest_base: str,
    org_id: str,
    target_id: str,
    version: str,
) -> tuple[bool, str]:
    """``DELETE /rest/orgs/{{org_id}}/targets/{{targetId}}?version=...`` → expect 204."""
    base = rest_base.rstrip("/")
    url = f"{base}/rest/orgs/{org_id}/targets/{target_id}"
    r = session.delete(url, params={"version": version})
    if r.status_code == 204:
        return True, ""
    return False, r.text or r.reason


def project_matches_any_cluster_image(project: dict, cluster_images: set[str]) -> bool:
    proj_keys = snyk_project_image_keys(project)
    if not proj_keys:
        return False
    for c in cluster_images:
        if cluster_image_matches_snyk(c, proj_keys):
            return True
    return False


def cleanup_stale_deployed_projects(
    rest_session: requests.Session,
    v1_session: requests.Session,
    rest_base: str,
    v1_base: str,
    org_id: str,
    rest_version: str,
    cluster_images: set[str],
    tag_key: str,
    tag_value: str,
    *,
    dry_run: bool,
    require_tag: bool = True,
) -> int:
    """
    Remove container projects that **no longer match any** image string in ``cluster_images``
    (pod ``spec.image`` and ``status.image_id`` digests — i.e. what is actually running).

    When ``require_tag`` is True (default), the project list uses the REST ``tags`` query
    filter (``key:value``) so the server returns only matching projects; the
    ``is_likely_container_project`` check is skipped (tag scope is enough; avoids dropping
    deb/apk-typed linux base images). When ``require_tag=False``, type filtering applies.
    Set ``require_tag=False`` to list all projects and match on image identity only (no tag gate).

    After each **successful** v1 project delete, resolves the owning REST target from
    the **pre-delete** project body: ``relationships.target.data.id``. When all stale
    projects for that target are removed without error, calls
    ``GET /rest/orgs/{{orgId}}/projects?target_id={{id}}&limit=10``; if the page has
    no projects, calls ``DELETE /rest/orgs/{{orgId}}/targets/{{targetId}}``. Fully
    automatic (no manual steps).

    Returns the number of failed delete or follow-up operations (0 when ``dry_run``).
    """
    if require_tag and (not tag_key.strip() or not tag_value.strip()):
        print("Cleanup skipped: empty SNYK_IMPORT_TAG_KEY or SNYK_IMPORT_TAG_VALUE.", flush=True)
        return 0

    tag_token: str | None = None
    if require_tag:
        tag_token = f"{tag_key.strip()}:{tag_value.strip()}"
        print(
            f"\nCleanup: listing projects with REST tags={tag_token!r} and expand=target "
            f"({'dry-run; no deletes' if dry_run else 'stale projects will be deleted'})...",
            flush=True,
        )
    else:
        print(
            f"\nCleanup: scanning container projects (image match only; no tag filter — "
            f"{'dry-run; no deletes' if dry_run else 'stale projects will be deleted'})...",
            flush=True,
        )

    stale: list[tuple[str, dict]] = []
    try:
        for proj in iter_snyk_projects(
            rest_session,
            rest_base,
            org_id,
            rest_version,
            tags=[tag_token] if require_tag and tag_token else None,
            expand=["target"],
        ):
            # When require_tag=True, REST tags= scopes to script-managed projects;
            # skip project_type filtering (deb/apk linux base layers are still containers).
            if not require_tag and not is_likely_container_project(proj):
                continue
            if project_matches_any_cluster_image(proj, cluster_images):
                continue
            pid = proj.get("id")
            if not isinstance(pid, str) or not pid:
                continue
            stale.append((pid, proj))
    except requests.HTTPError as e:
        detail = f" Body: {e.response.text[:500]}" if e.response is not None else ""
        print(f"Cleanup: Snyk REST list failed: {e}.{detail}", file=sys.stderr)
        return 1
    except requests.RequestException as e:
        print(f"Cleanup: Snyk REST unreachable: {e}", file=sys.stderr)
        return 1

    if not stale:
        print(
            "Cleanup: no stale projects (all container projects in scope match the cluster image set).",
            flush=True,
        )
        return 0

    by_target: dict[str | None, list[tuple[str, dict]]] = defaultdict(list)
    for pid, proj in stale:
        tid = resolve_project_target_id(
            rest_session, rest_base, org_id, rest_version, proj
        )
        by_target[tid].append((pid, proj))

    print(f"Cleanup: {len(stale)} project(s) no longer match the cluster image set:", flush=True)
    failures = 0
    for target_id, entries in by_target.items():
        batch_failures = 0
        for pid, proj in entries:
            attrs = proj.get("attributes") or {}
            name = attrs.get("name") or pid
            if dry_run:
                tid_label = target_id or "(no target)"
                print(
                    f"  [dry-run] would DELETE project {pid} ({name!r}) "
                    f"[target {tid_label}]",
                    flush=True,
                )
                continue
            ok, err = delete_project_v1(v1_session, v1_base, org_id, pid)
            if ok:
                print(f"  deleted project {pid} ({name!r})", flush=True)
            else:
                print(f"  delete failed for {pid} ({name!r}): {err[:500]}", file=sys.stderr)
                batch_failures += 1
                failures += 1

        if dry_run:
            if target_id:
                print(
                    f"  [dry-run] would DELETE target {target_id} via REST if no projects remain",
                    flush=True,
                )
            continue

        # Orphan target removal: target_id comes from each project's relationships.target.data.id
        # (captured before v1 DELETE). Re-check with REST list; delete target only if count is zero.
        if target_id and batch_failures == 0:
            try:
                if target_has_remaining_projects(
                    rest_session, rest_base, org_id, rest_version, target_id
                ):
                    print(
                        f"  target {target_id} still has other project(s); not removing target",
                        flush=True,
                    )
                    continue
            except requests.HTTPError as e:
                detail = f" Body: {e.response.text[:500]}" if e.response is not None else ""
                print(
                    f"  could not list projects for target {target_id}: {e}{detail}",
                    file=sys.stderr,
                )
                failures += 1
                continue
            except requests.RequestException as e:
                print(f"  could not list projects for target {target_id}: {e}", file=sys.stderr)
                failures += 1
                continue
            tok, terr = delete_target_rest(
                rest_session, rest_base, org_id, target_id, rest_version
            )
            if tok:
                print(f"  deleted target {target_id} (no remaining projects)", flush=True)
            else:
                print(f"  delete target failed for {target_id}: {terr[:500]}", file=sys.stderr)
                failures += 1
        elif not target_id and batch_failures == 0:
            print(
                "  warning: could not resolve REST target id for this group; "
                "skipping DELETE /targets (orphan target may remain).",
                flush=True,
            )

    return failures


def tag_projects_from_import_job(
    session: requests.Session,
    v1_base: str,
    org_id: str,
    job_payload: dict,
    tags: list[tuple[str, str]],
    context: str,
) -> int:
    """
    Apply tags to every project id found in a completed import job.
    Returns the number of failed tag operations.
    """
    if not tags:
        return 0
    pids = project_ids_from_import_job(job_payload)
    if not pids:
        print(
            f"  warning: could not find project ids in import job to apply tags ({context})",
            file=sys.stderr,
        )
        return 0
    failures = 0
    for pid in pids:
        ok, err = add_project_tags(session, v1_base, org_id, pid, tags)
        if ok:
            label = ", ".join(f"{k}={v}" for k, v in tags)
            print(f"  tagged {context} project {pid} ({label})", flush=True)
        else:
            print(
                f"  tag failed for project {pid} ({context}): {err[:500]}",
                file=sys.stderr,
            )
            failures += 1
    return failures


def poll_import_job(session: requests.Session, job_url: str, interval_sec: float = 5.0) -> dict:
    while True:
        r = session.get(job_url)
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "pending":
            return data
        time.sleep(interval_sec)


# ---------------------------------------------------------------------------
# File-based image override
# ---------------------------------------------------------------------------

def resolve_images_file_path(root: Path, arg: str) -> Path:
    raw = Path(arg).expanduser()
    candidates = [raw.resolve()] if raw.is_absolute() else [
        (root / raw).resolve(), (Path.cwd() / raw).resolve()
    ]
    for p in candidates:
        if not p.is_file():
            continue
        for base in (root.resolve(), Path.cwd().resolve()):
            try:
                p.relative_to(base)
                return p
            except ValueError:
                continue
    raise RuntimeError(f"Images file not found under project or cwd. Got: {arg!r}")


def load_images_file(path: Path) -> set[str]:
    if not path.is_file():
        raise RuntimeError(f"Images file not found: {path}")
    images = {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    if not images:
        raise RuntimeError(f"No image references in {path}")
    return images


def run_reconcile_pipeline(
    cluster_refs_raw: set[str],
    *,
    token: str,
    org_id: str,
    routing: IntegrationRouting,
    rest_base: str,
    v1_base: str,
    rest_version: str,
    tag_pairs: list[tuple[str, str]],
    tag_key: str,
    tag_value: str,
    cleanup_require_tag: bool,
    wait_import: bool,
    dry_run: bool,
    verbose_import: bool = False,
    import_targets: set[str] | None = None,
) -> int:
    """
    Dedupe images, import to Snyk, optional tagging, cleanup stale projects.

    ``cluster_refs_raw`` is the complete observed image set (spec + status
    digests) used for cleanup matching. ``import_targets`` is the per-container
    set returned by ``collect_cluster_images`` — when supplied, we use it
    directly so that two pods sharing one repo with different tags produce two
    imports (not four). When omitted (e.g. ``--images-file`` mode where pairing
    info is unavailable), we fall back to ``dedupe_cluster_images_by_content``
    over the raw set, which uses repo-base heuristics.
    """
    if import_targets is not None:
        # Container-level pairing already chose one ref per container; still
        # run the content dedup as defense-in-depth (catches the rare case of
        # two containers referencing the same image as tag vs. digest).
        cluster_images = dedupe_cluster_images_by_content(set(import_targets))
    else:
        cluster_images = dedupe_cluster_images_by_content(set(cluster_refs_raw))
    n_before = len(import_targets) if import_targets is not None else len(cluster_refs_raw)
    if len(cluster_images) < n_before:
        print(
            f"Deduplicated {n_before} strings to {len(cluster_images)} "
            "import target(s) (same digest from spec + status counts once).",
            flush=True,
        )

    if not cluster_images:
        print("No images found — nothing to reconcile.")
        return 0

    rest_session = requests.Session()
    rest_session.headers.update({
        "Authorization": f"token {token}",
        "Accept": "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
    })
    v1_session = requests.Session()
    v1_session.headers.update({
        "Authorization": f"token {token}",
        "Content-Type": "application/json; charset=utf-8",
    })

    to_import = sorted(cluster_images)
    print(
        f"\nImporting {len(to_import)} cluster image(s) "
        "(reimport every run; integration id chosen per registry).",
        flush=True,
    )
    for m in to_import:
        print(f"  - {m}")

    failures = 0
    if tag_pairs:
        print(
            f"\nAfter each import completes, projects get tag "
            f"{tag_key}={tag_value} "
            f"(override with SNYK_IMPORT_TAG_*; disable with SNYK_TAG_IMPORTED_PROJECTS=0).",
            flush=True,
        )

    for img in to_import:
        iid = integration_id_for_image(img, routing)
        target_sent = strip_registry_hostname(img)
        ok, detail, http_status = import_image_v1(v1_session, v1_base, org_id, iid, img)
        if not ok:
            print(
                f"Import failed: cluster_ref={img!r} target.name={target_sent!r} "
                f"http={http_status} integration={iid} -> {detail[:800]}",
                file=sys.stderr,
            )
            failures += 1
            continue
        print(
            f"Import started: cluster_ref={img!r} target.name={target_sent!r} "
            f"http={http_status} integration={iid} -> {detail}",
            flush=True,
        )
        if verbose_import:
            print(
                f"  (Snyk UI import activity usually keys off target.name, not the full ECR hostname.)",
                flush=True,
            )
        poll_for_job = bool(detail) and (wait_import or bool(tag_pairs))
        if poll_for_job and detail:
            try:
                final = poll_import_job(v1_session, detail)
            except Exception as e:
                print(f"  import job poll failed ({img}): {e}", file=sys.stderr)
                failures += 1
                continue
            if wait_import:
                print(f"  job status: {final.get('status')} {final.get('error', '')}")
            if tag_pairs:
                failures += tag_projects_from_import_job(
                    v1_session, v1_base, org_id, final, tag_pairs, context=img
                )

    failures += cleanup_stale_deployed_projects(
        rest_session,
        v1_session,
        rest_base,
        v1_base,
        org_id,
        rest_version,
        cluster_refs_raw,
        tag_key,
        tag_value,
        dry_run=dry_run,
        require_tag=cleanup_require_tag,
    )

    return 1 if failures else 0
