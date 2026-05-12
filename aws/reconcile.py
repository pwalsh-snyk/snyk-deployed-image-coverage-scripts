#!/usr/bin/env python3
"""
Reconcile container images running in Amazon EKS with Snyk projects.

Bearer tokens are minted inline with ``botocore.signers.RequestSigner`` (no ``aws eks get-token``).

Environment variables: see **README.md** and **Technical-Details-EKS.md** in this folder. Loads **repository root `.env`** then **`aws/.env`** (provider overrides).

Usage:
  python aws/reconcile.py
  python aws/reconcile.py --dry-run
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
import tempfile
from pathlib import Path
from typing import Iterable

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    import boto3
    from botocore.signers import RequestSigner
except ImportError:
    print("Install AWS deps: pip install -r aws/requirements.txt", file=sys.stderr)
    raise

from dotenv import load_dotenv
from kubernetes import client as k8s_client

from shared.core import (
    DEFAULT_IMPORT_TAG_KEY,
    DEFAULT_IMPORT_TAG_VALUE,
    DEFAULT_REST_VERSION,
    KUBE_SYSTEM_NAMESPACE,
    collect_cluster_images,
    configure_logging,
    load_images_file,
    load_integration_routing,
    resolve_images_file_path,
    run_reconcile_pipeline,
    _env_optional,
    _env_truthy,
)

EKS_TOKEN_PREFIX = "k8s-aws-v1."
EKS_STS_PRESIGN_EXPIRES_SEC = 900


def eks_regions_from_env() -> list[str]:
    raw = os.environ.get("EKS_REGIONS", "").strip()
    if raw:
        return [r.strip() for r in raw.split(",") if r.strip()]
    single = os.environ.get("AWS_REGION", "").strip() or os.environ.get("AWS_DEFAULT_REGION", "").strip()
    if single:
        return [single]
    return []


def mint_eks_bearer_token(
    *,
    cluster_name: str,
    region: str,
    botocore_session,
    expires_in: int = EKS_STS_PRESIGN_EXPIRES_SEC,
) -> str:
    credentials = botocore_session.get_credentials()
    if credentials is None:
        raise RuntimeError("No AWS credentials available (configure the boto3 default chain).")
    emitter = botocore_session.get_component("event_emitter")
    sts = botocore_session.create_client("sts", region_name=region)
    service_model = sts.meta.service_model
    signer = RequestSigner(
        service_model.service_id,
        region,
        "sts",
        "v4",
        credentials,
        emitter,
    )
    operation_model = service_model.operation_model("GetCallerIdentity")
    request_dict = sts._convert_to_request_dict(
        api_params={},
        operation_model=operation_model,
        endpoint_url=sts.meta.endpoint_url.rstrip("/"),
        context={"is_presign_request": True},
        headers={},
        set_user_agent_header=False,
    )
    request_dict["method"] = "GET"
    request_dict.setdefault("headers", {})["x-k8s-aws-id"] = cluster_name
    presigned_url = signer.generate_presigned_url(
        request_dict=request_dict,
        operation_name="GetCallerIdentity",
        expires_in=expires_in,
    )
    b64 = base64.urlsafe_b64encode(presigned_url.encode("utf-8")).decode("utf-8").rstrip("=")
    return EKS_TOKEN_PREFIX + b64


def make_k8s_core_v1_eks(
    region: str,
    cluster_name: str,
    boto_session: boto3.Session,
) -> k8s_client.CoreV1Api:
    eks = boto_session.client("eks", region_name=region)
    resp = eks.describe_cluster(name=cluster_name)
    cluster = resp["cluster"]
    endpoint = cluster["endpoint"].rstrip("/")
    ca_b64 = cluster["certificateAuthority"]["data"]

    bc_session = boto_session._session
    bearer = mint_eks_bearer_token(cluster_name=cluster_name, region=region, botocore_session=bc_session)

    ca_pem = base64.standard_b64decode(ca_b64)
    fd, ca_path = tempfile.mkstemp(suffix="-eks-ca.crt")
    try:
        os.write(fd, ca_pem)
    finally:
        os.close(fd)

    cfg = k8s_client.Configuration()
    cfg.host = endpoint
    cfg.verify_ssl = True
    cfg.ssl_ca_cert = ca_path
    cfg.api_key_prefix["authorization"] = "Bearer"
    cfg.api_key["authorization"] = bearer

    api_client = k8s_client.ApiClient(configuration=cfg)
    return k8s_client.CoreV1Api(api_client=api_client)


def iter_eks_cluster_names(eks_client) -> Iterable[str]:
    token = None
    while True:
        kwargs: dict = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = eks_client.list_clusters(**kwargs)
        for name in resp.get("clusters", []):
            yield name
        token = resp.get("nextToken")
        if not token:
            break


def collect_all_images_eks(
    regions: list[str],
    boto_session: boto3.Session,
    *,
    include_kube_system: bool = False,
    only_running_pods: bool = True,
    exclude_init_containers: bool = False,
) -> set[str]:
    all_images: set[str] = set()

    for region in regions:
        print(f"Discovering EKS clusters in region {region}...", flush=True)
        eks = boto_session.client("eks", region_name=region)
        try:
            cluster_names = list(iter_eks_cluster_names(eks))
        except Exception as e:
            print(f"  Failed to list clusters: {e}", file=sys.stderr)
            continue

        if not cluster_names:
            print("  No EKS clusters found.")
            continue

        for name in cluster_names:
            print(f"  Collecting images from cluster: {name} (region: {region})", flush=True)
            if not include_kube_system:
                print(
                    f"    (skipping namespace {KUBE_SYSTEM_NAMESPACE!r}; "
                    "use --include-kube-system or INCLUDE_KUBE_SYSTEM=1 to include)",
                    flush=True,
                )
            if only_running_pods:
                print(
                    "    (only pods with phase Running; "
                    "--all-pod-phases or INCLUDE_ALL_POD_PHASES=1 for all phases)",
                    flush=True,
                )
            if exclude_init_containers:
                print(
                    "    (excluding initContainer images; "
                    "--exclude-init-containers / EXCLUDE_INIT_CONTAINERS=1)",
                    flush=True,
                )
            try:
                core_v1 = make_k8s_core_v1_eks(region, name, boto_session)
                images = collect_cluster_images(
                    core_v1,
                    include_kube_system=include_kube_system,
                    only_running_pods=only_running_pods,
                    exclude_init_containers=exclude_init_containers,
                )
                print(f"    {len(images)} unique image references found.")
                all_images.update(images)
            except Exception as e:
                print(f"    Skipping {name}: {e}", file=sys.stderr)

    return all_images


def main() -> int:
    load_dotenv(_ROOT / ".env")
    load_dotenv(_ROOT / "aws" / ".env", override=True)
    load_dotenv()

    parser = argparse.ArgumentParser(
        prog="aws/reconcile.py",
        description="Reconcile Amazon EKS running images with Snyk container projects.",
    )
    parser.add_argument(
        "--images-file",
        metavar="PATH",
        help="Read image refs from a file (one per line) instead of querying EKS.",
    )
    parser.add_argument("--wait-import", action="store_true")
    parser.add_argument("--include-kube-system", action="store_true")
    parser.add_argument("--all-pod-phases", action="store_true")
    parser.add_argument("--exclude-init-containers", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument(
        "--verbose-import",
        action="store_true",
        help="Extra hint after each import (Snyk UI keys off target.name without registry host).",
    )
    args = parser.parse_args()

    configure_logging(debug=args.debug or _env_truthy("SNYK_DEBUG", default=False))

    include_kube_system = args.include_kube_system or _env_truthy(
        "INCLUDE_KUBE_SYSTEM", default=False
    )
    include_all_phases = args.all_pod_phases or _env_truthy(
        "INCLUDE_ALL_POD_PHASES", default=False
    )
    only_running_pods = not include_all_phases
    exclude_init_containers = args.exclude_init_containers or _env_truthy(
        "EXCLUDE_INIT_CONTAINERS", default=False
    )

    token = os.environ.get("SNYK_TOKEN", "").strip()
    org_id = os.environ.get("SNYK_ORG_ID", "").strip()
    routing = load_integration_routing()
    rest_base = os.environ.get("SNYK_REST_BASE", "https://api.snyk.io").rstrip("/")
    v1_base = os.environ.get("SNYK_V1_BASE", "https://snyk.io").rstrip("/")
    rest_version = os.environ.get("SNYK_REST_VERSION", DEFAULT_REST_VERSION)

    if not token or not org_id or routing is None:
        print("Set SNYK_TOKEN, SNYK_ORG_ID, and SNYK_INTEGRATION_ID.", file=sys.stderr)
        return 1

    tag_imported = _env_truthy("SNYK_TAG_IMPORTED_PROJECTS", default=True)
    tag_key = (_env_optional("SNYK_IMPORT_TAG_KEY") or DEFAULT_IMPORT_TAG_KEY).strip()
    tag_value = (_env_optional("SNYK_IMPORT_TAG_VALUE") or DEFAULT_IMPORT_TAG_VALUE).strip()
    tag_pairs: list[tuple[str, str]] = (
        [(tag_key, tag_value)] if tag_imported and tag_key and tag_value else []
    )
    cleanup_require_tag = _env_truthy("SNYK_CLEANUP_REQUIRE_TAG", default=True)

    if args.images_file:
        img_path = resolve_images_file_path(_ROOT, args.images_file)
        print(f"Loading images from {img_path}...", flush=True)
        cluster_refs_raw = load_images_file(img_path)
        print(f"Found {len(cluster_refs_raw)} unique image references in file.", flush=True)
    else:
        regions = eks_regions_from_env()
        if not regions:
            print(
                "Set EKS_REGIONS (comma-separated) or AWS_REGION / AWS_DEFAULT_REGION.",
                file=sys.stderr,
            )
            return 1
        boto_session = boto3.Session()
        cluster_refs_raw = collect_all_images_eks(
            regions,
            boto_session,
            include_kube_system=include_kube_system,
            only_running_pods=only_running_pods,
            exclude_init_containers=exclude_init_containers,
        )
        print(f"\nTotal: {len(cluster_refs_raw)} unique image references across all clusters.", flush=True)

    return run_reconcile_pipeline(
        cluster_refs_raw,
        token=token,
        org_id=org_id,
        routing=routing,
        rest_base=rest_base,
        v1_base=v1_base,
        rest_version=rest_version,
        tag_pairs=tag_pairs,
        tag_key=tag_key,
        tag_value=tag_value,
        cleanup_require_tag=cleanup_require_tag,
        wait_import=args.wait_import,
        dry_run=args.dry_run,
        verbose_import=args.verbose_import,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from None
