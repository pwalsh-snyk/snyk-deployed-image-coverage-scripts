#!/usr/bin/env python3
"""
Reconcile container images running in AKS with Snyk projects.

Environment variables: see **README.md** and **Technical-Details-AKS.md** in this folder. Loads **repository root `.env`** then **`azure/.env`** (provider overrides).

Usage:
  python azure/reconcile.py
  python azure/reconcile.py --dry-run --images-file ../cluster-images.example.txt
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import yaml
from dotenv import load_dotenv

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.containerservice import ContainerServiceClient
except ImportError:
    print(
        "Install Azure deps: pip install -r azure/requirements.txt",
        file=sys.stderr,
    )
    raise

from kubernetes import client as k8s_client
from kubernetes.config import kube_config as kube_cfg

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


def _resource_group_from_id(arm_id: str) -> str:
    parts = re.split(r"/resourcegroups/", arm_id, maxsplit=1, flags=re.IGNORECASE)
    if len(parts) < 2:
        raise ValueError(f"Not a valid ARM resource id (no resourceGroups segment): {arm_id!r}")
    return parts[1].split("/", 1)[0]


def _kubeconfig_dict_from_azure_value(value: str | bytes) -> dict:
    if isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raw = value
    if raw.lstrip().startswith(b"apiVersion:"):
        text = raw.decode("utf-8")
    else:
        pad = b"=" * (-len(raw) % 4)
        text = base64.b64decode(raw + pad).decode("utf-8")
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise RuntimeError("Kubeconfig from Azure is not a YAML mapping")
    return doc


def make_k8s_core_v1(
    subscription_id: str,
    resource_group: str,
    cluster_name: str,
) -> k8s_client.CoreV1Api:
    credential = DefaultAzureCredential()
    acs = ContainerServiceClient(credential, subscription_id)
    result = acs.managed_clusters.list_cluster_user_credentials(resource_group, cluster_name)

    if not result.kubeconfigs:
        raise RuntimeError(
            f"No kubeconfig returned for cluster {cluster_name!r} "
            f"(resource group: {resource_group!r}). "
            "Check that your identity has at least 'Azure Kubernetes Service Cluster User Role'."
        )

    kubeconfig_dict = _kubeconfig_dict_from_azure_value(result.kubeconfigs[0].value)

    cfg = k8s_client.Configuration()
    loader = kube_cfg.KubeConfigLoader(config_dict=kubeconfig_dict)
    loader.load_and_set(cfg)
    api_client = k8s_client.ApiClient(configuration=cfg)
    return k8s_client.CoreV1Api(api_client=api_client)


def discover_aks_clusters(
    subscription_id: str,
    resource_group: str | None = None,
) -> list[tuple[str, str, str]]:
    credential = DefaultAzureCredential()
    acs = ContainerServiceClient(credential, subscription_id)

    clusters = (
        acs.managed_clusters.list_by_resource_group(resource_group)
        if resource_group
        else acs.managed_clusters.list()
    )

    return [
        (subscription_id, _resource_group_from_id(c.id), c.name)
        for c in clusters
    ]


def collect_all_images(
    subscription_ids: list[str],
    resource_group: str | None = None,
    *,
    include_kube_system: bool = False,
    only_running_pods: bool = True,
    exclude_init_containers: bool = False,
) -> tuple[set[str], set[str]]:
    """Returns ``(all_refs, import_targets)`` aggregated across all clusters."""
    all_images: set[str] = set()
    import_targets: set[str] = set()

    for sub_id in subscription_ids:
        print(f"Discovering AKS clusters in subscription {sub_id}...", flush=True)
        try:
            clusters = discover_aks_clusters(sub_id, resource_group)
        except Exception as e:
            print(f"  Failed to list clusters: {e}", file=sys.stderr)
            continue

        if not clusters:
            print("  No AKS clusters found.")
            continue

        for sub, rg, name in clusters:
            print(f"  Collecting images from cluster: {name} (resource group: {rg})", flush=True)
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
                core_v1 = make_k8s_core_v1(sub, rg, name)
                images, targets = collect_cluster_images(
                    core_v1,
                    include_kube_system=include_kube_system,
                    only_running_pods=only_running_pods,
                    exclude_init_containers=exclude_init_containers,
                )
                print(
                    f"    {len(images)} unique image references found "
                    f"({len(targets)} import target(s) after per-container pairing)."
                )
                all_images.update(images)
                import_targets.update(targets)
            except Exception as e:
                print(f"    Skipping {name}: {e}", file=sys.stderr)

    return all_images, import_targets


def main() -> int:
    load_dotenv(_ROOT / ".env")
    load_dotenv(_ROOT / "azure" / ".env", override=True)
    load_dotenv()

    parser = argparse.ArgumentParser(
        prog="azure/reconcile.py",
        description="Reconcile AKS running images with Snyk container projects.",
    )
    parser.add_argument(
        "--images-file",
        metavar="PATH",
        help="Read image refs from a file (one per line) instead of querying Azure.",
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

    import_targets: set[str] | None = None
    if args.images_file:
        img_path = resolve_images_file_path(_ROOT, args.images_file)
        print(f"Loading images from {img_path}...", flush=True)
        cluster_refs_raw = load_images_file(img_path)
        print(f"Found {len(cluster_refs_raw)} unique image references in file.", flush=True)
    else:
        sub_env = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
        if not sub_env:
            print("Set AZURE_SUBSCRIPTION_ID (comma-separated for multiple).", file=sys.stderr)
            return 1
        subscription_ids = [s.strip() for s in sub_env.split(",") if s.strip()]
        resource_group = _env_optional("AZURE_RESOURCE_GROUP")
        cluster_refs_raw, import_targets = collect_all_images(
            subscription_ids,
            resource_group,
            include_kube_system=include_kube_system,
            only_running_pods=only_running_pods,
            exclude_init_containers=exclude_init_containers,
        )
        print(
            f"\nTotal: {len(cluster_refs_raw)} unique image references across all clusters "
            f"({len(import_targets)} import target(s) after per-container pairing).",
            flush=True,
        )

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
        import_targets=import_targets,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from None
