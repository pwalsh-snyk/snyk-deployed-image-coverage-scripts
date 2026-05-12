# Azure AKS reconcile

Entry point: **`azure/reconcile.py`** (run from repository root: `python azure/reconcile.py`).

Install:

```bash
pip install -r azure/requirements.txt
```

## Prerequisites

- An Azure subscription with at least one AKS cluster
- `az login` (or a service principal via env vars — see below)
- Identity needs **Azure Kubernetes Service Cluster User Role** on each cluster

## Environment variables

Load order: **repository root `.env`** (shared Snyk), then **`azure/.env`** (same key in `azure/.env` wins). Copy from [`.env.example`](../.env.example) and [`azure/.env.example`](.env.example).

| Variable | File | Required | Description |
|----------|------|----------|-------------|
| `SNYK_TOKEN`, `SNYK_ORG_ID`, `SNYK_INTEGRATION_ID` | root `.env` | Yes | Snyk API access |
| `AZURE_SUBSCRIPTION_ID` | `azure/.env` (or root) | Yes* | Subscription(s), comma-separated |
| `AZURE_RESOURCE_GROUP` | `azure/.env` (or root) | No | Limit discovery to one resource group |

\* Skip `AZURE_SUBSCRIPTION_ID` if you only use `--images-file`.

Optional Snyk routing and tagging: root `.env` (`SNYK_INTEGRATION_ID_*`, `SNYK_IMPORT_TAG_*`, etc.).

Deep dive: **[Technical-Details-AKS.md](Technical-Details-AKS.md)**.

## Auth

Uses **`DefaultAzureCredential`**:

1. `az login` — typical for local dev  
2. `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` — service principals in CI  
3. Managed identity — on Azure VMs or AKS  

No local kubeconfig file is required; kubeconfigs are fetched from the Azure API per cluster.

## Usage

```bash
.venv/bin/python azure/reconcile.py
.venv/bin/python azure/reconcile.py --dry-run
.venv/bin/python azure/reconcile.py --images-file cluster-images.example.txt
```

See root **README.md** for shared flags (`--include-kube-system`, `--all-pod-phases`, `--exclude-init-containers`, `--wait-import`, `--debug`).
