# Amazon EKS reconcile

Entry point: **`aws/reconcile.py`** (run from repository root: `python aws/reconcile.py`).

Install:

```bash
pip install -r aws/requirements.txt
```

## Prerequisites

- AWS credentials for the account that owns the clusters (default boto3 credential chain)
- IAM permission for `eks:ListClusters` and `eks:DescribeCluster` in the regions you scan
- Principal allowed on each cluster’s Kubernetes API (`aws-auth` or EKS access entries) with RBAC to list pods cluster-wide
- **ECR** images route to `SNYK_INTEGRATION_ID_ECR` when hostname matches `amazonaws.com` / `.ecr.` (see shared routing in `shared/core.py`)

## Snyk import UI vs what we send

The v1 import API expects **`target.name`** without the registry hostname (for example `juice-shop-repo:reconcile-smoke-arm64-…`, not `992382539141.dkr.ecr.…/juice-shop-repo:…`). Snyk’s import activity / logs usually show that **short** name. If you search the UI for the full ECR string, you may not see a hit even when the import ran. Run the script and read the **`target.name=`** line printed for each `Import started:` row.

Use **`--verbose-import`** for an extra reminder line after each successful POST.

## Token signing

IAM bearer tokens are minted **inline** with **`botocore.signers.RequestSigner`** (presigned `sts:GetCallerIdentity`, `k8s-aws-v1.*`, including `x-k8s-aws-id`). No `aws eks get-token` subprocess and no `eks-token` package.

## Environment variables

Load order: **repository root `.env`** (shared Snyk), then **`aws/.env`** (same key in `aws/.env` wins). Copy from [`.env.example`](../.env.example) and [`aws/.env.example`](.env.example).

| Variable | File | Required | Description |
|----------|------|----------|-------------|
| `SNYK_TOKEN`, `SNYK_ORG_ID`, `SNYK_INTEGRATION_ID` | root `.env` | Yes | Snyk API access |
| `EKS_REGIONS` | `aws/.env` (or root) | Yes* | Comma-separated regions (e.g. `us-east-1,eu-west-1`) |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | `aws/.env` (or root) | Yes* | Single region if `EKS_REGIONS` is unset |

\* Skip region vars if you only use `--images-file`.

Optional Snyk routing/tags: root `.env`.

Deep dive: **[Technical-Details-EKS.md](Technical-Details-EKS.md)**.

### Network access

If the cluster Kubernetes API is reachable **only inside the VPC** (private or hybrid endpoint access), the machine running `aws/reconcile.py` needs a network path to that API server URL — for example VPN or Direct Connect into the VPC, a bastion with connectivity to the control plane, or a runner inside the VPC (EC2, VPC-attached CI, etc.). AWS API calls like `DescribeCluster` may succeed from the public internet while pod listing fails without that path.

## Usage

```bash
.venv/bin/python aws/reconcile.py
.venv/bin/python aws/reconcile.py --dry-run
.venv/bin/python aws/reconcile.py --images-file cluster-images.example.txt
```

Shared flags are the same as for Azure; see root **README.md**.

## Scope notes

This port does **not** include multi-account AssumeRole chains, retry/backoff tuning, or special-case registry routing for ECR pull-through cache hostnames beyond the existing patterns in `integration_id_for_image`.
