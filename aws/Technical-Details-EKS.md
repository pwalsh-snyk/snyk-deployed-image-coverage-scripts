# Technical details — Amazon EKS

This document covers **EKS discovery, IAM authentication to the Kubernetes API, and region configuration**. **Snyk import, tagging, deduplication, and cleanup** live in **`shared/core.py`** (`run_reconcile_pipeline`). For **Azure AKS**, see **[azure/Technical-Details-AKS.md](../azure/Technical-Details-AKS.md)**.

## Environment files

Load order in **`aws/reconcile.py`**:

1. **Repository root `.env`** — shared Snyk variables (`SNYK_TOKEN`, `SNYK_ORG_ID`, integrations, tagging, optional `SNYK_DEBUG`). See root **`.env.example`**.
2. **`aws/.env`** — EKS / AWS region settings only; **overrides** the same keys from root if present. See **`aws/.env.example`**.

Credentials use the **boto3 default chain** (`aws configure`, `AWS_PROFILE`, instance/role credentials, etc.); they are not read from a custom filename beyond what you export yourself.

## End-to-end flow (EKS entry script)

1. **Regions** — `EKS_REGIONS` (comma-separated) or `AWS_REGION` / `AWS_DEFAULT_REGION` when `EKS_REGIONS` is unset.
2. **List clusters** — `eks:ListClusters` per region (paginated).
3. **Per cluster** — `eks:DescribeCluster` for API endpoint and CA certificate.
4. **Bearer token** — Inline **`botocore.signers.RequestSigner`**: presigned `sts:GetCallerIdentity` URL, wrapped as `k8s-aws-v1.<base64url>`, with header **`x-k8s-aws-id`** set to the cluster name. No `aws eks get-token` subprocess and no `eks-token` package.
5. **Kubernetes client** — In-memory `Configuration` with `ssl_ca_cert` (PEM from describe-cluster) and Bearer token.
6. **Pod images** — `CoreV1Api.list_pod_for_all_namespaces()` (same filters as AKS path: **Running** pods by default, **`kube-system`** skipped unless opted in). Namespace of the workload does not matter except for that filter.
7. **Snyk** — **`run_reconcile_pipeline`** in `shared/core.py`: dedupe, v1 import per target, optional tag + cleanup.

## Network access

If the API server endpoint is **only reachable inside the VPC**, the host running the script must have connectivity (VPN, Direct Connect, bastion path, or runner inside the VPC). `DescribeCluster` can succeed from the public internet while `list pods` fails without that path.

## Snyk `target.name` vs full image ref

Imports send **`strip_registry_hostname(image_ref)`** as `target.name`. Snyk import activity and project names typically show **`repo:tag`** or **`repo@sha256:…`**, not the full `*.dkr.ecr.*.amazonaws.com/...` string. Use **`--verbose-import`** on the CLI to print both cluster ref and `target.name` per POST.

## API summary (AWS-specific)

| Concern | AWS / API |
|---------|-----------|
| List clusters | `eks:ListClusters` |
| Cluster CA + endpoint | `eks:DescribeCluster` |
| IAM token material | `sts:GetCallerIdentity` (presigned URL inside `k8k-aws-v1.*` bearer) |
| Pod images | Kubernetes `GET /api/v1/pods` (via client-go / official Python client) |

Snyk REST and v1 endpoints are the same as in the Azure technical doc; see **`shared/core.py`** for paths and behavior.
