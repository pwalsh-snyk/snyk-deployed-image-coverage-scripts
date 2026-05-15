# Technical details — Amazon EKS

This document covers **EKS discovery, IAM authentication to the Kubernetes API, and region configuration** plus Kubernetes pod image collection. **Snyk import, tagging, deduplication, and cleanup** are implemented in **`shared/core.py`** (`run_reconcile_pipeline`). For **Azure AKS**, see **[azure/Technical-Details-AKS.md](../azure/Technical-Details-AKS.md)**.

## The problem this solves

Snyk has no native concept of “deployed.” When a customer imports container images, Snyk does not know which of those images are actually running on their clusters right now.

The most common thing we hear from customers around container scanning: **“Show me issues on my deployed images. The rest is noise.”** This script bridges that gap by connecting two data sources (the Kubernetes API and the Snyk API) and keeping them in sync automatically.

## Execution flow overview

On each run, an entry script executes these steps in order (EKS variant):

1. Authenticate to AWS via the **boto3 default credential chain** (`aws configure`, `AWS_PROFILE`, instance/role credentials, etc.)  
2. **AWS SDK:** discover all EKS clusters in configured region(s)  
3. **Kubernetes API:** collect running pod images (spec tag + sha256 digest), paired per container  
4. **Snyk:** dedupe images, **re-import every distinct deployed image every run** via the v1 Import API  
5. **Snyk v1 Tags API:** tag imported projects (configurable; default `image=deployed`)  
6. **Cleanup:** delete Snyk projects in scope whose image identity no longer matches any running workload string  
7. **Target cleanup:** delete orphaned Snyk targets with no remaining projects  

---

## Step 1: AWS authentication and configuration

The script uses the **boto3 default credential chain**. No kubeconfig or `kubectl` installation is required.

- **`aws configure` / shared credentials file** (recommended for local development)  
- **Environment variables:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` (for CI or assumed roles)  
- **Instance / task role** (for running on EC2, ECS, or similar inside AWS)  

### Environment files

Load order in **`aws/reconcile.py`**:

1. **Repository root `.env`** — shared Snyk variables (`SNYK_TOKEN`, `SNYK_ORG_ID`, integrations, tagging, optional `SNYK_DEBUG`). See root **`.env.example`**.  
2. **`aws/.env`** — EKS / AWS region settings only; **overrides** the same keys from root if present. See **`aws/.env.example`**.  

**Regions:** set `EKS_REGIONS` (comma-separated, e.g. `us-east-1,eu-west-1`) or a single `AWS_REGION` / `AWS_DEFAULT_REGION` when `EKS_REGIONS` is unset. Region variables are not required if you only use `--images-file`.

---

## Step 2: EKS cluster discovery

**AWS API:** `eks:ListClusters` (paginated, per configured region)

The script lists every EKS cluster in each region you configure. It auto-discovers clusters with no need to hard-code cluster names or API endpoints.

**AWS API:** `eks:DescribeCluster`

For each discovered cluster, the script fetches the API server endpoint and CA certificate. It then mints an IAM bearer token and builds an in-memory Kubernetes client (no local kubeconfig file).

### IAM bearer token (inline signing)

Tokens are created with **`botocore.signers.RequestSigner`**: a presigned `sts:GetCallerIdentity` URL, wrapped as `k8s-aws-v1.<base64url>`, with header **`x-k8s-aws-id`** set to the cluster name. There is no `aws eks get-token` subprocess and no `eks-token` package.

Your principal must be allowed on the cluster Kubernetes API (**`aws-auth` ConfigMap** or **EKS access entries**) with RBAC to list pods cluster-wide (`eks:ListClusters` and `eks:DescribeCluster` alone are not enough).

### Network access

If the API server endpoint is **only reachable inside the VPC** (private or hybrid endpoint access), the host running the script must have connectivity (VPN, Direct Connect, bastion path, or runner inside the VPC). `DescribeCluster` can succeed from the public internet while `list pods` fails without that path.

---

## Step 3: Collecting running images from the cluster

**Kubernetes API:** `CoreV1Api.list_pod_for_all_namespaces()`

Returns every pod across every namespace. For each pod the script pulls two different image representations:

- **Spec image** (`pod.spec.containers[].image`): what was requested when the pod was created  
  _Example:_ `746630811623.dkr.ecr.us-west-2.amazonaws.com/juice-shop-repo:juice-shop-app`  
- **Runtime digest** (`pod.status.containerStatuses[].image_id`): what is actually running, resolved to a content digest by the container runtime  
  _Example:_ `docker-pullable://746630811623.dkr.ecr.us-west-2.amazonaws.com/juice-shop-repo@sha256:abc123...`  

**Why both?** The spec ref uses a tag (`:juice-shop-app`) which can be reassigned to a different image. The digest (`sha256:`) is immutable — it is the fingerprint of the exact image content running on the node. The full set (`all_refs`) is kept for **cleanup matching** so Snyk projects can be matched against either form.

### Per-container pairing (import targets)

Spec and status strings are **paired by container name** (`pod.spec.containers[].name` ↔ `pod.status.containerStatuses[].name`). Each container contributes **one** import target: prefer **`spec.image`** (tag form for Snyk UI), fall back to **`status.image_id`** when spec is missing.

This prevents double-importing the same workload as both `repo:tag` and `repo@sha256:…`, and correctly handles **multiple tags in one ECR repository** (e.g. `juice-shop-repo:juice-shop-app` and `juice-shop-repo:nginx-alpine` on different pods) without collapsing them into one image.

### Default filters during collection

- Only **Running** pods; excludes completed or failed Job/CronJob pods that would pull in stale images  
- Excludes **kube-system**, avoiding importing cluster addon images (CoreDNS, metrics-server, etc.)  
- **Init containers** included by default; can be excluded with `--exclude-init-containers`  

---

## Step 4: Deduplication

Before comparing against Snyk, the script collapses duplicate image references where appropriate.

- **Live cluster runs:** deduplication runs on **`import_targets`** (one ref per container after pairing), not on the raw spec+digest union. You may still see **N unique image references** in logs (spec + status per pod) alongside **M import target(s)** — only **M** images are sent to Snyk.  
- **`--images-file` mode:** pairing is unavailable; the script falls back to **`dedupe_cluster_images_by_content`** over the file’s image list (repo-base + digest heuristics).

This prevents Snyk from receiving separate import requests for the same container’s tag and digest, and avoids incorrect merging when two different tags share one ECR repository name.

---

## Step 5: Snyk pipeline (shared `shared/core.py`)

After deduplication, **`run_reconcile_pipeline`** drives the rest of the run:

- **Import:** `POST` every deduped image to the Snyk v1 import API **each run** (re-scan), with registry integration routing and hostname stripping for `target.name`. **ECR** hostnames (`*.amazonaws.com`, `*.ecr.*`) route to `SNYK_INTEGRATION_ID_ECR` when set.  
- **Tag:** When enabled, poll each import job and tag created projects (default `image=deployed`).  
- **Cleanup:** Page tagged projects via Snyk REST, delete any whose image identity does not match **any** current cluster image string in **`all_refs`**. Matching includes digest and **registry-stripped** forms so full `*.dkr.ecr.*.amazonaws.com/...` pod refs align with Snyk’s repo-only names.

---

## Step 6: Importing running images (detail)

**Snyk API:** `POST /api/v1/org/{orgId}/integrations/{integrationId}/import`

The script submits **every** running cluster image to Snyk’s import API, not just new ones. Re-importing an image that Snyk has already scanned is intentional: it triggers a fresh scan against the latest vulnerability database, which is important for good appsec practice. A project that was clean six months ago may have new CVEs today, and a scheduled run of this script ensures Snyk’s results stay current.

Two things happen before each import call:

- **Registry routing:** the script checks the image hostname to pick the right Snyk integration. Images from `*.amazonaws.com` / `*.ecr.*` use the ECR integration ID, ACR images use the ACR integration ID, GCP images use the GCP integration ID, and so on. This matters because Snyk authenticates to each registry separately.  
- **Hostname stripping:** Snyk’s import API expects only the repository path, not the full image reference. Passing the registry hostname causes an “Unauthorized access” error even with valid credentials.  
  _Example:_ `746630811623.dkr.ecr.us-west-2.amazonaws.com/juice-shop-repo:juice-shop-app` → `juice-shop-repo:juice-shop-app`  

Snyk import activity and project names typically show that **short** `target.name`, not the full ECR string. Use **`--verbose-import`** on the CLI to print both `cluster_ref` and `target.name` per POST.

The import call returns a job URL. The script polls that URL until the job completes, then tags the newly created projects `image=deployed` before moving on.

---

## Step 7: Tagging imported projects

**Snyk API:** `POST /api/v1/org/{orgId}/project/{projectId}/tags`

Once an import job completes, the API response includes the project IDs that were created. The script applies an `image=deployed` tag to each one (key and value are configurable via `SNYK_IMPORT_TAG_*` env vars).

This tag is what makes cleanup possible. It marks the projects this script created and manages. Projects tagged by other means are left alone.

---

## Step 8: Cleanup — removing stale projects

**Snyk API:** `GET /rest/orgs/{orgId}/projects?tags=image:deployed&expand=target`

The script fetches only projects tagged `image=deployed` (the ones it manages) and checks each one against the current cluster image set using the shared matching rules (including digest and registry-stripped keys).

If a tagged project’s image does not match any currently running image, that project is considered stale and deleted:

**Snyk API:** `DELETE /api/v1/org/{orgId}/project/{projectId}`

The `expand=target` parameter in the list call is important. It tells Snyk to include the target relationship in the response so the script knows which Snyk target owns each project, without making a separate GET request per project.

---

## Step 9: Orphaned target cleanup

When a project is deleted, its parent target (the grouping container in the Snyk UI) remains even if it now has zero projects. This creates noise in the Snyk UI.

After deleting projects, the script checks whether the parent target is now empty:

**Snyk API:** `GET /rest/orgs/{orgId}/projects?target_id={targetId}&limit=10`

If the response has no projects, the target is deleted:

**Snyk API:** `DELETE /rest/orgs/{orgId}/targets/{targetId}`

This is fully automatic; no manual cleanup is needed in the Snyk UI.

---

## API reference summary

| Step | API / surface | Endpoint or call |
|------|----------------|-------------------|
| Cluster discovery | AWS SDK | `eks:ListClusters` |
| Cluster endpoint + CA | AWS SDK | `eks:DescribeCluster` |
| IAM token material | AWS STS (presigned) | `sts:GetCallerIdentity` (inside `k8s-aws-v1.*` bearer) |
| Pod image collection | Kubernetes | `GET /api/v1/pods` |
| List projects (cleanup) | Snyk REST | `GET /rest/orgs/{id}/projects` (with `tags`, `expand`) |
| Import image | Snyk v1 | `POST /api/v1/org/{id}/integrations/{id}/import` |
| Tag project | Snyk v1 | `POST /api/v1/org/{id}/project/{id}/tags` |
| Delete project | Snyk v1 | `DELETE /api/v1/org/{id}/project/{id}` |
| Check target projects | Snyk REST | `GET /rest/orgs/{id}/projects?target_id={id}` |
| Delete orphan target | Snyk REST | `DELETE /rest/orgs/{id}/targets/{id}` |

---

## What this proves

The “deployed” context customers ask for is not a product gap that requires a new Snyk feature. It is achievable today by joining data already available from the cloud provider and Kubernetes APIs with the Snyk API, and the missing piece was the reconciliation layer, which is what this script does.

For **AKS**, see **[azure/Technical-Details-AKS.md](../azure/Technical-Details-AKS.md)**. **GCP (GKE)** would follow the same pattern as either provider: swap cluster discovery and kube auth; reuse **`shared/core.py`** for Snyk.

**GitHub:** [github.com/pwalsh-snyk/snyk-deployed-image-coverage](https://github.com/pwalsh-snyk/snyk-deployed-image-coverage)
