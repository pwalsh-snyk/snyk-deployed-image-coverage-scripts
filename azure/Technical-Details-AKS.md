# Technical details — Azure AKS

This document covers **AKS discovery and kubeconfig** plus Kubernetes pod image collection. **Snyk import, tagging, deduplication, and cleanup** are implemented in **`shared/core.py`** (`run_reconcile_pipeline`). For **Amazon EKS**, see **[aws/Technical-Details-EKS.md](../aws/Technical-Details-EKS.md)**.

## The problem this solves

Snyk has no native concept of “deployed.” When a customer imports container images, Snyk does not know which of those images are actually running on their clusters right now.

The most common thing we hear from customers around container scanning: **“Show me issues on my deployed images. The rest is noise.”** This script bridges that gap by connecting two data sources (the Kubernetes API and the Snyk API) and keeping them in sync automatically.

## Execution flow overview

On each run, an entry script executes these steps in order (AKS variant):

1. Authenticate to Azure via `az login` or service principal  
2. **Azure SDK:** discover all AKS clusters in the subscription  
3. **Kubernetes API:** collect running pod images (spec tag + sha256 digest)  
4. **Snyk:** dedupe images, **re-import every distinct deployed image every run** via the v1 Import API  
5. **Snyk v1 Tags API:** tag imported projects (configurable; default `image=deployed`)  
6. **Cleanup:** delete Snyk projects in scope whose image identity no longer matches any running workload string  
7. **Target cleanup:** delete orphaned Snyk targets with no remaining projects  

---

## Step 1: Azure authentication

The script uses **DefaultAzureCredential** from the Azure Python SDK. It tries credential sources in order; no kubeconfig or `kubectl` installation is required.

- **`az login` session** (recommended for local development)  
- **Environment variables:** `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` (for service principals in CI)  
- **Managed identity** (for running on Azure VMs or AKS itself)  

---

## Step 2: AKS cluster discovery

**Azure API:** `managed_clusters.list()`

The script calls the Azure Resource Manager API to list every AKS cluster in the configured subscription. It auto-discovers clusters with no need to hard-code cluster names or hostnames, optionally scoped to a single resource group with `AZURE_RESOURCE_GROUP`.

**Azure API:** `managed_clusters.list_cluster_user_credentials()`

For each discovered cluster, the script fetches a kubeconfig directly from the Azure API (the same credential file `kubectl` would use) and loads it into memory to create a Kubernetes API client. No local kubeconfig file is required.

---

## Step 3: Collecting running images from the cluster

**Kubernetes API:** `CoreV1Api.list_pod_for_all_namespaces()`

Returns every pod across every namespace. For each pod the script pulls two different image representations:

- **Spec image** (`pod.spec.containers[].image`): what was requested when the pod was created  
  _Example:_ `pwalshobaks2025.azurecr.io/frontend:v0.10.5`  
- **Runtime digest** (`pod.status.containerStatuses[].image_id`): what is actually running, resolved to a content digest by the container runtime  
  _Example:_ `docker-pullable://pwalshobaks2025.azurecr.io/frontend@sha256:abc123...`  

**Why both?** The spec ref uses a tag (`:v0.10.5`) which can be reassigned to a different image. The digest (`sha256:`) is immutable — it is the fingerprint of the exact image content running on the node. Using both gives the script more ways to match against Snyk projects and prevents false “not found” results.

### Default filters during collection

- Only **Running** pods; excludes completed or failed Job/CronJob pods that would pull in stale images  
- Excludes **kube-system**, avoiding importing cluster addon images (CoreDNS, metrics-server, etc.)  
- **Init containers** included by default; can be excluded with `--exclude-init-containers`  

---

## Step 4: Deduplication

Before comparing against Snyk, the script collapses duplicate image references. A single running container typically produces two strings (a tag ref from spec and a digest ref from status) that both point to the same image content. The script detects these pairs by matching the digest and reduces them to one import target per unique image.

This prevents Snyk from receiving two separate import requests for what is logically the same image.

---

## Step 5: Snyk pipeline (shared `shared/core.py`)

After deduplication, **`run_reconcile_pipeline`** drives the rest of the run:

- **Import:** `POST` every deduped image to the Snyk v1 import API **each run** (re-scan), with registry integration routing and hostname stripping for `target.name`.  
- **Tag:** When enabled, poll each import job and tag created projects (default `image=deployed`).  
- **Cleanup:** Page tagged projects via Snyk REST, delete any whose image identity does not match **any** current cluster image string. Matching includes digest and **registry-stripped** forms so full `*.azurecr.io/...` pod refs align with Snyk’s repo-only names.

---

## Step 6: Importing running images (detail)

**Snyk API:** `POST /api/v1/org/{orgId}/integrations/{integrationId}/import`

The script submits **every** running cluster image to Snyk’s import API, not just new ones. Re-importing an image that Snyk has already scanned is intentional: it triggers a fresh scan against the latest vulnerability database, which is important for good appsec practice. A project that was clean six months ago may have new CVEs today, and a scheduled run of this script ensures Snyk’s results stay current.

Two things happen before each import call:

- **Registry routing:** the script checks the image hostname to pick the right Snyk integration. Images from `*.azurecr.io` use the ACR integration ID, GCP images use the GCP integration ID, ECR uses the ECR integration ID, and so on. This matters because Snyk authenticates to each registry separately.  
- **Hostname stripping:** Snyk’s import API expects only the repository path, not the full image reference. Passing the registry hostname causes an “Unauthorized access” error even with valid credentials.  
  _Example:_ `pwalshobaks2025.azurecr.io/frontend:v0.10.5` → `frontend:v0.10.5`  

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
| Cluster discovery | Azure SDK | `managed_clusters.list()` |
| Cluster credentials | Azure SDK | `managed_clusters.list_cluster_user_credentials()` |
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

For **EKS**, see **[aws/Technical-Details-EKS.md](../aws/Technical-Details-EKS.md)**. **GCP (GKE)** would follow the same pattern as either provider: swap cluster discovery and kube auth; reuse **`shared/core.py`** for Snyk.

**GitHub:** [github.com/pwalsh-snyk/snyk-deployed-image-coverage](https://github.com/pwalsh-snyk/snyk-deployed-image-coverage)
