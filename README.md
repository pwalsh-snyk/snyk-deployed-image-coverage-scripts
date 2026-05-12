# snyk-deployed-image-coverage

## Why this exists

When customers talk about container scanning with Snyk, the ask is almost always the same: *scan what's actually deployed, not everything in the registry.* Snyk has no native way to determine which scanned images are actively running on your clusters. This script closes that gap.

On each run it:

1. Discovers all AKS clusters in your Azure subscription(s) using the Azure SDK (no kubectl required).
2. Collects every image reference from running pods — both the `spec` tag string and the resolved `sha256` digest from `status.containerStatuses[].image_id`.
3. Triggers a Snyk v1 import for **each** distinct deployed image (after digest dedupe), every run — routing to the right registry integration by hostname — so images are re-scanned on a schedule, not only on first sight.
4. Tags projects `image=deployed` (configurable) after successful imports so you can filter in the Snyk UI.
5. Deletes Snyk projects tagged `image=deployed` whose image is no longer running, then removes the orphaned Snyk target if no projects remain.

## What this is

Snyk scans container images well, but it does not know which images are **actually running** in your clusters versus sitting unused in a registry. This repo is a small **reconciliation layer**: it learns what is deployed from the Kubernetes API, keeps Snyk aligned with that reality (re-imports on a schedule, tags what it manages, and can remove projects for images that are no longer running), and does so **without** checking in a kubeconfig—each cloud entry script discovers clusters and obtains API access the idiomatic way for that provider.

The **approach** is the same everywhere: **discover workloads → collect image refs from running pods → dedupe → Snyk import + tagging → optional cleanup of stale tagged projects.** Provider-specific pieces are only **how we authenticate and find clusters**; the Snyk and pod-image logic lives in **`shared/`** and is shared by both scripts.

---

## Pick your cloud

| Your environment | Go here |
|--------------------|---------|
| **Azure Kubernetes Service (AKS)** | **[`azure/README.md`](azure/README.md)** — install, env files, run `azure/reconcile.py`, flags, and **[technical details](azure/Technical-Details-AKS.md)** |
| **Amazon Elastic Kubernetes Service (EKS)** | **[`aws/README.md`](aws/README.md)** — install, env files, run `aws/reconcile.py`, flags, and **[technical details](aws/Technical-Details-EKS.md)** |

Run commands **from the repository root** (for example `.venv/bin/python azure/reconcile.py` or `.venv/bin/python aws/reconcile.py`) so imports resolve.

---

## Quick start (any cloud)

1. Python **3.10+** and a Snyk org with a container registry integration configured for your images.  
2. Create a virtualenv and install deps (full install, or only `azure/` or `aws/` per the README in that folder):

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```

3. Copy the **`.env.example`** files (root + the folder for your cloud) into `.env` / `azure/.env` / `aws/.env` as described in the provider README, then follow that README for auth and first run.

Details, CLI flags (`--dry-run`, `--images-file`, …), networking, and troubleshooting stay in the **Azure** and **AWS** READMEs above—this page stays at the overview so you can jump straight to the script that matches your environment.
