# snyk-deployed-image-coverage

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
