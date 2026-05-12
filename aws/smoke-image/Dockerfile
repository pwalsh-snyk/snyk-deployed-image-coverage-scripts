# Minimal image pushed for reconcile smoke tests — not intended for workloads.
FROM alpine:3.19
RUN echo "snyk-reconcile-smoke" > /etc/smoke-marker && chmod 644 /etc/smoke-marker
# Default CMD for local runs; k8s pod.yaml overrides with sleep for long-running workload.
CMD ["cat", "/etc/smoke-marker"]
