# AI Remediation Suggestion for CKV_K8S_11: CPU/Memory Resource Limits Not Guaranteed

**Target File:** `k8s/juice-shop.yaml`
**Scanner Source:** `Checkov`

### Root Cause Analysis:
Pod specifications must explicitly cap resources to prevent Denial-of-Service via noisy neighbor resource starvation.

### Proposed Code Fix:
```yaml
        resources:
          limits:
            cpu: "500m"
            memory: "512Mi"
          requests:
            cpu: "250m"
            memory: "256Mi"
```
