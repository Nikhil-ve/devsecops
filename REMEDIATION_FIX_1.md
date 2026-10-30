# AI Remediation Suggestion for CKV_K8S_21: Missing Default Namespace & Security Context Limits

**Target File:** `k8s/juice-shop.yaml`
**Scanner Source:** `Checkov`

### Root Cause Analysis:
The deployment manifest does not enforce read-only root filesystems or runAsNonRoot execution, allowing container breakout.

### Proposed Code Fix:
```yaml
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
```
