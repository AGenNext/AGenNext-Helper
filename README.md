# AGenNext Helper

Provider-neutral standards adapters for enterprise agent authentication, authorization, provisioning, approvals, audit, and governance.

This repository implements compatibility helpers against open standards. It does **not** include provider-specific integrations.

## Product Boundary

```text
If a provider follows the standard, it works.
If not, the customer bridges it to the standard.
```

## Standards Supported

| Capability | Standard / Interface |
|---|---|
| Authentication | OIDC / OAuth2 / SAML |
| Provisioning / IGA | SCIM 2.0 |
| Authorization | AuthZEN |
| Policy | OPA / Rego |
| PAM / JIT Access | Standard approval webhook/API pattern |
| Audit / SIEM | JSONL, syslog, HTTP webhook |
| Secrets | Vault-compatible API / env references |

## Package

```text
agennext_helper/
  iam_oidc.py
  scim_sync.py
  pam_approval.py
  siem_export.py
```

## Install

```bash
pip install git+https://github.com/AGenNext/AGenNext-Helper.git
```

## Runtime Usage

Agent runtimes can depend on this package for standards adapters, while keeping policy enforcement in their own runtime.
