# Security policy

## Supported version

Security fixes are applied to the latest tagged release.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository. Do
not open a public issue for credential exposure, unsafe output, insufficient
redaction, path traversal, response confusion, or another security concern.

Include only synthetic reproduction material. Never include:

- API tokens, passwords, cookies, or Authorization headers;
- real site URLs, tenant IDs, rule IDs, issue IDs, or account IDs;
- HAR files;
- real Automation configuration, Audit CSV, or detailed JSON;
- customer names or operational values.

If a real credential was exposed, revoke it with the provider before reporting
the software issue.

## Scope boundary

The collector uses an undocumented Atlassian internal endpoint. Endpoint
availability, authentication changes, and upstream response changes are not
security vulnerabilities in this project by themselves. Unsafe handling of
those responses or disclosure of sensitive data is in scope.
