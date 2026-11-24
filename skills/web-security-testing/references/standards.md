# Standards

- OWASP ASVS: cite the version (4.0.3 uses chapters V1 to V14; ASVS 5.0 renumbered and reorganized chapters). Use ASVS for verification requirements per category (authentication, session management, access control, validation and encoding, API, files).
- OWASP Top 10 (2021): A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable and Outdated Components, A07 Identification and Authentication Failures, A08 Software and Data Integrity Failures, A09 Logging and Monitoring Failures, A10 SSRF.
- CWE examples: CWE-79 XSS, CWE-89 SQL injection, CWE-352 CSRF, CWE-22 path traversal, CWE-918 SSRF, CWE-639 authorization bypass through user-controlled key, CWE-798 hardcoded credentials, CWE-502 deserialization of untrusted data, CWE-614 sensitive cookie without Secure.
- Only cite a mapping when the finding actually matches it; do not decorate findings with extra ids.
