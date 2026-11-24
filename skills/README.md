# Skills

Sixteen independently installable Agent Skills (https://agentskills.io/specification). Each folder contains a `SKILL.md` and a `references/` directory and works on its own when copied by `npx skills add`; the `security-skills` CLI is optional. The CLI is intended to be installed from `pip install git+https://github.com/shikari00007/security-test-automation`; that is the intended location and the package is not yet published.

Skills: security-start, security-project-context, security-do, security-test-strategy, security-coverage-analysis, web-security-testing, api-security-testing, android-security-testing, ios-security-testing, desktop-security-testing, supply-chain-security, cloud-kubernetes-security, ai-llm-security, security-finding-validation, security-regression-generation, security-reporting.

Validate: `python3 -m security_runner skills validate skills`.

Out of scope: wireless, IoT and standalone Active Directory penetration testing. Enterprise authentication (LDAP, Kerberos, SSO, OIDC) is covered where relevant under web, API and desktop.

## Attribution

Methodology is inspired by, and no text is copied from, these MIT-licensed projects at pinned commits:

- cloudflare/security-audit-skill, commit c1c8a8c1471069fb0e188eeaff69b8e8db6564a8 (audit workflow and adversarial validation ideas)
- petrkindlmann/qa-skills, commit 5087a3461d49da76b1e794d9b0bfbd23f38dc75b (skill structure and QA workflow ideas)
- SnailSploit/Claude-Red, commit 6196ba7464662de34e8744d359f175d1a7bca530 (reference only; offensive content is not imported)

Standards cited in the references (OWASP ASVS, MASVS, API Top 10, LLM Top 10, CWE, CIS) belong to their respective organizations.
