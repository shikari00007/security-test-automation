# Verification notes: threat-modeling

Date: 2026-11-26. This skill has no network-facing behaviour; verification covers the cited standards and the bundled linter.

## Standards claims (independent re-check, not the author)

An independent reviewer re-fetched primary sources and checked 19 claim groups: ASVS 4.0.3 (1.1.2 to 1.1.5, 1.14.1), ASVS 5.0.0 (6.1.1, 6.3.1, 8.x, 14.x, 15.x, 5.2.1, 3.2.2, 16.3.2, release date 2025-05-30), CWE-639/862/285/306/352/770/117, OWASP LLM Top 10 2025 (LLM01 to LLM10), LINDDUN categories, STRIDE definitions (Microsoft Learn, updated 2026-03-04), the OWASP Threat Modeling Cheat Sheet, and the Threat Modeling Manifesto. All were correct except two, fixed afterwards:

- The STRIDE property-violated mapping was attributed to the OWASP cheat sheet, which has no such table. The text now cites Microsoft Learn for the category definitions and states that the property column is the conventional SDL mapping.
- The worked example (T-007) cited ASVS 5.0.0 16.3.2 for auditing successful admin actions. 16.3.2 covers failed authorization attempts only. The row now says so and cites no ASVS id for successful-action auditing.

## Linter (`tm-lint.md`)

- Independent run: worked example gives 0 problems; the template with a real date gives 0 problems; the placeholder date and all six deliberately broken copies are rejected.
- mermaid 11.17.2 `parse()` (jsdom) agreed with the linter's rules on the shipped diagrams. The review found two cases the linter missed (unquoted edge labels with `( ) : ; #`, and `end` as a node id), and that mermaid problems were reported at the diagram's first line.
- After the review changes, re-run in a sandbox: worked example 0 problems; an unquoted edge label on line 55 is reported as `FAIL line 55`; a quoted edge label passes; `end` as a node id is reported at its own line.

## Not verified

- No run on a real project with a human reviewer; the worked example is synthetic.
- The linter checks structure only (columns, ids, banded risk arithmetic, diagram syntax). It cannot judge whether the threats are the right ones.
- The `diff` mode and the LLM/LINDDUN prompts are guidance and were not measured for how often they change an outcome.
