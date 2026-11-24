#!/usr/bin/env python3
"""Read-only consistency checks for a proposed MIT-licensed public checkout.

Usage: python scripts/check_public_mit.py /path/to/public-checkout
This is a helper, not legal verification or a substitute for the project's test suite.
"""
import re
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        print('Usage: python check_public_mit.py PATH_TO_REPOSITORY')
        return 2
    repo = Path(sys.argv[1]).resolve()
    errors = []
    if not repo.is_dir():
        print('ERROR: repository directory not found')
        return 2
    license_text = (repo / 'LICENSE').read_text(encoding='utf-8') if (repo / 'LICENSE').is_file() else ''
    if not license_text.startswith('MIT License\n'):
        errors.append('LICENSE does not start with MIT License')
    proj = (repo / 'pyproject.toml').read_text(encoding='utf-8') if (repo / 'pyproject.toml').is_file() else ''
    if not re.search(r'^license\s*=\s*[\'\"]MIT[\'\"]\s*$', proj, re.MULTILINE):
        errors.append('pyproject.toml project license not MIT')
    skills = sorted((repo / 'skills').glob('*/SKILL.md'))
    if not skills:
        errors.append('No skills/*/SKILL.md found')
    for path in skills:
        txt = path.read_text(encoding='utf-8')
        front = txt.split('---', 2)[1] if txt.startswith('---') and txt.count('---') >= 2 else ''
        if not re.search(r'^license:\s*MIT\s*$',front,re.MULTILINE):
            errors.append(f'{path.relative_to(repo)} frontmatter license not MIT')
    for name in ('README.md', 'CONTRIBUTING.md'):
        if not (repo / name).is_file():
            errors.append(f'{name} missing')
    for line in errors:
        print('ERROR:', line)
    print(f'Inspected {len(skills)} skills; {len(errors)} issue(s).')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
