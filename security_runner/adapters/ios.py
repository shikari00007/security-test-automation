"""iOS static rules (SEC-IOS-001..004). Plists are scanned with line-oriented regex (no XML
entity expansion is ever performed); binary plists yield an inconclusive result."""
from __future__ import annotations

import re

from .android import rule, _scan, strip_c, strip_xml_comments, blank_strings, is_test_path
from .base import Observation, RuleResult, ScanContext


def _plist_true(rel: str, text: str, key: str, detail: str) -> list[Observation]:
    lines = strip_xml_comments(text).splitlines()
    out = []
    for i, ln in enumerate(lines):
        if re.search(rf"<key>\s*{re.escape(key)}\s*</key>", ln):
            tail = ln.split("</key>", 1)[1]
            nxt = tail if tail.strip() else ""
            j = i
            while not nxt.strip() and j + 1 < len(lines):
                j += 1
                nxt = lines[j]
            if re.match(r"\s*<true\s*/>", nxt):
                out.append(Observation(rel, i + 1, detail))
    return out


def _plist_rule(ctx: ScanContext, globs, key: str, detail: str, skip_debug: bool = False):
    files = ctx.match(*globs)
    if skip_debug:
        files = [f for f in files if "debug" not in f.rsplit("/", 1)[-1].lower()]
    if not files:
        return None
    obs, bad = [], []
    for rel in files:
        text = ctx.read(rel)
        if text.startswith("bplist"):
            bad.append(f"{rel}: binary plist not analysed")
            continue
        obs += _plist_true(rel, text, key, detail)
    if bad and not obs and len(bad) == len(files):
        return RuleResult([], notes="; ".join(bad), inconclusive=True)
    return RuleResult(obs, notes="; ".join(bad))


@rule("SEC-IOS-001")
def ats_disabled(ctx: ScanContext):
    return _plist_rule(ctx, ["Info.plist"], "NSAllowsArbitraryLoads",
                       "App Transport Security disabled (NSAllowsArbitraryLoads=true)")


@rule("SEC-IOS-002")
def get_task_allow(ctx: ScanContext):
    # Debug-configuration entitlements legitimately carry get-task-allow=true (Xcode default).
    return _plist_rule(ctx, ["*.entitlements"], "get-task-allow",
                       "get-task-allow=true lets any debugger attach", skip_debug=True)


_KC = re.compile(r"\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b")
_UD = re.compile(
    r"(?:\.set\s*\(|\bsetObject:|\bsetValue\s*\(|\bsetValue:)(.*)forKey:\s*@?\"([^\"]*"
    r"(?:password|passwd|token|secret|api_?key)[^\"]*)\"", re.I)
_UD_BENIGN = re.compile(r"(?:hint|type|label|policy|url|uri|prompt|title|placeholder|regex|pattern|length|"
                        r"expir\w*|name|enabled|shown|visible|count|status)$", re.I)
_LITERAL_VAL = re.compile(r"^\s*(?:@?(?:true|false|YES|NO)|@?-?\d+(?:\.\d+)?)\s*,?\s*$")


@rule("SEC-IOS-003")
def keychain_userdefaults(ctx: ScanContext):
    files = [f for f in ctx.match("*.swift", "*.m", "*.mm") if not is_test_path(f)]
    if not files:
        return None
    obs = []
    for rel in files:
        code = strip_c(ctx.read(rel))
        obs += _scan(rel, blank_strings(code), _KC, "Keychain item readable while device is locked (Always accessibility)")
        for i, ln in enumerate(code.splitlines(), 1):
            if not re.search(r"efaults", ln):
                continue
            m = _UD.search(ln)
            if not m or _UD_BENIGN.search(m.group(2).strip("_ ")):
                continue
            # value argument: `set(<value>, forKey:` / `setObject:<value> forKey:` ; literal flags/numbers are not secrets
            if _LITERAL_VAL.match(m.group(1).rstrip().rstrip(",")) or _LITERAL_VAL.match(m.group(1)):
                continue
            obs.append(Observation(rel, i, "secret stored in UserDefaults"))
    return RuleResult(obs)


@rule("SEC-IOS-004")
def webviews(ctx: ScanContext):
    files = ctx.match("*.swift", "*.m", "*.mm", "*.h")
    if not files:
        return None
    obs = []
    for rel in files:
        code = strip_c(ctx.read(rel))
        blanked = blank_strings(code).splitlines()
        for i, ln in enumerate(code.splitlines(), 1):
            if re.search(r"\bUIWebView\b", blanked[i - 1]):
                obs.append(Observation(rel, i, "deprecated UIWebView in use"))
            elif re.search(r"forKey:\s*@?\"allow(?:FileAccess|UniversalAccess)FromFileURLs\"", ln) and \
                    re.search(r"\btrue\b|\bYES\b|@YES", ln):
                obs.append(Observation(rel, i, "WKWebView file-URL access preference enabled"))
    return RuleResult(obs)
