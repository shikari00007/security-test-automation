"""Android static rules (SEC-AND-001..006). Read-only; XML is parsed defensively.

Also hosts small shared helpers (comment stripping, DOCTYPE-refusing XML parser) that the
ios/desktop/ai adapters import.
"""
from __future__ import annotations

import re
from xml.parsers import expat

from .base import Observation, RuleResult, ScanContext
from .base import rule as _register


def rule(check_id: str):
    """Register a rule, normalising output to one observation per (file, line), sorted."""
    def deco(fn):
        def wrapper(ctx):
            res = fn(ctx)
            if res is not None:
                seen, uniq = set(), []
                for o in sorted(res.observations, key=lambda o: (o.file, o.line)):
                    if (o.file, o.line) not in seen:
                        seen.add((o.file, o.line))
                        uniq.append(o)
                res.observations = uniq
            return res
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return _register(check_id)(wrapper)
    return deco


# --------------------------------------------------------------------------- shared helpers
def _blank(m: "re.Match[str]") -> str:
    return re.sub(r"[^\n]", " ", m.group(0))


def strip_c(text: str) -> str:
    """Blank C-style comments while preserving line numbers."""
    text = re.sub(r"/\*.*?\*/", _blank, text, flags=re.S)
    return re.sub(r"(?<![:\"'\w/])//[^\n]*", "", text)


def strip_xml_comments(text: str) -> str:
    return re.sub(r"<!--.*?-->", _blank, text, flags=re.S)


def strip_hash(text: str) -> str:
    return re.sub(r"(?m)^[ \t]*#.*$", "", text)


class XmlRefused(ValueError):
    """Raised when XML is refused (DTD/entity declarations) or malformed."""


class Elem:
    def __init__(self, tag: str, attrs: dict, line: int, parent: "Elem | None"):
        self.tag, self.attrs, self.line, self.parent = tag, attrs, line, parent
        self.text = ""
        self.children: list[Elem] = []

    def iter(self):
        yield self
        for c in self.children:
            yield from c.iter()

    def ancestors(self):
        p = self.parent
        while p is not None:
            yield p
            p = p.parent


_DTD_RX = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.I)


def parse_xml(text: str) -> Elem:
    """Parse XML with line numbers. DOCTYPE/ENTITY declarations are refused (XXE/billion
    laughs defence) *before* any parsing happens."""
    if _DTD_RX.search(text):
        raise XmlRefused("DOCTYPE/ENTITY declaration present; refusing to parse")
    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    stack: list[Elem] = []
    roots: list[Elem] = []

    def start(name, attrs):
        el = Elem(name, dict(attrs), parser.CurrentLineNumber, stack[-1] if stack else None)
        if stack:
            stack[-1].children.append(el)
        else:
            roots.append(el)
        stack.append(el)

    def end(_name):
        stack.pop()

    def chars(data):
        if stack and len(stack[-1].text) < 4096:
            stack[-1].text += data

    parser.CharacterDataHandler = chars
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    try:
        parser.Parse(text.lstrip("﻿").encode("utf-8"), True)
    except expat.ExpatError as exc:
        raise XmlRefused(f"malformed XML: {exc}") from exc
    if not roots:
        raise XmlRefused("no root element")
    return roots[0]


def attr_line(text: str, el_line: int, attr: str) -> int:
    lines = text.splitlines()
    for i in range(el_line - 1, min(len(lines), el_line + 40)):
        if attr in lines[i]:
            return i + 1
    return el_line


def _scan(rel: str, code: str, rx: "re.Pattern[str]", detail: str) -> list[Observation]:
    return [Observation(rel, i, detail) for i, ln in enumerate(code.splitlines(), 1) if rx.search(ln)]


def _inconclusive(rel: str, exc: Exception) -> RuleResult:
    return RuleResult([], notes=f"{rel}: {exc}", inconclusive=True)


_NON_RELEASE = re.compile(r"(?:^|/)src/(?:debug|androidTest|test|testDebug)/")
_TEST_PATH = re.compile(r"(?:^|/)(?:src/(?:androidTest|test)|androidTest|test|tests)/|(?:Test|Tests|Spec)\.(?:java|kt|swift|m|mm)$")


def is_non_release(rel: str) -> bool:
    """Debug / test source sets are not shipped in release builds."""
    return bool(_NON_RELEASE.search(rel))


def is_test_path(rel: str) -> bool:
    return bool(_TEST_PATH.search(rel))


def blank_strings(code: str) -> str:
    """Blank single-line string literal contents (keeps quotes, line numbers and columns)."""
    return re.sub(r'"(?:\\.|[^"\\\n])*"', lambda m: '"' + " " * (len(m.group(0)) - 2) + '"', code)


def _manifests(ctx: ScanContext) -> list[str]:
    """Manifests that can end up in a release build (src/debug, androidTest, test are skipped)."""
    return [f for f in ctx.match("AndroidManifest.xml") if not is_non_release(f)]


# --------------------------------------------------------------------------- rules
_LAUNCHER_CATS = {"android.intent.category.LAUNCHER", "android.intent.category.LEANBACK_LAUNCHER",
                  "android.intent.category.CAR_LAUNCHER"}
# Protected broadcasts: only the OS (system UID) may send these, so exporting the receiver is required, not a hole.
_SYSTEM_ACTIONS = {
    "android.intent.action.BOOT_COMPLETED", "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.MY_PACKAGE_REPLACED", "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.PACKAGE_ADDED", "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.TIMEZONE_CHANGED", "android.intent.action.TIME_SET",
    "android.intent.action.DATE_CHANGED", "android.intent.action.LOCALE_CHANGED",
    "android.intent.action.ACTION_POWER_CONNECTED", "android.intent.action.ACTION_POWER_DISCONNECTED",
    "android.intent.action.BATTERY_LOW", "android.intent.action.BATTERY_OKAY",
    "android.net.conn.CONNECTIVITY_CHANGE", "android.intent.action.USER_PRESENT",
    "android.intent.action.AIRPLANE_MODE", "android.intent.action.MY_PACKAGE_UNSUSPENDED",
}


def _only_system_broadcasts(filters) -> bool:
    acts = [g.attrs.get("android:name") for f in filters for g in f.children if g.tag == "action"]
    return bool(acts) and all(a in _SYSTEM_ACTIONS for a in acts)


_COMPONENTS = {"activity", "activity-alias", "service", "receiver", "provider"}


@rule("SEC-AND-001")
def exported_components(ctx: ScanContext):
    files = _manifests(ctx)
    if not files:
        return None
    obs: list[Observation] = []
    bad: list[str] = []
    for rel in files:
        try:
            root = parse_xml(ctx.read(rel))
        except XmlRefused as exc:
            bad.append(str(_inconclusive(rel, exc).notes))
            continue
        for el in root.iter():
            if el.tag not in _COMPONENTS:
                continue
            exported = el.attrs.get("android:exported")
            if exported == "false":
                continue
            filters = [c for c in el.children if c.tag == "intent-filter"]
            implicit = exported is None and bool(filters) and el.tag != "provider"
            if exported != "true" and not implicit:
                continue
            if el.attrs.get("tools:node") in ("remove", "removeAll"):
                continue          # stripped from the merged manifest
            launcher = any(
                any(g.tag == "category" and g.attrs.get("android:name") in _LAUNCHER_CATS
                    for g in f.children) for f in filters)
            if launcher and el.tag in ("activity", "activity-alias"):
                continue
            if el.tag == "receiver" and filters and _only_system_broadcasts(filters):
                continue
            if el.attrs.get("android:permission"):
                continue
            if el.tag == "provider" and el.attrs.get("android:readPermission") and el.attrs.get("android:writePermission"):
                continue
            why = "explicitly exported" if exported == "true" else "implicitly exported via intent-filter"
            obs.append(Observation(rel, el.line, f"{el.tag} {el.attrs.get('android:name', '?')} {why} without a permission"))
    if bad and not obs:
        return RuleResult([], notes="; ".join(bad), inconclusive=True)
    return RuleResult(obs, notes="; ".join(bad))


@rule("SEC-AND-002")
def debuggable(ctx: ScanContext):
    files = _manifests(ctx)
    if not files:
        return None
    obs, bad = [], []
    for rel in files:
        text = ctx.read(rel)
        try:
            root = parse_xml(text)
        except XmlRefused as exc:
            bad.append(f"{rel}: {exc}")
            continue
        for el in root.iter():
            if el.tag == "application" and el.attrs.get("android:debuggable") == "true":
                obs.append(Observation(rel, attr_line(text, el.line, "android:debuggable"),
                                       "application is android:debuggable=true"))
    if bad and not obs:
        return RuleResult([], notes="; ".join(bad), inconclusive=True)
    return RuleResult(obs, notes="; ".join(bad))


def _defines_app(application) -> bool:
    """Heuristic: the manifest is the app's own (has identity attrs or a launcher) rather than an overlay/library."""
    if any(k in application.attrs for k in ("android:icon", "android:roundIcon", "android:label", "android:name")):
        return True
    return any(g.tag == "category" and g.attrs.get("android:name") in _LAUNCHER_CATS
               for el in application.iter() for g in el.iter())


@rule("SEC-AND-003")
def allow_backup(ctx: ScanContext):
    files = _manifests(ctx)
    if not files:
        return None
    obs, bad = [], []
    for rel in files:
        text = ctx.read(rel)
        try:
            root = parse_xml(text)
        except XmlRefused as exc:
            bad.append(f"{rel}: {exc}")
            continue
        for el in root.iter():
            if el.tag != "application":
                continue
            val = el.attrs.get("android:allowBackup")
            if val == "true":
                obs.append(Observation(rel, attr_line(text, el.line, "android:allowBackup"),
                                       "android:allowBackup=true permits adb/cloud backup of app data"))
            elif val is None:
                if not _defines_app(el):
                    continue      # library / flavor-overlay manifest: the app module's manifest decides
                obs.append(Observation(rel, el.line, "android:allowBackup not set; defaults to true"))
    if bad and not obs:
        return RuleResult([], notes="; ".join(bad), inconclusive=True)
    return RuleResult(obs, notes="; ".join(bad))


@rule("SEC-AND-004")
def cleartext_traffic(ctx: ScanContext):
    manifests = _manifests(ctx)
    xmls = [f for f in ctx.match("res/xml/*.xml", "*/res/xml/*.xml") if not is_non_release(f)]
    if not manifests and not xmls:
        return None
    obs, bad = [], []
    read_any = False
    for rel in manifests:
        text = ctx.read(rel)
        read_any = True
        try:
            root = parse_xml(text)
        except XmlRefused as exc:
            bad.append(f"{rel}: {exc}")
            continue
        for el in root.iter():
            if el.tag == "application" and el.attrs.get("android:usesCleartextTraffic") == "true":
                obs.append(Observation(rel, attr_line(text, el.line, "android:usesCleartextTraffic"),
                                       "usesCleartextTraffic=true allows HTTP"))
    for rel in xmls:
        text = ctx.read(rel)
        if "<network-security-config" not in text:
            continue
        read_any = True
        try:
            root = parse_xml(text)
        except XmlRefused as exc:
            bad.append(f"{rel}: {exc}")
            continue
        for el in root.iter():
            if el.attrs.get("cleartextTrafficPermitted") == "true" and \
                    el.tag != "debug-overrides" and not any(a.tag == "debug-overrides" for a in el.ancestors()) and not _loopback_only(el):
                obs.append(Observation(rel, attr_line(text, el.line, "cleartextTrafficPermitted"),
                                       f"network security config permits cleartext in <{el.tag}>"))
    if not read_any and not bad:
        return None
    if bad and not obs:
        return RuleResult([], notes="; ".join(bad), inconclusive=True)
    return RuleResult(obs, notes="; ".join(bad))


_LOOPBACK = {"localhost", "127.0.0.1", "10.0.2.2", "10.0.3.2", "::1", "[::1]"}


def _loopback_only(el) -> bool:
    """domain-config whose domains are all loopback / emulator-host aliases (never reachable remotely)."""
    if el.tag != "domain-config":
        return False
    doms = [c for c in el.children if c.tag == "domain"]
    return bool(doms) and all(_text_of(c) in _LOOPBACK for c in doms)


def _text_of(el) -> str:
    return el.text.strip()


_JS_ON = re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)|\bjavaScriptEnabled\s*=\s*true")
_WV_RISK = re.compile(
    r"addJavascriptInterface\s*\(|setAllow(?:FileAccess|FileAccessFromFileURLs|UniversalAccessFromFileURLs)\s*\(\s*true"
    r"|\ballow(?:FileAccess|FileAccessFromFileURLs|UniversalAccessFromFileURLs)\s*=\s*true")


@rule("SEC-AND-005")
def webview(ctx: ScanContext):
    files = [f for f in ctx.match("*.java", "*.kt") if not is_test_path(f)]
    if not files:
        return None
    obs = []
    for rel in files:
        code = blank_strings(strip_c(ctx.read(rel)))
        if not _JS_ON.search(code):
            continue
        obs += _scan(rel, code, _WV_RISK, "WebView with JavaScript enabled exposes a JS bridge or file access")
    return RuleResult(obs)


_WORLD = re.compile(r"\bMODE_WORLD_(?:READABLE|WRITEABLE|WRITABLE)\b")
_PREF_SECRET = re.compile(
    r"\bput(?:String|StringSet)\s*\(\s*\"([^\"]*(?:password|passwd|pwd|token|secret|api_?key)[^\"]*)\"", re.I)
# keys that name a secret-adjacent *non-secret* (hint, type, label, url, ...)
_PREF_BENIGN = re.compile(r"(?:hint|type|label|policy|url|uri|prompt|title|placeholder|regex|pattern|length|"
                          r"expir\w*|name|enabled|shown|visible|count)$", re.I)


@rule("SEC-AND-006")
def insecure_storage(ctx: ScanContext):
    files = [f for f in ctx.match("*.java", "*.kt") if not is_test_path(f)]
    if not files:
        return None
    obs = []
    for rel in files:
        code = re.sub(r"(?m)^[ \t]*(?:import|package)\b.*$", "", strip_c(ctx.read(rel)))   # imports are not uses
        obs += _scan(rel, blank_strings(code), _WORLD, "world-readable/writeable file mode")
        if not re.search(r"EncryptedSharedPreferences|MasterKey", code):
            for i, ln in enumerate(code.splitlines(), 1):
                m = _PREF_SECRET.search(ln)
                if m and not _PREF_BENIGN.search(m.group(1).strip("_ ")):
                    obs.append(Observation(rel, i, "secret stored in plaintext SharedPreferences"))
    return RuleResult(obs)
