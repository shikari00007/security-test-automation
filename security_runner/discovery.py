"""Deterministic, read-only project discovery with per-domain confidence and evidence."""
from __future__ import annotations

import json
import os
import re
from fnmatch import fnmatch
from pathlib import Path

MAX_FILES = 5000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", ".next", "Pods", "target",
             "__pycache__", ".gradle", ".idea", "DerivedData"}

FILE_HINTS: dict[str, list[str]] = {
    "android": ["AndroidManifest.xml", "*.apk", "*.aab"],
    "ios": ["Info.plist", "*.entitlements", "*.xcodeproj", "project.pbxproj", "Podfile", "*.ipa"],
    "desktop": ["electron-builder.yml", "electron-builder.yaml", "*.csproj", "*.sln", "*.exe", "tauri.conf.json"],
    "cloud-kubernetes": ["Dockerfile", "Dockerfile.*", "docker-compose.yml", "docker-compose.yaml", "compose.yaml",
                         "Chart.yaml", "*.tf", "kustomization.yaml"],
    "ai-llm": [".mcp.json", "mcp.json", "mcp_config.json", "prompts.yaml", "prompts.yml"],
    "api": ["openapi.yaml", "openapi.yml", "openapi.json", "swagger.json", "swagger.yaml", "*.proto", "*.graphql", "schema.graphql"],
    "web": ["next.config.js", "next.config.mjs", "angular.json", "vite.config.ts", "vite.config.js", "*.html"],
}
NPM = {
    "web": {"next", "react", "vue", "@angular/core", "svelte", "express", "koa", "fastify"},
    "api": {"express", "fastify", "koa", "apollo-server", "@nestjs/core", "graphql", "@grpc/grpc-js"},
    "desktop": {"electron", "electron-builder", "@tauri-apps/api"},
    "ai-llm": {"openai", "@anthropic-ai/sdk", "anthropic", "langchain", "@langchain/core", "llamaindex",
               "@modelcontextprotocol/sdk"},
}
PY = {  # matched as whole requirement names, not substrings
    "api": {"fastapi", "django", "flask", "grpcio", "djangorestframework"},
    "web": {"django", "flask", "jinja2"},
    "ai-llm": {"openai", "anthropic", "langchain", "llama-index", "mcp", "transformers", "langgraph"},
}
SRC_EXT = {".js", ".ts", ".jsx", ".tsx", ".py", ".java", ".kt", ".swift", ".cs", ".go", ".rb", ".php"}


def walk(root: Path) -> tuple[list[str], bool]:
    files: list[str] = []
    for d, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not (Path(d) / x).is_symlink())
        for n in sorted(names):
            p = Path(d) / n
            if p.is_symlink() or not p.is_file():
                continue
            files.append(p.relative_to(root).as_posix())
            if len(files) >= MAX_FILES:
                return files, True
    return files, False


def _py_names(text: str) -> set[str]:
    names = set()
    for line in text.lower().splitlines():
        m = re.match(r"\s*([a-z0-9][a-z0-9._-]*)", line)
        if m:
            names.add(m.group(1).replace("_", "-"))
    # pyproject style: "pkg>=1" inside dependency arrays
    names |= {m.replace("_", "-") for m in re.findall(r"['\"]([a-z0-9][a-z0-9._-]*)\s*[<>=!~\[;'\"]", text.lower())}
    return names


def discover(target: str | Path) -> dict:
    """Return {root, files, domains:{name:{confidence, evidence[]}}, truncated}. Never executes target code."""
    root = Path(target).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("target must be an existing local directory")
    files, truncated = walk(root)
    ev: dict[str, list[str]] = {"supply-chain": ["baseline: every repository is eligible; checks decide applicability"]}

    def add(dom: str, e: str) -> None:
        if len(ev.setdefault(dom, [])) < 8:
            ev[dom].append(e)

    for rel in files:
        base = rel.rsplit("/", 1)[-1]
        for dom, pats in FILE_HINTS.items():
            if any(fnmatch(base, p) or fnmatch(rel.split("/")[0], p) for p in pats):
                # *.html alone is weak evidence; Dockerfile etc. are strong
                add(dom, f"file:{rel}")
        if base.endswith(".gradle") or base.endswith(".gradle.kts"):
            if "com.android" in _safe_text(root / rel):
                add("android", f"gradle-android-plugin:{rel}")
        if base == "Package.swift" or base.endswith(".swift"):
            if any(".xcodeproj/" in f for f in files):
                add("ios", f"swift-project:{rel}")
        if base in ("kustomization.yaml",) or (base.endswith((".yaml", ".yml")) and rel.count("/") < 6
                                                 and re.search(r"^kind:\s*(Deployment|StatefulSet|DaemonSet|Pod|Service|ClusterRole\w*|Secret)\b",
                                                               _safe_text(root / rel), re.M)):
            add("cloud-kubernetes", f"k8s-manifest:{rel}")
        if base == "package.json":
            try:
                info = json.loads(_safe_text(root / rel))
                pk = set(info.get("dependencies", {})) | set(info.get("devDependencies", {}))
                for dom, known in NPM.items():
                    hit = sorted(known & pk)
                    if hit:
                        add(dom, f"npm:{rel}:{','.join(hit[:4])}")
            except (ValueError, AttributeError, TypeError):
                pass
        if base in ("requirements.txt", "pyproject.toml", "Pipfile"):
            names = _py_names(_safe_text(root / rel))
            for dom, known in PY.items():
                hit = sorted(known & names)
                if hit:
                    add(dom, f"python:{rel}:{','.join(hit[:4])}")
        if base.endswith(".csproj") and re.search(r"UseWPF|UseWindowsForms|WinExe", _safe_text(root / rel)):
            add("desktop", f"dotnet-desktop:{rel}")
        if base.endswith(".csproj") and re.search(r"Microsoft\.NET\.Sdk\.Web|AspNetCore", _safe_text(root / rel)):
            add("api", f"aspnet:{rel}")
        if base in ("pom.xml", "build.gradle") and re.search(r"spring-boot-starter-web", _safe_text(root / rel)):
            add("api", f"spring:{rel}")

    domains = {}
    for dom, e in sorted(ev.items()):
        strong = any(not x.startswith("file:") or not x.endswith(".html") for x in e)
        domains[dom] = {"confidence": "high" if len(e) >= 2 and strong else "medium" if strong else "low",
                        "evidence": e}
    # a lone html file is weak: report as low-confidence web
    return {"root": str(root), "files": files, "domains": domains, "truncated": truncated}


def _safe_text(p: Path, limit: int = 1_048_576) -> str:
    try:
        if p.stat().st_size > limit:
            return ""
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
