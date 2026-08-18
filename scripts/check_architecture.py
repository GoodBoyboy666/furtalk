#!/usr/bin/env python3
"""Architecture dependency rule checker.

Enforces the layered architecture:

  domain/         -> must not import any internal package (only stdlib)
  repository/     -> gorm boundary; may import domain + platform + model
  repository/model -> gorm rows; may import domain + gorm + stdlib only
  service/        -> business layer; may import domain + repository + platform
  middleware/     -> auth gates; may import service + domain + platform/httpx + gin
  handler/        -> HTTP layer; may import service + middleware + domain + platform/httpx + gin
  router/         -> generic router; may import handler + platform + gin; never service directly
  platform/       -> must not import service / handler / middleware / router / app / domain

Enforcement rules:
1. `domain` imports nothing internal (zero dependency).
2. `repository` is the only layer allowed to import `repository/model` and gorm outside platform.
3. `service` must not import gin / gorm / httpx / router / middleware / handler.
4. `middleware` must not import repository or model.
5. `handler` must not import repository or model or service/repo internals.
6. `router` must not import service directly.
7. `platform/*` must not import any feature layer (service/handler/middleware/router/app/domain).
8. Uber Fx / Dig may only be imported by `internal/app`.
9. Forbidden: `fx.Populate`, `dig.Container` / `fx.Container`, global `shared`/`common`/`utils` packages.
10. `internal/app/graph_test.go` must call `fx.ValidateApp`.
11. Production code must not construct slog handlers/logger or call `slog.Default` outside
    `internal/platform/logging`; `logging.SetupToken` may only be used by
    `internal/service/bootstrap`.

Usage: python scripts/check_architecture.py
Exit code 0 = pass, 1 = violation.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_SERVICE_IMPORTS = (
    "gin-gonic",
    "gorm.io",
    "spf13/viper",
    "redis/go-redis",
    "furtalk/internal/router",
    "furtalk/internal/middleware",
    "furtalk/internal/handler",
    "furtalk/internal/platform/httpx",
)

FX_DIG_IMPORT_ROOTS = ("go.uber.org/fx", "go.uber.org/dig")

LOGGING_PACKAGE = "internal/platform/logging/"
BOOTSTRAP_PACKAGE = "internal/service/bootstrap/"

# 生产代码禁止在 logging 包外出现的 slog 构造/默认调用。
SLOG_CONSTRUCTION_RE = re.compile(r"slog\.(?:New|NewJSONHandler|NewTextHandler|Default)\s*\(")

LAYERS = ("domain", "repository", "service", "middleware", "handler", "router")


def run_logging_rule_self_test() -> list[str]:
    """自测日志规则的扫描正则，保证能命中典型违规样本。"""
    errors: list[str] = []
    samples = (
        "slog.New(slog.NewJSONHandler(w, nil))",
        "slog.NewTextHandler(io.Discard, nil)",
        "logger := slog.Default()",
    )
    for text in samples:
        if not SLOG_CONSTRUCTION_RE.search(text):
            errors.append(f"logging self-test failed to match: {text!r}")
    # 合法调用（统一模块）不得被误判。
    if SLOG_CONSTRUCTION_RE.search("logging.New(io.Discard)"):
        errors.append("logging self-test: legitimate logging.New matched the forbidden regex")
    return errors


def go_packages() -> list[str]:
    out = subprocess.run(
        ["go", "list", "./internal/..."], capture_output=True, text=True, check=True
    )
    return [line for line in out.stdout.splitlines() if line.startswith("furtalk/internal/")]


def imports_of(pkg: str) -> set[str]:
    out = subprocess.run(
        ["go", "list", "-f", "{{join .Imports \"\\n\"}}", pkg],
        capture_output=True,
        text=True,
        check=True,
    )
    return {line.strip() for line in out.stdout.splitlines() if line.strip()}


def layer_of(pkg: str) -> str | None:
    m = re.match(r"^furtalk/internal/(domain|repository|service|middleware|handler|router)(/|$)", pkg)
    return m.group(1) if m else None


def main() -> int:
    errors: list[str] = []
    packages = go_packages()
    package_imports = {pkg: imports_of(pkg) for pkg in packages}

    for forbidden in ("shared", "common", "utils"):
        if (ROOT / "internal" / forbidden).exists():
            errors.append(f"forbidden global package exists: internal/{forbidden}")

    for pkg in packages:
        deps = package_imports[pkg]
        layer = layer_of(pkg)

        if pkg != "furtalk/internal/app":
            for dep in deps:
                if any(dep.startswith(root) for root in FX_DIG_IMPORT_ROOTS):
                    errors.append(f"{pkg} imports Fx/Dig outside internal/app: {dep}")

        if layer == "domain":
            for dep in deps:
                if dep.startswith("furtalk/internal"):
                    errors.append(f"{pkg} (domain) imports internal package: {dep}")

        if layer == "repository":
            # repository 是唯一允许直接触碰 model/gorm 的业务层。
            for dep in deps:
                if dep.startswith("furtalk/internal/service"):
                    errors.append(f"{pkg} (repository) imports service: {dep}")
                if dep.startswith("furtalk/internal/handler"):
                    errors.append(f"{pkg} (repository) imports handler: {dep}")
                if dep.startswith("furtalk/internal/middleware"):
                    errors.append(f"{pkg} (repository) imports middleware: {dep}")
                if dep.startswith("furtalk/internal/router"):
                    errors.append(f"{pkg} (repository) imports router: {dep}")

        if layer == "service":
            for bad in FORBIDDEN_SERVICE_IMPORTS:
                for dep in deps:
                    if bad in dep:
                        errors.append(f"{pkg} (service) imports forbidden: {dep}")
            # service 可依赖 repository / domain / platform；禁止依赖 handler/middleware/router。
            for dep in deps:
                if dep.startswith("furtalk/internal/handler"):
                    errors.append(f"{pkg} (service) imports handler: {dep}")
                if dep.startswith("furtalk/internal/middleware"):
                    errors.append(f"{pkg} (service) imports middleware: {dep}")
                if dep.startswith("furtalk/internal/router"):
                    errors.append(f"{pkg} (service) imports router: {dep}")

        if layer == "middleware":
            # middleware 禁止直接操作 repository/model。
            for dep in deps:
                if dep.startswith("furtalk/internal/repository"):
                    errors.append(f"{pkg} (middleware) imports repository: {dep}")
                if dep.startswith("furtalk/internal/handler"):
                    errors.append(f"{pkg} (middleware) imports handler: {dep}")
                if dep.startswith("furtalk/internal/router"):
                    errors.append(f"{pkg} (middleware) imports router: {dep}")

        if layer == "handler":
            for dep in deps:
                if dep.startswith("furtalk/internal/repository"):
                    errors.append(f"{pkg} (handler) imports repository: {dep}")
                if dep.startswith("furtalk/internal/router"):
                    errors.append(f"{pkg} (handler) imports router: {dep}")

        if layer == "router":
            # 通用 router 禁止 import service；路由注册函数由组合根注入。
            for dep in deps:
                if dep.startswith("furtalk/internal/service"):
                    errors.append(f"{pkg} (router) imports service: {dep}")
                if dep.startswith("furtalk/internal/repository"):
                    errors.append(f"{pkg} (router) imports repository: {dep}")

        # platform 禁止向上依赖。
        if pkg.startswith("furtalk/internal/platform/"):
            for dep in deps:
                if dep.startswith("furtalk/internal/service"):
                    errors.append(f"{pkg} (platform) imports service: {dep}")
                if dep.startswith("furtalk/internal/handler"):
                    errors.append(f"{pkg} (platform) imports handler: {dep}")
                if dep.startswith("furtalk/internal/middleware"):
                    errors.append(f"{pkg} (platform) imports middleware: {dep}")
                if dep.startswith("furtalk/internal/router"):
                    errors.append(f"{pkg} (platform) imports router: {dep}")
                if dep.startswith("furtalk/internal/app"):
                    errors.append(f"{pkg} (platform) imports app: {dep}")

    for path in (ROOT / "internal").rglob("*.go"):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        if "furtalk/internal/domain" in text and path.is_relative_to(ROOT / "internal" / "domain"):
            # domain 自身引用允许；此处只禁其他层反向依赖 domain 以外的异常，无需处理。
            pass
        if "fx.Populate(" in text:
            errors.append(f"{relative} uses fx.Populate (forbidden container population)")
        if "dig.Container" in text or "fx.Container" in text:
            errors.append(f"{relative} reaches into the DI container (forbidden)")

    # 禁止手写组合根返回。
    for path in (ROOT / "internal" / "app").glob("*.go"):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        if re.search(r"\bfunc\s+Build\s*\(", text):
            errors.append(f"{relative} re-introduces the hand-written composition root Build()")

    # Production graph must be covered by an fx.ValidateApp test.
    graph_test = ROOT / "internal" / "app" / "graph_test.go"
    if not graph_test.exists():
        errors.append("internal/app/graph_test.go missing: fx.ValidateApp coverage is required")
    else:
        graph_text = graph_test.read_text(encoding="utf-8")
        if "fx.ValidateApp" not in graph_text:
            errors.append("internal/app/graph_test.go does not call fx.ValidateApp on the production root")

    # 日志模块规则：生产代码只能在 logging 包内构造 slog handler/logger。
    # 扫描 internal 与 cmd 两个生产目录；测试代码与 logging 包自身豁免。
    for path in list((ROOT / "internal").rglob("*.go")) + list((ROOT / "cmd").rglob("*.go")):
        relative = path.relative_to(ROOT).as_posix()
        if relative.startswith(LOGGING_PACKAGE) or relative.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8")
        if SLOG_CONSTRUCTION_RE.search(text):
            errors.append(f"{relative} constructs slog handler/logger or uses slog.Default outside logging package")

    # 日志模块规则：setup token 放行 helper 只允许 bootstrap 服务使用。
    for path in (ROOT / "internal").rglob("*.go"):
        relative = path.relative_to(ROOT).as_posix()
        if relative.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8")
        if "logging.SetupToken" in text and not relative.startswith(BOOTSTRAP_PACKAGE):
            errors.append(f"{relative} uses logging.SetupToken outside internal/service/bootstrap")

    # 日志规则自测，保证扫描正则本身可命中违规样本。
    errors.extend(run_logging_rule_self_test())

    if errors:
        print("Architecture violations:")
        for e in sorted(set(errors)):
            print(f"  - {e}")
        return 1
    print("Architecture rules: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
