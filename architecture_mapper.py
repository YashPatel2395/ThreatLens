"""
architecture_mapper.py — Static detection of repository architecture.

Analyses the repository file tree to detect:
  language, framework, database, auth, deployment,
  package_manager, entry_points.

The result is passed to the LLM so it can produce
context-aware impact assessments instead of generic ones.
"""
import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_IGNORED_DIRS = {
    "node_modules", "venv", ".venv", "dist", "build",
    ".git", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    ".claude", ".cursor", ".vscode", ".idea",
}


def _is_ignored(path: Path) -> bool:
    return any(part in _IGNORED_DIRS for part in path.parts)


def _read_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _read_json_safe(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Language
# ---------------------------------------------------------------------------

_EXT_LANG: dict[str, str] = {
    ".py":   "Python",
    ".js":   "JavaScript",
    ".ts":   "TypeScript",
    ".java": "Java",
    ".go":   "Go",
    ".rb":   "Ruby",
    ".php":  "PHP",
    ".cs":   "C#",
    ".rs":   "Rust",
    ".cpp":  "C++",
    ".c":    "C",
    ".kt":   "Kotlin",
    ".swift":"Swift",
}


def _detect_languages(repo: Path) -> list[str]:
    counts: dict[str, int] = {}
    for f in repo.rglob("*"):
        if f.is_file() and not _is_ignored(f) and f.suffix in _EXT_LANG:
            lang = _EXT_LANG[f.suffix]
            counts[lang] = counts.get(lang, 0) + 1
    return [lang for lang, _ in sorted(counts.items(), key=lambda x: -x[1])]


# ---------------------------------------------------------------------------
# Framework
# ---------------------------------------------------------------------------

def _detect_framework(repo: Path) -> str:
    req = _read_safe(repo / "requirements.txt").lower()
    if req:
        for pkg, fw in [
            ("fastapi",   "FastAPI"),
            ("django",    "Django"),
            ("flask",     "Flask"),
            ("tornado",   "Tornado"),
            ("starlette", "Starlette"),
            ("aiohttp",   "aiohttp"),
            ("pyramid",   "Pyramid"),
            ("falcon",    "Falcon"),
        ]:
            if pkg in req:
                return fw

    pkg_json = _read_json_safe(repo / "package.json")
    if pkg_json:
        deps = {**pkg_json.get("dependencies", {}), **pkg_json.get("devDependencies", {})}
        for pkg, fw in [
            ("next",            "Next.js"),
            ("nuxt",            "Nuxt.js"),
            ("@nestjs/core",    "NestJS"),
            ("express",         "Express.js"),
            ("react",           "React"),
            ("vue",             "Vue.js"),
            ("@angular/core",   "Angular"),
            ("svelte",          "Svelte"),
            ("hapi",            "Hapi.js"),
            ("fastify",         "Fastify"),
        ]:
            if pkg in deps:
                return fw

    pom = _read_safe(repo / "pom.xml").lower()
    if pom:
        for token, fw in [
            ("spring-boot", "Spring Boot"),
            ("spring",      "Spring"),
            ("quarkus",     "Quarkus"),
            ("micronaut",   "Micronaut"),
        ]:
            if token in pom:
                return fw

    gemfile = _read_safe(repo / "Gemfile").lower()
    if gemfile:
        if "rails" in gemfile:
            return "Ruby on Rails"
        if "sinatra" in gemfile:
            return "Sinatra"

    go_mod = _read_safe(repo / "go.mod")
    if go_mod:
        for token, fw in [
            ("gin-gonic/gin", "Gin"),
            ("labstack/echo", "Echo"),
            ("gofiber/fiber", "Fiber"),
            ("beego",         "Beego"),
        ]:
            if token in go_mod:
                return fw

    return "None detected"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def _detect_database(repo: Path) -> list[str]:
    found: list[str] = []

    def add(db: str) -> None:
        if db not in found:
            found.append(db)

    req = _read_safe(repo / "requirements.txt").lower()
    if req:
        if "psycopg2" in req or "asyncpg" in req or "databases" in req:
            add("PostgreSQL")
        if "pymysql" in req or "mysql-connector" in req or "aiomysql" in req:
            add("MySQL / MariaDB")
        if "pymongo" in req or "motor" in req:
            add("MongoDB")
        if "redis" in req or "aioredis" in req:
            add("Redis")
        if "elasticsearch" in req:
            add("Elasticsearch")
        if "cassandra" in req:
            add("Cassandra")
        if "sqlalchemy" in req or "peewee" in req or "tortoise" in req:
            if not any(x in found for x in ["PostgreSQL", "MySQL / MariaDB", "MongoDB"]):
                add("SQL (ORM detected, engine unknown)")

    pkg_json = _read_json_safe(repo / "package.json")
    if pkg_json:
        deps = {**pkg_json.get("dependencies", {}), **pkg_json.get("devDependencies", {})}
        if "pg" in deps or "postgres" in deps:
            add("PostgreSQL")
        if "mysql2" in deps or "mysql" in deps:
            add("MySQL / MariaDB")
        if "mongodb" in deps or "mongoose" in deps:
            add("MongoDB")
        if "redis" in deps or "ioredis" in deps:
            add("Redis")
        if "sequelize" in deps or "typeorm" in deps or "prisma" in deps:
            if not any(x in found for x in ["PostgreSQL", "MySQL / MariaDB", "MongoDB"]):
                add("SQL (ORM detected, engine unknown)")

    for cf in ["docker-compose.yml", "docker-compose.yaml", "docker-compose.dev.yml"]:
        dc = _read_safe(repo / cf).lower()
        if dc:
            if "postgres" in dc:
                add("PostgreSQL")
            if "mysql" in dc or "mariadb" in dc:
                add("MySQL / MariaDB")
            if "mongo" in dc:
                add("MongoDB")
            if "redis" in dc:
                add("Redis")

    # SQLite db files
    if list(repo.glob("**/*.db")) or list(repo.glob("**/*.sqlite*")):
        add("SQLite")
    # sqlite3 in Python stdlib is always present but only flag if used
    for py in list(repo.glob("**/*.py"))[:80]:
        if _is_ignored(py):
            continue
        if "sqlite3" in _read_safe(py) and "SQLite" not in found:
            add("SQLite")
            break

    return found or ["None detected"]


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _detect_auth(repo: Path) -> list[str]:
    found: list[str] = []

    def add(a: str) -> None:
        if a not in found:
            found.append(a)

    req = _read_safe(repo / "requirements.txt").lower()
    if req:
        if "pyjwt" in req or "python-jose" in req:
            add("JWT (PyJWT / python-jose)")
        if "flask-jwt-extended" in req or "flask-jwt" in req:
            add("Flask-JWT-Extended")
        if "flask-login" in req:
            add("Flask-Login (session)")
        if "django-allauth" in req:
            add("Django-AllAuth (OAuth / social)")
        if "simplejwt" in req:
            add("DRF SimpleJWT")
        if "authlib" in req:
            add("Authlib (OAuth2)")
        if "passlib" in req or "bcrypt" in req or "argon2" in req:
            add("Password hashing library")
        if "python-keycloak" in req:
            add("Keycloak")
        if "boto3" in req or "botocore" in req:
            add("AWS Cognito (possible)")

    pkg_json = _read_json_safe(repo / "package.json")
    if pkg_json:
        deps = {**pkg_json.get("dependencies", {}), **pkg_json.get("devDependencies", {})}
        if "passport" in deps:
            add("Passport.js")
        if "jsonwebtoken" in deps:
            add("JWT (jsonwebtoken)")
        if "next-auth" in deps:
            add("NextAuth.js")
        if "@auth0/nextjs-auth0" in deps or "@auth0/auth0-react" in deps:
            add("Auth0")
        if "firebase" in deps or "firebase-admin" in deps:
            add("Firebase Auth")
        if "keycloak-js" in deps:
            add("Keycloak")

    return found or ["None detected"]


# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------

def _detect_deployment(repo: Path) -> list[str]:
    found: list[str] = []

    def add(d: str) -> None:
        if d not in found:
            found.append(d)

    if (repo / "Dockerfile").exists() or list(repo.glob("Dockerfile.*")):
        add("Docker")
    if (repo / "docker-compose.yml").exists() or (repo / "docker-compose.yaml").exists():
        add("Docker Compose")
    if list(repo.glob("k8s/**/*.yaml")) or list(repo.glob("kubernetes/**/*.yaml")):
        add("Kubernetes")
    if (repo / "Procfile").exists():
        add("Heroku")
    if (repo / ".github" / "workflows").exists():
        add("GitHub Actions")
    if (repo / ".gitlab-ci.yml").exists():
        add("GitLab CI/CD")
    if (repo / ".circleci" / "config.yml").exists():
        add("CircleCI")
    if (repo / "serverless.yml").exists() or (repo / "serverless.yaml").exists():
        add("Serverless Framework")
    if list(repo.glob("*.tf")) or (repo / "terraform").is_dir():
        add("Terraform")
    if (repo / "app.yaml").exists():
        add("Google App Engine")
    if (repo / "template.yaml").exists() or (repo / "sam.yaml").exists():
        add("AWS SAM / CloudFormation")
    if (repo / "fly.toml").exists():
        add("Fly.io")
    if (repo / "render.yaml").exists():
        add("Render")

    return found or ["None detected"]


# ---------------------------------------------------------------------------
# Package managers
# ---------------------------------------------------------------------------

def _detect_package_managers(repo: Path) -> list[str]:
    found: list[str] = []

    def add(p: str) -> None:
        if p not in found:
            found.append(p)

    if (repo / "poetry.lock").exists():
        add("Poetry")
    if (repo / "Pipfile").exists():
        add("Pipenv")
    if (repo / "requirements.txt").exists() or (repo / "pyproject.toml").exists() or (repo / "setup.py").exists():
        add("pip")
    if (repo / "pnpm-lock.yaml").exists():
        add("pnpm")
    elif (repo / "yarn.lock").exists():
        add("Yarn")
    elif (repo / "package.json").exists():
        add("npm")
    if (repo / "Gemfile").exists():
        add("Bundler")
    if (repo / "go.mod").exists():
        add("Go Modules")
    if (repo / "pom.xml").exists():
        add("Maven")
    if (repo / "build.gradle").exists() or (repo / "build.gradle.kts").exists():
        add("Gradle")
    if (repo / "Cargo.toml").exists():
        add("Cargo")
    if (repo / "mix.exs").exists():
        add("Mix (Elixir)")

    return found or ["Unknown"]


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

_ENTRY_POINT_NAMES = [
    "main.py", "app.py", "server.py", "manage.py", "run.py",
    "wsgi.py", "asgi.py", "cli.py",
    "index.js", "server.js", "app.js",
    "index.ts", "server.ts", "app.ts",
    "Main.java", "Application.java",
    "main.go",
    "main.rs",
    "app.rb", "config.ru",
]


def _detect_entry_points(repo: Path) -> list[str]:
    return [name for name in _ENTRY_POINT_NAMES if (repo / name).exists()] or ["None detected"]


# ---------------------------------------------------------------------------
# Monorepo / subproject detection
# ---------------------------------------------------------------------------

_MONOREPO_SUBDIR_NAMES = [
    "frontend", "backend", "client", "server", "api",
    "web", "app", "ui", "admin", "dashboard", "mobile",
    "services", "packages", "apps",
]

_JS_FRAMEWORK_DEPS: list[tuple[str, str]] = [
    ("next",          "Next.js"),
    ("nuxt",          "Nuxt.js"),
    ("@nestjs/core",  "NestJS"),
    ("express",       "Express.js"),
    ("react",         "React"),
    ("vue",           "Vue.js"),
    ("@angular/core", "Angular"),
    ("svelte",        "Svelte"),
    ("fastify",       "Fastify"),
    ("vite",          "Vite"),
    ("hapi",          "Hapi.js"),
]

_PY_FRAMEWORK_DEPS: list[tuple[str, str]] = [
    ("fastapi",   "FastAPI"),
    ("django",    "Django"),
    ("flask",     "Flask"),
    ("tornado",   "Tornado"),
    ("starlette", "Starlette"),
]


def _detect_subprojects(repo: Path) -> list[dict]:
    """
    Detect monorepo subprojects that have their own package.json or requirements.txt.
    Returns a list of subproject dicts with path, language, framework, package_manager, entry_points.
    """
    subprojects: list[dict] = []

    for subdir_name in _MONOREPO_SUBDIR_NAMES:
        subdir = repo / subdir_name
        if not subdir.is_dir():
            continue

        # JavaScript / TypeScript subproject
        if (subdir / "package.json").exists():
            pkg = _read_json_safe(subdir / "package.json")
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

            framework = "unknown"
            for pkg_name, fw in _JS_FRAMEWORK_DEPS:
                if pkg_name in deps:
                    framework = fw
                    break

            if (subdir / "pnpm-lock.yaml").exists():
                pm = "pnpm"
            elif (subdir / "yarn.lock").exists():
                pm = "yarn"
            else:
                pm = "npm"

            language = "TypeScript" if (subdir / "tsconfig.json").exists() else "JavaScript"

            entry_points = [
                ep for ep in [
                    "index.js", "src/index.js", "index.ts", "src/index.ts",
                    "src/main.ts", "src/main.js", "src/app.ts", "server.js", "server.ts",
                ]
                if (subdir / ep).exists()
            ]

            subprojects.append({
                "path":            subdir_name,
                "language":        language,
                "framework":       framework,
                "package_manager": pm,
                "entry_points":    entry_points or ["unknown"],
            })

        # Python subproject
        elif (subdir / "requirements.txt").exists() or (subdir / "pyproject.toml").exists():
            req = _read_safe(subdir / "requirements.txt").lower()
            framework = "unknown"
            for pkg_name, fw in _PY_FRAMEWORK_DEPS:
                if pkg_name in req:
                    framework = fw
                    break

            entry_points = [
                ep for ep in ["main.py", "app.py", "server.py", "run.py", "manage.py"]
                if (subdir / ep).exists()
            ]

            subprojects.append({
                "path":            subdir_name,
                "language":        "Python",
                "framework":       framework,
                "package_manager": "pip",
                "entry_points":    entry_points or ["unknown"],
            })

    return subprojects


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_architecture(repo_path: Path) -> dict[str, Any]:
    """
    Statically analyse a repository and return a structured architecture summary.

    Args:
        repo_path: Absolute path to the repository.

    Returns:
        Dict with keys: language, all_languages, framework, database, auth,
        deployment, package_manager, entry_points.
    """
    repo = repo_path.resolve()
    log.info("Mapping architecture of %s …", repo)

    languages   = _detect_languages(repo)
    subprojects = _detect_subprojects(repo)
    is_monorepo = len(subprojects) >= 2

    result: dict[str, Any] = {
        "language":        languages[0] if languages else "Unknown",
        "all_languages":   languages,
        "framework":       _detect_framework(repo),
        "database":        _detect_database(repo),
        "auth":            _detect_auth(repo),
        "deployment":      _detect_deployment(repo),
        "package_manager": _detect_package_managers(repo),
        "entry_points":    _detect_entry_points(repo),
        "is_monorepo":     is_monorepo,
        "subprojects":     subprojects,
    }

    log.info(
        "Architecture detected — lang=%s fw=%s db=%s monorepo=%s",
        result["language"], result["framework"], result["database"], is_monorepo,
    )
    return result
