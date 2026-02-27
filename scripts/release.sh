#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
  echo "Usage: ./scripts/release.sh <version>"
  echo "Example: ./scripts/release.sh 0.1.1"
  exit 1
fi

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version must be SemVer format: x.y.z"
  exit 1
fi

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet is required."
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit or stash changes before releasing."
  exit 1
fi

TAG="v$VERSION"

if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "Tag $TAG already exists."
  exit 1
fi

echo "Bumping version in CodeWorks.Auth.csproj to $VERSION"
python3 - <<'PY' "$VERSION"
import re
import sys
from pathlib import Path

version = sys.argv[1]
path = Path("CodeWorks.Auth.csproj")
text = path.read_text()
updated = re.sub(r"<Version>[^<]+</Version>", f"<Version>{version}</Version>", text, count=1)
if text == updated:
    raise SystemExit("Could not find <Version> element in CodeWorks.Auth.csproj")
path.write_text(updated)
PY

echo "Running release pack validation"
dotnet pack CodeWorks.Auth.csproj -c Release /p:GeneratePackageOnBuild=false

echo "Committing version bump"
git add CodeWorks.Auth.csproj
if [[ -f readme.md ]]; then
  git add readme.md || true
fi
if [[ -f packaging.md ]]; then
  git add packaging.md || true
fi
git commit -m "chore(release): v$VERSION"

echo "Creating and pushing tag $TAG"
git tag "$TAG"
git push origin HEAD
git push origin "$TAG"

echo "Release tag pushed. GitHub Action should now publish from tag $TAG."
