#!/usr/bin/env bash
# Creates and pushes a release tag. The Release workflow then builds, signs and
# publishes the release.
#
#   ./tag.sh v1.2.1
set -euo pipefail

TAG_VERSION="${1:-}"
if [[ ! "${TAG_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
    echo "usage: $0 vMAJOR.MINOR.PATCH[-PRERELEASE]" >&2
    exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
    echo "working tree is not clean; commit or stash changes first" >&2
    exit 1
fi

if ! grep -q "^# ${TAG_VERSION}\b" CHANGELOG.md; then
    echo "CHANGELOG.md has no '# ${TAG_VERSION}' section" >&2
    exit 1
fi
if grep -q "^# ${TAG_VERSION} (Unreleased)" CHANGELOG.md; then
    echo "CHANGELOG.md still marks ${TAG_VERSION} as Unreleased" >&2
    exit 1
fi

if git rev-parse -q --verify "refs/tags/${TAG_VERSION}" >/dev/null; then
    echo "tag ${TAG_VERSION} already exists" >&2
    exit 1
fi

git tag -a "${TAG_VERSION}" -m "${TAG_VERSION}"
git push origin "${TAG_VERSION}"
