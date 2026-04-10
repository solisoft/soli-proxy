#!/bin/bash
set -e

if [ $# -ne 1 ] || [[ ! "$1" =~ ^(major|minor|patch)$ ]]; then
    echo "Usage: $0 <major|minor|patch>"
    exit 1
fi

BUMP=$1

get_version() {
    grep '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/'
}

bump_version() {
    local version=$1
    local bump=$2
    local major minor patch
    
    IFS='.' read -r major minor patch <<< "$version"
    
    case $bump in
        major) ((major++)); minor=0; patch=0 ;;
        minor) ((minor++)); patch=0 ;;
        patch) ((patch++)) ;;
    esac
    
    echo "$major.$minor.$patch"
}

OLD_VERSION=$(get_version)
NEW_VERSION=$(bump_version "$OLD_VERSION" "$BUMP")
NEW_TAG="v${NEW_VERSION}"

if git rev-parse "$NEW_TAG" >/dev/null 2>&1; then
    echo "Error: Tag $NEW_TAG already exists"
    exit 1
fi

sed -i "s/^version = \"$OLD_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml

git add Cargo.toml
git commit -m "chore: bump version to $NEW_VERSION"
git tag "$NEW_TAG"
git push origin "$NEW_TAG"
echo "Done. Released $NEW_TAG and pushed."