# Creating a Release

## General Notes
* Avoid tagging commits in the `master` branch.
* Release branches should have annotated tags and a CHANGELOG.md.
* The steps below detail creation of a brand new 1.x release.
  Some steps would be omitted for minor releases.

## Create the Branch
Release branches have names of the form `release/vN.x`, where N is the major
version (and x is a literal -- not a placeholder).

```
git checkout -b release/v1.x master
```

## Create a CHANGELOG.md and version.txt

```
vim CHANGELOG.md
git add CHANGELOG.md

git describe --long --dirty > version.txt
git add version.txt

git commit
```

## Create a Tag

An initial release would be tagged as follows:

```
git tag -a v1.0.0 -m ''
```

## Push

```
# push the branch
git push origin release/v1.x

# push the tag
git push origin :v1.0.0
```

# Maintaining a Release

Maintaining a release branch involves cherry-picking hotfixes and similar commits
from the master branch, while following the rules for Semantic Versioning.

