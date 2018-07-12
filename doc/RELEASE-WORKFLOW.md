# Releases

## General Notes
* Avoid tagging commits in the `master` branch.
* Release branches should have annotated tags and a CHANGELOG.md.
* The steps below detail creation of a brand new 1.0.0 release.
  Some steps would be omitted for minor releases.

## Creating an Initial Release

### Create the Branch
Release branches have names of the form `release/N.x`, where N is the major
version (and x is a literal -- not a placeholder).

```
git checkout -b release/1.x master
```

### Create a CHANGELOG.md and version.txt

```
vim CHANGELOG.md
git add CHANGELOG.md

echo 1.0.0 > version.txt
git add -f version.txt

git commit
```

### Create a Tag

An initial release would be tagged as follows:

```
git tag -a v1.0.0 -m ''
```

### Push

```
# push the branch
git push origin release/1.x

# push the tag
git push origin v1.0.0
```

## Creating a New Release

Maintaining a release branch involves cherry-picking hotfixes and similar commits
from the `master` branch, while following the rules for Semantic Versioning.

The steps below will show the release of version 1.0.1.

### Add the Desired Changes

Cherry-pick the appropriate commits into the appropriate `release/N.x` branch.

To see what commits are in `master` that are not in the release branch, you
can observe the lines starting with `+` in:

```
git cherry -v release/1.x master
```

It is often useful to pick a range of commits. For example:

```
git cherry-pick a57b36f^..e23352c
```

From here, you can follow the steps for an initial release, starting with [Create (Update) a CHANGELOG.md and version.txt](#create-a-changelogmd-and-versiontxt).

