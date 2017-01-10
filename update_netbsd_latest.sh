#!/bin/bash -ex

root=$(pwd)
tempdir=$(mktemp -d)
pushd $tempdir
cvs -d :ext:anoncvs@anoncvs.NetBSD.org:/cvsroot checkout -d netpgp-latest src/crypto/external/bsd/netpgp
#rsync -aP netbsd-latest/* $root

# rsync instead of mv in order to override files
#cp -RL netbsd-latest ./
# rm -rf netbsd-latest

echo "Updated to latest NetBSD sourced NetPGP. Please review changes."
