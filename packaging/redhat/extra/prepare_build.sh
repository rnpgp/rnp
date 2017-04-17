#!/bin/bash


BUILD_PKGS="automake gcc make openssl-devel zlib-devel bzip2-devel libtool git which"

# gcc-c++ is necessary for building botan
BOTAN_PKGS="gcc-c++"

CMOCKA_PKGS="cmake"

RPM_PKGS="rpmdevtools rpm-build rpm-sign chrpath createrepo rpmlint"

yum install -y ${BUILD_PKGS} \
  ${BOTAN_PKGS} \
  ${CMOCKA_PKGS} \
  ${RPM_PKGS}

# yum install -y fedora-review

rpmdev-setuptree
