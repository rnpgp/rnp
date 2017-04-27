#!/bin/bash

install_rpms() {
  BUILD_PKGS="automake gcc make openssl-devel zlib-devel bzip2-devel boost-devel libtool git which"

  # gcc-c++ is necessary for building botan
  BOTAN_PKGS="gcc-c++"

  # libcmocka is only available through EPEL
  CMOCKA_PKGS="libcmocka-devel"

  RPM_PKGS="rpmdevtools rpm-build rpm-sign chrpath createrepo rpmlint"

  yum install -y epel-release
  yum install -y ${BUILD_PKGS} \
    ${BOTAN_PKGS} \
    ${CMOCKA_PKGS} \
    ${RPM_PKGS}
}

install_botan_stable() {
  BOTAN_URL=https://botan.randombit.net/releases/Botan-2.1.0.tgz
  BOTAN_SHA=460f2d7205aed113f898df4947b1f66ccf8d080eec7dac229ef0b754c9ad6294

  t=$(mktemp -d)
  botan_file=${t}/botan.tgz
  curl -fsSL ${BOTAN_URL} -o ${botan_file} \
  && echo "${BOTAN_SHA}  ${botan_file}" | sha256sum -c - \
  && pushd ${t} \
  && tar -xzf ${botan_file} \
  && pushd Botan-2.1.0 \
  && ./configure.py --prefix=/usr/local \
  && make \
  && make install
}

install_botan_dev() {
  BOTAN_DEV_GIT_REPO=https://github.com/randombit/botan
  BOTAN_DEV_GIT_BRANCH=master

  t=$(mktemp -d) \
  && pushd ${t} \
  && git clone --single-branch --depth 1 -b ${BOTAN_DEV_GIT_BRANCH} ${BOTAN_DEV_GIT_REPO} \
  && pushd botan \
  && ./configure.py --prefix=/usr/local --with-bzip2 --with-zlib --with-boost \
  && make \
  && make install
}

main() {
  install_rpms
  # yum install -y fedora-review

  # Setup the rpm build tree
  rpmdev-setuptree

  # TODO: Detect whether botan is already installed and skip
  install_botan_dev
}

main "$@"

exit 0
