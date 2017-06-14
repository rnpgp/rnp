#!/bin/bash

CORES="2" && [ -r /proc/cpuinfo ] && CORES=$(grep -c '^$' /proc/cpuinfo)

[ "x${RNP_BUILD_DIR}" = "x" ] && \
  export RNP_BUILD_DIR=$(mktemp -d)

RNP_DEPS_PREFIX=/usr/local
BOTAN_PREFIX=${RNP_DEPS_PREFIX}

install_rpms() {
  BUILD_PKGS="automake gcc make openssl-devel zlib-devel bzip2-devel boost-devel libtool git which"

  # gcc-c++ is necessary for building botan
  BOTAN_PKGS="gcc-c++"

  # libcmocka is only available through EPEL
  CMOCKA_PKGS="libcmocka libcmocka-devel"
  JSONC_PKGS="json-c json-c-devel"

  RPM_PKGS="rpmdevtools rpm-build rpm-sign chrpath createrepo rpmlint"

  yum install -y epel-release
  yum install -y ${BUILD_PKGS} \
    ${BOTAN_PKGS} \
    ${CMOCKA_PKGS} \
    ${JSONC_PKGS} \
    ${RPM_PKGS}

  # For json-c 0.12.1
  #if [ ! -s /etc/yum.repos.d/ribose.repo ]; then
  #  rpm --import https://github.com/riboseinc/yum/raw/master/ribose-packages.pub
  #  curl -L https://github.com/riboseinc/yum/raw/master/ribose.repo > /etc/yum.repos.d/ribose.repo
  #fi
  #yum install -y json-c12 json-c12-devel
}

install_botan_stable() {
  BOTAN_URL=https://botan.randombit.net/releases/Botan-2.1.0.tgz
  BOTAN_SHA=460f2d7205aed113f898df4947b1f66ccf8d080eec7dac229ef0b754c9ad6294

  if [ ! -e "${BOTAN_PREFIX}/lib/libbotan-2.so" ]; then
    t=${RNP_BUILD_DIR}/botan
    mkdir -p ${t}

    botan_file=${t}/botan.tgz
    curl -fsSL ${BOTAN_URL} -o ${botan_file} \
    && echo "${BOTAN_SHA}  ${botan_file}" | sha256sum -c - \
    && pushd ${t} \
    && tar -xzf ${botan_file} \
    && pushd Botan-2.1.0 \
    && ./configure.py --prefix=${BOTAN_PREFIX} --with-bzip2 --with-zlib --with-boost \
    && make -j${CORES} install
  fi
}

install_botan_dev() {
  BOTAN_DEV_GIT_REPO=https://github.com/randombit/botan
  BOTAN_DEV_GIT_BRANCH=master

  if [ ! -e "${BOTAN_PREFIX}/lib/libbotan-2.so" ]; then
    t=${RNP_BUILD_DIR}/botan-dev
    mkdir -p ${t}

    pushd ${t} \
    && git clone --single-branch --depth 1 -b ${BOTAN_DEV_GIT_BRANCH} ${BOTAN_DEV_GIT_REPO} \
    && pushd botan \
    && ./configure.py --prefix=${BOTAN_PREFIX} --with-bzip2 --with-zlib --with-boost \
    && make -j${CORES} install
  fi
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
