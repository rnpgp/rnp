#!/bin/sh
set -ex

. ci/utils.inc.sh

macos_install() {
  [ "${CI-}" = true ] || brew bundle
}

freebsd_install() {
  packages="
    git
    bash
    gnupg
    devel/pkgconf
    wget
    cmake
    gmake
    autoconf
    automake
    libtool
    gettext-tools
    python
    ruby25
"
  # Note: we assume sudo is already installed
  sudo pkg install -y ${packages}

  cd /usr/ports/devel/ruby-gems
  sudo make -DBATCH RUBY_VER=2.5 install
  cd

  mkdir -p ~/.gnupg
  echo "disable-ipv6" >> ~/.gnupg/dirmngr.conf
  dirmngr </dev/null
  dirmngr --daemon
}

openbsd_install() {
  echo ""
}

netbsd_install() {
  echo ""
}

linux_install() {
  echo ""
}

"$(get_os)_install"

