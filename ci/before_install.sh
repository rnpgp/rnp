#!/bin/sh
set -ex

. ci/utils.inc.sh

macos_install() {
  brew update
  packages="
    openssl
    make
    cmake
    autoconf
    automake
    libtool
    pkg-config
    cmocka
    gnupg
    gnutls
    wget
    python2
"
	# gnutls for manual compile of gnupg
	for p in ${packages}; do
		brew install ${p} || brew upgrade ${p}
	done

  mkdir -p ${CMOCKA_INSTALL}
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
    ruby
    devel/ruby-gems
"
  # Note: we assume sudo is already installed
  sudo pkg install -y ${packages}
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

