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

crossplat_install() {
  echo ""
}

main() {
  case $(get_os) in
    freebsd*)
      freebsd_install ;;
    netbsd*)
      netbsd_install ;;
    openbsd*)
      openbsd_install ;;
    darwin*)
      macos_install ;;
    linux*)
      linux_install ;;
    *) echo "unknown"; exit 1 ;;
  esac

  crossplat_install
}

main
