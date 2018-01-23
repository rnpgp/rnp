#!/bin/sh
set -ex

# https://gist.github.com/marcusandre/4b88c2428220ea255b83
get_os() {
  if [ -z $OSTYPE ]; then
    echo "$(uname | tr '[:upper:]' '[:lower:]')"
  else
    echo "$(echo $OSTYPE | tr '[:upper:]' '[:lower:]')"
  fi
}

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
  sudo pkg install -y python
  sudo pkg install -y cmake
  sudo pkg install -y gettext-tools
  sudo pkg install -y gnupg
}

openbsd_install() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "need to run as root"
    exit 1
  fi

  export PKG_PATH="https://cloudflare.cdn.openbsd.org/pub/OpenBSD/$(uname -r)/packages/$(uname -m)"

  # CI script and build dependencies
  for pkg in bash git wget bzip2 cmake gmake gettext-tools libiconv; do
    pkg_info | grep -q "${pkg}" && \
      continue

    pkg_add -I "${pkg}"
  done

  rm -f /bin/bash
  ln -s /usr/local/bin/bash /bin/bash
  grep -q "^/bin/bash" /etc/shells || \
    echo "/bin/bash" >> /etc/shells

  for pkg in automake gnupg; do
    pkg_ver="$(pkg_add -In ${pkg} 2>&1 | grep ^Ambiguous | tr ' ' '\n' | grep ${pkg}- | sort -V | tail -1)"

    pkg_info | grep -q "${pkg_ver}" && \
      continue

    echo "Installing: ${pkg_ver}"
    pkg_add -I "${pkg_ver}"
  done

  # Create link to expected gpg binary name and location
  rm -f ${GPG21_INSTALL}/bin/gpg
  ln /usr/local/bin/gpg2 ${GPG21_INSTALL}/bin/gpg

  # Python will be installed as a dependency of gnupg
  rm -f /bin/python
  ln -s /usr/local/bin/python2.7 /bin/python
}

netbsd_install() {
  echo ""
  pkgin -y install gnupg
  pkgin -y install cmake
  pkgin -y install gettext-tools
  pkgin -y install clang
  pkgin -y install wget
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
