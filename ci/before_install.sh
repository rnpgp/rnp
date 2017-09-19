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
  brew install openssl
  brew install make
  brew install cmake
  brew install autoconf
  brew install automake
  brew install libtool
  brew install cmocka
  brew install pkg-config
  brew install gnupg
	mkdir -p ${CMOCKA_INSTALL}
}

freebsd_install() {
	sudo pkg install -y python
	sudo pkg install -y cmake
	sudo pkg install -y gettext-tools
	sudo pkg install -y gnupg
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
