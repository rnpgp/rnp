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

linux_install_centos() {
  sudo yum -y update
  sudo yum -y -q install epel-release centos-release-scl
  sudo rpm --import https://github.com/riboseinc/yum/raw/master/ribose-packages.pub
  sudo curl -L https://github.com/riboseinc/yum/raw/master/ribose.repo -o /etc/yum.repos.d/ribose.repo
  sudo yum -y -q install sudo wget git cmake3 gcc gcc-c++ make autoconf automake libtool bzip2 gzip \
    ncurses-devel which rh-ruby25 rh-ruby25-ruby-devel bzip2-devel zlib-devel byacc gettext-devel \
    bison ribose-automake116 llvm-toolset-7.0
}

linux_install_ubuntu() {
  sudo apt-get update
  sudo apt-get install ruby`ruby -e 'puts RUBY_VERSION[/\d+\.\d+/]'`-dev
  sudo apt-get -y install g++-8 cmake libbz2-dev zlib1g-dev libjson-c-dev libbotan-2-dev build-essential gettext ruby-bundler
}

linux_install() {
  local dist=$(get_linux_dist)
  type "linux_install_$dist" | grep -qwi 'function' && "linux_install_$dist"
  true
}

msys_install() {
  packages="
    tar
    zlib-devel
    libbz2-devel
    git
    automake
    autoconf
    libtool
    automake-wrapper
    gnupg2
    make
    pkgconfig
    mingw64/mingw-w64-x86_64-cmake
    mingw64/mingw-w64-x86_64-gcc
    mingw64/mingw-w64-x86_64-json-c
    mingw64/mingw-w64-x86_64-libbotan
    mingw64/mingw-w64-x86_64-python2
  "
  pacman --noconfirm -S --needed ${packages}

  # msys includes ruby 2.6.1 while we need lower version
  wget http://repo.msys2.org/mingw/x86_64/mingw-w64-x86_64-ruby-2.5.3-1-any.pkg.tar.xz -O /tmp/ruby-2.5.3.pkg.tar.xz
  pacman --noconfirm --needed -U /tmp/ruby-2.5.3.pkg.tar.xz
  rm /tmp/ruby-2.5.3.pkg.tar.xz
}

"$(get_os)_install"
