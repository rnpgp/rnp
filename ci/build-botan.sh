#!/bin/bash
set -eu

if [ ! -e "$HOME/builds/botan-install/lib/libbotan-2.so" ]; then
  git clone https://github.com/randombit/botan ~/builds/botan
  cd ~/builds/botan
  ./configure.py --prefix="$HOME/builds/botan-install"
  make install
fi

