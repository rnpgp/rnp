# Derived from: https://gist.github.com/marcusandre/4b88c2428220ea255b83
get_os() {
  local ostype=$(echo $OSTYPE | tr '[:upper:]' '[:lower:]')
  if [ -z "$ostype" ]; then
    ostype=$(uname | tr '[:upper:]' '[:lower:]')
  fi

  case $ostype in
    freebsd*) echo "freebsd" ;;
    netbsd*) echo "netbsd" ;;
    openbsd*) echo "openbsd" ;;
    darwin*) echo "macos" ;;
    linux*) echo "linux" ;;
    cygwin*) echo "cygwin" ;;
    msys*) echo "msys" ;;
    mingw*) echo "win" ;;
    *) echo "unknown"; exit 1 ;;
  esac
}

get_linux_dist() {
  if [ -f /etc/os-release ]; then
    sh -c '. /etc/os-release && echo $ID'
  elif type lsb_release >/dev/null 2>&1; then
    lsb_release -si | tr '[:upper:]' '[:lower:]'
  fi
}

