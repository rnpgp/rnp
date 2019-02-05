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
    darwin*) echo "mac" ;;
    linux*) echo "linux" ;;
    cygwin*) echo "cygwin" ;;
    *) echo "unknown"; exit 1 ;;
  esac
}

