: "${CORES:=$(grep -c '^$' /proc/cpuinfo)}"
export CORES
export MAKE=make

case "$(get_linux_dist)" in
  centos)
    if rpm --quiet -q ribose-automake116; then
      # set ACLOCAL_PATH if using ribose-automake116
      ACLOCAL_PATH=$(scl enable ribose-automake116 -- aclocal --print-ac-dir):$(rpm --eval '%{_datadir}/aclocal')
      export ACLOCAL_PATH
      # set path etc
      . /opt/ribose/ribose-automake116/enable
    fi
    # use rh-ruby25 if installed
    if rpm --quiet -q rh-ruby25; then
      . /opt/rh/rh-ruby25/enable
      PATH=$HOME/bin:$PATH
      export PATH
    fi
    # use llvm-toolset-7 if installed
    if rpm --quiet -q llvm-toolset-7.0; then
      . /opt/rh/llvm-toolset-7.0/enable
    fi
    ;;
  ubuntu)
    export GPG_INSTALL="/usr"
    export JSONC_INSTALL="/usr"
    ;;
esac

