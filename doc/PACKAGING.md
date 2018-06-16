# CentOS 7

## Launch a container

```sh
git clone https://github.com/riboseinc/rnp
docker run -ti --rm -v $PWD/rnp:/usr/local/rnp centos:7 bash
```

## Inside the container

```sh
# for newer cmake and other things
yum -y install epel-release
# rnp
yum -y install git cmake3 make gcc-c++
yum -y install bzip2-devel zlib-devel json-c12-devel libcmocka-devel

# botan
# This should really be installed as an RPM. Otherwise it may be neccessary
# to turn AUTOREQPROV off in order to install the created rnp RPM.
yum -y install gcc-c++ boost-devel
yum -y install wget
wget https://github.com/randombit/botan/archive/2.6.0.tar.gz
tar xzf 2.6.0.tar.gz
cd botan-2.6.0
./configure.py --prefix=/usr/local
make install

# rnp rpm
yum -y install rpm-build
mkdir ~/build
cd ~/build
cmake3 -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=off -DCPACK_GENERATOR=RPM /usr/local/rnp
make package
```

