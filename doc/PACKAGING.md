# CentOS 7

## Launch a container

```sh
git clone https://github.com/riboseinc/rnp
cd rnp
docker run -ti --rm -v $PWD:/usr/local/rnp centos:7 bash
```

## Inside the container

```sh
# for newer cmake and other things
yum -y install epel-release
# rnp
yum -y install git cmake3 make gcc-c++
yum -y install bzip2-devel zlib-devel json-c12-devel libcmocka-devel

# botan
rpm --import https://github.com/riboseinc/yum/raw/master/ribose-packages.pub
curl -L https://github.com/riboseinc/yum/raw/master/ribose.repo > /etc/yum.repos.d/ribose.repo
yum -y install botan2-devel

# rnp rpm
yum -y install rpm-build
mkdir ~/build
cd ~/build
cmake3 -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=off -DCPACK_GENERATOR=RPM /usr/local/rnp
make package
```

