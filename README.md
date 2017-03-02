Prerequisites
=============

Compile
=======

(Prefix /usr/local by default)
```
./build.sh
make install
```

Clean build artifacts
=====================
```
./remove_artifacts.sh
```

Otherwise use `git clean`.

Running commands
================

```
netpgp
netpgpkeys
netpgpverify
```

Building RPM
============

Start container:
```
docker run -v ~/src/netpgp:/usr/local/netpgp -it centos:7 bash
```

Set up build environment.
```
/usr/local/netpgp/packaging/redhat/extra/prepare_build.sh
```

Run the rpmbuild script.
```
cd /usr/local/netpgp
./remove_artifacts.sh

# Import your packager key
gpg --import your-packager.key

cat <<MACROS >~/.rpmmacros
%_signature gpg
%_gpg_path $HOME/.gnupg
%_gpg_name Your Packager <your@packager.com>
%_gpgbin /usr/bin/gpg
%packager Your Packager <your@packager.com>
%_topdir $HOME/rpmbuild
MACROS

cd /usr/local
netpgp/packaging/redhat/extra/build_rpm.sh
```

Installing RPMs
===============

```
rpm --import https://raw.githubusercontent.com/riboseinc/yum/master/ribose-packages.pub
curl -o https://raw.githubusercontent.com/riboseinc/yum/master/ribose.repo /etc/yum.repos.d
yum install netpgp
```
