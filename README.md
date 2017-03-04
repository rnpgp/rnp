Binaries installed
==================
```
netpgp
netpgpkeys
netpgpverify
```

Prerequisites
=============

This README assumes that you have `docker` installed.
It's not strictly necessary, but just provides a consistent baseline for
this guide to work.

Clone source:
```
# cd ~/src
git clone https://github.com/riboseinc/netpgp
```

Start container (assuming you git cloned to `~/src/netpgp`. Change
accordingly):
```
docker run -v ~/src/netpgp:/usr/local/netpgp -it centos:7 bash
```

Compile
=======
(In the container:)
```
cd /usr/local/netpgp
./build.sh
make install
```

Clean build artifacts
=====================
(In the container:)
```
cd /usr/local/netpgp
./remove_artifacts.sh
```

Otherwise use `git clean`.

Building RPM
============
Set up build environment.

(In the container:)
```
/usr/local/netpgp/packaging/redhat/extra/prepare_build.sh
```

And if you're going to sign the RPM,

(In the container:)
```
# Import your packager private key.
gpg --import your-packager.key

# Edit your identities.
PACKAGER="${PACKAGER:-Your Packager <your@packager.com>}"
GPG_NAME="${GPG_NAME:-${PACKAGER}}"

cat <<MACROS >~/.rpmmacros
%_signature gpg
%_gpg_path $HOME/.gnupg
%_gpg_name ${GPG_NAME}
%_gpgbin /usr/bin/gpg
%packager ${PACKAGER}
%_topdir $HOME/rpmbuild
MACROS
```

And if you're just going to test the RPM build process without GPG-signing,
(In the container:)
```
export SIGN=
```

Run the rpmbuild script.
(In the container:)
```
cd /usr/local/netpgp
./remove_artifacts.sh

cd /usr/local
netpgp/packaging/redhat/extra/build_rpm.sh
```

The you can copy out the RPMs from the container:
```
cp ~/rpmbuild/SRPMS/netpgp*.rpm ~/rpmbuild/RPMS/x86_64/*.rpm /usr/local/netpgp
```

Installing RPMs
===============

```
rpm --import https://github.com/riboseinc/yum/raw/master/ribose-packages.pub
curl -L https://github.com/riboseinc/yum/raw/master/ribose.repo > /etc/yum.repos.d/ribose.repo
yum install -y netpgp
```
