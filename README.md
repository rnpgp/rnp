Prerequisites
=============

Compile
=======
```
cd /usr/local/netpgp
./build.sh
make install
```

Clean build artifacts
=====================
```
cd /usr/local/netpgp
./remove_artifacts.sh
```

Otherwise use `git clean`.

Binaries installed
==================
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

And if you're going to sign the RPM,
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
```
export SIGN=
```

Run the rpmbuild script.
```
cd /usr/local/netpgp
./remove_artifacts.sh

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
