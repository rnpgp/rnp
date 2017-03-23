# Introduction

"rnp" is the Ribose fork of NetPGP originally written for NetBSD that
works on Linux and macOS.

# Install

## Binaries installed

* `netpgp`
* `netpgpkeys`
* `netpgpverify`

## On macOS using Homebrew

``` sh
brew tap riboseinc/rnp
brew install rnp
```

## On RHEL and CentOS via YUM

``` sh
rpm --import https://github.com/riboseinc/yum/raw/master/ribose-packages.pub
curl -L https://github.com/riboseinc/yum/raw/master/ribose.repo > /etc/yum.repos.d/ribose.repo
yum install -y netpgp
```

## On Debian

(WIP)


## Compiling from source

Clone this repo or download a release and expand it.

``` sh
./build.sh
make install
```


# Packaging

## Prerequisites

These steps require `docker` installed. It's not strictly necessary,
but just provides a consistent baseline for this guide to work.

Clone source:
```
# cd ~/src
git clone https://github.com/riboseinc/rnp
```

Start container (assuming you git cloned to `~/src/rnp`. Change
accordingly):

```
docker run -v ~/src/rnp:/usr/local/rnp -it centos:7 bash
```

## Compile

In the container:

```
cd /usr/local/rnp
./build.sh
make install
```

## Clean build artifacts

In the container:
```
cd /usr/local/rnp
./remove_artifacts.sh
```

Otherwise use `git clean`.

## Building an RPM

Set up build environment.

In the container:
```
/usr/local/rnp/packaging/redhat/extra/prepare_build.sh
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
cd /usr/local/rnp
./remove_artifacts.sh
packaging/redhat/extra/build_rpm.sh
```

The you can copy out the RPMs from the container:
```
cp ~/rpmbuild/SRPMS/netpgp*.rpm ~/rpmbuild/RPMS/x86_64/*.rpm /usr/local/netpgp
```

