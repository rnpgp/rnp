Prerequisites
=============

Start container:
```
docker run -v ~/src/netpgp:/usr/local/netpgp -it centos:7 bash
```

Compile
=======

(Prefix /usr/local by default)
```
./build.sh
make install
```

Clean build artifacts
===============
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

Set up build environment.
```
./prepare_build.sh
```

Run the rpmbuild script.
```
./remove_artifacts.sh
./build_rpm.sh
```

