dnl This gets processed by m4.
dnl Macros:
dnl   PACKAGE_VERSION
dnl   BINARY_TARGET
dnl   PREFIX
dnl   SOURCE_TARBALL_NAME

Name: netpgp
Version: PACKAGE_VERSION
Release: 1
License: BSD
Vendor: NetBSD
URL: http://www.netpgp.com/
Packager: Package Maintainer <releases@netbsd.org>
Summary: Freely licensed PGP implementation
Source: SOURCE_TARBALL_NAME
BuildRequires: openssl-devel, zlib-devel, bzip2-devel
Requires: netpgpverify = %{version}

%define _unpackaged_files_terminate_build 0

%prep
%setup

%description
NetPGP is a PGP-compatible tool for encrypting, signing, decrypting, and verifying files.

%build
./configure --prefix=`'PREFIX`'; make;
(cd src/netpgpverify; ./configure --prefix=`'PREFIX`'; make;)

%install
make install DESTDIR="%{buildroot}";
(cd src/netpgpverify; make install DESTDIR="%{buildroot}";)
find "%{buildroot}"/`'PREFIX`'/lib -name "*.la" -delete;
# chrpath -d "%{buildroot}"/`'PREFIX`'/bin/netpgp;
# chrpath -d "%{buildroot}"/`'PREFIX`'/bin/netpgpkeys;
# chrpath -d "%{buildroot}"/`'PREFIX`'/bin/netpgpverify;
chmod 0644 "%{buildroot}"/`'PREFIX`'/lib/lib*.so.*;

%pre

%post

%preun

%postun

%clean

%files
%defattr(-,root,root)
%attr(0755,root,root) `'PREFIX`'/bin/netpgp
%attr(0755,root,root) `'PREFIX`'/bin/netpgpkeys
%attr(0644,root,root) `'PREFIX`'/share/man/man1/netpgp.1
%attr(0644,root,root) `'PREFIX`'/share/man/man1/netpgpkeys.1

%package -n libmj
Summary: JSON support for netpgp

%description -n libmj
libmj provides JSON routines required by libnetpgp.

%pre -n libmj

%post -n libmj

%preun -n libmj

%postun -n libmj

%files -n libmj
%defattr(-,root,root)
`'PREFIX`'/lib/libmj.so
%attr(0644,root,root) `'PREFIX`'/lib/libmj.so.*
%attr(0644,root,root) `'PREFIX`'/share/man/man3/libmj.3

%package -n libnetpgp
Summary: JSON support for netpgp
Requires: libmj = %{version}

%description -n libnetpgp
libnetpgp provides cryptographic routines and support for PGP.

%pre -n libnetpgp

%post -n libnetpgp

%preun -n libnetpgp

%postun -n libnetpgp

%files -n libnetpgp
%defattr(-,root,root)
`'PREFIX`'/lib/libnetpgp.so
%attr(0644,root,root) `'PREFIX`'/lib/libnetpgp.so.*
%attr(0644,root,root) `'PREFIX`'/share/man/man3/libnetpgp.3

%package -n libnetpgp-devel
Requires: libnetpgp = %{version}
Summary: netpgp development headers and libraries

%description -n libnetpgp-devel
libnetpgp provides cryptographic routines and support for PGP.

%pre -n libnetpgp-devel

%post -n libnetpgp-devel

%preun -n libnetpgp-devel

%postun -n libnetpgp-devel

%files -n libnetpgp-devel
%defattr(-,root,root)
%attr(0644,root,root) `'PREFIX`'/include/netpgp.h
%attr(0644,root,root) `'PREFIX`'/lib/libnetpgp.a

%package -n netpgpverify
Summary: signature verifier

%description -n netpgpverify
netpgpverify verifies PGP signatures.

%pre -n netpgpverify

%post -n netpgpverify

%preun -n netpgpverify

%postun -n netpgpverify

%files -n netpgpverify
%defattr(-,root,root)
%attr(0755,root,root) `'PREFIX`'/bin/netpgpverify
%attr(0644,root,root) `'PREFIX`'/share/man/man1/netpgpverify.1

