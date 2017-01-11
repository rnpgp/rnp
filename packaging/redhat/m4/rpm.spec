dnl Frank Trampe wrote this.
dnl The file is hereby released under the license of the enclosing project.
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
Packager: Jeffrey Lau <jeffrey.lau@ribose.com>
Summary: Freely licensed PGP implementation
Source: SOURCE_TARBALL_NAME
BuildRequires: openssl-devel, zlib-devel, bzip2-devel, chrpath
Requires: netpgpverify = %{version}

%define _unpackaged_files_terminate_build 0
ifdef(`PREFIX',%define _prefix PREFIX)

%prep
%setup

%description
NetPGP is a PGP-compatible tool for encrypting, signing, decrypting, and verifying files.

%build
autoreconf -ivf
./configure --prefix=%{_prefix} --libdir=%{_libdir} && make clean && make;
(cd src/netpgpverify && ./configure --prefix=%{_prefix} --mandir=%{_mandir} && make clean && make;)

%install
make install DESTDIR="%{buildroot}";
(cd src/netpgpverify; make install DESTDIR="%{buildroot}";)
find "%{buildroot}"/%{_libdir} -name "*.la" -delete;
chrpath -d "%{buildroot}"/%{_prefix}/bin/netpgp;
chrpath -d "%{buildroot}"/%{_prefix}/bin/netpgpkeys;
chrpath -d "%{buildroot}"/%{_prefix}/bin/netpgpverify;
chrpath -d "%{buildroot}"/%{_libdir}/lib*.so.*;
chmod 0755 "%{buildroot}"/%{_libdir}/lib*.so.*;
for file in %{_mandir}/man1/netpgp.1 \
  %{_mandir}/man1/netpgpkeys.1 \
  %{_mandir}/man3/libmj.3 \
  %{_mandir}/man3/libnetpgp.3 \
  %{_mandir}/man1/netpgpverify.1; \
do
  if [ ! -e "%{buildroot}"/"$file" ]; then
    gzip -9 "%{buildroot}"/"$file";
  fi;
done;

%pre

%post

%preun

%postun

%clean

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/netpgp
%attr(0755,root,root) %{_bindir}/netpgpkeys
%attr(0644,root,root) %{_mandir}/man1/netpgp.1.gz
%attr(0644,root,root) %{_mandir}/man1/netpgpkeys.1.gz

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
%attr(0755,root,root) %{_libdir}/libmj.so
%attr(0755,root,root) %{_libdir}/libmj.so.*
%attr(0644,root,root) %{_mandir}/man3/libmj.3.gz

%package -n libnetpgp
Summary: cryptography library
Requires: libmj = %{version}

%description -n libnetpgp
libnetpgp provides cryptographic routines and support for PGP.

%pre -n libnetpgp

%post -n libnetpgp

%preun -n libnetpgp

%postun -n libnetpgp

%files -n libnetpgp
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/libnetpgp.so
%attr(0755,root,root) %{_libdir}/libnetpgp.so.*
%attr(0644,root,root) %{_mandir}/man3/libnetpgp.3.gz

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
%attr(0644,root,root) %{_prefix}/include/netpgp.h
%attr(0644,root,root) %{_libdir}/libnetpgp.a

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
%attr(0755,root,root) %{_prefix}/bin/netpgpverify
%attr(0644,root,root) %{_mandir}/man1/netpgpverify.1.gz

