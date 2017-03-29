dnl (c) 2017 Ribose Inc.
dnl Frank Trampe, Jeffrey Lau and Ronald Tse.
dnl The file is hereby released under the license of the enclosing project.
dnl This gets processed by m4.
dnl Macros:
dnl   PACKAGE_VERSION
dnl   SOURCE_TARBALL_NAME
dnl   RELEASE


Name: rnp
Version: PACKAGE_VERSION
Release: RELEASE%{?dist}
License: BSD
URL: https://github.com/riboseinc/rnp
Summary: Freely licensed PGP implementation
Source: SOURCE_TARBALL_NAME
BuildRequires: openssl-devel, zlib-devel, bzip2-devel, chrpath, autoconf, automake, libtool
Requires: rnpv = %{version}-%{release}

%prep
%setup -q

%description
RNP is a PGP-compatible tool for encrypting, signing, decrypting, and
verifying files, a fork from NetBSD's netpgp.

%build
autoreconf -ivf;
%configure 
sed -i -e 's! -shared ! -Wl,--as-needed\0!g' libtool
make;

%install
%make_install
find "%{buildroot}"/%{_libdir} -name "*.la" -delete;

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/rnp
%attr(0755,root,root) %{_bindir}/rnpkeys
%attr(0644,root,root) %{_mandir}/man1/rnp.1.gz
%attr(0644,root,root) %{_mandir}/man1/rnpkeys.1.gz
%doc Licence


%package -n librnp
Summary: Cryptography library

%description -n librnp
RNP provides cryptographic routines and support for PGP.

%post -n librnp -p /sbin/ldconfig

%postun -n librnp -p /sbin/ldconfig

%files -n librnp
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/librnp.so.*


%package -n librnp-devel
Requires: librnp = %{version}
Summary: RNP development headers and libraries

%description -n librnp-devel
librnp provides cryptographic routines and support for PGP.

%files -n librnp-devel
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/librnp.so
%attr(0644,root,root) %{_prefix}/include/rnp.h
%attr(0644,root,root) %{_mandir}/man3/librnp.3.gz


%package -n librnp-static
Requires: librnp-devel = %{version}
Summary: Static lib for librnp

%description -n librnp-static
Librnp provides cryptographic routines and support for PGP.

%files -n librnp-static
%defattr(-,root,root)
%attr(0644,root,root) %{_libdir}/librnp.a


%package -n rnpv
Summary: Command line utility to verify signatures

%description -n rnpv
rnpv verifies PGP signatures.

%files -n rnpv
%defattr(-,root,root)
%attr(0755,root,root) %{_prefix}/bin/rnpv
%attr(0644,root,root) %{_mandir}/man1/rnpv.1.gz

%changelog
* Sun Mar 26 2017 Zoltan Gyarmati <mr.zoltan.gyarmati@gmail.com> - 3.99.18-2
- remove libmj installed packages as it's not installed anymore
- rename packages, installed files, etc to *rnp* according to the new package name

* Fri Mar 10 2017 Zoltan Gyarmati <mr.zoltan.gyarmati@gmail.com> - 3.99.18-1
- Fix rpmlint and fedora-review errors
- Add libnetpgp-static package
- Add ldconfig calls to post and postun scriplets
- add libmj-devel -static packages

* Mon Mar 6 2017 Jeffrey Lau <jeffrey.lau@ribose.com>
- Fix RPM build requirements
