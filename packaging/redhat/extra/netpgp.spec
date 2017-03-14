

Name: netpgp
Version: 3.99.18
Release: 1%{?dist}
License: BSD
URL: https://github.com/riboseinc/rp
Summary: Freely licensed PGP implementation
Source: netpgp-3.99.18.tar.bz2
BuildRequires: openssl-devel, zlib-devel, bzip2-devel, chrpath, autoconf, automake, libtool
Requires: netpgpverify = %{version}-%{release}

%prep
%setup -q

%description
NetPGP is a PGP-compatible tool for encrypting, signing, decrypting, and
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
%attr(0755,root,root) %{_bindir}/netpgp
%attr(0755,root,root) %{_bindir}/netpgpkeys
%attr(0644,root,root) %{_mandir}/man1/netpgp.1.gz
%attr(0644,root,root) %{_mandir}/man1/netpgpkeys.1.gz
%doc Licence


%package -n libnetpgp
Summary: Cryptography library
Requires: libmj = %{version}

%description -n libnetpgp
libnetpgp provides cryptographic routines and support for PGP.

%post -n libnetpgp -p /sbin/ldconfig

%postun -n libnetpgp -p /sbin/ldconfig

%files -n libnetpgp
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/libnetpgp.so.*


%package -n libnetpgp-devel
Requires: libnetpgp = %{version}
Summary: NetPGP development headers and libraries

%description -n libnetpgp-devel
libnetpgp provides cryptographic routines and support for PGP.

%files -n libnetpgp-devel
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/libnetpgp.so
%attr(0644,root,root) %{_prefix}/include/netpgp.h
%attr(0644,root,root) %{_mandir}/man3/libnetpgp.3.gz


%package -n libnetpgp-static
Requires: libnetpgp-devel = %{version}
Summary: Static lib for libnetpgp

%description -n libnetpgp-static
libnetpgp provides cryptographic routines and support for PGP.

%files -n libnetpgp-static
%defattr(-,root,root)
%attr(0644,root,root) %{_libdir}/libnetpgp.a


%package -n libmj
Summary: JSON support for netpgp

%description -n libmj
libmj provides JSON routines required by libnetpgp.

%post  -n libmj -p /sbin/ldconfig

%postun -n libmj -p /sbin/ldconfig

%files -n libmj
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/libmj.so.*
%attr(0644,root,root) %{_mandir}/man3/libmj.3.gz


%package -n libmj-devel
Requires: libmj = %{version}
Summary:  Development headers and libraries for libmj

%description -n libmj-devel
Development files for libmj, the JSON library used in libnetpgp

%files -n libmj-devel
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/libmj.so
%attr(0644,root,root) %{_prefix}/include/mj.h
%attr(0644,root,root) %{_mandir}/man3/libmj.3.gz


%package -n libmj-static
Requires: libmj-devel = %{version}
Summary:  Static library for libmj

%description -n libmj-static
Static library files for libmj, the JSON library used in libnetpgp

%files -n libmj-static
%defattr(-,root,root)
%attr(0755,root,root) %{_libdir}/libmj.a


%package -n netpgpverify
Summary: Command line utility to verify signatures

%description -n netpgpverify
netpgpverify verifies PGP signatures.

%files -n netpgpverify
%defattr(-,root,root)
%attr(0755,root,root) %{_prefix}/bin/netpgpverify
%attr(0644,root,root) %{_mandir}/man1/netpgpverify.1.gz

%changelog
* Fri Mar 10 2017 Zoltan Gyarmati <mr.zoltan.gyarmati@gmail.com> - 3.99.18-1
- Fix rpmlint and fedora-review errors
- Add libnetpgp-static package
- Add ldconfig calls to post and postun scriplets
- add libmj-devel -static packages

* Mon Mar 6 2017 Jeffrey Lau <jeffrey.lau@ribose.com>
- Fix RPM build requirements
