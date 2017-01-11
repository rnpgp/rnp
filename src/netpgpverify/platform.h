#ifndef NETPGPVERIFY_PLATFORM_H
#define NETPGPVERIFY_PLATFORM_H
#ifdef __linux__
#define __dead __attribute__ ((dead))
// The __USE hack is probably necessary on all non-NetBSD platforms.
// But we cannot risk breaking something that Frank cannot test.
#ifndef __USE
#define __USE(a) ((void)(a))
#endif
#endif
#endif

