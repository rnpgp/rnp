#ifndef RNPV_PLATFORM_H
#define RNPV_PLATFORM_H
#ifdef __linux__
#ifndef VASPRINTF_H
#include <stdarg.h>
int vasprintf(char **, const char *, va_list);
#endif

#ifndef ASPRINTF_H
int asprintf(char **, const char *, ...);
#endif
#define __dead __attribute__ ((dead))
// The __USE hack is probably necessary on all non-NetBSD platforms.
// But we cannot risk breaking something that Frank cannot test.
#ifndef __USE
#define __USE(a) ((void)(a))
#endif
#endif
#endif
