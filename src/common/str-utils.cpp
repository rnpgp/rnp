/*
 * Copyright (c) 2017 [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/** String utilities
 *  @file
 */

#include <cstddef>
#include <cstring>
#include "str-utils.h"
#ifdef _WIN32
#include <locale>
#include <codecvt>
#endif

using std::size_t;
using std::strlen;

char *
rnp_strip_eol(char *s)
{
    size_t len = strlen(s);

    while ((len > 0) && ((s[len - 1] == '\n') || (s[len - 1] == '\r'))) {
        s[--len] = '\0';
    }

    return s;
}

bool
rnp_is_blank_line(const char *line, size_t len)
{
    for (size_t i = 0; i < len && line[i]; i++) {
        if (line[i] != ' ' && line[i] != '\t' && line[i] != '\r') {
            return false;
        }
    }
    return true;
}

#ifdef _WIN32
std::wstring
wstr_from_utf8(const char *s)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8conv;
    return utf8conv.from_bytes(s);
}

std::wstring
wstr_from_utf8(const char *first, const char *last)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8conv;
    return utf8conv.from_bytes(first, last);
}

std::wstring
wstr_from_utf8(const std::string &s)
{
    return wstr_from_utf8(s.c_str());
}

std::string
wstr_to_utf8(const wchar_t *ws)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8conv;
    return utf8conv.to_bytes(ws);
}

std::string
wstr_to_utf8(const std::wstring &ws)
{
    return wstr_to_utf8(ws.c_str());
}
#endif