/*
 * Copyright (c) 2026 [Ribose Inc](https://www.ribose.com).
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
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <tlhelp32.h>

#include <stdio.h>
#include <string>

#include "dll-verify.h"

namespace {

/* Checks whether the file has a valid embedded Authenticode signature which
 * chains to a trusted root. Revocation is not checked so the verification
 * also works on offline systems. */
bool
file_has_valid_signature(const std::wstring &path)
{
    WINTRUST_FILE_INFO file = {};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();

    GUID          policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data = {};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOCATION_CHECK_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;

    HWND dummy = static_cast<HWND>(INVALID_HANDLE_VALUE);
    LONG res = WinVerifyTrust(dummy, &policy, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(dummy, &policy, &data);
    return res == ERROR_SUCCESS;
}

std::wstring
directory_of(const std::wstring &path)
{
    size_t pos = path.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? std::wstring() : path.substr(0, pos);
}

bool
path_in_directory(const std::wstring &path, const std::wstring &dir)
{
    if (dir.empty() || path.size() <= dir.size() + 1) {
        return false;
    }
    if (_wcsnicmp(path.c_str(), dir.c_str(), dir.size()) != 0) {
        return false;
    }
    return path[dir.size()] == L'\\' || path[dir.size()] == L'/';
}

} // namespace

bool
rnp_dll_verify_modules()
{
    wchar_t exepath[32768] = {0};
    if (!GetModuleFileNameW(NULL, exepath, 32768)) {
        return true;
    }
    std::wstring exe(exepath);
    /* Unsigned executable is a development build: a swapped DLL does not gain
     * any trusted-process status, so there is nothing to enforce. */
    if (!file_has_valid_signature(exe)) {
        return true;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"warning: could not enumerate loaded modules.\n");
        return true;
    }

    std::wstring   exedir = directory_of(exe);
    bool           trusted = true;
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snap, &entry)) {
        do {
            std::wstring path(entry.szExePath);
            if (path == exe || !path_in_directory(path, exedir)) {
                continue;
            }
            if (!file_has_valid_signature(path)) {
                fwprintf(stderr,
                         L"error: module '%s' is loaded from the application directory "
                         L"but has no valid digital signature - possible DLL "
                         L"side-loading. Refusing to continue.\n",
                         path.c_str());
                trusted = false;
            }
        } while (Module32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return trusted;
}
