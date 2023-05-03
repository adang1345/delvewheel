/* Copyright (C) 2023 Aohan Dang - All Rights Reserved
 *
 * You may use, distribute, and modify this code under the terms of the MIT
 * License. You should have received a copy of the MIT License with this file.
 * If not, please visit https://github.com/adang1345/delvewheel.
 */

#include <Windows.h>
#include <delayimp.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>


/* When a delay-load DLL dependency is loaded, ensure that paths added with
 * os.add_dll_directory() and the directory containing the delay-load
 * dependency are included in the DLL search path. */
FARPROC WINAPI delayHook(unsigned dliNotify, PDelayLoadInfo pdli) {
    if (dliNotify == dliNotePreLoadLibrary) {
        HMODULE hm;
        if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCTSTR)delayHook, &hm)) {
            // failed to get handle to current DLL; call GetLastError() for details
            return NULL;
        }
        TCHAR path[MAX_PATH];
        DWORD size = _countof(path);
        LPTSTR p_path = path;
        DWORD len = GetModuleFileName(hm, p_path, size);
        if (!len) {
            // failed to get path to current DLL; call GetLastError() for details
            return NULL;
        }
        while (len == size && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            // path to current DLL is longer than MAX_PATH-1; allocate memory dynamically
            size *= 2;  // double memory size until we have enough
            if (p_path == path) {
                if (!(p_path = malloc(size * sizeof(TCHAR)))) {
                    // failed to allocate memory
                    return NULL;
                }
            } else {
                LPTSTR p_path_old = p_path;
                if (!(p_path = realloc(p_path, size * sizeof(TCHAR)))) {
                    // failed to allocate memory
                    free(p_path_old);
                    return NULL;
                }
            }
            if (!(len = GetModuleFileName(hm, p_path, size))) {
                // failed to get path to current DLL; call GetLastError() for details
                free(p_path);
                return NULL;
            }
        }
        TCHAR *backslash = _tcsrchr(p_path, TEXT('\\'));
        if (!backslash) {
            // backslash not found in path to current DLL
            if (p_path != path) {
                free(p_path);
            }
            return NULL;
        }
        ptrdiff_t backslash_offset = backslash - p_path;
        size_t size_needed = backslash_offset + strlen(pdli->szDll) + 2;
        if (size_needed > size) {
            if (p_path == path) {
                if (!(p_path = malloc(size_needed * sizeof(TCHAR)))) {
                    // failed to allocate memory
                    return NULL;
                }
                _tcsncpy(p_path, path, backslash_offset + 1);
                p_path[backslash_offset + 1] = TEXT('\0');
            } else {
                LPTSTR p_path_old = p_path;
                if (!(p_path = realloc(p_path, size_needed * sizeof(TCHAR)))) {
                    // failed to allocate memory
                    free(p_path_old);
                    return NULL;
                }
            }
        }
        _stprintf(p_path + backslash_offset + 1, TEXT("%hs"), pdli->szDll);
        hm = LoadLibraryEx(p_path, NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
        if (p_path != path) {
            free(p_path);
        }
        return (FARPROC)hm;
    }
    return NULL;
}

ExternC const PfnDliHook __pfnDliNotifyHook2 = delayHook;
