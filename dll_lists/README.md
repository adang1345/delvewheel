This folder contains lists of files found in `C:\Windows\System32` and `C:\Windows\SysWOW64` with extensions `.dll` and `.drv` for vanilla installations of various versions of Windows. For Windows arm64, `C:\Windows\System32` contains some non-arm64 DLLs, which are excluded using `arm64_filter.py`.

Run `generate.py x86`, `generate.py x64`, or `generate.py arm64` to generate a list of DLLs that are present in all lists pertaining to the given architecture.
