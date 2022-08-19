# Warbird Hook
On Windows 10 21H2, PatchGuard does not (afaik) verify the integrity of pointers of `nt!g_kernelCallbacks`, unlike `nt!SeCiCallbacks`. The callback table contains pointers to an image named `ClipSp.sys`, which is a signed driver protected by Microsoft Warbird used for licensing checks (called from `nt!SPCall2ServerInternal`).  

The interesting thing about it is that PatchGuard does not verify the integrity of several image sections, including `PAGEwx`, which the driver contains in order to decrypt and re-encrypt its own code during runtime.  

Thanks to this, we can do the following things:
- Redirect function pointers in `g_kernelCallbacks` to our own code
- Inject our own shellcode into `PAGEwx` sections and encrypt it so that Warbird will automatically decrypt and execute our shellcode without hijacking any pointers

## References
- [Reversal of Windows' Client Licensing Service (ClipSp.sys)](https://github.com/KiFilterFiberContext/windows-software-policy)
- [Reversal of Warbird integration in the MSVC compiler](https://github.com/KiFilterFiberContext/warbird-obfuscate)
- [Warbird Runtime Reversed Engineered Code](https://github.com/KiFilterFiberContext/microsoft-warbird/)

## Disclaimer
Offsets for function pointers are hardcoded for Windows 10 version 19044.1889
