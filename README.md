# Warbird Hook
On Windows 10 21H2, `ntoskrnl.exe` contains a table of pointers named `g_kernelCallbacks` used for licensing checks (called from `nt!SPCall2ServerInternal`). The callback table contains pointers to functions in an image named `ClipSp.sys`, which is a signed driver protected by Microsoft Warbird .  

The interesting thing about it is that PatchGuard does not verify the integrity of several image sections, including `PAGEwx`, which the driver contains in order to decrypt and re-encrypt its own code during runtime.  

Thanks to this, we can do the following things:
- Redirect function pointers in `g_kernelCallbacks` to our own code
- Inject our own shellcode into `PAGEwx` sections and encrypt it so that Warbird will automatically decrypt and execute our shellcode without hijacking any pointers

## References
- [Reversal of Windows' Client Licensing Service (ClipSp.sys)](https://github.com/KiFilterFiberContext/windows-software-policy)
- [Reversal of Warbird integration in the MSVC compiler](https://github.com/KiFilterFiberContext/warbird-obfuscate)
- [Warbird Runtime Reversed Engineered Code](https://github.com/KiFilterFiberContext/microsoft-warbird/)

## Disclaimer
- Offsets for function pointers are hardcoded for Windows 10 version 19044.1889
- There is a possibility that modifying the encrypted sections may fail because Warbird performs checksums over the decrypted instructions. 
The structures passed to `WarbirdRuntime::CEncryption::DoCrypt` contains a checksum field that is verified at the end of the encryption and decryption routines:
```cpp
struct ENCRYPTED_BLOCK_DATA_READ_WRITE_$(RI)
{
#pragma warbird(begin_shuffle)
    WORD                    dummy1:2;
#pragma warbird(next_shuffle)
    WORD                    dummy2:3;
#pragma warbird(next_shuffle)
    WORD                    dummy3:1;
#pragma warbird(next_shuffle)
    WORD                    fIsEncrypted:1;
#pragma warbird(next_shuffle)
    WORD                    fIsRelocated:1;
#pragma warbird(next_shuffle)
    WORD                    Checksum:CHECKSUM_BIT_COUNT;
#pragma warbird(end_shuffle)
};
```
One can recalculate the checksum and modify the global structure to circumvent this.
