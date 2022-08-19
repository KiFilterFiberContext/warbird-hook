#include <ntddk.h>
#include <ntstrsafe.h>
#include "utils.hpp"

static volatile ULONG64 ClipSpIsAppLicensed_o;

static volatile ULONG64 WarbirdSegmentDecrypt3;
static volatile ULONG64 WarbirdSegmentEncrypt3;
static volatile ULONG64 WarbirdSegmentDecrypt4;
static volatile ULONG64 WarbirdSegmentEncrypt4;

NTSTATUS ClipSpIsAppLicensed_hk( void )
{
	// trigger PG verification just to verify
	KiSwInterrupt( );

	Log( "[+] Called into ClipSpIsAppLicensed! Return is 0x%llx\n", _ReturnAddress( ) );
	return FALSE;
}

NTSTATUS SpIsAppLicensed_hk( void )
{
	KiSwInterrupt( );

	Log( "[+] Called into SpIsAppLicensed! Return is 0x%llx\n", _ReturnAddress( ) );
	return FALSE;
}

NTSTATUS DriverEntry( PDRIVER_OBJECT DrivObj, PUNICODE_STRING Reg )
{
	UNREFERENCED_PARAMETER( DrivObj );
	UNREFERENCED_PARAMETER( Reg );

	NTSTATUS Status = STATUS_SUCCESS;
	Log( "[!] Started Driver 3!\n" );

	PVOID ntbase;
	PVOID clipbase;

	RtlPcToFileHeader( IoCreateDevice, &ntbase );

	Log( "[+] ntoskrnl.exe image Base: 0x%llx\n", (ULONG64) ntbase );

	( ULONG64 ) ClipSpIsAppLicensed_o = *( ULONG64* ) (( ULONG64 ) ntbase + 0xD2D3F8);
	*( ULONG64* ) (( ULONG64 ) ntbase + 0xD2D3F8) = ( ULONG64 ) ClipSpIsAppLicensed_hk;

	RtlPcToFileHeader( ( PVOID ) ClipSpIsAppLicensed_o, &clipbase );
	Log( "[+] ClipSp.sys: 0x%llx\n", ClipSpIsAppLicensed_o, (ULONG64) clipbase );
	
	// get function pointers from WarbirdRuntime::CEncryption to unpack and pack our shellcode (PAGEwx4 and PAGEwx3)
	WarbirdSegmentDecrypt4 = ( ULONG64 ) (( ULONG64 ) clipbase + 0x11E4);
	WarbirdSegmentEncrypt4 = ( ULONG64 ) (( ULONG64 ) clipbase + 0x1270);

	WarbirdSegmentDecrypt3 = ( ULONG64 ) (( ULONG64 ) clipbase + 0x1158);
	WarbirdSegmentEncrypt3 = ( ULONG64 ) (( ULONG64 ) clipbase + 0x10C8);

	PVOID g_EncryptedSegmentConstData_3 = ( PVOID ) (( ULONG64 ) clipbase + 0xA2F90);
	PVOID g_EncryptedSegmentReadWriteData_3 = ( PVOID ) (( ULONG64 ) clipbase + 0xAB8E0);
	PVOID g_EncryptedSegmentConstData_4 = ( PVOID ) (( ULONG64 ) clipbase + 0xA3640);
	PVOID g_EncryptedSegmentReadWriteData_4 = ( PVOID ) (( ULONG64 ) clipbase + 0xABA80 );

	ULONG64 SpIsAppLicensed = ( ULONG64 ) (( ULONG64 ) clipbase + 0x100660 );

	Log( "[+] BEFORE DECRYPTION: SpIsAppLicensed (val) => %llx\n", *( ULONG64* ) SpIsAppLicensed );
	Log( "[+] SpIsAppLicensed Hook => %llx (orig: %llx)\n", ( ULONG64) SpIsAppLicensed_hk, SpIsAppLicensed );

	// unpack the page using warbird
	( ( HRESULT (*)( PVOID, PVOID ) ) WarbirdSegmentDecrypt3 ) ( g_EncryptedSegmentConstData_3, g_EncryptedSegmentReadWriteData_3 );
	( ( HRESULT (*)( PVOID, PVOID ) ) WarbirdSegmentDecrypt4 ) ( g_EncryptedSegmentConstData_4, g_EncryptedSegmentReadWriteData_4 );

	Log( "[+] AFTER DECRYPTION: SpIsAppLicensed (val) => %llx\n", *( ULONG64* ) SpIsAppLicensed );
	
	// change protection so we can write our shellcode to the unpacked page
	PMDL mdl = IoAllocateMdl( ( PVOID ) SpIsAppLicensed, 0x1000, FALSE, FALSE, NULL );
	if ( !mdl )
	{
		( ( HRESULT (*)( PVOID, PVOID ) ) WarbirdSegmentEncrypt4 )( g_EncryptedSegmentConstData_4, g_EncryptedSegmentReadWriteData_4 );
		( ( HRESULT (*)( PVOID, PVOID ) ) WarbirdSegmentEncrypt3 )( g_EncryptedSegmentConstData_3, g_EncryptedSegmentReadWriteData_3 );

		Log( "[!] Failed to allocate MDL!\n" );
		return FALSE;
	}

	MmProbeAndLockPages( mdl, KernelMode, IoModifyAccess );

	PVOID Dest = MmGetSystemAddressForMdlSafe( mdl, NormalPagePriority );
	if ( Dest == NULL )
	{
		MmUnlockPages( mdl );
		IoFreeMdl( mdl );
		( ( HRESULT (*)( PVOID, PVOID ) ) WarbirdSegmentEncrypt4 )( g_EncryptedSegmentConstData_4, g_EncryptedSegmentReadWriteData_4 );
		( ( HRESULT (*)( PVOID, PVOID ) ) WarbirdSegmentEncrypt3 )( g_EncryptedSegmentConstData_3, g_EncryptedSegmentReadWriteData_3 );

		Log( "[!] Failed to remap pages!\n" );
		return FALSE;
	}

	MmProtectMdlSystemAddress( mdl, PAGE_READWRITE );

	// when unpacked, the code should look like:
	// mov rax, SpIsAppLicensed_hk
	// jmp rax
	memcpy( Dest, ( PVOID ) "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xE0", 12 );
	*( ULONG64* ) (( ULONG64 ) Dest + 2) = (ULONG64) SpIsAppLicensed_hk;
	*( ULONG32* ) (( ULONG64 ) Dest + 10) = ( ULONG32 ) 0xFFE0FFE0;

	MmProtectMdlSystemAddress( mdl, PAGE_READONLY );

	MmUnmapLockedPages( Dest, mdl );
	MmUnlockPages( mdl );
	IoFreeMdl( mdl );

	Log( "[+] AFTER INJECTING: SpIsAppLicensed (val) => %llx\n", *( ULONG64* ) SpIsAppLicensed );

	// re-encrypt the page and optionally restore function pointer from g_kernelCallbacks
	( (HRESULT (*)( PVOID, PVOID ) ) WarbirdSegmentEncrypt4 ) ( g_EncryptedSegmentConstData_4, g_EncryptedSegmentReadWriteData_4 );
	( (HRESULT (*)( PVOID, PVOID ) ) WarbirdSegmentEncrypt3 ) ( g_EncryptedSegmentConstData_3, g_EncryptedSegmentReadWriteData_3 );

	Log( "[+] AFTER ENCRYPTING: SpIsAppLicensed (val) => %llx\n", *( ULONG64* ) SpIsAppLicensed );

	*( ULONG64* ) (( ULONG64 ) ntbase + 0xD2D3F8) = ClipSpIsAppLicensed_o;

	return Status;
}