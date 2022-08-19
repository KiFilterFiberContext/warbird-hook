#pragma once

#include <string.h>

extern "C" void __forceinline KiSwInterrupt( );

extern "C" 
NTKERNELAPI
PVOID RtlPcToFileHeader(
    PVOID PcValue,
    PVOID * BaseOfImage
);

// from TitanHide
void Log( const char* format, ... )
{
    char msg[ 1024 ] = "";
    va_list vl;
    va_start( vl, format );
    const int n = _vsnprintf( msg, sizeof( msg ) / sizeof( char ), format, vl );
    msg[ n ] = '\0';
    va_end( vl );

    va_end( format );
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES objAttr;
    RtlInitUnicodeString( &FileName, L"\\??\\C:\\loggy.log" );
    InitializeObjectAttributes( &objAttr, &FileName,
        OBJ_CASE_INSENSITIVE,
        NULL, NULL );
    if ( KeGetCurrentIrql( ) != PASSIVE_LEVEL )
    {
        return;
    }

    HANDLE handle;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS ntstatus = ZwCreateFile( &handle,
        FILE_APPEND_DATA,
        &objAttr, &ioStatusBlock, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_WRITE | FILE_SHARE_READ,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0 );
    if ( NT_SUCCESS( ntstatus ) )
    {
        size_t cb;
        ntstatus = RtlStringCbLengthA( msg, sizeof( msg ), &cb );
        if ( NT_SUCCESS( ntstatus ) )
            ZwWriteFile( handle, NULL, NULL, NULL, &ioStatusBlock, msg, ( ULONG ) cb, NULL, NULL );
        ZwClose( handle );
    }
}

// from Kernel-Bridge

// pattern = "\x11\x22\x00\x33\x00\x00\x44"
// mask = "..?.??."
// finds 0x11 0x22 ?? 0x33 ?? ?? 0x44, where ?? is any byte.
void* find_signature( void* memory, size_t size, const char* pattern, const char* mask )
{
    size_t sig_length = strlen( mask );
    if ( sig_length > size ) return nullptr;

    for ( size_t i = 0; i < size - sig_length; i++ )
    {
        bool found = true;
        for ( size_t j = 0; j < sig_length; j++ )
            found &= mask[ j ] == '?' || pattern[ j ] == *(( char* ) memory + i + j);

        if ( found )
            return ( char* ) memory + i;
    }
    return nullptr;
}