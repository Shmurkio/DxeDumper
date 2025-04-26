#pragma warning(disable : 4201)
#pragma warning(disable : 4083)
#pragma warning(disable : 4005)

#pragma once

#include <ntddk.h>
#include <cstdint>

#define HOOK_JUMP_BACKUP(BackupName) \
    uint8_t gOrig##BackupName[12]

extern "C" PLIST_ENTRY PsLoadedModuleList;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BITS(x) (IN_RANGE((x&(~0x20)),'A','F')?((x&(~0x20))-'A'+0xA):(IN_RANGE(x,'0','9')?x-'0':0))
#define GET_BYTE(a, b) (GET_BITS(a) << 4 | GET_BITS(b))

#define IMAGE_DOS_SIGNATURE 0x5A4D  // 'MZ' signature
#define IMAGE_NT_SIGNATURE  0x00004550  // 'PE\0\0' signature

// IMAGE_DOS_HEADER definition (for the DOS stub)
typedef struct _IMAGE_DOS_HEADER {
    uint16_t e_magic;           // Magic number (0x5A4D == 'MZ')
    uint16_t e_cblp;            // Bytes on last page of file
    uint16_t e_cp;              // Pages in file
    uint16_t e_crlc;            // Relocations
    uint16_t e_cparhdr;         // Size of header in paragraphs
    uint16_t e_minalloc;        // Minimum extra paragraphs needed
    uint16_t e_maxalloc;        // Maximum extra paragraphs needed
    uint16_t e_ss;              // Initial SS value
    uint16_t e_sp;              // Initial SP value
    uint16_t e_csum;            // Checksum
    uint16_t e_ip;              // Initial IP value
    uint16_t e_cs;              // Initial CS value
    uint16_t e_lfarlc;          // File address of relocation table
    uint16_t e_ovno;            // Overlay number
    uint16_t e_res[4];          // Reserved words
    uint16_t e_oemid;           // OEM identifier
    uint16_t e_oeminfo;         // OEM information
    uint16_t e_res2[10];        // Reserved words
    uint32_t e_lfanew;          // File address of new exe header
} IMAGE_DOS_HEADER;

// IMAGE_FILE_HEADER definition (common for both 32-bit and 64-bit headers)
typedef struct _IMAGE_FILE_HEADER {
    uint16_t Machine;           // The architecture type (e.g., IMAGE_FILE_MACHINE_AMD64)
    uint16_t NumberOfSections;  // Number of sections in the PE file
    uint32_t TimeDateStamp;     // Time and date the file was created
    uint32_t PointerToSymbolTable;  // Pointer to symbol table (optional)
    uint32_t NumberOfSymbols;   // Number of symbols in the symbol table (optional)
    uint16_t SizeOfOptionalHeader;  // Size of the optional header
    uint16_t Characteristics;   // File characteristics (e.g., executable, system file)
} IMAGE_FILE_HEADER;

// IMAGE_OPTIONAL_HEADER64 definition (64-bit specific)
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;                  // Magic number (e.g., 0x20b for 64-bit)
    uint8_t MajorLinkerVersion;      // Major version of the linker
    uint8_t MinorLinkerVersion;      // Minor version of the linker
    uint32_t SizeOfCode;             // Size of the code section
    uint32_t SizeOfInitializedData;  // Size of initialized data
    uint32_t SizeOfUninitializedData;// Size of uninitialized data
    uint32_t AddressOfEntryPoint;    // Address of entry point function
    uint32_t BaseOfCode;             // Base address of the code section
    uint64_t ImageBase;              // Preferred load address of the image
    uint32_t SectionAlignment;       // Alignment of sections in memory
    uint32_t FileAlignment;          // Alignment of sections in the file
    uint16_t MajorOperatingSystemVersion; // OS version number
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;            // Size of the image
    uint32_t SizeOfHeaders;          // Size of the headers
    uint32_t CheckSum;               // Image checksum
    uint16_t Subsystem;              // Subsystem type (e.g., IMAGE_SUBSYSTEM_WINDOWS_CUI)
    uint16_t DllCharacteristics;     // DLL characteristics (e.g., IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    uint64_t SizeOfStackReserve;     // Size of stack reserved
    uint64_t SizeOfStackCommit;      // Size of stack committed
    uint64_t SizeOfHeapReserve;      // Size of heap reserved
    uint64_t SizeOfHeapCommit;       // Size of heap committed
    uint32_t LoaderFlags;            // Loader flags (optional)
    uint32_t NumberOfRvaAndSizes;    // Number of data directory entries
    // Data directories are stored after this structure
} IMAGE_OPTIONAL_HEADER64;

// IMAGE_NT_HEADERS64 definition (combines both IMAGE_FILE_HEADER and IMAGE_OPTIONAL_HEADER64)
typedef struct _IMAGE_NT_HEADERS64 {
    uint32_t Signature;                // 'PE\0\0' signature
    IMAGE_FILE_HEADER FileHeader;      // Common file header
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;  // Optional header for 64-bit
} IMAGE_NT_HEADERS64;

namespace Util
{
    template<typename T>
    NTSTATUS
    FindPattern(
        void* BaseAddress,
        uint64_t Size,
        const char* Pattern,
        T& Out
    )
    {
        uint8_t* FirstMatch = nullptr;
        const char* CurrentPattern = Pattern;
        uint8_t* Start = static_cast<uint8_t*>(BaseAddress);
        uint8_t* End = Start + Size;

        for (uint8_t* Current = Start; Current < End; ++Current)
        {
            uint8_t Byte = CurrentPattern[0];

            if (!Byte)
            {
                Out = reinterpret_cast<T>(FirstMatch);
                return STATUS_SUCCESS;
            }

            if (Byte == '\?' || *Current == GET_BYTE(Byte, CurrentPattern[1]))
            {
                if (!FirstMatch)
                    FirstMatch = Current;

                if (!CurrentPattern[2])
                {
                    Out = reinterpret_cast<T>(FirstMatch);
                    return STATUS_SUCCESS;
                }

                if (Byte == '\?')
                    CurrentPattern += 2;
                else
                    CurrentPattern += 3;
            }
            else
            {
                CurrentPattern = Pattern;
                FirstMatch = nullptr;
            }
        }

        Out = 0ULL;
        return STATUS_NOT_FOUND;
    }

    NTSTATUS
    GetModuleByName(
        _In_ const char* ModuleName,
        _Out_ PLDR_DATA_TABLE_ENTRY& Module
    );

    template<typename T>
    T
    ReadPhysicalMemory(
        _In_ void* Address
    )
    {
        PHYSICAL_ADDRESS PhysicalAddress;
        PhysicalAddress.QuadPart = reinterpret_cast<LONGLONG>(Address);

        T Value{};
        size_t Size = sizeof(T);

        void* Mapped = MmMapIoSpace(PhysicalAddress, Size, MmNonCached);

        if (Mapped)
        {
            Value = *reinterpret_cast<T*>(Mapped);
            MmUnmapIoSpace(Mapped, Size);
        }

        return Value;
    }

    uint16_t
    SwitchEndianness16(
        uint16_t Value
    );

    uint32_t
    SwitchEndianness32(
        uint32_t Value
    );

    uint64_t
    SwitchEndianness64(
        uint64_t Value
    );

    template<typename T>
    NTSTATUS
    GetImageBase(
        _In_ T Address,
        _Out_ T& ImageBase
    )
    {
        if (reinterpret_cast<uint64_t>(Address) < PAGE_SIZE)
        {
            ImageBase = nullptr;
            return STATUS_INVALID_PARAMETER;
        }

        uint64_t AddressVal = reinterpret_cast<uint64_t>(Address);
        AddressVal &= ~(PAGE_SIZE - 1);

        while (AddressVal >= PAGE_SIZE)
        {
            IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(AddressVal);

            if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
            {
                if (DosHeader->e_lfanew >= sizeof(IMAGE_DOS_HEADER) && DosHeader->e_lfanew < 1024)
                {
                    IMAGE_NT_HEADERS64* PeHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(AddressVal + DosHeader->e_lfanew);

                    if (PeHeader->Signature == IMAGE_NT_SIGNATURE)
                    {
                        ImageBase = reinterpret_cast<T*>(AddressVal);
                        return STATUS_SUCCESS;
                    }
                }
            }

            AddressVal -= PAGE_SIZE;
        }

        ImageBase = nullptr;
        return STATUS_NOT_FOUND;
    }

    NTSTATUS
    GetImageSize(
        _In_ void* ImageBase,
        _Out_ size_t& ImageSize
    );

    NTSTATUS
    HookJump(
        _In_ void* Address,
        _In_ void* JumpTo
    );

    NTSTATUS
    HookJumpBackup(
        _In_ void* Address,
        _In_ uint8_t(&Backup)[12]
    );

    NTSTATUS
    UnhookJump(
        _In_ void* Address,
        _In_ uint8_t* Backup
    );

    NTSTATUS
    DumpMemoryToFile(
        _In_ void* Address,
        _In_ size_t Size,
        _In_ const wchar_t* Path
    );
}