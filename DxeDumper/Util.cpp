#include "Util.hpp"

NTSTATUS
Util::GetModuleByName(
    _In_ const char* ModuleName,
    _Out_ PLDR_DATA_TABLE_ENTRY& Module
)
{
    ANSI_STRING AnsiString;
    UNICODE_STRING UnicodeString;

    RtlInitAnsiString(&AnsiString, ModuleName);

    NTSTATUS Status = RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    PLIST_ENTRY List = PsLoadedModuleList;
    PLIST_ENTRY Current = List->Flink;

    while (Current != List)
    {
        PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(Current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (RtlCompareUnicodeString(&UnicodeString, &Entry->BaseDllName, TRUE) == 0)
        {
            RtlFreeUnicodeString(&UnicodeString);
            Module = Entry;
            return STATUS_SUCCESS;
        }

        Current = Current->Flink;
    }

    RtlFreeUnicodeString(&UnicodeString);
    Module = nullptr;
    return STATUS_NOT_FOUND;
}

uint32_t
Util::SwitchEndianness32(
    uint32_t Value
)
{
    return ((Value >> 24) & 0x000000FF) |
        ((Value >> 8) & 0x0000FF00) |
        ((Value << 8) & 0x00FF0000) |
        ((Value << 24) & 0xFF000000);
}

uint16_t
Util::SwitchEndianness16(
    uint16_t Value
)
{
    return (Value >> 8) | (Value << 8);
}

uint64_t
Util::SwitchEndianness64(
    uint64_t Value
)
{
    return ((Value >> 56) & 0x00000000000000FF) |
        ((Value >> 40) & 0x000000000000FF00) |
        ((Value >> 24) & 0x0000000000FF0000) |
        ((Value >> 8) & 0x00000000FF000000) |
        ((Value << 8) & 0x000000FF00000000) |
        ((Value << 24) & 0x0000FF0000000000) |
        ((Value << 40) & 0x00FF000000000000) |
        ((Value << 56) & 0xFF00000000000000);
}

NTSTATUS
Util::GetImageSize(
    _In_ void* ImageBase,
    _Out_ size_t& ImageSize
)
{
    if (!ImageBase)
    {
        ImageSize = 0;
        return STATUS_INVALID_PARAMETER;
    }

    IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ImageBase);

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ImageSize = 0;
        return STATUS_INVALID_PARAMETER;
    }

    IMAGE_NT_HEADERS64* NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<uint64_t>(ImageBase) + DosHeader->e_lfanew);

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        ImageSize = 0;
        return STATUS_INVALID_PARAMETER;
    }

    ImageSize = NtHeaders->OptionalHeader.SizeOfImage;
    return STATUS_SUCCESS;
}

NTSTATUS
Util::HookJump(
    _In_ void* Address,
    _In_ void* JumpTo
)
{
    if (!Address || !JumpTo)
    {
        return STATUS_INVALID_PARAMETER;
    }

    uint8_t MachineCode[] =
    {
        //
        // MOV RAX, Pointer
        //
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        //
        // JMP RAX
        //
        0xFF, 0xE0
    };

    *reinterpret_cast<uint64_t*>(&MachineCode[2]) = reinterpret_cast<uint64_t>(JumpTo);

    RtlCopyMemory(Address, MachineCode, sizeof(MachineCode));

    if (RtlCompareMemory(Address, MachineCode, sizeof(MachineCode)) != sizeof(MachineCode))
    {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
Util::HookJumpBackup(
    _In_ void* Address,
    _In_ uint8_t(&Backup)[12]
)
{
    if (!Address || !Backup)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(Backup, Address, sizeof(Backup));

    if (RtlCompareMemory(Address, Backup, sizeof(Backup)) != sizeof(Backup))
    {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
Util::UnhookJump(
    _In_ void* Address,
    _In_ uint8_t* Backup
)
{
    if (!Address || !Backup)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(Address, Backup, 12);

    if (RtlCompareMemory(Address, Backup, 12) != sizeof(Backup))
    {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
Util::DumpMemoryToFile(
    _In_ void* Address,
    _In_ size_t Size,
    _In_ const wchar_t* Path
)
{
    UNICODE_STRING FilePath;
    RtlInitUnicodeString(&FilePath, Path);

    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle;

    InitializeObjectAttributes(&ObjectAttributes, &FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    NTSTATUS Status = ZwCreateFile(&FileHandle, GENERIC_WRITE, &ObjectAttributes, &IoStatusBlock, nullptr, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = ZwWriteFile(FileHandle,  nullptr, nullptr, nullptr, &IoStatusBlock, Address, static_cast<ULONG>(Size), nullptr, nullptr);

    ZwClose(FileHandle);
    return Status;
}