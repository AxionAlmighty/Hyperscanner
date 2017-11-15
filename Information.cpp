#include "Information.h"

using namespace Hyperscan;

BOOL HYPERSCAN_CHECK::IsHandleValid(HANDLE ProcessHandle)
{
	if (NULL == ProcessHandle || INVALID_HANDLE_VALUE == ProcessHandle)
	{
		return FALSE;
	}

	DWORD HandleInformation;

	if (TRUE == GetHandleInformation(ProcessHandle, &HandleInformation))
	{
		return TRUE;
	}

	return FALSE;
}

BOOL HYPERSCAN_CHECK::IsProcess64Bit(HANDLE ProcessHandle)
{
	if (NULL == ProcessHandle || INVALID_HANDLE_VALUE == ProcessHandle)
	{
		return FALSE;
	}

	if (TRUE == HYPERSCAN_CHECK::IsHandleValid(ProcessHandle))
	{
		BOOL CheckResult = FALSE;

		if (TRUE == IsWow64Process(ProcessHandle, &CheckResult))
		{
			return CheckResult;
		}

		return FALSE;
	}

	return FALSE;
}

struct SECTION_INFO
{
	WORD Length;
	WORD MaximumLength;
	wchar_t * DataBuffer;
	BYTE Data[MAX_PATH * 2];
};

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI * hsNtQueryVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID Buffer, SIZE_T Length, PSIZE_T ResultLength
	);

#define NT_SUCCESS(Status) ((Status) >= 0)

BOOL HYPERSCAN_CHECK::IsAddressStatic(DWORD ProcessID, BYTE * &Address)
{
	if (NULL == ProcessID || nullptr == Address)
	{
		return FALSE;
	}

	LPVOID QueryVirtualMemoryAddress = GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtQueryVirtualMemory");

	if (nullptr == QueryVirtualMemoryAddress)
	{
		return FALSE;
	}

	hsNtQueryVirtualMemory QueryVirtualMemory = reinterpret_cast<hsNtQueryVirtualMemory>(QueryVirtualMemoryAddress);

	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

	if (FALSE == HYPERSCAN_CHECK::IsHandleValid(ProcessHandle))
	{
		return FALSE;
	}

	SECTION_INFO SectionInformation;

	NTSTATUS ReturnStatus = QueryVirtualMemory(ProcessHandle, Address, MemoryMappedFilenameInformation, &SectionInformation, sizeof(SectionInformation), nullptr);

	if (!NT_SUCCESS(ReturnStatus))
	{
		CloseHandle(ProcessHandle);
		return FALSE;
	}

	wchar_t * DeviceName = SectionInformation.DataBuffer;
	wchar_t * FilePath = DeviceName;

	while (*(FilePath++) != '\\');
	while (*(FilePath++) != '\\');
	while (*(FilePath++) != '\\');
	*(FilePath - 1) = 0;

	wchar_t * DriveLetters = new wchar_t[MAX_PATH + 1];
	auto DriveSize = GetLogicalDriveStringsW(MAX_PATH, DriveLetters);

	if (DriveSize > MAX_PATH)
	{
		delete[] DriveLetters;
		DriveLetters = new wchar_t[DriveSize + 1];
		DriveSize = GetLogicalDriveStringsW(DriveSize, DriveLetters);
	}

	for (int i = 0; i != DriveSize / 4; ++i)
	{
		DriveLetters[i * 4 + 2] = 0;
		wchar_t Buffer[64]{ 0 };

		QueryDosDeviceW(&DriveLetters[i * 4], Buffer, sizeof(Buffer));

		if (!wcscmp(Buffer, DeviceName))
		{
			FilePath -= 3;
			FilePath[2] = '\\';
			FilePath[1] = ':';
			FilePath[0] = DriveLetters[i * 4];

			delete[] DriveLetters;

			BYTE * Ret = reinterpret_cast<BYTE*>(GetModuleHandleW(FilePath));

			if (nullptr == Ret)
			{
				CloseHandle(ProcessHandle);
				return FALSE;
			}

			Address = Ret;

			CloseHandle(ProcessHandle);
			return TRUE;
		}
	}

	delete[] DriveLetters;
	CloseHandle(ProcessHandle);

	return FALSE;
}

HANDLE HYPERSCAN_INFORMATION::MapFile(const std::wstring & PathToFile)
{
	HANDLE FileHandle = CreateFileW(PathToFile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (INVALID_HANDLE_VALUE == FileHandle)
	{
		return nullptr;
	}

	HANDLE MapHandle = CreateFileMappingW(FileHandle, NULL, PAGE_READONLY, NULL, NULL, NULL);

	if (INVALID_HANDLE_VALUE == MapHandle)
	{
		CloseHandle(FileHandle);
		return nullptr;
	}

	HANDLE FileBase = MapViewOfFile(MapHandle, FILE_MAP_READ, NULL, NULL, NULL);

	if (nullptr == FileBase)
	{
		CloseHandle(FileHandle);
		CloseHandle(MapHandle);
		return nullptr;
	}

	return FileBase;
}

IMAGE_DOS_HEADER * HYPERSCAN_INFORMATION::GetDosHeader(HANDLE FileBase)
{
	if (nullptr == FileBase)
	{
		return nullptr;
	}

	IMAGE_DOS_HEADER * DosHeader;
	DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(FileBase);

	if (nullptr == DosHeader)
	{
		return nullptr;
	}

	return DosHeader;
}

IMAGE_NT_HEADERS32 * HYPERSCAN_INFORMATION::GetNtHeader86(IMAGE_DOS_HEADER * DosHeader)
{
	if (nullptr == DosHeader)
	{
		return nullptr;
	}

	IMAGE_NT_HEADERS32 * NtHeader;
	NtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(reinterpret_cast<DWORD>(DosHeader) + (DosHeader->e_lfanew));

	if (nullptr == NtHeader)
	{
		return nullptr;
	}

	return NtHeader;
}

IMAGE_NT_HEADERS64 * HYPERSCAN_INFORMATION::GetNtHeader64(IMAGE_DOS_HEADER * DosHeader)
{
	if (nullptr == DosHeader)
	{
		return nullptr;
	}

	IMAGE_NT_HEADERS64 * NtHeader;
	NtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<DWORD>(DosHeader) + (DosHeader->e_lfanew));

	if (nullptr == NtHeader)
	{
		return nullptr;
	}

	return NtHeader;
}

IMAGE_FILE_HEADER HYPERSCAN_INFORMATION::GetFileHeader(IMAGE_NT_HEADERS32 * NtHeader)
{
	if (nullptr == NtHeader)
	{
		return *reinterpret_cast<IMAGE_FILE_HEADER*>(NULL);
	}

	IMAGE_FILE_HEADER FileHeader;
	FileHeader = NtHeader->FileHeader;

	return FileHeader;
}

IMAGE_FILE_HEADER HYPERSCAN_INFORMATION::GetFileHeader(IMAGE_NT_HEADERS64 * NtHeader)
{
	if (nullptr == NtHeader)
	{
		return *reinterpret_cast<IMAGE_FILE_HEADER*>(NULL);
	}

	IMAGE_FILE_HEADER FileHeader;
	FileHeader = NtHeader->FileHeader;

	return FileHeader;
}

IMAGE_OPTIONAL_HEADER32 HYPERSCAN_INFORMATION::GetOptionalHeader86(IMAGE_NT_HEADERS32 * NtHeader)
{
	if (nullptr == NtHeader)
	{
		return *reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(NULL);
	}

	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
	OptionalHeader = NtHeader->OptionalHeader;

	return OptionalHeader;
}

IMAGE_OPTIONAL_HEADER64 HYPERSCAN_INFORMATION::GetOptionalHeader64(IMAGE_NT_HEADERS64 * NtHeader)
{
	if (nullptr == NtHeader)
	{
		return *reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(NULL);
	}

	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
	OptionalHeader = NtHeader->OptionalHeader;

	return OptionalHeader;
}