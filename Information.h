#pragma once
#include <windows.h>
#include <string>

namespace Hyperscan
{
	typedef class HYPERSCAN_CHECK
	{
	public: static BOOL IsHandleValid(HANDLE ProcessHandle);

	public: static BOOL IsProcess64Bit(HANDLE ProcessHandle);

	public: static BOOL IsAddressStatic(DWORD ProcessID, BYTE * &Address);
	} *PHYPERSCAN_CHECK;

	typedef class HYPERSCAN_INFORMATION
	{
		static HANDLE MapFile(const std::wstring & PathToFile);

		static IMAGE_DOS_HEADER * GetDosHeader(HANDLE FileBase);

		static IMAGE_NT_HEADERS32 * GetNtHeader86(IMAGE_DOS_HEADER * DosHeader);

		static IMAGE_NT_HEADERS64 * GetNtHeader64(IMAGE_DOS_HEADER * DosHeader);

		static IMAGE_FILE_HEADER GetFileHeader(IMAGE_NT_HEADERS32 * NtHeader);

		static IMAGE_FILE_HEADER GetFileHeader(IMAGE_NT_HEADERS64 * NtHeader);

		static IMAGE_OPTIONAL_HEADER32 GetOptionalHeader86(IMAGE_NT_HEADERS32 * NtHeader);

		static IMAGE_OPTIONAL_HEADER64 GetOptionalHeader64(IMAGE_NT_HEADERS64 * NtHeader);
	} *PHYPERSCAN_INFORMATION;
}