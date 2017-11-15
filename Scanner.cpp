#include "Scanner.h"
#include "Information.h"
#include <assert.h>
#include <algorithm>
#include <Tlhelp32.h>

using namespace Hyperscan;

std::vector<UINT_PTR> HYPERSCAN_SCANNER::ScanModulesCallback(DWORD ProcessID, UINT_PTR ModuleBaseAddress, UINT_PTR ModuleSize, INT ScanValue,
	ScanAllignment AllignmentOfScan, ScanType TypeOfScan)
{
	std::vector<UINT_PTR> AddressHolder;
	AddressHolder.clear();

	if (NULL == ProcessID || NULL == ModuleBaseAddress || NULL == ModuleSize || NULL == AllignmentOfScan 
		|| NULL == TypeOfScan)
	{
		return AddressHolder;
	}

	_MEMORY_BASIC_INFORMATION BasicInformation;
	UINT_PTR AddressForScan = ModuleBaseAddress;
	HANDLE QueryHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

#ifndef _WIN64
	if (TRUE == Hyperscan::HYPERSCAN_CHECK::IsProcess64Bit(QueryHandle))
	{
		assert("Incompatibility in architectures!");
	}
#endif


	if (INVALID_HANDLE_VALUE == QueryHandle)
	{
		return AddressHolder;
	}

	while (VirtualQueryEx(QueryHandle, reinterpret_cast<VOID*>(AddressForScan), &BasicInformation, sizeof(BasicInformation))
		&& AddressForScan < (ModuleBaseAddress + ModuleSize))
	{
		if ((BasicInformation.State & MEM_COMMIT))
		{
			UCHAR * MemoryBlock = new UCHAR[BasicInformation.RegionSize];
			if (ReadProcessMemory(QueryHandle, reinterpret_cast<VOID*>(AddressForScan), MemoryBlock, BasicInformation.RegionSize,
				nullptr))
			{
				for (unsigned int scanIndex = 0; scanIndex != BasicInformation.RegionSize / AllignmentOfScan; ++scanIndex)
				{
					if (HyperscanTypeAll == TypeOfScan)
					{
						AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
					}
					else if (HyperscanTypeExact == TypeOfScan)
					{
						if (*reinterpret_cast<INT*>(MemoryBlock + scanIndex * AllignmentOfScan) == ScanValue)
						{
							AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
						}
					}
					else if (HyperscanTypeSmaller == TypeOfScan)
					{
						if (*reinterpret_cast<INT*>(MemoryBlock + scanIndex * AllignmentOfScan) < ScanValue)
						{
							AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
						}
					}
					else if (HyperscanTypeBigger == TypeOfScan)
					{
						if (*reinterpret_cast<INT*>(MemoryBlock + scanIndex * AllignmentOfScan) > ScanValue)
						{
							AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
						}
					}
					else if (HyperscanTypeDifferent == TypeOfScan)
					{
						if (*reinterpret_cast<INT*>(MemoryBlock + scanIndex * AllignmentOfScan) != ScanValue)
						{
							AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
						}
					}
					else
					{
						if (*reinterpret_cast<INT*>(MemoryBlock + scanIndex * AllignmentOfScan) == ScanValue)
						{
							AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
						}
					}
				}
			}
	 		delete[] MemoryBlock;
		}
		AddressForScan = reinterpret_cast<UINT_PTR>(BasicInformation.BaseAddress) + BasicInformation.RegionSize;
	}

	CloseHandle(QueryHandle);
	return AddressHolder;
}

std::vector<UINT_PTR> HYPERSCAN_SCANNER::ScanModules(DWORD ProcessID, INT ScanValue, ScanAllignment AllignmentOfScan,
	ScanType TypeOfScan)
{
	std::vector<UINT_PTR> AddressHolder;
	AddressHolder.clear();

	if (NULL == ProcessID || NULL == AllignmentOfScan || NULL == TypeOfScan)
	{
		return AddressHolder;
	}

	HANDLE ModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessID);

	if (INVALID_HANDLE_VALUE == ModuleSnapshot)
	{
		return AddressHolder;
	}

	MODULEENTRY32 ModuleEntry;
	ModuleEntry.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(ModuleSnapshot, &ModuleEntry))
	{
		do
		{
			std::vector<UINT_PTR> TemporaryAddressHolder;
			TemporaryAddressHolder.clear();

			TemporaryAddressHolder = ScanModulesCallback(ProcessID, reinterpret_cast<UINT_PTR>(ModuleEntry.modBaseAddr), ModuleEntry.modBaseSize,
				ScanValue, AllignmentOfScan, TypeOfScan);

			AddressHolder.insert(AddressHolder.end(), TemporaryAddressHolder.begin(), TemporaryAddressHolder.end());
		} while (Module32Next(ModuleSnapshot, &ModuleEntry));
	}

	CloseHandle(ModuleSnapshot);
	return AddressHolder;
}

std::vector<UINT_PTR> HYPERSCAN_SCANNER::ScanWholeMemoryWithDelimiters(DWORD ProcessID, INT ScanValue, ScanAllignment AllignmentOfScan,
	ScanType TypeOfScan, DWORD BeginAddress, DWORD EndAddress)
{
	std::vector<UINT_PTR> AddressHolder;
	AddressHolder.clear();

	if (NULL == ProcessID || NULL == EndAddress || NULL == AllignmentOfScan || NULL == TypeOfScan)
	{
		return AddressHolder;
	}

	_MEMORY_BASIC_INFORMATION BasicInformation;
	UINT_PTR AddressForScan = BeginAddress;
	HANDLE QueryHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

#ifndef _WIN64
	if (TRUE == HYPERSCAN_CHECK::IsProcess64Bit(QueryHandle))
	{
		assert("Incompatibility in architectures!");
	}
#endif

	if (INVALID_HANDLE_VALUE == QueryHandle)
	{
		return AddressHolder;
	}

	while (VirtualQueryEx(QueryHandle, reinterpret_cast<VOID*>(AddressForScan), &BasicInformation, sizeof(BasicInformation))
		&& AddressForScan < EndAddress)
	{
		if ((BasicInformation.State & MEM_COMMIT))
		{
			UCHAR * MemoryBlock = new UCHAR[BasicInformation.RegionSize];
			if (ReadProcessMemory(QueryHandle, reinterpret_cast<VOID*>(AddressForScan), MemoryBlock, BasicInformation.RegionSize,
				nullptr))
			{
				for (unsigned int scanIndex = 0; scanIndex != BasicInformation.RegionSize / AllignmentOfScan; ++scanIndex)
				{
					if (HyperscanTypeAll == TypeOfScan)
					{
						AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
					}
					else if (HyperscanTypeExact == TypeOfScan)
					{
						if (*reinterpret_cast<INT*>(MemoryBlock + scanIndex * AllignmentOfScan) == ScanValue)
						{
							AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
						}
					}
					else if (HyperscanTypeSmaller == TypeOfScan)
					{
						if (*reinterpret_cast<INT*>(MemoryBlock + scanIndex * AllignmentOfScan) < ScanValue)
						{
							AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
						}
					}
					else if (HyperscanTypeBigger == TypeOfScan)
					{
						if (*reinterpret_cast<INT*>(MemoryBlock + scanIndex * AllignmentOfScan) > ScanValue)
						{
							AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
						}
					}
					else if (HyperscanTypeDifferent == TypeOfScan)
					{
						if (*reinterpret_cast<INT*>(MemoryBlock + scanIndex * AllignmentOfScan) != ScanValue)
						{
							AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
						}
					}
					else
					{
						if (*reinterpret_cast<INT*>(MemoryBlock + scanIndex * AllignmentOfScan) == ScanValue)
						{
							AddressHolder.push_back(AddressForScan + scanIndex * AllignmentOfScan);
						}
					}
				}
			}
			delete[] MemoryBlock;
		}
		AddressForScan = reinterpret_cast<UINT_PTR>(BasicInformation.BaseAddress) + BasicInformation.RegionSize;
	}

	CloseHandle(QueryHandle);
	return AddressHolder;
}

std::vector<UINT_PTR> HYPERSCAN_SCANNER::Scan(DWORD ProcessID, INT ScanValue, ScanAllignment AllignmentOfScan, ScanType TypeOfScan)
{
	std::vector<UINT_PTR> AddressHolder;
	AddressHolder.clear();

	if (NULL == ProcessID || NULL == AllignmentOfScan || NULL == TypeOfScan)
	{
		return AddressHolder;
	}

	std::vector<UINT_PTR> ModuleScan;
	ModuleScan.clear();

	std::vector<UINT_PTR> MemoryScan;
	MemoryScan.clear();

	ModuleScan = HYPERSCAN_SCANNER::ScanModules(ProcessID, ScanValue, AllignmentOfScan, TypeOfScan);
	MemoryScan = HYPERSCAN_SCANNER::ScanWholeMemoryWithDelimiters(ProcessID, ScanValue, AllignmentOfScan, TypeOfScan);

	AddressHolder.insert(AddressHolder.end(), ModuleScan.begin(), ModuleScan.end());
	AddressHolder.insert(AddressHolder.end(), MemoryScan.begin(), MemoryScan.end());

	return AddressHolder;
}

std::vector<UINT_PTR> HYPERSCAN_SCANNER::ScanString(DWORD ProcessID, const std::string & String, UINT_PTR StringSize, BOOL IsUnicode,
	BOOL CaseSensitive, DWORD BeginAddress, DWORD EndAddress)
{
	std::vector<UINT_PTR> AddressHolder;
	AddressHolder.clear();

	if (NULL == ProcessID || NULL == EndAddress || NULL == EndAddress || NULL == StringSize || String.empty())
	{
		return AddressHolder;
	}

	std::string NormalString = String;
	std::wstring UnicodeString(NormalString.begin(), NormalString.end());

	_MEMORY_BASIC_INFORMATION BasicInformation;
	UINT_PTR AddressForScan = BeginAddress;
	HANDLE QueryHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

#ifndef _WIN64
	if (TRUE == HYPERSCAN_CHECK::IsProcess64Bit(QueryHandle))
	{
		assert("Incompatibility in architectures!");
	}
#endif

	if (INVALID_HANDLE_VALUE == QueryHandle)
	{
		return AddressHolder;
	}

	while (VirtualQueryEx(QueryHandle, reinterpret_cast<VOID*>(AddressForScan), &BasicInformation, sizeof(BasicInformation))
		&& AddressForScan < EndAddress)
	{
		if ((BasicInformation.State & MEM_COMMIT))
		{
			UCHAR * MemoryBlock = new UCHAR[BasicInformation.RegionSize];
			if (ReadProcessMemory(QueryHandle, reinterpret_cast<VOID*>(AddressForScan), MemoryBlock, BasicInformation.RegionSize,
				nullptr))
			{
				for (unsigned int scanIndex = 0; scanIndex != BasicInformation.RegionSize / HyperscanAllignmentString; ++scanIndex)
				{
					if (TRUE == IsUnicode)
					{
						if (FALSE == (wmemcmp(UnicodeString.c_str(), reinterpret_cast<wchar_t*>(&MemoryBlock[scanIndex]), StringSize)))
						{
							AddressHolder.push_back(AddressForScan + scanIndex);
						}
					}
					else if (FALSE == IsUnicode)
					{
						if (FALSE == (memcmp(NormalString.c_str(), reinterpret_cast<char*>(&MemoryBlock[scanIndex]), StringSize)))
						{
							AddressHolder.push_back(AddressForScan + scanIndex);
						}
					}
					else
					{
						if (FALSE == (memcmp(NormalString.c_str(), reinterpret_cast<char*>(&MemoryBlock[scanIndex]), StringSize)))
						{
							AddressHolder.push_back(AddressForScan + scanIndex);
						}
					}
				}
			}
			delete[] MemoryBlock;
		}
		AddressForScan = reinterpret_cast<UINT_PTR>(BasicInformation.BaseAddress) + BasicInformation.RegionSize;
	}

	CloseHandle(QueryHandle);
	return AddressHolder;
}

DWORD HYPERSCAN_PROCESS::GrabId(const std::wstring & ProcessName)
{
	if (ProcessName.empty())
	{
		return NULL;
	}

	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32FirstW(Snapshot, &ProcessEntry) == TRUE)
	{
		while (Process32NextW(Snapshot, &ProcessEntry) == TRUE)
		{
			if (wcsicmp(ProcessEntry.szExeFile, ProcessName.c_str()) == 0)
			{
				DWORD ProcessID = ProcessEntry.th32ProcessID;
				CloseHandle(Snapshot);

				return ProcessID;
			}
		}
	}

	CloseHandle(Snapshot);
	return NULL;
}

std::wstring HYPERSCAN_PROCESS::GrabName(const DWORD ProcessID)
{
	std::wstring ProcessName;

	if (NULL == ProcessID)
	{
		return ProcessName;
	}

	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32FirstW(Snapshot, &ProcessEntry) == TRUE)
	{
		while (Process32NextW(Snapshot, &ProcessEntry) == TRUE)
		{
			if (ProcessEntry.th32ProcessID == ProcessID)
			{
				ProcessName = ProcessEntry.szExeFile;
				CloseHandle(Snapshot);

				return ProcessName;
			}
		}
	}

	CloseHandle(Snapshot);
	return ProcessName;
}