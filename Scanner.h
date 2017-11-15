#pragma once
#include <iostream>
#include <windows.h>
#include <vector>

#ifndef _WIN64
#undef INT
#define INT int32_t
#else
#undef INT
#define INT int64_t
#endif

namespace Hyperscan
{
	enum ScanAllignment : DWORD
	{
		HyperscanAllignmentByte = 0x1,
		HyperscanAllignmentFloat = 0x1,
		HyperscanAllignmentDouble = 0x1,
		HyperscanAllignment2Bytes = 0x2,
		HyperscanAllignment4Bytes = 0x4,
		HyperscanAllignment8Bytes = 0x8,
		HyperscanAllignmentString = 0x1
	};

	enum ScanType : DWORD
	{
		HyperscanTypeExact = 0x00E,
		HyperscanTypeSmaller = 0x0E,
		HyperscanTypeBigger = 0x000E,
		HyperscanTypeDifferent = 0x0000A,
		HyperscanTypeAll = 0xABCDEF
	};

	enum ScanMode : DWORD
	{
		HyperscanScanFirst = 0xFF0,
		HyperscanScanNext = 0x0FF
	};

	typedef class HYPERSCAN_SCANNER
	{
	private: static std::vector<UINT_PTR> ScanModulesCallback(DWORD ProcessID, UINT_PTR ModuleBaseAddress, UINT_PTR ModuleSize, INT ScanValue,
		ScanAllignment AllignmentOfScan, ScanType TypeOfScan);

	private: static std::vector<UINT_PTR> ScanModules(DWORD ProcessID, INT ScanValue, ScanAllignment AllignmentOfScan,
		ScanType TypeOfScan);

	private: static std::vector<UINT_PTR> ScanWholeMemoryWithDelimiters(DWORD ProcessID, INT ScanValue, ScanAllignment AllignmentOfScan,
				ScanType TypeOfScan, DWORD BeginAddress = 0x000000000, DWORD EndAddress = 0x7FFFFFFFF);

	public: static std::vector<UINT_PTR> Scan(DWORD ProcessID, INT ScanValue, ScanAllignment AllignmentOfScan, ScanType TypeOfScan);

	public: static std::vector<UINT_PTR> ScanString(DWORD ProcessID, const std::string & String, UINT_PTR StringSize, 
		BOOL IsUnicode = FALSE, BOOL CaseSensitive = FALSE, DWORD BeginAddress = 0x000000000, DWORD EndAddress = 0x7FFFFFFFF);
	} *PHYPERSCAN_SCANNER;

	typedef class HYPERSCAN_PROCESS
	{
	public: static DWORD GrabId(const std::wstring & ProcessName);

	public: static std::wstring GrabName(const DWORD ProcessID);
	} *PHYPERSCAN_PROCESS;
}