#include "Scanner.h"
#include "Information.h"
#include <sstream>
#include <locale>
#include <chrono>

std::string WideToNarrow(std::wstring & WideString)
{
	setlocale(LC_CTYPE, "");
	std::string String(WideString.begin(), WideString.end());

	return String;
}

std::wstring NarrowToWide(std::string & String)
{
	setlocale(LC_CTYPE, "");
	std::wstring Wide(String.begin(), String.end());

	return Wide;
}

std::wstring InterpretProcessIDHex(DWORD ProcessID)
{
	std::stringstream Stream;
	std::string String;
	Stream << std::hex << ProcessID;
	String = Stream.str();
	std::wstring Wide(String.begin(), String.end());

	return Wide;
}

std::wstring InterpretInteger(DWORD Integer)
{
	std::stringstream Stream;
	std::string String;
	Stream << std::dec << Integer;
	String = Stream.str();
	std::wstring Wide(String.begin(), String.end());

	return Wide;
}

BOOL SetAttachTitle(DWORD ProcessID, int NumberOfValues, double TimeTaken)
{
	std::wstring ProcessName = Hyperscan::HYPERSCAN_PROCESS::GrabName(ProcessID);

	if (ProcessName.empty())
	{
		ProcessName = L"???.exe";
	}

	std::wstring Wide = L"Hyperscan - " + ProcessName + L" (0x" + InterpretProcessIDHex(ProcessID) + L") Found " + InterpretInteger(NumberOfValues) + L" addresses in " + InterpretInteger(TimeTaken) + L" ms";

	if (TRUE == SetConsoleTitleW(Wide.c_str()))
	{
		return TRUE;
	}

	return FALSE;
}

int main(int ArgumentCount, char *Arguments[])
{
	if (ArgumentCount < 3)
	{
		return FALSE;
	}

	SetConsoleTitleW(L"Hyperscan");

	// Below is the code for scanning for strings
	/*std::string ValueParameter = Arguments[2];
	std::wstring ValueForScan(ValueParameter.begin(), ValueParameter.end());
	std::string ProcessArgument = Arguments[1];
	DWORD ProcessIDForScan = Hyperscan::HYPERSCAN_PROCESS::GrabId(NarrowToWide(ProcessArgument));

	auto CounterStart = std::chrono::high_resolution_clock::now();

	SetConsoleTitleW(L"Hyperscan - Scanning...");

	std::vector<UINT_PTR> AddressHolder = Hyperscan::HYPERSCAN_SCANNER::ScanString(ProcessIDForScan, ValueParameter, ValueForScan.size(),
		0x000000000, 0x7FFFFFFFF, FALSE);

	auto CounterMiliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()
		- CounterStart);
	std::chrono::duration<double, std::milli> CounterMilisecondsConversion(std::chrono::high_resolution_clock::now() - CounterStart);
	double TimeTaken = CounterMilisecondsConversion.count();

	SetAttachTitle(ProcessIDForScan, AddressHolder.size(), TimeTaken);

	printf("Press any key to list the addresses...\n");
	getchar();
	system("cls");

	HANDLE OutputAttribute = GetStdHandle(STD_OUTPUT_HANDLE);
	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessIDForScan);

	for (auto HolderParse = AddressHolder.begin(); HolderParse != AddressHolder.end(); ++HolderParse)
	{
		PBYTE CurrentAddress = reinterpret_cast<PBYTE>(*HolderParse);

		if (TRUE == Hyperscan::HYPERSCAN_CHECK::IsAddressStatic(ProcessIDForScan, CurrentAddress))
		{
			SetConsoleTextAttribute(OutputAttribute, 0x0D);
			printf("\n|| Location = 0x%X || Value = %s (Intermodular) ||", *HolderParse, ValueParameter);
		}
		else
		{
			SetConsoleTextAttribute(OutputAttribute, 0x0F);
			printf("\n|| Location = 0x%X || Value = %s (Ungategorized | Dynamic) ||", *HolderParse, ValueParameter);
		}

		Sleep(10);
	}

	CloseHandle(ProcessHandle);
	getchar();

	SetConsoleTextAttribute(OutputAttribute, 0x0F);

	return FALSE;*/

	INT ValueForScan = std::atoi(Arguments[2]);
	std::string ProcessArgument = Arguments[1];
	DWORD ProcessIDForScan = Hyperscan::HYPERSCAN_PROCESS::GrabId(NarrowToWide(ProcessArgument));

	auto CounterStart = std::chrono::high_resolution_clock::now();

	std::vector<UINT_PTR> AddressHolder = Hyperscan::HYPERSCAN_SCANNER::Scan(ProcessIDForScan, ValueForScan, Hyperscan::HyperscanAllignment4Bytes,
		Hyperscan::HyperscanTypeExact);

	auto CounterMiliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()
		- CounterStart);
	std::chrono::duration<double, std::milli> CounterMilisecondsConversion(std::chrono::high_resolution_clock::now() - CounterStart);
	double TimeTaken = CounterMilisecondsConversion.count();

	SetAttachTitle(ProcessIDForScan, AddressHolder.size(), TimeTaken);

	printf("Press any key to list the addresses...\n");
	getchar();
	system("cls");

	HANDLE OutputAttribute = GetStdHandle(STD_OUTPUT_HANDLE);
	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessIDForScan);

	for (auto HolderParse = AddressHolder.begin(); HolderParse != AddressHolder.end(); ++HolderParse)
	{
		INT CurrentValue = NULL;

		ReadProcessMemory(ProcessHandle, reinterpret_cast<VOID*>(*HolderParse), &CurrentValue, sizeof(INT), nullptr);

		PBYTE CurrentAddress = reinterpret_cast<PBYTE>(*HolderParse);

		if (TRUE == Hyperscan::HYPERSCAN_CHECK::IsAddressStatic(ProcessIDForScan, CurrentAddress))
		{
			SetConsoleTextAttribute(OutputAttribute, 0x0D);
			printf("\n|| Location = 0x%X || Value = %d (Intermodular) ||", *HolderParse, ValueForScan);
		}
		else
		{
			SetConsoleTextAttribute(OutputAttribute, 0x0F);
			printf("\n|| Location = 0x%X || Value = %d (Ungategorized | Dynamic) ||", *HolderParse, ValueForScan);
		}

		Sleep(10);
	}

	CloseHandle(ProcessHandle);
	getchar();

	SetConsoleTextAttribute(OutputAttribute, 0x0F);

	return FALSE;
}
