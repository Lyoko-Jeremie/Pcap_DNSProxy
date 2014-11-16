// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
// Copyright (C) 2012-2014 Chengr28
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


#include "Pcap_DNSProxy.h"

extern Configuration Parameter;
extern std::vector<uint16_t> AcceptTypeList;
extern std::mutex ErrLogLock, RunningLogLock;

//Print error(s) to log file
size_t __fastcall PrintError(const size_t Type, const PWSTR Message, const SSIZE_T ErrCode, const PWSTR FileName, const size_t Line)
{
//Print Error: Enable/Disable.
	if (!Parameter.PrintError /* || Parameter.ErrorLogPath == nullptr || Message == nullptr */ )
		return EXIT_SUCCESS;

//Get current date&time.
/*
//Windows API
	SYSTEMTIME TimeStructure = {0};
	GetLocalTime(&TimeStructure);
	fwprintf_s(Output, L"%u%u/%u %u:%u:%u -> %ls.\n", TimeStructure.wYear, TimeStructure.wMonth, TimeStructure.wDay, TimeStructure.wHour, TimeStructure.wMinute, TimeStructure.wSecond, Message);

//Get and convert to ASCII string.
	char TimeBuffer[ADDR_STRING_MAXSIZE] = {0};
	asctime_s(TimeBuffer, &TimeStructure);
	fwprintf_s(Output, L"%s -> %ls.\n", TimeBuffer, Message);
*/
	tm TimeStructure = {0};
	time_t TimeValues = 0;
	time(&TimeValues);
	localtime_s(&TimeStructure, &TimeValues);

//Print to screen.
	if (Parameter.Console)
	{
		switch (Type)
		{
		//System Error
			case LOG_ERROR_SYSTEM:
			{
				if (ErrCode == NULL)
				{
					wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				}
				else {
				//About System Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx.
					if (ErrCode == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
						wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT(The service process could not connect to the service controller).\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
					else 
						wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, error Code is %d.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message, (int)ErrCode);
				}
			}break;
		//Parameter Error
			case LOG_ERROR_PARAMETER:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Parameter Error: %ls", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase((size_t)sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line != NULL)
						wprintf_s(L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						wprintf_s(L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode != NULL)
					wprintf_s(L", error Code is %d", (int)ErrCode);

				wprintf_s(L".\n");
			}break;
		//IPFilter Error
			case LOG_ERROR_IPFILTER:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Error: %ls", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase((size_t)sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line != NULL)
						wprintf_s(L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						wprintf_s(L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode != NULL)
					wprintf_s(L", error Code is %d", (int)ErrCode);

				wprintf_s(L".\n");
			}break;
		//Hosts Error
			case LOG_ERROR_HOSTS:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Hosts Error: %ls", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase((size_t)sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line != NULL)
						wprintf_s(L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						wprintf_s(L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode != NULL)
					wprintf_s(L", error Code is %d", (int)ErrCode);

				wprintf_s(L".\n");
			}break;
		//Winsock Error
		//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
			case LOG_ERROR_WINSOCK:
			{
				if (ErrCode == NULL)
					wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Winsock Error: %ls.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				else 
					wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Winsock Error: %ls, error Code is %d.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message, (int)ErrCode);
			}break;
		//WinPcap Error
			case LOG_ERROR_WINPCAP:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> WinPcap Error: %ls.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
			}break;
		//DNSCurve Error
			case LOG_ERROR_DNSCURVE:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> DNSCurve Error: %ls.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
			}break;
			default:
			{
				return EXIT_FAILURE;
			}
		}
	}

//Check whole file size.
	std::unique_lock<std::mutex> ErrLogMutex(ErrLogLock);
	HANDLE ErrorFileHandle = CreateFileW(Parameter.ErrorLogPath->c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (ErrorFileHandle != INVALID_HANDLE_VALUE)
	{
		LARGE_INTEGER ErrorFileSize = {0};
		if (GetFileSizeEx(ErrorFileHandle, &ErrorFileSize) == 0)
		{
			CloseHandle(ErrorFileHandle);
		}
		else {
			CloseHandle(ErrorFileHandle);
			if (ErrorFileSize.QuadPart > 0 && (size_t)ErrorFileSize.QuadPart >= Parameter.LogMaxSize && 
				DeleteFileW(Parameter.ErrorLogPath->c_str()) != 0)
					PrintError(LOG_ERROR_SYSTEM, L"Old Error Log file deleted", NULL, nullptr, NULL);
		}
	}

//Main print
	FILE *Output = nullptr;
	_wfopen_s(&Output, Parameter.ErrorLogPath->c_str(), L"a,ccs=UTF-8");
	if (Output != nullptr)
	{
		switch (Type)
		{
		//System Error
			case LOG_ERROR_SYSTEM:
			{
				if (ErrCode == NULL)
				{
					fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				}
				else {
				//About System Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx.
					if (ErrCode == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
						fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT(The service process could not connect to the service controller).\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
					else 
						fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, error Code is %d.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message, (int)ErrCode);
				}
			}break;
		//Parameter Error
			case LOG_ERROR_PARAMETER:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Parameter Error: %ls", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase((size_t)sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line != NULL)
						fwprintf_s(Output, L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						fwprintf_s(Output, L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode != NULL)
					fwprintf_s(Output, L", error Code is %d", (int)ErrCode);

				fwprintf_s(Output, L".\n");
			}break;
		//IPFilter Error
			case LOG_ERROR_IPFILTER:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Error: %ls", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase((size_t)sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line != NULL)
						fwprintf_s(Output, L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						fwprintf_s(Output, L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode != NULL)
					fwprintf_s(Output, L", error Code is %d", (int)ErrCode);

				fwprintf_s(Output, L".\n");
			}break;
		//Hosts Error
			case LOG_ERROR_HOSTS:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Hosts Error: %ls", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase((size_t)sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line != NULL)
						fwprintf_s(Output, L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						fwprintf_s(Output, L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode != NULL)
					fwprintf_s(Output, L", error Code is %d", (int)ErrCode);

				fwprintf_s(Output, L".\n");
			}break;
		//Winsock Error
		//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
			case LOG_ERROR_WINSOCK:
			{
				if (ErrCode == NULL)
					fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Winsock Error: %ls.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
				else 
					fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Winsock Error: %ls, error Code is %d.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message, (int)ErrCode);
			}break;
		//WinPcap Error
			case LOG_ERROR_WINPCAP:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> WinPcap Error: %ls.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
			}break;
		//DNSCurve Error
			case LOG_ERROR_DNSCURVE:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> DNSCurve Error: %ls.\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
			}break;
			default:
			{
				fclose(Output);
				return EXIT_FAILURE;
			}
		}

	//Close file.
		fclose(Output);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Print running status to log file
size_t __fastcall PrintStatus( /* const size_t Level, */ const PWSTR Message /* , const PWSTR Message_B */ )
{
//Print Running Status: Enable/Disable.
	if (Parameter.RunningLogPath == nullptr /* || Level > Parameter.PrintStatus || Message_A == nullptr */ )
		return EXIT_SUCCESS;

//Get current date&time.
	tm TimeStructure = {0};
	time_t TimeValues = 0;
	time(&TimeValues);
	localtime_s(&TimeStructure, &TimeValues);

//Print to screen.
	if (Parameter.Console)
//	{
//		if (Message_B == nullptr)
		wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> %ls\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
//		else 
//			wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> %ls %ls.", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message_A, Message_B);
//	}

//Check whole file size.
	std::unique_lock<std::mutex> RunningLogMutex(RunningLogLock);
	HANDLE RunningFileHandle = CreateFileW(Parameter.RunningLogPath->c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (RunningFileHandle != INVALID_HANDLE_VALUE)
	{
		LARGE_INTEGER RunningFileSize = {0};
		if (GetFileSizeEx(RunningFileHandle, &RunningFileSize) == 0)
		{
			CloseHandle(RunningFileHandle);
		}
		else {
			CloseHandle(RunningFileHandle);
			if (RunningFileSize.QuadPart > 0 && (size_t)RunningFileSize.QuadPart >= Parameter.LogMaxSize && 
				DeleteFileW(Parameter.RunningLogPath->c_str()) != 0)
					PrintError(LOG_ERROR_SYSTEM, L"Old Running Log file deleted", NULL, nullptr, NULL);
		}
	}

//Main print
	FILE *Output = nullptr;
	_wfopen_s(&Output, Parameter.RunningLogPath->c_str(), L"a,ccs=UTF-8");
	if (Output != nullptr)
	{
//		if (Message_B == nullptr)
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> %ls\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message);
//		else
//			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> %ls %ls.", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, Message_A, Message_B);

	//Close file.
		fclose(Output);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

size_t __fastcall PrintParameterList(void)
{
//Get current date&time.
	tm TimeStructure = {0};
	time_t TimeValues = 0;
	time(&TimeValues);
	localtime_s(&TimeStructure, &TimeValues);

//Main print
	FILE *Output = nullptr;
	_wfopen_s(&Output, Parameter.RunningLogPath->c_str(), L"a,ccs=UTF-8");
	if (Output != nullptr)
	{
	//Initialization
		std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
//		std::shared_ptr<wchar_t> wAddr(new wchar_t[ADDR_STRING_MAXSIZE]());
		//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista. [Roy Tam]
	#ifdef _WIN64
	#else //x86
		DWORD BufferLength = 0;
		sockaddr_storage SockAddr = {0};
	#endif

	//Print to screen.
		if (Parameter.Console)
		{
			;
		}
		
	//Print to file.
		//Start.
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ==================== Global Parameter List ====================\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec); //Start.
		//[Base] block
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"Configuration file version: %.1lf\n", Parameter.Version); //Version
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.FileRefreshTime == 0) //File Refresh Time
			fwprintf_s(Output, L"File Refresh Time: OFF\n");
		else 
			fwprintf_s(Output, L"File Refresh Time: %u seconds\n", (UINT)(Parameter.FileRefreshTime / SECOND_TO_MILLISECOND));
		if (Parameter.FileHash) //File Hash
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> File Hash: ON\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> File Hash: OFF\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		//[Log] block
		if (Parameter.PrintError) //Print Error
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Print Error: ON\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Print Error: OFF\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"Log Maximum Size: %u bytes\n",  (UINT)Parameter.LogMaxSize); //Log Maximum Size
		//[DNS] block
		if (Parameter.RquestMode == REQUEST_TCPMODE) //Protocol
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Protocol: TCP\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Protocol: UDP\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.HostsOnly) //Hosts Only
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Hosts Only: ON\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Hosts Only: OFF\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.LocalMain) //Local Main
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Local Main: ON\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Local Main: OFF\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.CacheType == CACHE_TIMER) //Cache Type
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Cache Type: Timer\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else if (Parameter.CacheType == CACHE_QUEUE)
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Cache Type: Queue\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Cache Type: OFF\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"Cache Parameter: %u\n", (UINT)Parameter.CacheParameter); //Cache Parameter
		//[Listen] block
		if (Parameter.PcapCapture) //Pcap Capture
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Pcap Capture: ON\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Pcap Capture: OFF\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.OperationMode == LISTEN_PRIVATEMODE) //Operation Mode
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Operation Mode: Private\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else if (Parameter.CacheType == LISTEN_SERVERMODE)
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Operation Mode: Server\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else if (Parameter.CacheType == LISTEN_CUSTOMMODE)
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Operation Mode: Custom\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Operation Mode: Proxy\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.ListenProtocol == LISTEN_IPV4_IPV6) //Listen Protocol
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Listen Protocol: IPv4 + IPv6\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else if (Parameter.CacheType == LISTEN_IPV6)
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Listen Protocol: IPv6\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Listen Protocol: IPv4\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"Listen Port: %u\n", ntohs(Parameter.ListenPort)); //Listen Port
		if (Parameter.IPFilterOptions.Type) //IPFilter Type
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Type: Permit\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Type: Deny\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.IPFilterOptions.IPFilterLevel == 0) //IPFilter Level
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Level: N/A\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Level < %u\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec, (UINT)Parameter.IPFilterOptions.IPFilterLevel);
		if (AcceptTypeList.empty())
		{
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Accept Type: N/A\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		}
		else {
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Accept Type: ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
			for (auto AcceptTypeIter:AcceptTypeList)
			{
				if (AcceptTypeIter == AcceptTypeList.at(AcceptTypeList.size()))
					fwprintf_s(Output, L"%u", AcceptTypeIter);
				else 
					fwprintf_s(Output, L"%u|", AcceptTypeIter);
			}
			fwprintf_s(Output, L"\n");
		}

		//[Addresses] block
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv4 DNS Address: ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec); //IPv4 DNS Address
		if (Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_family == NULL)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#ifdef _WIN64
			inet_ntop(AF_INET, (PSTR)&Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#else //x86
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
			WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in), NULL, Addr.get(), &BufferLength);
		#endif
/*			if (MultiByteToWideChar(CP_ACP, NULL, Addr.get(), MBSTOWCS_NULLTERMINATE, wAddr.get(), ADDR_STRING_MAXSIZE) <= 0)
			{
				PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);
				return EXIT_FAILURE;
			}
*/
			fwprintf_s(Output, L"<");
			for (size_t Index = 0;Index < strlen(Addr.get());Index++)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L":%u>\n", ntohs(Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port));
//			fwprintf_s(Output, L"<%ls:%u>\n", wAddr.get(), ntohs(Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port));
//			memset(wAddr.get(), 0, ADDR_STRING_MAXSIZE * sizeof(wchar_t));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv4 Alternate DNS Address: ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec); //IPv4 Alternate DNS Address
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_family == NULL)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#ifdef _WIN64
			inet_ntop(AF_INET, (PSTR)&Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#else //x86
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in), NULL, Addr.get(), &BufferLength);
		#endif
/*			if (MultiByteToWideChar(CP_ACP, NULL, Addr.get(), MBSTOWCS_NULLTERMINATE, wAddr.get(), ADDR_STRING_MAXSIZE) <= 0)
			{
				PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);
				return EXIT_FAILURE;
			}
*/
			fwprintf_s(Output, L"<");
			for (size_t Index = 0;Index < strlen(Addr.get());Index++)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L":%u>\n", ntohs(Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port));
//			fwprintf_s(Output, L"%ls:%u>\n", wAddr.get(), ntohs(Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port));
//			memset(wAddr.get(), 0, ADDR_STRING_MAXSIZE * sizeof(wchar_t));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv4 Local DNS Address: ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec); //IPv4 Local DNS Address
		if (Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_family == NULL)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#ifdef _WIN64
			inet_ntop(AF_INET, (PSTR)&Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#else //x86
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr;
			WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in), NULL, Addr.get(), &BufferLength);
		#endif
/*			if (MultiByteToWideChar(CP_ACP, NULL, Addr.get(), MBSTOWCS_NULLTERMINATE, wAddr.get(), ADDR_STRING_MAXSIZE) <= 0)
			{
				PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);
				return EXIT_FAILURE;
			}
*/
			fwprintf_s(Output, L"<");
			for (size_t Index = 0;Index < strlen(Addr.get());Index++)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L":%u>\n", ntohs(Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port));
//			fwprintf_s(Output, L"<%ls:%u>\n", wAddr.get(), ntohs(Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port));
//			memset(wAddr.get(), 0, ADDR_STRING_MAXSIZE * sizeof(wchar_t));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv4 Local Alternate DNS Address: ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec); //IPv4 Local Alternate DNS Address
		if (Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_family == NULL)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#ifdef _WIN64
			inet_ntop(AF_INET, (PSTR)&Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#else //x86
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr;
			WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in), NULL, Addr.get(), &BufferLength);
		#endif
/*			if (MultiByteToWideChar(CP_ACP, NULL, Addr.get(), MBSTOWCS_NULLTERMINATE, wAddr.get(), ADDR_STRING_MAXSIZE) <= 0)
			{
				PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);
				return EXIT_FAILURE;
			}
*/
			fwprintf_s(Output, L"<");
			for (size_t Index = 0;Index < strlen(Addr.get());Index++)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L":%u>\n", ntohs(Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port));
//			fwprintf_s(Output, L"<%ls:%u>\n", wAddr.get(), ntohs(Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port));
//			memset(wAddr.get(), 0, ADDR_STRING_MAXSIZE * sizeof(wchar_t));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv6 DNS Address: ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec); //IPv6 DNS Address
		if (Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_family == NULL)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#ifdef _WIN64
			inet_ntop(AF_INET6, (PSTR)&Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#else //x86
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
			WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in6), NULL, Addr.get(), &BufferLength);
		#endif
			CaseConvert(true, Addr.get(), strlen(Addr.get()));
/*			if (MultiByteToWideChar(CP_ACP, NULL, Addr.get(), MBSTOWCS_NULLTERMINATE, wAddr.get(), ADDR_STRING_MAXSIZE) <= 0)
			{
				PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);
				return EXIT_FAILURE;
			}
*/		
			fwprintf_s(Output, L"[");
			for (size_t Index = 0;Index < strlen(Addr.get());Index++)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L"]:%u\n", ntohs(Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port));
//			fwprintf_s(Output, L"[%ls]:%u\n", wAddr.get(), ntohs(Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port));
//			memset(wAddr.get(), 0, ADDR_STRING_MAXSIZE * sizeof(wchar_t));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv6 Alternate DNS Address: ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec); //IPv6 Alternate DNS Address
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_family == NULL)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#ifdef _WIN64
			inet_ntop(AF_INET6, (PSTR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#else //x86
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in6), NULL, Addr.get(), &BufferLength);
		#endif
			CaseConvert(true, Addr.get(), strlen(Addr.get()));
/*			if (MultiByteToWideChar(CP_ACP, NULL, Addr.get(), MBSTOWCS_NULLTERMINATE, wAddr.get(), ADDR_STRING_MAXSIZE) <= 0)
			{
				PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);
				return EXIT_FAILURE;
			}
*/
			fwprintf_s(Output, L"[");
			for (size_t Index = 0;Index < strlen(Addr.get());Index++)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L"]:%u\n", ntohs(Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port));
//			fwprintf_s(Output, L"[%ls]:%u\n", wAddr.get(), ntohs(Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port));
//			memset(wAddr.get(), 0, ADDR_STRING_MAXSIZE * sizeof(wchar_t));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv6 Local DNS Address: ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec); //IPv6 Local DNS Address
		if (Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_family == NULL)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#ifdef _WIN64
			inet_ntop(AF_INET6, (PSTR)&Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#else //x86
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr;
			WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in6), NULL, Addr.get(), &BufferLength);
		#endif
			CaseConvert(true, Addr.get(), strlen(Addr.get()));
/*			if (MultiByteToWideChar(CP_ACP, NULL, Addr.get(), MBSTOWCS_NULLTERMINATE, wAddr.get(), ADDR_STRING_MAXSIZE) <= 0)
			{
				PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);
				return EXIT_FAILURE;
			}
*/
			fwprintf_s(Output, L"[");
			for (size_t Index = 0;Index < strlen(Addr.get());Index++)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L"]:%u\n", ntohs(Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port));
//			fwprintf_s(Output, L"[%ls]:%u\n", wAddr.get(), ntohs(Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port));
//			memset(wAddr.get(), 0, ADDR_STRING_MAXSIZE * sizeof(wchar_t));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv6 Local Alternate DNS Address: ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec); //IPv6 Local Alternate DNS Address
		if (Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_family == NULL)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#ifdef _WIN64
			inet_ntop(AF_INET6, (PSTR)&Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#else //x86
			BufferLength = ADDR_STRING_MAXSIZE;
			SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr;
			WSAAddressToStringA((LPSOCKADDR)&SockAddr, sizeof(sockaddr_in6), NULL, Addr.get(), &BufferLength);
		#endif
			CaseConvert(true, Addr.get(), strlen(Addr.get()));
/*			if (MultiByteToWideChar(CP_ACP, NULL, Addr.get(), MBSTOWCS_NULLTERMINATE, wAddr.get(), ADDR_STRING_MAXSIZE) <= 0)
			{
				PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);
				return EXIT_FAILURE;
			}
*/
			fwprintf_s(Output, L"[");
			for (size_t Index = 0;Index < strlen(Addr.get());Index++)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L"]:%u\n", ntohs(Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port));
//			fwprintf_s(Output, L"[%ls]:%u\n", wAddr.get(), ntohs(Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port));
//			memset(wAddr.get(), 0, ADDR_STRING_MAXSIZE * sizeof(wchar_t));
		}

		//[Values] block
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"EDNS0 Payload Size: %u bytes\n", (UINT)Parameter.EDNS0PayloadSize); //EDNS0 Payload Size
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0) //IPv4 TTL
			fwprintf_s(Output, L"IPv4 TTL: Auto\n");
		else 
			fwprintf_s(Output, L"IPv4 TTL: %u\n", Parameter.DNSTarget.IPv4.HopLimitData.TTL);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0) //IPv6 Hop Limits
			fwprintf_s(Output, L"IPv6 Hop Limits: Auto\n");
		else
			fwprintf_s(Output, L"IPv6 Hop Limits: %u\n", Parameter.DNSTarget.IPv6.HopLimitData.HopLimit);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0) //IPv4 Alternate TTL
			fwprintf_s(Output, L"IPv4 Alternate TTL: Auto\n");
		else
			fwprintf_s(Output, L"IPv4 Alternate TTL: %u\n", Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0) //IPv6 Alternate Hop Limits
			fwprintf_s(Output, L"IPv6 Alternate Hop Limits: Auto\n");
		else
			fwprintf_s(Output, L"IPv6 Alternate Hop Limits: %u\n", Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"Hop Limits Fluctuation: %u hops\n", Parameter.HopLimitFluctuation); //Hop Limits Fluctuation
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"ICMP Test: %u seconds\n", (UINT)(Parameter.ICMPOptions.ICMPSpeed / SECOND_TO_MILLISECOND)); //ICMP Test
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"Domain Test: %u seconds\n", (UINT)(Parameter.DomainTestOptions.DomainTestSpeed / SECOND_TO_MILLISECOND)); //Domain Test
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"Alternate Times: %u\n", (UINT)Parameter.AlternateOptions.AlternateTimes); //Alternate Times
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"Alternate Time Range: %u seconds\n", (UINT)(Parameter.AlternateOptions.AlternateTimeRange / SECOND_TO_MILLISECOND)); //Alternate Time Range
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"Alternate Reset Time: %u seconds\n", (UINT)(Parameter.AlternateOptions.AlternateResetTime / SECOND_TO_MILLISECOND)); //Alternate Reset Time
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.MultiRequestTimes <= 1U) //Multi Request Times
			fwprintf_s(Output, L"Multi Request Times: OFF\n");
		else 
			fwprintf_s(Output, L"Multi Request Times: %u\n", (UINT)(Parameter.MultiRequestTimes - 1U));

		//[Switches] block
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.DomainCaseConversion) //Domain Case Conversion
			fwprintf_s(Output, L"Domain Case Conversion: ON\n");
		else
			fwprintf_s(Output, L"Domain Case Conversion: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.EDNS0Label) //EDNS0 Label
			fwprintf_s(Output, L"EDNS0 Label: ON\n");
		else
			fwprintf_s(Output, L"EDNS0 Label: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.DNSSECRequest) //DNSSEC Request
			fwprintf_s(Output, L"DNSSEC Request: ON\n");
		else
			fwprintf_s(Output, L"DNSSEC Request: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.AlternateMultiRequest) //Alternate Multi Request
			fwprintf_s(Output, L"Alternate Multi Request: ON\n");
		else
			fwprintf_s(Output, L"Alternate Multi Request: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.IPv4DataCheck) //IPv4 Data Filter
			fwprintf_s(Output, L"IPv4 Data Filter: ON\n");
		else
			fwprintf_s(Output, L"IPv4 Data Filter: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.TCPDataCheck) //TCP Data Filter
			fwprintf_s(Output, L"TCP Data Filter: ON");
		else
			fwprintf_s(Output, L"TCP Data Filter: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.DNSDataCheck) //DNS Data Filter
			fwprintf_s(Output, L"DNS Data Filter: ON\n");
		else
			fwprintf_s(Output, L"DNS Data Filter: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.Blacklist) //Blacklist Filter
			fwprintf_s(Output, L"Blacklist Filter: ON\n");
		else
			fwprintf_s(Output, L"Blacklist Filter: OFF\n");

		//[Data] block
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"ICMP ID: %u\n", ntohs(Parameter.ICMPOptions.ICMPID)); //ICMP ID
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"ICMP Sequence: %u\n", ntohs(Parameter.ICMPOptions.ICMPSequence)); //ICMP Sequence
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"ICMP PaddingData: "); //ICMP PaddingData
		for (size_t Index = 0;Index < Parameter.ICMPOptions.PaddingDataLength;Index++)
			fwprintf_s(Output, L"%x", Parameter.ICMPOptions.PaddingData[Index]);
		fwprintf_s(Output, L"\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"Domain Test ID: %u\n", ntohs(Parameter.DomainTestOptions.DomainTestID)); //Domain Test ID
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		if (Parameter.DomainTestOptions.DomainTestData == nullptr) //Domain Test Data
		{
			fwprintf_s(Output, L"Domain Test Data: Auto\n");
		}
		else {
			fwprintf_s(Output, L"Domain Test Data: ");
			for (size_t Index = 0;Index < strlen(Parameter.DomainTestOptions.DomainTestData);Index++)
				fwprintf_s(Output, L"%c", Parameter.DomainTestOptions.DomainTestData[Index]);
			fwprintf_s(Output, L"\n");
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);
		fwprintf_s(Output, L"Localhost Server Name: "); //Localhost Server Name
		DNSQueryToChar(Parameter.LocalServerOptions.LocalFQDN, Addr.get());
		for (size_t Index = 0;Index < strlen(Addr.get());Index++)
			fwprintf_s(Output, L"%c", Addr.get()[Index]);
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
		fwprintf_s(Output, L"\n");

		//End.
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ==================== Global Parameter List ====================\n", TimeStructure.tm_year + 1900, TimeStructure.tm_mon + 1, TimeStructure.tm_mday, TimeStructure.tm_hour, TimeStructure.tm_min, TimeStructure.tm_sec);


	//Close file.
		fclose(Output);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}