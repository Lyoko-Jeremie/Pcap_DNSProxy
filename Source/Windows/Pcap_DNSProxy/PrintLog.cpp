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
size_t __fastcall PrintStatus(const size_t Level, const PWSTR Message)
{
//Print Running Status: Enable/Disable.
	if (Parameter.RunningLogPath == nullptr || Level > Parameter.PrintStatus /* || Message == nullptr */ )
		return EXIT_SUCCESS;

//Get current date&time.
	tm TimeStructure = {0};
	time_t TimeValues = 0;
	time(&TimeValues);
	localtime_s(&TimeStructure, &TimeValues);

//Print to screen.
	std::unique_lock<std::mutex> RunningLogMutex(RunningLogLock);
	if (Parameter.Console)
		wprintf_s(L"%ls.", Message);

//Check whole file size.
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

	//Close file.
		fclose(Output);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}
