// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2015 Chengr28
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


#include "PrintLog.h"

//Print errors to log file
size_t __fastcall PrintError(const size_t ErrType, const wchar_t *Message, const SSIZE_T ErrCode, const wchar_t *FileName, const size_t Line)
{
//Print Error: Enable/Disable.
	if (!Parameter.PrintError)
		return EXIT_SUCCESS;

//Print Start Time at first printing.
	time_t InnerStartTime = 0;
	if (StartTime > 0)
	{
		InnerStartTime = StartTime;
		StartTime = 0;
	}

//Get current date and time.
	std::shared_ptr<tm> TimeStructure(new tm());
	memset(TimeStructure.get(), 0, sizeof(tm));
	time_t TimeValues = 0;
	time(&TimeValues);
	localtime_s(TimeStructure.get(), &TimeValues);

//Print to screen.
	if (Parameter.Console)
	{
	//Print start time before print errors.
		if (InnerStartTime > 0)
		{
			std::shared_ptr<tm> TimeStructureTemp(new tm());
			memset(TimeStructureTemp.get(), 0, sizeof(tm));
			localtime_s(TimeStructureTemp.get(), &InnerStartTime);
			wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Log opened at this moment.\n", TimeStructureTemp->tm_year + 1900, TimeStructureTemp->tm_mon + 1, TimeStructureTemp->tm_mday, TimeStructureTemp->tm_hour, TimeStructureTemp->tm_min, TimeStructureTemp->tm_sec);
		}

	//Print errors.
		switch (ErrType)
		{
		//System Error
			case LOG_ERROR_SYSTEM:
			{
				if (ErrCode == 0)
				{
					wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				}
				else {
				#if defined(PLATFORM_WIN)
				//About System Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx.
					if (ErrCode == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
						wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT(The service process could not connect to the service controller).\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
					else 
				#endif
						wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, error code is %d.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message, (int)ErrCode);
				}
			}break;
		//Parameter Error
			case LOG_ERROR_PARAMETER:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Parameter Error: %ls", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase(sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line > 0)
						wprintf_s(L" in line %d of %ls", (int)Line, sFileName.c_str());
					else
						wprintf_s(L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode > 0)
					wprintf_s(L", error code is %d", (int)ErrCode);

				wprintf_s(L".\n");
			}break;
		//IPFilter Error
			case LOG_ERROR_IPFILTER:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Error: %ls", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase(sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line > 0)
						wprintf_s(L" in line %d of %ls", (int)Line, sFileName.c_str());
					else
						wprintf_s(L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode > 0)
					wprintf_s(L", error code is %d", (int)ErrCode);

				wprintf_s(L".\n");
			}break;
		//Hosts Error
			case LOG_ERROR_HOSTS:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Hosts Error: %ls", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase(sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line > 0)
						wprintf_s(L" in line %d of %ls", (int)Line, sFileName.c_str());
					else
						wprintf_s(L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode > 0)
					wprintf_s(L", error code is %d", (int)ErrCode);

				wprintf_s(L".\n");
			}break;
		//Network Error
		//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
			case LOG_ERROR_NETWORK:
			{
				if (ErrCode == 0)
					wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Network Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				else
					wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Network Error: %ls, error code is %d.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message, (int)ErrCode);
			}break;
		//WinPcap Error
			case LOG_ERROR_PCAP:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Pcap Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			}break;
		//DNSCurve Error
		#if defined(ENABLE_LIBSODIUM)
			case LOG_ERROR_DNSCURVE:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> DNSCurve Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			}break;
		#endif
			default:
			{
				return EXIT_FAILURE;
			}
		}
	}

//Check whole file size.
	std::unique_lock<std::mutex> ErrLogMutex(ErrLogLock);
#if defined(PLATFORM_WIN)
	HANDLE ErrorFileHandle = CreateFileW(Parameter.ErrorLogPath->c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (ErrorFileHandle != INVALID_HANDLE_VALUE)
	{
		std::shared_ptr<LARGE_INTEGER> ErrorFileSize(new LARGE_INTEGER());
		memset(ErrorFileSize.get(), 0, sizeof(LARGE_INTEGER));
		if (GetFileSizeEx(ErrorFileHandle, ErrorFileSize.get()) == 0)
		{
			CloseHandle(ErrorFileHandle);
		}
		else {
			CloseHandle(ErrorFileHandle);
			if (ErrorFileSize->QuadPart > 0 && (size_t)ErrorFileSize->QuadPart >= Parameter.LogMaxSize && 
				DeleteFileW(Parameter.ErrorLogPath->c_str()) != 0)
					PrintError(LOG_ERROR_SYSTEM, L"Old Error Log file was deleted", 0, nullptr, 0);
		}
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::shared_ptr<struct stat> FileStat(new struct stat());
	memset(FileStat.get(), 0, sizeof(struct stat));
	if (stat(Parameter.sErrorLogPath->c_str(), FileStat.get()) == 0)
	{
		if (FileStat->st_size >= (off_t)Parameter.LogMaxSize && remove(Parameter.sErrorLogPath->c_str()) == 0)
			PrintError(LOG_ERROR_SYSTEM, L"Old Error Log file was deleted", 0, nullptr, 0);
	}
#endif

//Main print
#if defined(PLATFORM_WIN)
	FILE *Output = nullptr;
	_wfopen_s(&Output, Parameter.ErrorLogPath->c_str(), L"a,ccs=UTF-8");
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	auto Output = fopen(Parameter.sErrorLogPath->c_str(), "a");
#endif
	if (Output != nullptr)
	{
	//Print start time before print errors.
		if (InnerStartTime > 0)
		{
			std::shared_ptr<tm> TimeStructureTemp(new tm());
			memset(TimeStructureTemp.get(), 0, sizeof(tm));
			localtime_s(TimeStructureTemp.get(), &InnerStartTime);
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Log opened at this moment.\n", TimeStructureTemp->tm_year + 1900, TimeStructureTemp->tm_mon + 1, TimeStructureTemp->tm_mday, TimeStructureTemp->tm_hour, TimeStructureTemp->tm_min, TimeStructureTemp->tm_sec);
		}

	//Print errors.
		switch (ErrType)
		{
		//System Error
			case LOG_ERROR_SYSTEM:
			{
				if (ErrCode == 0)
				{
					fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				}
				else {
				#if defined(PLATFORM_WIN)
				//About System Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx.
					if (ErrCode == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
						fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT(The service process could not connect to the service controller).\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
					else 
				#endif
						fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, error code is %d.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message, (int)ErrCode);
				}
			}break;
		//Parameter Error
			case LOG_ERROR_PARAMETER:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Parameter Error: %ls", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase(sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line > 0)
						fwprintf_s(Output, L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						fwprintf_s(Output, L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode > 0)
					fwprintf_s(Output, L", error code is %d", (int)ErrCode);

				fwprintf_s(Output, L".\n");
			}break;
		//IPFilter Error
			case LOG_ERROR_IPFILTER:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Error: %ls", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase(sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line > 0)
						fwprintf_s(Output, L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						fwprintf_s(Output, L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode > 0)
					fwprintf_s(Output, L", error code is %d", (int)ErrCode);

				fwprintf_s(Output, L".\n");
			}break;
		//Hosts Error
			case LOG_ERROR_HOSTS:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Hosts Error: %ls", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				if (FileName != nullptr)
				{
				//Delete double backslash.
					std::wstring sFileName(FileName);
					while (sFileName.find(L"\\\\") != std::wstring::npos)
						sFileName.erase(sFileName.find(L"\\\\"), 1U);

				//Write to file
					if (Line > 0)
						fwprintf_s(Output, L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						fwprintf_s(Output, L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrCode > 0)
					fwprintf_s(Output, L", error code is %d", (int)ErrCode);

				fwprintf_s(Output, L".\n");
			}break;
		//Network Error
		//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
			case LOG_ERROR_NETWORK:
			{
				if (ErrCode == 0)
					fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Network Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				else 
					fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Network Error: %ls, error code is %d.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message, (int)ErrCode);
			}break;
		//WinPcap Error
			case LOG_ERROR_PCAP:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> WinPcap Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			}break;
		//DNSCurve Error
		#if defined(ENABLE_LIBSODIUM)
			case LOG_ERROR_DNSCURVE:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> DNSCurve Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			}break;
			default:
			{
				fclose(Output);
				return EXIT_FAILURE;
			}
		#endif
		}

	//Close file.
		fclose(Output);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Print running status to log file
size_t __fastcall PrintRunningStatus(const wchar_t *Message)
{
//Print Start Time of Running Log part at first printing.
	time_t InnerStartTime = 0;
	if (RunningLogStartTime > 0)
	{
		InnerStartTime = RunningLogStartTime;
		RunningLogStartTime = 0;
	}

//Get current date and time.
	std::shared_ptr<tm> TimeStructure(new tm());
	memset(TimeStructure.get(), 0, sizeof(tm));
	time_t TimeValues = 0;
	time(&TimeValues);

//Push messages back to writing list.
	if (Parameter.RunningLogRefreshTime > 0)
	{
		RUNNING_LOG_DATA RunningLogDataTemp;
		RunningLogDataTemp.Message = Message;
		RunningLogDataTemp.TimeValues = TimeValues;

		std::unique_lock<std::mutex> RunningLogMutex(RunningLogLock);
		Parameter.RunningLogWriteQueue->push_back(RunningLogDataTemp);
		return EXIT_SUCCESS;
	}
	else {
		localtime_s(TimeStructure.get(), &TimeValues);
	}

//Print to screen.
	if (Parameter.Console)
	{
	//Print start time(Running Log part) before printing Running Log.
		if (InnerStartTime > 0)
		{
			std::shared_ptr<tm> TimeStructureTemp(new tm());
			memset(TimeStructureTemp.get(), 0, sizeof(tm));
			localtime_s(TimeStructureTemp.get(), &InnerStartTime);
			wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Log opened at this moment.\n", TimeStructureTemp->tm_year + 1900, TimeStructureTemp->tm_mon + 1, TimeStructureTemp->tm_mday, TimeStructureTemp->tm_hour, TimeStructureTemp->tm_min, TimeStructureTemp->tm_sec);
		}

	//Print Running Log.
		wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> %ls\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
	}

//Check whole file size.
	std::unique_lock<std::mutex> RunningLogMutex(RunningLogLock);
#if defined(PLATFORM_WIN)
	HANDLE RunningFileHandle = CreateFileW(Parameter.RunningLogPath->c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (RunningFileHandle != INVALID_HANDLE_VALUE)
	{
		std::shared_ptr<LARGE_INTEGER> RunningFileSize(new LARGE_INTEGER());
		memset(RunningFileSize.get(), 0, sizeof(LARGE_INTEGER));
		if (GetFileSizeEx(RunningFileHandle, RunningFileSize.get()) == 0)
		{
			CloseHandle(RunningFileHandle);
		}
		else {
			CloseHandle(RunningFileHandle);
			if (RunningFileSize->QuadPart > 0 && (size_t)RunningFileSize->QuadPart >= Parameter.LogMaxSize && 
				DeleteFileW(Parameter.RunningLogPath->c_str()) != 0)
					PrintError(LOG_ERROR_SYSTEM, L"Old Running Log file was deleted", 0, nullptr, 0);
		}
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::shared_ptr<struct stat> FileStat(new struct stat());
	memset(FileStat.get(), 0, sizeof(struct stat));
	if (stat(Parameter.sRunningLogPath->c_str(), FileStat.get()) == 0)
	{
		if (FileStat->st_size >= (off_t)Parameter.LogMaxSize && remove(Parameter.sRunningLogPath->c_str()) == 0)
			PrintError(LOG_ERROR_SYSTEM, L"Old Running Log file was deleted", 0, nullptr, 0);
	}
#endif

//Main print
#if defined(PLATFORM_WIN)
	FILE *Output = nullptr;
	_wfopen_s(&Output, Parameter.RunningLogPath->c_str(), L"a,ccs=UTF-8");
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	auto Output = fopen(Parameter.sRunningLogPath->c_str(), "a");
#endif
	if (Output != nullptr)
	{
	//Print start time(Running Log part) before printing Running Log.
		if (InnerStartTime > 0)
		{
			std::shared_ptr<tm> TimeStructureTemp(new tm());
			memset(TimeStructureTemp.get(), 0, sizeof(tm));
			localtime_s(TimeStructureTemp.get(), &InnerStartTime);
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Log opened at this moment.\n", TimeStructureTemp->tm_year + 1900, TimeStructureTemp->tm_mon + 1, TimeStructureTemp->tm_mday, TimeStructureTemp->tm_hour, TimeStructureTemp->tm_min, TimeStructureTemp->tm_sec);
		}

	//Print Running Log.
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> %ls\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);

	//Close file.
		fclose(Output);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

size_t __fastcall PrintParameterList(void)
{
	size_t Index = 0;

//Get current date&time.
	std::shared_ptr<tm> TimeStructure(new tm());
	memset(TimeStructure.get(), 0, sizeof(tm));
	time_t TimeValues = 0;
	time(&TimeValues);
	localtime_s(TimeStructure.get(), &TimeValues);

//Main print
#if defined(PLATFORM_WIN)
	FILE *Output = nullptr;
	_wfopen_s(&Output, Parameter.RunningLogPath->c_str(), L"a,ccs=UTF-8");
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	auto Output = fopen(Parameter.sRunningLogPath->c_str(), "a");
#endif
	if (Output != nullptr)
	{
	//Initialization
		std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
		//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista(Windows XP with SP3 support). [Roy Tam]
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
		DWORD BufferLength = 0;
		std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
		memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	#endif

	//Print to screen.
		if (Parameter.Console)
		{
			;
		}

	//Print to file.
		//Start.
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ==================== Global Parameter List ====================\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec); //Start.
		//[Base] block
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Configuration file version: %.1lf\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Parameter.Version); //Version
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.FileRefreshTime == 0) //File Refresh Time
			fwprintf_s(Output, L"File Refresh Time: OFF\n");
		else 
			fwprintf_s(Output, L"File Refresh Time: %u seconds\n", (UINT)(Parameter.FileRefreshTime / SECOND_TO_MILLISECOND));
		if (Parameter.FileHash) //File Hash
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> File Hash: ON\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> File Hash: OFF\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.Path != nullptr && Parameter.Path->size() > 1U)
		{
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Additional Path: \n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
			for (Index = 1U;Index < Parameter.Path->size();++Index)
			{
				if (Index == 1U)
					fwprintf_s(Output, L"%ls", Parameter.Path->at(Index).c_str());
				else 
					fwprintf_s(Output, L"|%ls", Parameter.Path->at(Index).c_str());
			}

			fwprintf_s(Output, L"\n");
		}
		if (Parameter.HostsFileList != nullptr)
		{
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Hosts File Name: \n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
			for (Index = 1U; Index < Parameter.HostsFileList->size(); ++Index)
			{
				if (Index == 1U)
					fwprintf_s(Output, L"%ls", Parameter.HostsFileList->at(Index).c_str());
				else
					fwprintf_s(Output, L"|%ls", Parameter.HostsFileList->at(Index).c_str());
			}

			fwprintf_s(Output, L"\n");
		}
		if (Parameter.IPFilterFileList != nullptr)
		{
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter File Name: \n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
			for (Index = 1U; Index < Parameter.IPFilterFileList->size(); ++Index)
			{
				if (Index == 1U)
					fwprintf_s(Output, L"%ls", Parameter.IPFilterFileList->at(Index).c_str());
				else
					fwprintf_s(Output, L"|%ls", Parameter.IPFilterFileList->at(Index).c_str());
			}

			fwprintf_s(Output, L"\n");
		}
		//[Log] block
		if (Parameter.PrintError) //Print Error
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Print Error: ON\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Print Error: OFF\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Log Maximum Size: %u bytes\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, (UINT)Parameter.LogMaxSize); //Log Maximum Size
		//[DNS] block
		if (Parameter.RequestMode == REQUEST_TCPMODE) //Protocol
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Protocol: TCP\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Protocol: UDP\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.HostsOnly) //Hosts Only
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Hosts Only: ON\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Hosts Only: OFF\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.LocalMain) //Local Main
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Local Main: ON\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Local Main: OFF\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.LocalHosts) //Local Hosts
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Local Hosts: ON\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Local Hosts: OFF\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.LocalRouting) //Local Routing
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Local Routing: ON\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Local Routing: OFF\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.CacheType == CACHE_TIMER) //Cache Type
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Cache Type: Timer\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else if (Parameter.CacheType == CACHE_QUEUE)
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Cache Type: Queue\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else 
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Cache Type: OFF\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Cache Parameter: %u\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, (UINT)Parameter.CacheParameter); //Cache Parameter
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Default TTL: %u seconds\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, (UINT)Parameter.HostsDefaultTTL); //Default TTL
		//[Listen] block
		if (Parameter.PcapCapture) //Pcap Capture
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Pcap Capture: ON\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Pcap Capture: OFF\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.OperationMode == LISTEN_PRIVATEMODE) //Operation Mode
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Operation Mode: Private\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else if (Parameter.CacheType == LISTEN_SERVERMODE)
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Operation Mode: Server\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else if (Parameter.CacheType == LISTEN_CUSTOMMODE)
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Operation Mode: Custom\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Operation Mode: Proxy\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);




		if (Parameter.ListenProtocol_NetworkLayer == LISTEN_IPV6_IPV4) //Listen Protocol(Network Layer)
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Listen Protocol: IPv4 + IPv6", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else if (Parameter.CacheType == LISTEN_IPV6)
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Listen Protocol: IPv6", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Listen Protocol: IPv4", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.ListenProtocol_TransportLayer == LISTEN_TCP_UDP) //Listen Protocol(Transport Layer)
			fwprintf_s(Output, L" TCP + UDP\n");
		else if (Parameter.CacheType == LISTEN_TCP)
			fwprintf_s(Output, L" TCP\n");
		else if (Parameter.CacheType == LISTEN_UDP)
			fwprintf_s(Output, L" UDP\n");
		else 
			fwprintf_s(Output, L" \n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"Listen Port: %u\n", ntohs(Parameter.ListenPort->front())); //Listen Port
		if (Parameter.IPFilterType) //IPFilter Type
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Type: Permit\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Type: Deny\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.IPFilterLevel == 0) //IPFilter Level
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Level: N/A\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		else
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPFilter Level < %u\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, (UINT)Parameter.IPFilterLevel);
		if (Parameter.AcceptTypeList->empty())
		{
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Accept Type: N/A\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		}
		else {
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Accept Type: ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
			for (auto AcceptTypeTableIter:*Parameter.AcceptTypeList)
			{
				if (AcceptTypeTableIter == Parameter.AcceptTypeList->at(Parameter.AcceptTypeList->size()))
					fwprintf_s(Output, L"%u", AcceptTypeTableIter);
				else 
					fwprintf_s(Output, L"%u|", AcceptTypeTableIter);
			}
			fwprintf_s(Output, L"\n");
		}

		//[Addresses] block
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv4 Listen Address: ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec); //IPv4 Listen Address
/*		if (Parameter.ListenAddress_IPv4 == nullptr || Parameter.ListenAddress_IPv4->ss_family == 0)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#ifdef _WIN64
			inet_ntop(AF_INET, &((PSOCKADDR_IN)Parameter.ListenAddress_IPv4)->sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#elif (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET, &((PSOCKADDR_IN)Parameter.ListenAddress_IPv4)->sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET;
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = ((PSOCKADDR_IN)Parameter.ListenAddress_IPv4)->sin_addr;
				WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in), nullptr, Addr.get(), &BufferLength);
			}
		#endif
			fwprintf_s(Output, L"<");
//			for (Index = 0;Index < strlen(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
			for (Index = 0;Index < strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L":%u>\n", ntohs(((PSOCKADDR_IN)Parameter.ListenAddress_IPv4)->sin_port));
		}
*/
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv4 DNS Address: ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec); //IPv4 DNS Address
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET, &Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET;
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in), nullptr, Addr.get(), &BufferLength);
			}
		#else
			inet_ntop(AF_INET, &Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#endif

			fwprintf_s(Output, L"<");
			for (Index = 0;Index < strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L":%u>\n", ntohs(Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv4 Alternate DNS Address: ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec); //IPv4 Alternate DNS Address
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET, &Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET;
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in), nullptr, Addr.get(), &BufferLength);
			}
		#else
			inet_ntop(AF_INET, &Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#endif

			fwprintf_s(Output, L"<");
			for (Index = 0;Index < strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L":%u>\n", ntohs(Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv4 Local DNS Address: ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec); //IPv4 Local DNS Address
		if (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == 0)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET, &Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET;
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr;
				WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in), nullptr, Addr.get(), &BufferLength);
			}
		#else
			inet_ntop(AF_INET, &Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#endif

			fwprintf_s(Output, L"<");
			for (Index = 0;Index < strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L":%u>\n", ntohs(Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv4 Local Alternate DNS Address: ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec); //IPv4 Local Alternate DNS Address
		if (Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family == 0)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET, &Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET;
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr;
				WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in), nullptr, Addr.get(), &BufferLength);
			}
		#else
			inet_ntop(AF_INET, &Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#endif

			fwprintf_s(Output, L"<");
			for (Index = 0;Index < strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L":%u>\n", ntohs(Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv6 Listen Address: ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec); //IPv6 Listen Address
/*		if (Parameter.ListenAddress_IPv6 == nullptr || Parameter.ListenAddress_IPv6->ss_family == 0)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#ifdef _WIN64
			inet_ntop(AF_INET6, &((PSOCKADDR_IN6)Parameter.ListenAddress_IPv6)->sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#elif (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET6, &((PSOCKADDR_IN6)Parameter.ListenAddress_IPv6)->sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET6;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = ((PSOCKADDR_IN6)Parameter.ListenAddress_IPv6)->sin6_addr;
				WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6), nullptr, Addr.get(), &BufferLength);
			}
		#endif
			CaseConvert(true, Addr.get(), strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE));
			fwprintf_s(Output, L"[");
			for (Index = 0;Index < strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L"]:%u\n", ntohs(((PSOCKADDR_IN6)Parameter.ListenAddress_IPv6)->sin6_port));
		}
*/
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv6 DNS Address: ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec); //IPv6 DNS Address
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET6, &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET6;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
				WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6), nullptr, Addr.get(), &BufferLength);
			}
		#else
			inet_ntop(AF_INET6, &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#endif

			CaseConvert(true, Addr.get(), strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE));
			fwprintf_s(Output, L"[");
			for (Index = 0;Index < strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L"]:%u\n", ntohs(Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv6 Alternate DNS Address: ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec); //IPv6 Alternate DNS Address
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET6, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET6;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6), nullptr, Addr.get(), &BufferLength);
			}
		#else
			inet_ntop(AF_INET6, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#endif

			CaseConvert(true, Addr.get(), strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE));
			fwprintf_s(Output, L"[");
			for (Index = 0;Index < strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L"]:%u\n", ntohs(Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv6 Local DNS Address: ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec); //IPv6 Local DNS Address
		if (Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family == 0)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET6, &Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET6;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr;
				WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6), nullptr, Addr.get(), &BufferLength);
			}
		#else
			inet_ntop(AF_INET6, &Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#endif

			CaseConvert(true, Addr.get(), strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE));
			fwprintf_s(Output, L"[");
			for (Index = 0;Index < strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L"]:%u\n", ntohs(Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port));
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> IPv6 Local Alternate DNS Address: ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec); //IPv6 Local Alternate DNS Address
		if (Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family == 0)
		{
			fwprintf_s(Output, L"N/A\n");
		}
		else {
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.Inet_Ntop_PTR != nullptr)
			{
				(*Parameter.Inet_Ntop_PTR)(AF_INET6, &Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
			}
			else {
				BufferLength = ADDR_STRING_MAXSIZE;
				SockAddr->ss_family = AF_INET6;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr;
				WSAAddressToStringA((PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6), nullptr, Addr.get(), &BufferLength);
			}
		#else
			inet_ntop(AF_INET6, &Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE);
		#endif

			CaseConvert(true, Addr.get(), strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE));
			fwprintf_s(Output, L"[");
			for (Index = 0;Index < strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
				fwprintf_s(Output, L"%c", Addr.get()[Index]);
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			fwprintf_s(Output, L"]:%u\n", ntohs(Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port));
		}

		//[Values] block
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"EDNS0 Payload Size: %u bytes\n", (UINT)Parameter.EDNS0PayloadSize); //EDNS0 Payload Size
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0) //IPv4 TTL
			fwprintf_s(Output, L"IPv4 TTL: Auto\n");
		else 
			fwprintf_s(Output, L"IPv4 TTL: %u\n", Parameter.DNSTarget.IPv4.HopLimitData.TTL);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0) //IPv6 Hop Limits
			fwprintf_s(Output, L"IPv6 Hop Limits: Auto\n");
		else
			fwprintf_s(Output, L"IPv6 Hop Limits: %u\n", Parameter.DNSTarget.IPv6.HopLimitData.HopLimit);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0) //IPv4 Alternate TTL
			fwprintf_s(Output, L"IPv4 Alternate TTL: Auto\n");
		else
			fwprintf_s(Output, L"IPv4 Alternate TTL: %u\n", Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0) //IPv6 Alternate Hop Limits
			fwprintf_s(Output, L"IPv6 Alternate Hop Limits: Auto\n");
		else
			fwprintf_s(Output, L"IPv6 Alternate Hop Limits: %u\n", Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit);
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"Hop Limits Fluctuation: %u hops\n", Parameter.HopLimitFluctuation); //Hop Limits Fluctuation
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"ICMP Test: %u seconds\n", (UINT)(Parameter.ICMPSpeed / SECOND_TO_MILLISECOND)); //ICMP Test
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"Domain Test: %u seconds\n", (UINT)(Parameter.DomainTestSpeed / SECOND_TO_MILLISECOND)); //Domain Test
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"Alternate Times: %u\n", (UINT)Parameter.AlternateTimes); //Alternate Times
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"Alternate Time Range: %u seconds\n", (UINT)(Parameter.AlternateTimeRange / SECOND_TO_MILLISECOND)); //Alternate Time Range
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"Alternate Reset Time: %u seconds\n", (UINT)(Parameter.AlternateResetTime / SECOND_TO_MILLISECOND)); //Alternate Reset Time
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.MultiRequestTimes <= 1U) //Multi Request Times
			fwprintf_s(Output, L"Multi Request Times: OFF\n");
		else 
			fwprintf_s(Output, L"Multi Request Times: %u\n", (UINT)(Parameter.MultiRequestTimes - 1U));

		//[Switches] block
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.DomainCaseConversion) //Domain Case Conversion
			fwprintf_s(Output, L"Domain Case Conversion: ON\n");
		else
			fwprintf_s(Output, L"Domain Case Conversion: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.EDNS0Label) //EDNS0 Label
			fwprintf_s(Output, L"EDNS0 Label: ON\n");
		else
			fwprintf_s(Output, L"EDNS0 Label: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.DNSSECRequest) //DNSSEC Request
			fwprintf_s(Output, L"DNSSEC Request: ON\n");
		else
			fwprintf_s(Output, L"DNSSEC Request: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.AlternateMultiRequest) //Alternate Multi Request
			fwprintf_s(Output, L"Alternate Multi Request: ON\n");
		else
			fwprintf_s(Output, L"Alternate Multi Request: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.IPv4DataCheck) //IPv4 Data Filter
			fwprintf_s(Output, L"IPv4 Data Filter: ON\n");
		else
			fwprintf_s(Output, L"IPv4 Data Filter: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.TCPDataCheck) //TCP Data Filter
			fwprintf_s(Output, L"TCP Data Filter: ON");
		else
			fwprintf_s(Output, L"TCP Data Filter: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.DNSDataCheck) //DNS Data Filter
			fwprintf_s(Output, L"DNS Data Filter: ON\n");
		else
			fwprintf_s(Output, L"DNS Data Filter: OFF\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.Blacklist) //Blacklist Filter
			fwprintf_s(Output, L"Blacklist Filter: ON\n");
		else
			fwprintf_s(Output, L"Blacklist Filter: OFF\n");

		//[Data] block
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"ICMP ID: %u\n", ntohs(Parameter.ICMPID)); //ICMP ID
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"ICMP Sequence: %u\n", ntohs(Parameter.ICMPSequence)); //ICMP Sequence
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"ICMP PaddingData: "); //ICMP PaddingData
		for (Index = 0;Index < Parameter.ICMPPaddingDataLength;++Index)
			fwprintf_s(Output, L"%x", Parameter.ICMPPaddingData[Index]);
		fwprintf_s(Output, L"\n");
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"Domain Test ID: %u\n", ntohs(Parameter.DomainTestID)); //Domain Test ID
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		if (Parameter.DomainTestData == nullptr) //Domain Test Data
		{
			fwprintf_s(Output, L"Domain Test Data: Auto\n");
		}
		else {
			fwprintf_s(Output, L"Domain Test Data: ");
			for (Index = 0;Index < strnlen_s(Parameter.DomainTestData, DOMAIN_MAXSIZE);++Index)
				fwprintf_s(Output, L"%c", Parameter.DomainTestData[Index]);
			fwprintf_s(Output, L"\n");
		}
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);
		fwprintf_s(Output, L"Localhost Server Name: "); //Localhost Server Name
		DNSQueryToChar(Parameter.LocalFQDN, Addr.get());
		for (Index = 0;Index < strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);++Index)
			fwprintf_s(Output, L"%c", Addr.get()[Index]);
		memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
		fwprintf_s(Output, L"\n");

		//End.
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ==================== Global Parameter List ====================\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec);


	//Close file.
		fclose(Output);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}
