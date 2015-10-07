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
bool __fastcall PrintError(
	const size_t ErrorType, 
	const wchar_t *Message, 
	const SSIZE_T ErrorCode, 
	const wchar_t *FileName, 
	const size_t Line)
{
//Print Error: Enable/Disable.
	if (!Parameter.PrintError || //PrintError parameter check
		Message == nullptr || CheckEmptyBuffer(Message, wcsnlen_s(Message, ORIGINAL_PACKET_MAXSIZE) * sizeof(wchar_t)) || //Message check
		FileName != nullptr && CheckEmptyBuffer(FileName, wcsnlen_s(FileName, ORIGINAL_PACKET_MAXSIZE) * sizeof(wchar_t))) //FileName check
			return false;

//Get current date and time.
	std::shared_ptr<tm> TimeStructure(new tm());
	memset(TimeStructure.get(), 0, sizeof(tm));
	auto TimeValues = time(nullptr);
#if defined(PLATFORM_WIN)
	if (localtime_s(TimeStructure.get(), &TimeValues) > 0)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (localtime_r(&TimeValues, TimeStructure.get()) == nullptr)
#endif
		return false;

//Print Start Time at first printing.
	time_t LogStartupTime = 0;
	if (GlobalRunningStatus.StartupTime > 0)
	{
		LogStartupTime = GlobalRunningStatus.StartupTime;
		GlobalRunningStatus.StartupTime = 0;
	}

//Print to screen.
#if defined(PLATFORM_WIN)
	if (GlobalRunningStatus.Console)
#elif defined(PLATFORM_LINUX)
	if (!GlobalRunningStatus.Daemon)
#endif
	{
	//Print start time before print errors.
		if (LogStartupTime > 0)
		{
			std::shared_ptr<tm> TimeStructureTemp(new tm());
			memset(TimeStructureTemp.get(), 0, sizeof(tm));
		#if defined(PLATFORM_WIN)
			if (localtime_s(TimeStructureTemp.get(), &LogStartupTime) > 0)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (localtime_r(&LogStartupTime, TimeStructureTemp.get()) == nullptr)
		#endif
				return false;

			wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Log opened at this moment.\n", TimeStructureTemp->tm_year + 1900, TimeStructureTemp->tm_mon + 1, TimeStructureTemp->tm_mday, TimeStructureTemp->tm_hour, TimeStructureTemp->tm_min, TimeStructureTemp->tm_sec);
		}

	//Print errors.
		switch (ErrorType)
		{
		//System Error
			case LOG_ERROR_SYSTEM:
			{
				if (ErrorCode == 0)
				{
					wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				}
				else {
				#if defined(PLATFORM_WIN)
				//About System Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx.
					if (ErrorCode == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
						wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT(The service process could not connect to the service controller).\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
					else 
				#endif
						wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, error code is %d.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message, (int)ErrorCode);
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
						sFileName.erase(sFileName.find(L"\\\\"), wcslen(L"\\"));

				//Write to file
					if (Line > 0)
						wprintf_s(L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						wprintf_s(L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrorCode > 0)
					wprintf_s(L", error code is %d", (int)ErrorCode);

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
						sFileName.erase(sFileName.find(L"\\\\"), wcslen(L"\\"));

				//Write to file
					if (Line > 0)
						wprintf_s(L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						wprintf_s(L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrorCode > 0)
					wprintf_s(L", error code is %d", (int)ErrorCode);

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
						sFileName.erase(sFileName.find(L"\\\\"), wcslen(L"\\"));

				//Write to file
					if (Line > 0)
						wprintf_s(L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						wprintf_s(L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrorCode > 0)
					wprintf_s(L", error code is %d", (int)ErrorCode);

				wprintf_s(L".\n");
			}break;
		//Network Error
		//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
			case LOG_ERROR_NETWORK:
			{
				if (ErrorCode == 0)
					wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Network Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			#if defined(PLATFORM_WIN)
				else if (ErrorCode == WSAENETUNREACH) //Block error messages when network is unreachable.
					return true;
			#endif
				else 
					wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Network Error: %ls, error code is %d.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message, (int)ErrorCode);
			}break;
		//WinPcap Error
		#if defined(ENABLE_PCAP)
			case LOG_ERROR_PCAP:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Pcap Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			}break;
		#endif
		//DNSCurve Error
		#if defined(ENABLE_LIBSODIUM)
			case LOG_ERROR_DNSCURVE:
			{
			#if defined(PLATFORM_WIN)
				if (ErrorCode == WSAENETUNREACH) //Block error messages when network is unreachable.
					return true;
				else 
			#endif
					wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> DNSCurve Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			}break;
		#endif
		//Message Notice
			case LOG_MESSAGE_NOTICE:
			{
				wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> Notice: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			}break;
		}
	}

//Check whole file size.
	std::unique_lock<std::mutex> ErrLogMutex(ErrorLogLock);
#if defined(PLATFORM_WIN)
	std::shared_ptr<WIN32_FILE_ATTRIBUTE_DATA> File_WIN32_FILE_ATTRIBUTE_DATA(new WIN32_FILE_ATTRIBUTE_DATA());
	memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
	if (GetFileAttributesExW(GlobalRunningStatus.Path_ErrorLog->c_str(), GetFileExInfoStandard, File_WIN32_FILE_ATTRIBUTE_DATA.get()) != FALSE)
	{
		std::shared_ptr<LARGE_INTEGER> ErrorFileSize(new LARGE_INTEGER());
		memset(ErrorFileSize.get(), 0, sizeof(LARGE_INTEGER));
		ErrorFileSize->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeHigh;
		ErrorFileSize->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeLow;
		if (ErrorFileSize->QuadPart > 0 && (size_t)ErrorFileSize->QuadPart >= Parameter.LogMaxSize && 
			DeleteFileW(GlobalRunningStatus.Path_ErrorLog->c_str()) != 0)
				PrintError(LOG_ERROR_SYSTEM, L"Old Error Log file was deleted", 0, nullptr, 0);
	}

	File_WIN32_FILE_ATTRIBUTE_DATA.reset();
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::shared_ptr<struct stat> FileStat(new struct stat());
	memset(FileStat.get(), 0, sizeof(struct stat));
	if (stat(GlobalRunningStatus.sPath_ErrorLog->c_str(), FileStat.get()) == EXIT_SUCCESS && FileStat->st_size >= (off_t)Parameter.LogMaxSize && 
		remove(GlobalRunningStatus.sPath_ErrorLog->c_str()) == EXIT_SUCCESS)
			PrintError(LOG_ERROR_SYSTEM, L"Old Error Log file was deleted", 0, nullptr, 0);

	FileStat.reset();
#endif

//Main print
#if defined(PLATFORM_WIN)
	FILE *Output = nullptr;
	if (_wfopen_s(&Output, GlobalRunningStatus.Path_ErrorLog->c_str(), L"a,ccs=UTF-8") == EXIT_SUCCESS && Output != nullptr)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	auto Output = fopen(GlobalRunningStatus.sPath_ErrorLog->c_str(), "a");
	if (Output != nullptr)
#endif
	{
	//Print start time before print errors.
		if (LogStartupTime > 0)
		{
			std::shared_ptr<tm> TimeStructureTemp(new tm());
			memset(TimeStructureTemp.get(), 0, sizeof(tm));
			
		#if defined(PLATFORM_WIN)
			if (localtime_s(TimeStructureTemp.get(), &LogStartupTime) > 0)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (localtime_r(&LogStartupTime, TimeStructureTemp.get()) == nullptr)
		#endif
			{
				fclose(Output);
				return false;
			}

			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Log opened at this moment.\n", TimeStructureTemp->tm_year + 1900, TimeStructureTemp->tm_mon + 1, TimeStructureTemp->tm_mday, TimeStructureTemp->tm_hour, TimeStructureTemp->tm_min, TimeStructureTemp->tm_sec);
		}

	//Print errors.
		switch (ErrorType)
		{
		//System Error
			case LOG_ERROR_SYSTEM:
			{
				if (ErrorCode == 0)
				{
					fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
				}
				else {
				#if defined(PLATFORM_WIN)
				//About System Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx.
					if (ErrorCode == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
						fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT(The service process could not connect to the service controller).\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
					else 
				#endif
						fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> System Error: %ls, error code is %d.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message, (int)ErrorCode);
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
						sFileName.erase(sFileName.find(L"\\\\"), wcslen(L"\\"));

				//Write to file
					if (Line > 0)
						fwprintf_s(Output, L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						fwprintf_s(Output, L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrorCode > 0)
					fwprintf_s(Output, L", error code is %d", (int)ErrorCode);

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
						sFileName.erase(sFileName.find(L"\\\\"), wcslen(L"\\"));

				//Write to file
					if (Line > 0)
						fwprintf_s(Output, L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						fwprintf_s(Output, L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrorCode > 0)
					fwprintf_s(Output, L", error code is %d", (int)ErrorCode);

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
						sFileName.erase(sFileName.find(L"\\\\"), wcslen(L"\\"));

				//Write to file
					if (Line > 0)
						fwprintf_s(Output, L" in line %d of %ls", (int)Line, sFileName.c_str());
					else 
						fwprintf_s(Output, L" in %ls", sFileName.c_str());
				}

			//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
				if (ErrorCode > 0)
					fwprintf_s(Output, L", error code is %d", (int)ErrorCode);

				fwprintf_s(Output, L".\n");
			}break;
		//Network Error
		//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
			case LOG_ERROR_NETWORK:
			{
				if (ErrorCode == 0)
					fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Network Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			#if defined(PLATFORM_WIN)
				else if (ErrorCode == WSAENETUNREACH) //Block error messages when network is unreachable.
					break;
			#endif
				else 
					fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Network Error: %ls, error code is %d.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message, (int)ErrorCode);
			}break;
		//WinPcap Error
		#if defined(ENABLE_PCAP)
			case LOG_ERROR_PCAP:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> WinPcap Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			}break;
		#endif
		//DNSCurve Error
		#if defined(ENABLE_LIBSODIUM)
			case LOG_ERROR_DNSCURVE:
			{
			#if defined(PLATFORM_WIN)
				if (ErrorCode == WSAENETUNREACH) //Block error messages when network is unreachable.
					break;
				else 
			#endif
					fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> DNSCurve Error: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			}break;
		#endif
		//Message Notice
			case LOG_MESSAGE_NOTICE:
			{
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Notice: %ls.\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, Message);
			}break;
			default:
			{
				fclose(Output);
				return false;
			}
		}

	//Close file.
		fclose(Output);
		return true;
	}

	return false;
}
