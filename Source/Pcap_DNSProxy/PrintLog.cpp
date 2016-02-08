// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2016 Chengr28
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
//Print Error: Enable/Disable, parameter check, message check and file name check
	if (!Parameter.PrintError || //PrintError 
		Message == nullptr || CheckEmptyBuffer(Message, wcsnlen_s(Message, ORIGINAL_PACKET_MAXSIZE) * sizeof(wchar_t)) || 
		FileName != nullptr && CheckEmptyBuffer(FileName, wcsnlen_s(FileName, ORIGINAL_PACKET_MAXSIZE) * sizeof(wchar_t)))
			return false;

//Convert file name.
	std::wstring FileNameString, ErrorMessage;
	if (FileName != nullptr)
	{
		FileNameString.append(L" in ");

	//Add line number.
		if (Line > 0)
			FileNameString.append(L"line %d of ");

	//Delete double backslash.
		FileNameString.append(FileName);
		while (FileNameString.find(L"\\\\") != std::wstring::npos)
			FileNameString.erase(FileNameString.find(L"\\\\"), wcslen(L"\\"));
	}

//Add log error type.
	switch (ErrorType)
	{
	//Message Notice
		case LOG_MESSAGE_NOTICE:
		{
			ErrorMessage.append(L"Notice: ");
			ErrorMessage.append(Message);

		//Copy file name and its line number to error log.
			if (!FileNameString.empty())
				ErrorMessage.append(FileNameString);

		//Add error code.
			if (ErrorCode == 0)
				ErrorMessage.append(L".\n");
			else 
				ErrorMessage.append(L", error code is %d.\n");
		}break;
	//System Error
	//About System Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx.
		case LOG_ERROR_SYSTEM:
		{
			ErrorMessage.append(L"System Error: ");
			ErrorMessage.append(Message);

		//Copy file name and its line number to error log.
			if (!FileNameString.empty())
				ErrorMessage.append(FileNameString);

		//Add error code.
			if (ErrorCode == 0)
				ErrorMessage.append(L".\n");
		#if defined(PLATFORM_WIN)
			else if (ErrorCode == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
				ErrorMessage.append(L", ERROR_FAILED_SERVICE_CONTROLLER_CONNECT(The service process could not connect to the service controller).\n");
		#endif
			else 
				ErrorMessage.append(L", error code is %d.\n");
		}break;
	//Parameter Error
		case LOG_ERROR_PARAMETER:
		{
			ErrorMessage.append(L"Parameter Error: ");
			ErrorMessage.append(Message);

		//Copy file name and its line number to error log.
			if (!FileNameString.empty())
				ErrorMessage.append(FileNameString);

		//Add error code.
			if (ErrorCode == 0)
				ErrorMessage.append(L".\n");
			else 
				ErrorMessage.append(L", error code is %d.\n");
		}break;
	//IPFilter Error
	//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
		case LOG_ERROR_IPFILTER:
		{
			ErrorMessage.append(L"IPFilter Error: ");
			ErrorMessage.append(Message);

		//Copy file name and its line number to error log.
			if (!FileNameString.empty())
				ErrorMessage.append(FileNameString);

		//Add error code.
			if (ErrorCode == 0)
				ErrorMessage.append(L".\n");
			else 
				ErrorMessage.append(L", error code is %d.\n");
		}break;
	//Hosts Error
	//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
		case LOG_ERROR_HOSTS:
		{
			ErrorMessage.append(L"Hosts Error: ");
			ErrorMessage.append(Message);

		//Copy file name and its line number to error log.
			if (!FileNameString.empty())
				ErrorMessage.append(FileNameString);

		//Add error code.
			if (ErrorCode == 0)
				ErrorMessage.append(L".\n");
			else 
				ErrorMessage.append(L", error code is %d.\n");
		}break;
	//Network Error
	//About Windows Sockets Error Codes, see http://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
		case LOG_ERROR_NETWORK:
		{
			ErrorMessage.append(L"Network Error: ");
			ErrorMessage.append(Message);

		//Copy file name and its line number to error log.
			if (!FileNameString.empty())
				ErrorMessage.append(FileNameString);

		//Add error code.
			if (ErrorCode == 0)
				ErrorMessage.append(L".\n");
		#if defined(PLATFORM_WIN)
			else if (ErrorCode == WSAENETUNREACH || //Block error messages when getting Network Unreachable error.
				ErrorCode == WSAEHOSTUNREACH) //Block error messages when getting Host Unreachable error.
					return true;
		#endif
			else 
				ErrorMessage.append(L", error code is %d.\n");
		}break;
	//WinPcap Error
	#if defined(ENABLE_PCAP)
		case LOG_ERROR_PCAP:
		{
			ErrorMessage.append(L"Pcap Error: ");
			ErrorMessage.append(Message);

		//Copy file name and its line number to error log.
			if (!FileNameString.empty())
				ErrorMessage.append(FileNameString);

/* There are no any error codes to be reported in LOG_ERROR_PCAP.
		//Add error code.
			if (ErrorCode == 0)
				ErrorMessage.append(L".\n");
			else 
				ErrorMessage.append(L", error code is %d.\n");
*/
			ErrorMessage.append(L"\n");
		}break;
	#endif
	//DNSCurve Error
	#if defined(ENABLE_LIBSODIUM)
		case LOG_ERROR_DNSCURVE:
		{
			ErrorMessage.append(L"DNSCurve Error: ");
			ErrorMessage.append(Message);

		//Copy file name and its line number to error log.
			if (!FileNameString.empty())
				ErrorMessage.append(FileNameString);

		//Add error code.
			if (ErrorCode == 0)
				ErrorMessage.append(L".\n");
			else 
				ErrorMessage.append(L", error code is %d.\n");
		}break;
	#endif
	//SOCKS Error
		case LOG_ERROR_SOCKS:
		{
			ErrorMessage.append(L"SOCKS Error: ");
			ErrorMessage.append(Message);

		//Copy file name and its line number to error log.
			if (!FileNameString.empty())
				ErrorMessage.append(FileNameString);

		//Add error code.
			if (ErrorCode == 0)
				ErrorMessage.append(L".\n");
			else 
				ErrorMessage.append(L", error code is %d.\n");
		}break;
	//HTTP Error
		case LOG_ERROR_HTTP:
		{
			ErrorMessage.append(L"HTTP Error: ");
			ErrorMessage.append(Message);

		//Copy file name and its line number to error log.
			if (!FileNameString.empty())
				ErrorMessage.append(FileNameString);

		//Add error code.
			if (ErrorCode == 0)
				ErrorMessage.append(L".\n");
			else 
				ErrorMessage.append(L", error code is %d.\n");
		}break;
		default:
		{
			return false;
		}
	}

//Print error log.
	return PrintScreenAndWriteFile(ErrorMessage, ErrorCode, Line);
}

//Print to screen and write to file
bool __fastcall PrintScreenAndWriteFile(
	const std::wstring Message, 
	const SSIZE_T ErrorCode, 
	const size_t Line)
{
//Get current date and time.
	auto TimeStructure = std::make_shared<tm>();
	memset(TimeStructure.get(), 0, sizeof(tm));
	auto TimeValues = time(nullptr);
#if defined(PLATFORM_WIN)
	if (localtime_s(TimeStructure.get(), &TimeValues) > 0)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (localtime_r(&TimeValues, TimeStructure.get()) == nullptr)
#endif
		return false;

//Print startup time at first printing.
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
		std::unique_lock<std::mutex> ScreenMutex(ScreenLock);

	//Print startup time.
		if (LogStartupTime > 0)
		{
			fwprintf_s(stderr, L"%d-%02d-%02d %02d:%02d:%02d -> Log opened at this moment.\n", 
				TimeStructure->tm_year + 1900, 
				TimeStructure->tm_mon + 1, 
				TimeStructure->tm_mday, 
				TimeStructure->tm_hour, 
				TimeStructure->tm_min, 
				TimeStructure->tm_sec);
		}

	//Print message.
		fwprintf_s(stderr, L"%d-%02d-%02d %02d:%02d:%02d -> ", 
			TimeStructure->tm_year + 1900, 
			TimeStructure->tm_mon + 1, 
			TimeStructure->tm_mday, 
			TimeStructure->tm_hour, 
			TimeStructure->tm_min, 
			TimeStructure->tm_sec);
		if (Line > 0 && ErrorCode > 0)
			fwprintf_s(stderr, Message.c_str(), Line, ErrorCode);
		else if (Line > 0)
			fwprintf_s(stderr, Message.c_str(), Line);
		else if (ErrorCode > 0)
			fwprintf_s(stderr, Message.c_str(), ErrorCode);
		else 
			fwprintf_s(stderr, Message.c_str());
	}

//Check whole file size.
	std::unique_lock<std::mutex> ErrorLogMutex(ErrorLogLock);

#if defined(PLATFORM_WIN)
	auto File_WIN32_FILE_ATTRIBUTE_DATA = std::make_shared<WIN32_FILE_ATTRIBUTE_DATA>();
	memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
	if (GetFileAttributesExW(GlobalRunningStatus.Path_ErrorLog->c_str(), GetFileExInfoStandard, File_WIN32_FILE_ATTRIBUTE_DATA.get()) != FALSE)
	{
		auto ErrorFileSize = std::make_shared<LARGE_INTEGER>();
		memset(ErrorFileSize.get(), 0, sizeof(LARGE_INTEGER));
		ErrorFileSize->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeHigh;
		ErrorFileSize->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeLow;
		if (ErrorFileSize->QuadPart > 0 && (size_t)ErrorFileSize->QuadPart >= Parameter.LogMaxSize)
		{
			if (DeleteFileW(GlobalRunningStatus.Path_ErrorLog->c_str()) != FALSE)
			{
				ErrorLogMutex.unlock();
				PrintError(LOG_ERROR_SYSTEM, L"Old error log file was deleted", 0, nullptr, 0);
				ErrorLogMutex.lock();
			}
			else {
				return false;
			}
		}
	}

	File_WIN32_FILE_ATTRIBUTE_DATA.reset();
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	auto FileStat = std::make_shared<struct stat>();
	memset(FileStat.get(), 0, sizeof(struct stat));
	if (stat(GlobalRunningStatus.sPath_ErrorLog->c_str(), FileStat.get()) == 0 && FileStat->st_size >= (off_t)Parameter.LogMaxSize)
	{
		if (remove(GlobalRunningStatus.sPath_ErrorLog->c_str()) == 0)
		{
			ErrorLogMutex.unlock();
			PrintError(LOG_ERROR_SYSTEM, L"Old error log file was deleted", 0, nullptr, 0);
			ErrorLogMutex.lock();
		}
		else {
			return false;
		}
	}

	FileStat.reset();
#endif

//Write to file.
#if defined(PLATFORM_WIN)
	FILE *Output = nullptr;
	if (_wfopen_s(&Output, GlobalRunningStatus.Path_ErrorLog->c_str(), L"a,ccs=UTF-8") == 0 && Output != nullptr)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	auto Output = fopen(GlobalRunningStatus.sPath_ErrorLog->c_str(), "a");
	if (Output != nullptr)
#endif
	{
	//Print startup time.
		if (LogStartupTime > 0)
		{
			fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> Log opened at this moment.\n", 
				TimeStructure->tm_year + 1900, 
				TimeStructure->tm_mon + 1, 
				TimeStructure->tm_mday, 
				TimeStructure->tm_hour, 
				TimeStructure->tm_min, 
				TimeStructure->tm_sec);
		}

	//Print message.
		fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> ", 
			TimeStructure->tm_year + 1900, 
			TimeStructure->tm_mon + 1, 
			TimeStructure->tm_mday, 
			TimeStructure->tm_hour, 
			TimeStructure->tm_min, 
			TimeStructure->tm_sec);
		if (Line > 0 && ErrorCode > 0)
			fwprintf_s(Output, Message.c_str(), Line, ErrorCode);
		else if (Line > 0)
			fwprintf_s(Output, Message.c_str(), Line);
		else if (ErrorCode > 0)
			fwprintf_s(Output, Message.c_str(), ErrorCode);
		else 
			fwprintf_s(Output, Message.c_str());

		fclose(Output);
	}
	else {
		return false;
	}

	return true;
}
