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
bool PrintError(
	const size_t ErrorLevel, 
	const size_t ErrorType, 
	const wchar_t *Message, 
	const ssize_t ErrorCode, 
	const wchar_t *FileName, 
	const size_t Line)
{
//Print log level check, parameter check, message check and file name check
	if (Parameter.PrintLogLevel == LOG_LEVEL_0 || ErrorLevel > Parameter.PrintLogLevel || 
		Message == nullptr || CheckEmptyBuffer(Message, sizeof(wchar_t) * wcsnlen_s(Message, ORIGINAL_PACKET_MAXSIZE)) || 
		(FileName != nullptr && CheckEmptyBuffer(FileName, sizeof(wchar_t) * wcsnlen_s(FileName, ORIGINAL_PACKET_MAXSIZE))))
			return false;

//Convert file name.
	std::wstring FileNameString, ErrorMessage;
	if (FileName != nullptr)
	{
	//Add file name and line number.
		FileNameString.append(L" in ");
		if (Line > 0)
			FileNameString.append(L"line %d of ");

	//Delete double backslash.
		FileNameString.append(FileName);
	#if defined(PLATFORM_WIN)
		while (FileNameString.find(L"\\\\") != std::wstring::npos)
			FileNameString.erase(FileNameString.find(L"\\\\"), wcslen(L"\\"));
	#endif
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
	//About System Error Codes, see https://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx.
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
	//About Windows Sockets Error Codes, see https://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
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
	//About Windows Sockets Error Codes, see https://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
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
	//About Windows Sockets Error Codes, see https://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
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
bool PrintScreenAndWriteFile(
	const std::wstring Message, 
	const ssize_t ErrorCode, 
	const size_t Line)
{
//Get current date and time.
	tm TimeStructure;
	memset(&TimeStructure, 0, sizeof(TimeStructure));
	auto TimeValues = time(nullptr);
#if defined(PLATFORM_WIN)
	if (localtime_s(&TimeStructure, &TimeValues) > 0)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (localtime_r(&TimeValues, &TimeStructure) == nullptr)
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
	//Print startup time.
		if (LogStartupTime > 0)
		{
			PrintToScreen(true, L"%d-%02d-%02d %02d:%02d:%02d -> Log opened at this moment.\n", 
				TimeStructure.tm_year + 1900, 
				TimeStructure.tm_mon + 1, 
				TimeStructure.tm_mday, 
				TimeStructure.tm_hour, 
				TimeStructure.tm_min, 
				TimeStructure.tm_sec);
		}

	//Print message.
		std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
		PrintToScreen(false, L"%d-%02d-%02d %02d:%02d:%02d -> ", 
			TimeStructure.tm_year + 1900, 
			TimeStructure.tm_mon + 1, 
			TimeStructure.tm_mday, 
			TimeStructure.tm_hour, 
			TimeStructure.tm_min, 
			TimeStructure.tm_sec);
		if (Line > 0 && ErrorCode > 0)
			PrintToScreen(false, Message.c_str(), Line, ErrorCode);
		else if (Line > 0)
			PrintToScreen(false, Message.c_str(), Line);
		else if (ErrorCode > 0)
			PrintToScreen(false, Message.c_str(), ErrorCode);
		else 
			PrintToScreen(false, Message.c_str());
	}

//Check whole file size.
	auto IsFileDeleted = false;
	std::lock_guard<std::mutex> ErrorLogMutex(ErrorLogLock);
#if defined(PLATFORM_WIN)
	WIN32_FILE_ATTRIBUTE_DATA FileAttributeData;
	memset(&FileAttributeData, 0, sizeof(FileAttributeData));
	if (GetFileAttributesExW(GlobalRunningStatus.Path_ErrorLog->c_str(), GetFileExInfoStandard, &FileAttributeData) != FALSE)
	{
		LARGE_INTEGER ErrorFileSize;
		memset(&ErrorFileSize, 0, sizeof(ErrorFileSize));
		ErrorFileSize.HighPart = FileAttributeData.nFileSizeHigh;
		ErrorFileSize.LowPart = FileAttributeData.nFileSizeLow;
		if (ErrorFileSize.QuadPart > 0 && (size_t)ErrorFileSize.QuadPart >= Parameter.LogMaxSize)
		{
			if (DeleteFileW(GlobalRunningStatus.Path_ErrorLog->c_str()) != FALSE)
				IsFileDeleted = true;
			else 
				return false;
		}
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	struct stat FileStatData;
	memset(&FileStatData, 0, sizeof(FileStatData));
	if (stat(GlobalRunningStatus.sPath_ErrorLog->c_str(), &FileStatData) == 0 && FileStatData.st_size >= (off_t)Parameter.LogMaxSize)
	{
		if (remove(GlobalRunningStatus.sPath_ErrorLog->c_str()) == 0)
			IsFileDeleted = true;
		else 
			return false;
	}
#endif

//Write to file.
#if defined(PLATFORM_WIN)
	FILE *FileHandle = nullptr;
	if (_wfopen_s(&FileHandle, GlobalRunningStatus.Path_ErrorLog->c_str(), L"a,ccs=UTF-8") == 0 && FileHandle != nullptr)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	auto FileHandle = fopen(GlobalRunningStatus.sPath_ErrorLog->c_str(), "a");
	if (FileHandle != nullptr)
#endif
	{
	//Print startup time.
		if (LogStartupTime > 0)
		{
			fwprintf_s(FileHandle, L"%d-%02d-%02d %02d:%02d:%02d -> Log opened at this moment.\n", 
				TimeStructure.tm_year + 1900, 
				TimeStructure.tm_mon + 1, 
				TimeStructure.tm_mday, 
				TimeStructure.tm_hour, 
				TimeStructure.tm_min, 
				TimeStructure.tm_sec);
		}

	//Print old file deleted message.
		if (IsFileDeleted)
		{
			fwprintf_s(FileHandle, L"%d-%02d-%02d %02d:%02d:%02d -> Notice: Old log file was deleted.\n", 
				TimeStructure.tm_year + 1900, 
				TimeStructure.tm_mon + 1, 
				TimeStructure.tm_mday, 
				TimeStructure.tm_hour, 
				TimeStructure.tm_min, 
				TimeStructure.tm_sec);
		}

	//Print main message.
		fwprintf_s(FileHandle, L"%d-%02d-%02d %02d:%02d:%02d -> ", 
			TimeStructure.tm_year + 1900, 
			TimeStructure.tm_mon + 1, 
			TimeStructure.tm_mday, 
			TimeStructure.tm_hour, 
			TimeStructure.tm_min, 
			TimeStructure.tm_sec);
		if (Line > 0 && ErrorCode > 0)
			fwprintf_s(FileHandle, Message.c_str(), Line, ErrorCode);
		else if (Line > 0)
			fwprintf_s(FileHandle, Message.c_str(), Line);
		else if (ErrorCode > 0)
			fwprintf_s(FileHandle, Message.c_str(), ErrorCode);
		else 
			fwprintf_s(FileHandle, Message.c_str());

		fclose(FileHandle);
	}
	else {
		return false;
	}

	return true;
}

//Print words to screen.
void PrintToScreen(
	const bool IsInnerLock, 
	const wchar_t *Format, 
	...
)
{
//Initialization
	va_list ArgList;
	memset(&ArgList, 0, sizeof(ArgList));
	va_start(ArgList, Format);

//Print data to screen.
	if (IsInnerLock)
	{
		std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
		vfwprintf_s(stderr, Format, ArgList);
	}
	else {
		vfwprintf_s(stderr, Format, ArgList);
	}

//Cleanup
	va_end(ArgList);
	return;
}

//Print error of reading text
void ReadTextPrintLog(
	const size_t InputType, 
	const size_t FileIndex, 
	const size_t Line)
{
	switch (InputType)
	{
		case READ_TEXT_HOSTS: //ReadHosts
		{
			PrintError(LOG_LEVEL_2, LOG_ERROR_HOSTS, L"Data of a line is too short", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		}break;
		case READ_TEXT_IPFILTER: //ReadIPFilter
		{
			PrintError(LOG_LEVEL_2, LOG_ERROR_IPFILTER, L"Data of a line is too short", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
		}break;
		case READ_TEXT_PARAMETER: //ReadParameter
		{
			PrintError(LOG_LEVEL_2, LOG_ERROR_PARAMETER, L"Data of a line is too short", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		}break;
		case READ_TEXT_PARAMETER_MONITOR: //ReadParameter(Monitor mode)
		{
			PrintError(LOG_LEVEL_2, LOG_ERROR_PARAMETER, L"Data of a line is too short", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		}break;
	}

	return;
}

#if defined(ENABLE_LIBSODIUM)
//DNSCurve print error of servers
void DNSCurvePrintLog(
	const size_t ServerType, 
	std::wstring &Message)
{
	Message.clear();
	switch (ServerType)
	{
		case DNSCURVE_MAIN_IPV6:
		{
			Message = L"IPv6 Main Server ";
		}break;
		case DNSCURVE_MAIN_IPV4:
		{
			Message = L"IPv4 Main Server ";
		}break;
		case DNSCURVE_ALTERNATE_IPV6:
		{
			Message = L"IPv6 Alternate Server ";
		}break;
		case DNSCURVE_ALTERNATE_IPV4:
		{
			Message = L"IPv4 Alternate Server ";
		}break;
	}

	return;
}
#endif
