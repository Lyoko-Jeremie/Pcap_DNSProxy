// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on packet capturing
// Copyright (C) 2012-2019 Chengr28
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


#ifndef PCAP_DNSPROXY_INCLUDE_H
#define PCAP_DNSPROXY_INCLUDE_H

#include "Template.h"

//////////////////////////////////////////////////
// Global function
// 
//Buffer.cpp
bool CheckEmptyBuffer(
	const void * const Buffer, 
	const size_t Length);
void GenerateRandomBuffer(
	void * const BufferPointer, 
	const size_t BufferSize, 
	const void * Distribution, 
	const uint64_t Lower, 
	const uint64_t Upper);
/*	uint32_t GetFCS(
	const uint8_t *Buffer, 
	const size_t Length);
*/
size_t GetDomainNameLength(
	const uint8_t * const NameBuffer, 
	const size_t MaxSize);
bool PacketQueryToString(
	const uint8_t * const PacketBuffer, 
	const size_t PacketLength, 
	const uint8_t * const PacketName, 
	const size_t NameLength, 
	std::vector<uint16_t> * PointerAlreadyUse, 
	std::string &StringName);
size_t GetStringToDomainSize(
	const size_t StringLength);

//Destructor.cpp
void ReleaseTemporaryResource(
	GLOBAL_STATUS * const Reference);

//Environment.cpp
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
uint64_t IncreaseMillisecondTime(
	const uint64_t CurrentTime, 
	const timeval IncreaseTime);
uint64_t GetCurrentSystemTime(
	void);
#endif
bool CheckLibraryVersion(
	void);
bool LoadPathFileName(
	void);
bool SetScreenBuffer(
	void);
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
bool SetProgramDaemon(
	void);
#endif
#if defined(PLATFORM_WIN)
bool FileNameInit(
	const std::wstring &OriginalPath, 
	const bool IsStartupLoad, 
	const bool IsRewriteLogFile);
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool FileNameInit(
	const std::string &OriginalPath, 
	const bool IsStartupLoad, 
	const bool IsRewriteLogFile);
#endif
bool SetConsoleStartupTime(
	void);
#if defined(PLATFORM_WIN)
bool LoadWinsock(
	void);
bool SystemSecurityInit(
	const ACL * const ACL_Buffer, 
	SECURITY_ATTRIBUTES &SecurityAttributes, 
	SECURITY_DESCRIPTOR &SecurityDescriptor, 
	PSID &SID_Value);
#endif
bool CheckProcessUnique(
	void);
bool SetSignalHandler(
	void);
#if defined(PLATFORM_WIN)
BOOL WINAPI HandleSignal(
	const DWORD ControlType);
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
void HandleSignal(
	const int SignalType);
#endif
#if defined(PLATFORM_WIN)
bool FirewallTest(
	const uint16_t Protocol, 
	ssize_t &ErrorCode);
#endif

//File.cpp
ssize_t DeleteFullSizeFile(
#if defined(PLATFORM_WIN)
	const std::wstring &PathFileName, 
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	const std::string &PathFileName, 
#endif
	const uint64_t FullSize, 
	bool * const IsFileDeleted);

//Monitor.cpp
void GeneralMonitorLauncher(
	void);
void FlushDomainCache_Process(
	const uint8_t * const Domain);
#if defined(PLATFORM_WIN)
bool FlushDomainCache_MailslotListener(
	void);
bool WINAPI FlushDomainCache_MailslotSender(
	const wchar_t * const Domain);
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool FlushDomainCache_PipeListener(
	void);
bool FlushDomainCache_PipeSender(
	const uint8_t * const Domain);
#endif

//Network.cpp
bool SetSocketAttribute(
	SYSTEM_SOCKET &Socket, 
	const SOCKET_SETTING_TYPE SettingType, 
	const bool IsPrintError, 
	void * const DataPointer);

//PrintLog.cpp
void PrintToScreen(
	const bool IsInnerLock, 
	const bool IsStandardOut, 
	const wchar_t * const Format, 
	...
);
void ErrorCodeToMessage(
	const LOG_ERROR_TYPE ErrorType, 
	const ssize_t ErrorCode, 
	std::wstring &Message);
bool PrintError(
	const LOG_LEVEL_TYPE ErrorLevel, 
	const LOG_ERROR_TYPE ErrorType, 
	const wchar_t * const Message, 
	const ssize_t ErrorCode, 
	const wchar_t * const FileName, 
	const size_t Line);
bool WriteMessageToStream(
	const std::wstring &Message, 
	const ssize_t ErrorCode, 
	const size_t Line);

//ReadCommand.cpp
#if defined(PLATFORM_WIN)
bool ReadCommand(
	int argc, 
	wchar_t * argv[]);
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool ReadCommand(
	int argc, 
	char * argv[]);
#endif

//ReadConfiguration.cpp
/* Temporary Disabled
bool ReadConfiguration(
	const bool IsFirstRead);
*/

//Service.cpp
bool LoadService(
	void);

//Text.cpp
bool MBS_To_WCS_String(
	const uint8_t * const Buffer, 
	const size_t BufferSize, 
	std::wstring &Target);
bool WCS_To_MBS_String(
	const wchar_t * const Buffer, 
	const size_t BufferSize, 
	std::string &Target);
bool IsDigit(
	const uint8_t Character);
bool IsDigit(
	const wchar_t Character);
/* Temporary Disabled
bool IsAlphabetic(
	const uint8_t Character);
bool IsAlphabetic(
	const wchar_t Character);
*/
void CaseConvert(
	uint8_t * const Buffer, 
	const size_t Length, 
	const bool IsLowerToUpper);
void CaseConvert(
	std::string &Buffer, 
	const bool IsLowerToUpper);
void CaseConvert(
	std::wstring &Buffer, 
	const bool IsLowerToUpper);
void GetItemFromString(
	std::vector<std::string> &ItemData, 
	const std::string &WholeString, 
	const size_t DataOffset, 
	const size_t Length, 
	const uint8_t SeparatedSign, 
	const bool IsCaseConvert, 
	const bool IsKeepEmptyItem);
void GetItemFromString(
	std::vector<std::wstring> &ItemData, 
	const std::wstring &WholeString, 
	const size_t DataOffset, 
	const size_t Length, 
	const uint8_t SeparatedSign, 
	const bool IsCaseConvert, 
	const bool IsKeepEmptyItem);
bool CheckDomainAcceptable(
	const std::string &DomainString);
bool CheckDomainAcceptable(
	const std::wstring &DomainString);
#endif
