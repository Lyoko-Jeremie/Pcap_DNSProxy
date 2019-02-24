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


#ifndef PCAP_DNSPROXY_CLASS_H
#define PCAP_DNSPROXY_CLASS_H

#include "Type.h"

//////////////////////////////////////////////////
// Class definition
// 
typedef class GlobalStatus
{
public:
//Library initialization status
#if defined(PLATFORM_WIN)
	bool                                                                        IsLoad_WinSock;
#endif

//Startup status
	time_t                                                                      StartupTime;
#if defined(PLATFORM_WIN)
	bool                                                                        IsConsole;
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
	bool                                                                        IsDaemon;
#endif

//Running status
	std::atomic<bool>                                                           *IsNeedExit;
	std::default_random_engine                                                  *RandomEngine;
/* Temporary Disabled
	std::vector<FILE_DATA>                                                      *FileList_Config;
	std::vector<FILE_DATA>                                                      *FileList_IPFilter;
	std::vector<FILE_DATA>                                                      *FileList_Hosts;
	std::list<DNS_CACHE_DATA>                                                   *DNSCacheList;
	std::unordered_multimap<std::string, std::list<DNS_CACHE_DATA>::iterator>   *DNSCacheIndexMap;
*/

//Mutex status
#if defined(PLATFORM_WIN)
	HANDLE                                                                      MutexHandle;
	SECURITY_ATTRIBUTES                                                         MutexSecurityAttributes;
	SECURITY_DESCRIPTOR                                                         MutexSecurityDescriptor;
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	int                                                                         MutexHandle;
#endif
	std::mutex                                                                  *ScreenLock;
/* Temporary Disabled
	std::mutex                                                                  *DNSCacheLock;
*/

//Path list and file list
	std::vector<std::wstring>                                                   *Path_Global_WCS;
	std::wstring                                                                *Path_ErrorLog_WCS;
	std::vector<std::wstring>                                                   *FileList_Hosts_WCS;
	std::vector<std::wstring>                                                   *FileList_IPFilter_WCS;
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::vector<std::string>                                                    *Path_Global_MBS;
	std::string                                                                 *Path_ErrorLog_MBS;
	std::vector<std::string>                                                    *FileList_Hosts_MBS;
	std::vector<std::string>                                                    *FileList_IPFilter_MBS;
#endif

//Network status


//Local address status


//Redefine operator function
//	GlobalStatus() = default;
	GlobalStatus(const GlobalStatus &) = delete;
	GlobalStatus & operator=(const GlobalStatus &) = delete;

//Member function(Public)
	GlobalStatus(
		void);
//	GlobalStatus(
//		const GlobalStatus &Reference);
//	GlobalStatus & operator=(
//		const GlobalStatus &Reference);
	~GlobalStatus(
		void);

//Member function(Private)
//private:
//	void CopyMemberOperator(
//		const GlobalStatus &Reference);
}GLOBAL_STATUS;

typedef class ConfigurationTable
{
//Parameters from configure files
public:
//[Base] block
	size_t                               FileRefreshTime;
	size_t                               LargeBufferSize;

//[Log] block
	LOG_LEVEL_TYPE                       PrintLogLevel;
	size_t                               LogMaxSize;

//[Listen] block
	bool                                 IsProcessUnique;

//[Value] block
#if defined(PLATFORM_WIN)
	DWORD                                PacketHopLimits_IPv6_Begin;
	DWORD                                PacketHopLimits_IPv6_End;
	DWORD                                PacketHopLimits_IPv4_Begin;
	DWORD                                PacketHopLimits_IPv4_End;
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	int                                  PacketHopLimits_IPv6_Begin;
	int                                  PacketHopLimits_IPv6_End;
	int                                  PacketHopLimits_IPv4_Begin;
	int                                  PacketHopLimits_IPv4_End;
#endif
#if defined(PLATFORM_WIN)
	DWORD                                SocketTimeout_Reliable_Once;
	DWORD                                SocketTimeout_Reliable_Serial;
	DWORD                                SocketTimeout_Unreliable_Once;
	DWORD                                SocketTimeout_Unreliable_Serial;
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	timeval                              SocketTimeout_Reliable_Once;
	timeval                              SocketTimeout_Reliable_Serial;
	timeval                              SocketTimeout_Unreliable_Once;
	timeval                              SocketTimeout_Unreliable_Serial;
#endif
	size_t                               TCP_FastOpen;

//[Switch] block
	bool                                 DoNotFragment_IPv4;

//Redefine operator function
//	ConfigurationTable() = default;
	ConfigurationTable(const ConfigurationTable &) = delete;
	ConfigurationTable &operator=(const ConfigurationTable &) = delete;

//Member function(Public)
	ConfigurationTable(
		void);
//	ConfigurationTable(
//		const ConfigurationTable &Reference);
//	ConfigurationTable & operator=(
//		const ConfigurationTable &Reference);
	void SetToAlternate(
		void);
	~ConfigurationTable(
		void);

//Member function(Private)
//private:
//	void CopyMemberOperator(
//		const ConfigurationTable &Reference);
}CONFIGURATION_TABLE;

typedef class SocketValueTable
{
public:
	std::vector<SOCKET_DATA>                  ValueSet;

//Redefine operator functions
	SocketValueTable() = default;
	SocketValueTable(const SocketValueTable &) = delete;
	SocketValueTable & operator=(const SocketValueTable &) = delete;

//Member functions
//	SocketValueTable(
//		void);
	bool SocketValueInit(
		const uint16_t SocketNetwork, 
		const uint16_t SocketType, 
		const uint16_t SocketTransport, 
		const uint16_t SocketPort, 
		const void * const SocketAddress, 
		ssize_t * const ErrorCode);
	void ClearAllSocket(
		const bool IsPrintError);
	~SocketValueTable(
		void);
}SOCKET_VALUE_TABLE;

typedef class DNS_PacketTable
{
public:
//Pararmeter of packet
	bool                                       IsNeedWriteEDNS;

private:
//Packet structure
	uint16_t                                   PacketID;
	uint16_t                                   PacketFlags;
	std::vector<DNS_PACKET_QUESTION>           PacketQuestion;
	std::vector<DNS_PACKET_RECORD>             PacketAnswer;
	std::vector<DNS_PACKET_RECORD>             PacketAuthority;
	std::vector<DNS_PACKET_RECORD>             PacketAdditional;
	std::vector<DNS_PACKET_EXTENSION_RECORD>   PacketExtension;

//Packet data storage
	std::unique_ptr<uint8_t[]>                 StorageBuffer;
	size_t                                     StorageSize;
	size_t                                     StorageLength;

//Redefine operator functions
public:
//	DNS_PacketTable() = default;
	DNS_PacketTable(const DNS_PacketTable &) = delete;
	DNS_PacketTable & operator=(const DNS_PacketTable &) = delete;

//Member function(Public)
	DNS_PacketTable(
		void);
	bool IsEmpty(
		void);
	bool IsVaild(
		const bool IsResponse);
	bool WritePacketToTable(
		const uint8_t * const PacketBuffer, 
		const size_t PacketLength);
	size_t GetTableBufferLength(
		bool IsTCP);
	void GetTableHeader(
		uint16_t &UpdatePacketID, 
		uint16_t &UpdatePacketFlags);
	void UpdateTableHeader(
		const uint16_t UpdatePacketID, 
		const uint16_t UpdatePacketFlags);
	void GetTableQuestion(
		std::string &QuestionName, 
		uint16_t &QuestionType, 
		uint16_t &QuestionClass);
	bool UpdateTableQuestion(
		const uint8_t * const QuestionName, 
		const uint16_t QuestionType, 
		const uint16_t QuestionClass);
	void AddRecordToTable(
		const DNS_RECORD_SECTION RecordSection, 
		DNS_PACKET_RECORD RecordHeader, 
		const uint8_t * const RecordData);
	bool RemoveRecordFromTable(
		const DNS_RECORD_SECTION RecordSection, 
		const size_t RecordIndex);
	bool GetTableExtension(
		DNS_PACKET_EXTENSION_RECORD &ExtensionHeader, 
		uint8_t * const OptionData, 
		const size_t OptionSize);
	void UpdateTableExtension(
		DNS_PACKET_EXTENSION_RECORD ExtensionHeader, 
		const uint8_t * const OptionData);
	size_t WriteTableToPacket(
		uint8_t * const TargetBuffer, 
		const size_t TargetSize, 
		const bool IsTCP);
	void ClearTable(
		void);
//	~DNS_PacketTable(
//		void);

//Member function(Private)
private:
	void ExpandStorage(
		const size_t TargetSize);
	bool RebuildStorage(
		void);
}DNS_PACKET_TABLE;
#endif
