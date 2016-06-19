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


#include "Initialization.h"

//RFC domain and Base64 encoding/decoding table
static char DomainTable_Initialization[] = (".-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"); //Preferred name syntax(Section 2.3.1 in RFC 1035)
static char Base64_EncodeTable_Initialization[] = 
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 
	'w', 'x', 'y', 'z', '0', '1', '2', '3', 
	'4', '5', '6', '7', '8', '9', '+', '/'
};
/* Not necessary
static signed char Base64_DecodeTable_Initialization[] = //ASCII order for BASE 64 decode, -1 in unused character.
{
	'+', ',', '-', '.', '/', '0', '1', '2', 
	62,  -1,  -1,  -1,  63,  52,  53,  54, 
	'3', '4', '5', '6', '7', '8', '9', ':', 
	55,  56,  57,  58,  59,  60,  61,  -1, 
	';', '<', '=', '>', '?', '@', 'A', 'B', 
	-1,  -1,  -1,  -1,  -1,  -1,   0,  1, 
	'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
	2,   3,   4,   5,   6,   7,   8,   9, 
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 
	10,  11,  12,  13,  14,  15,  16,  17, 
	'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 
	18,  19,  20,  21,  22,  23,  24,  25, 
	'[', '\', ']', '^', '_', '`', 'a', 'b', 
	-1,  -1,  -1,  -1,  -1,  -1,  26,  27, 
	'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 
	28,  29,  30,  31,  32,  33,  34,  35, 
	'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 
	36,  37,  38,  39,  40,  41,  42,  43, 
	's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
	44,  45,  46,  47,  48,  49,  50,  51
};
*/

//ConfigurationTable class constructor
ConfigurationTable::ConfigurationTable(
	void)
{
	memset(this, 0, sizeof(CONFIGURATION_TABLE));
	try {
	//[Listen] block
	#if defined(ENABLE_PCAP)
		PcapDevicesBlacklist = new std::vector<std::string>();
	#endif
		ListenPort = new std::vector<uint16_t>();
		AcceptTypeList = new std::vector<uint16_t>();

	//[Addresses] block
		ListenAddress_IPv6 = new std::vector<sockaddr_storage>();
		ListenAddress_IPv4 = new std::vector<sockaddr_storage>();
		LocalhostSubnet.IPv6 = new ADDRESS_PREFIX_BLOCK();
		LocalhostSubnet.IPv4 = new ADDRESS_PREFIX_BLOCK();
		DNSTarget.IPv6_Multi = new std::vector<DNS_SERVER_DATA>();
		DNSTarget.IPv4_Multi = new std::vector<DNS_SERVER_DATA>();

	//[Data] block
	#if defined(ENABLE_PCAP)
		ICMP_PaddingData = new char[ICMP_PADDING_MAXSIZE]();
		DomainTest_Data = new char[DOMAIN_MAXSIZE]();
	#endif
		LocalFQDN_Response = new char[DOMAIN_MAXSIZE]();
		LocalFQDN_String = new std::string();
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		LocalServer_Response = new char[DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt)]();
	#endif

	//[Proxy] block
		SOCKS_TargetDomain = new std::string();
		SOCKS_Username = new std::string();
		SOCKS_Password = new std::string();
		HTTP_TargetDomain = new std::string();
		HTTP_Version = new std::string();
		HTTP_HeaderField = new std::string();
		HTTP_ProxyAuthorization = new std::string();
	}
	catch (std::bad_alloc)
	{
	//[Listen] block
	#if defined(ENABLE_PCAP)
		delete PcapDevicesBlacklist;
		PcapDevicesBlacklist = nullptr;
	#endif
		delete ListenPort;
		delete AcceptTypeList;
		ListenPort = nullptr;
		AcceptTypeList = nullptr;

	//[Addresses] block
		delete ListenAddress_IPv6;
		delete ListenAddress_IPv4;
		delete LocalhostSubnet.IPv6;
		delete LocalhostSubnet.IPv4;
		delete DNSTarget.IPv6_Multi;
		delete DNSTarget.IPv4_Multi;
		ListenAddress_IPv6 = nullptr;
		ListenAddress_IPv4 = nullptr;
		LocalhostSubnet.IPv6 = nullptr;
		LocalhostSubnet.IPv4 = nullptr;
		DNSTarget.IPv6_Multi = nullptr;
		DNSTarget.IPv4_Multi = nullptr;

	//[Data] block
	#if defined(ENABLE_PCAP)
		delete[] ICMP_PaddingData;
		delete[] DomainTest_Data;
		ICMP_PaddingData = nullptr;
		DomainTest_Data = nullptr;
	#endif
		delete[] LocalFQDN_Response;
		delete LocalFQDN_String;
		LocalFQDN_Response = nullptr;
		LocalFQDN_String = nullptr;
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		delete[] LocalServer_Response;
		LocalServer_Response = nullptr;
	#endif

	//[Proxy] block
		delete SOCKS_TargetDomain;
		delete SOCKS_Username;
		delete SOCKS_Password;
		delete HTTP_TargetDomain;
		delete HTTP_Version;
		delete HTTP_HeaderField;
		delete HTTP_ProxyAuthorization;
		SOCKS_TargetDomain = nullptr;
		SOCKS_Username = nullptr;
		SOCKS_Password = nullptr;
		HTTP_TargetDomain = nullptr;
		HTTP_Version = nullptr;
		HTTP_HeaderField = nullptr;
		HTTP_ProxyAuthorization = nullptr;

		exit(EXIT_FAILURE);
		return;
	}

	ConfigurationTableSetting(this);
	return;
}

//ConfigurationTable class constructor settings
void __fastcall ConfigurationTableSetting(
	ConfigurationTable *ConfigurationParameter)
{
//[Data] block
#if defined(ENABLE_PCAP)
	memset(ConfigurationParameter->ICMP_PaddingData, 0, ICMP_PADDING_MAXSIZE);
	memset(ConfigurationParameter->DomainTest_Data, 0, DOMAIN_MAXSIZE);
#endif
	memset(ConfigurationParameter->LocalFQDN_Response, 0, DOMAIN_MAXSIZE);
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	memset(ConfigurationParameter->LocalServer_Response, 0, DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt));
#endif

//Default values
	ConfigurationParameter->FileRefreshTime = DEFAULT_FILEREFRESH_TIME;
	ConfigurationParameter->LogMaxSize = DEFAULT_LOG_MAXSIZE;
#if defined(ENABLE_PCAP)
	ConfigurationParameter->PcapReadingTimeout = DEFAULT_PCAP_CAPTURE_TIMEOUT;
#endif
	ConfigurationParameter->HostsDefaultTTL = DEFAULT_HOSTS_TTL;
	ConfigurationParameter->BufferQueueSize = DEFAULT_BUFFER_QUEUE;
#if defined(PLATFORM_WIN)
	ConfigurationParameter->SocketTimeout_Reliable = DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	ConfigurationParameter->SocketTimeout_Unreliable = DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	ConfigurationParameter->SocketTimeout_Reliable.tv_sec = DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	ConfigurationParameter->SocketTimeout_Unreliable.tv_sec = DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
#endif
	ConfigurationParameter->AlternateTimes = DEFAULT_ALTERNATE_TIMES;
	ConfigurationParameter->AlternateTimeRange = DEFAULT_ALTERNATE_RANGE * SECOND_TO_MILLISECOND;
	ConfigurationParameter->AlternateResetTime = DEFAULT_ALTERNATE_RESET_TIME * SECOND_TO_MILLISECOND;
#if defined(ENABLE_PCAP)
	#if defined(PLATFORM_LINUX)
		ConfigurationParameter->DomainTest_ID = htons((uint16_t)pthread_self());
	#elif defined(PLATFORM_MACX)
		ConfigurationParameter->ICMP_ID = htons(*(uint16_t *)pthread_self());
	#else
		ConfigurationParameter->ICMP_ID = htons((uint16_t)GetCurrentProcessId()); //Default ICMP ID is current process ID.
	#endif
		ConfigurationParameter->ICMP_Sequence = htons(DEFAULT_SEQUENCE);
		ConfigurationParameter->DomainTest_Speed = DEFAULT_DOMAINTEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
	#if defined(PLATFORM_LINUX)
		ConfigurationParameter->DomainTest_ID = htons((uint16_t)pthread_self());
	#elif defined(PLATFORM_MACX)
		ConfigurationParameter->DomainTest_ID = htons(*(uint16_t *)pthread_self());
	#else
		ConfigurationParameter->DomainTest_ID = htons((uint16_t)GetCurrentProcessId()); //Default DNS ID is current process ID.
	#endif
	#if defined(PLATFORM_WIN)
		ConfigurationParameter->ICMP_PaddingLength = strlen(DEFAULT_ICMP_PADDING_DATA);
		memcpy_s(ConfigurationParameter->ICMP_PaddingData, ICMP_PADDING_MAXSIZE, DEFAULT_ICMP_PADDING_DATA, ConfigurationParameter->ICMP_PaddingLength); //Load default padding data.
	#elif defined(PLATFORM_LINUX)
		size_t CharData = ICMP_STRING_START_NUM_LINUX;
		for (size_t Index = 0;Index < ICMP_PADDING_LENGTH_LINUX;++Index, ++CharData)
			ConfigurationParameter->ICMP_PaddingData[Index] = CharData;
		ConfigurationParameter->ICMP_PaddingLength = strlen(ConfigurationParameter->ICMP_PaddingData);
	#elif defined(PLATFORM_MACX)
		size_t CharData = ICMP_STRING_START_NUM_MAC;
		for (size_t Index = 0;Index < ICMP_PADDING_LENGTH_MAC;++Index, ++CharData)
			ConfigurationParameter->ICMP_PaddingData[Index] = CharData;
		ConfigurationParameter->ICMP_PaddingLength = strlen(ConfigurationParameter->ICMP_PaddingData);
	#endif
#endif
	ConfigurationParameter->SOCKS_Protocol_Transport = REQUEST_MODE_TCP;
#if defined(PLATFORM_WIN)
	ConfigurationParameter->SOCKS_SocketTimeout_Reliable = DEFAULT_SOCKS_RELIABLE_SOCKET_TIMEOUT;
	ConfigurationParameter->SOCKS_SocketTimeout_Unreliable = DEFAULT_SOCKS_UNRELIABLE_SOCKET_TIMEOUT;
	ConfigurationParameter->HTTP_SocketTimeout = DEFAULT_HTTP_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	ConfigurationParameter->SOCKS_SocketTimeout_Reliable.tv_sec = DEFAULT_SOCKS_RELIABLE_SOCKET_TIMEOUT;
	ConfigurationParameter->SOCKS_SocketTimeout_Unreliable.tv_sec = DEFAULT_SOCKS_UNRELIABLE_SOCKET_TIMEOUT;
	ConfigurationParameter->HTTP_SocketTimeout.tv_sec = DEFAULT_HTTP_SOCKET_TIMEOUT;
#endif

	return;
}

//ConfigurationTable class destructor
ConfigurationTable::~ConfigurationTable(
	void)
{
//[Listen] block
#if defined(ENABLE_PCAP)
	delete PcapDevicesBlacklist;
	PcapDevicesBlacklist = nullptr;
#endif
	delete ListenPort;
	delete AcceptTypeList;
	ListenPort = nullptr;
	AcceptTypeList = nullptr;

//[Addresses] block
	delete ListenAddress_IPv6;
	delete ListenAddress_IPv4;
	delete LocalhostSubnet.IPv6;
	delete LocalhostSubnet.IPv4;
	delete DNSTarget.IPv6_Multi;
	delete DNSTarget.IPv4_Multi;
	ListenAddress_IPv6 = nullptr;
	ListenAddress_IPv4 = nullptr;
	LocalhostSubnet.IPv6 = nullptr;
	LocalhostSubnet.IPv4 = nullptr;
	DNSTarget.IPv6_Multi = nullptr;
	DNSTarget.IPv4_Multi = nullptr;

//[Data] block
#if defined(ENABLE_PCAP)
	delete[] ICMP_PaddingData;
	delete[] DomainTest_Data;
	ICMP_PaddingData = nullptr;
	DomainTest_Data = nullptr;
#endif
	delete[] LocalFQDN_Response;
	delete LocalFQDN_String;
	LocalFQDN_Response = nullptr;
	LocalFQDN_String = nullptr;
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	delete[] LocalServer_Response;
	LocalServer_Response = nullptr;
#endif

//[Proxy] block
	delete SOCKS_TargetDomain;
	delete SOCKS_Username;
	delete SOCKS_Password;
	delete HTTP_TargetDomain;
	delete HTTP_Version;
	delete HTTP_HeaderField;
	delete HTTP_ProxyAuthorization;
	SOCKS_TargetDomain = nullptr;
	SOCKS_Username = nullptr;
	SOCKS_Password = nullptr;
	HTTP_TargetDomain = nullptr;
	HTTP_Version = nullptr;
	HTTP_HeaderField = nullptr;
	HTTP_ProxyAuthorization = nullptr;

	return;
}

//ConfigurationTable class SetToMonitorItem function
void ConfigurationTable::SetToMonitorItem(
	void)
{
//[Listen] block
#if defined(ENABLE_PCAP)
	delete PcapDevicesBlacklist;
	PcapDevicesBlacklist = nullptr;
#endif
	delete ListenPort;
	ListenPort = nullptr;

//[Addresses] block
	delete ListenAddress_IPv6;
	delete ListenAddress_IPv4;
	delete LocalhostSubnet.IPv6;
	delete LocalhostSubnet.IPv4;
	delete DNSTarget.IPv6_Multi;
	delete DNSTarget.IPv4_Multi;
	ListenAddress_IPv6 = nullptr;
	ListenAddress_IPv4 = nullptr;
	LocalhostSubnet.IPv6 = nullptr;
	LocalhostSubnet.IPv4 = nullptr;
	DNSTarget.IPv6_Multi = nullptr;
	DNSTarget.IPv4_Multi = nullptr;

//[Data] block
#if defined(ENABLE_PCAP)
	delete[] ICMP_PaddingData;
	delete[] DomainTest_Data;
	ICMP_PaddingData = nullptr;
	DomainTest_Data = nullptr;
#endif
	delete[] LocalFQDN_Response;
	delete LocalFQDN_String;
	LocalFQDN_Response = nullptr;
	LocalFQDN_String = nullptr;
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	delete[] LocalServer_Response;
	LocalServer_Response = nullptr;
#endif

//Reset pointers.
//[Listen] block
#if defined(ENABLE_PCAP)
	PcapDevicesBlacklist = nullptr;
#endif
	ListenPort = nullptr;
//[Addresses] block
	ListenAddress_IPv6 = nullptr;
	ListenAddress_IPv4 = nullptr;
	LocalhostSubnet.IPv6 = nullptr;
	LocalhostSubnet.IPv4 = nullptr;
	DNSTarget.IPv6_Multi = nullptr;
	DNSTarget.IPv4_Multi = nullptr;
//[Data] block
#if defined(ENABLE_PCAP)
	ICMP_PaddingData = nullptr;
	DomainTest_Data = nullptr;
#endif
	LocalFQDN_Response = nullptr;
	LocalFQDN_String = nullptr;
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	LocalServer_Response = nullptr;
#endif

	return;
}

//ConfigurationTable class MonitorItemToUsing function
void ConfigurationTable::MonitorItemToUsing(
	ConfigurationTable *ConfigurationParameter)
{
//[Base] block
	ConfigurationParameter->Version = Version;
	ConfigurationParameter->FileRefreshTime = FileRefreshTime;

//[Log] block
	ConfigurationParameter->PrintLogLevel = PrintLogLevel;
	ConfigurationParameter->LogMaxSize = LogMaxSize;

//[Listen] block
	ConfigurationParameter->IPFilterType = IPFilterType;
	ConfigurationParameter->IPFilterLevel = IPFilterLevel;
	ConfigurationParameter->AcceptType = AcceptType;
	ConfigurationParameter->AcceptTypeList->swap(*AcceptTypeList);

//[DNS] block
	ConfigurationParameter->DirectRequest = DirectRequest;
	ConfigurationParameter->HostsDefaultTTL = HostsDefaultTTL;

//[Local DNS] block
	ConfigurationParameter->LocalProtocol_Network = LocalProtocol_Network;
	ConfigurationParameter->LocalProtocol_Transport = LocalProtocol_Transport;
	ConfigurationParameter->LocalForce = LocalForce;

//[Values] block
#if defined(ENABLE_PCAP)
	ConfigurationParameter->DNSTarget.IPv4.HopLimitData.TTL = DNSTarget.IPv4.HopLimitData.TTL;
	ConfigurationParameter->DNSTarget.IPv6.HopLimitData.HopLimit = DNSTarget.IPv6.HopLimitData.HopLimit;
	ConfigurationParameter->DNSTarget.Alternate_IPv4.HopLimitData.TTL = DNSTarget.Alternate_IPv4.HopLimitData.TTL;
	ConfigurationParameter->DNSTarget.Alternate_IPv6.HopLimitData.HopLimit = DNSTarget.Alternate_IPv6.HopLimitData.HopLimit;
#endif
	ConfigurationParameter->SocketTimeout_Reliable = SocketTimeout_Reliable;
	ConfigurationParameter->SocketTimeout_Unreliable = SocketTimeout_Unreliable;
	ConfigurationParameter->ReceiveWaiting = ReceiveWaiting;
#if defined(ENABLE_PCAP)
	ConfigurationParameter->ICMP_Speed = ICMP_Speed;
	ConfigurationParameter->DomainTest_Speed = DomainTest_Speed;
#endif
	ConfigurationParameter->MultiRequestTimes = MultiRequestTimes;

//[Switches] block
	ConfigurationParameter->DomainCaseConversion = DomainCaseConversion;
#if defined(ENABLE_PCAP)
	ConfigurationParameter->HeaderCheck_IPv4 = HeaderCheck_IPv4;
	ConfigurationParameter->HeaderCheck_TCP = HeaderCheck_TCP;
#endif
	ConfigurationParameter->HeaderCheck_DNS = HeaderCheck_DNS;

//[Proxy] block
	ConfigurationParameter->SOCKS_SocketTimeout_Reliable = SOCKS_SocketTimeout_Reliable;
	ConfigurationParameter->SOCKS_SocketTimeout_Unreliable = SOCKS_SocketTimeout_Unreliable;
	if (ConfigurationParameter->SOCKS_TargetDomain != nullptr && !SOCKS_TargetDomain->empty() && SOCKS_TargetDomain_Port > 0)
	{
	//Reset old items.
		memset(&ConfigurationParameter->SOCKS_TargetServer, 0, sizeof(ADDRESS_UNION_DATA));
		
	//Copy new items.
		*ConfigurationParameter->SOCKS_TargetDomain = *SOCKS_TargetDomain;
		ConfigurationParameter->SOCKS_TargetDomain_Port = SOCKS_TargetDomain_Port;
	}
	else if (SOCKS_TargetServer.Storage.ss_family > 0)
	{
	//Reset old items.
		if (ConfigurationParameter->SOCKS_TargetDomain != nullptr)
			ConfigurationParameter->SOCKS_TargetDomain->clear();
		ConfigurationParameter->SOCKS_TargetDomain_Port = 0;

	//Copy new items.
		memcpy_s(&ConfigurationParameter->SOCKS_TargetServer, sizeof(ADDRESS_UNION_DATA), &SOCKS_TargetServer, sizeof(ADDRESS_UNION_DATA));
	}
	if (ConfigurationParameter->SOCKS_Username != nullptr)
	{
		if (!SOCKS_Username->empty())
			*ConfigurationParameter->SOCKS_Username = *SOCKS_Username;
		else 
			ConfigurationParameter->SOCKS_Username->clear();
	}
	if (ConfigurationParameter->SOCKS_Password != nullptr)
	{
		if (!SOCKS_Password->empty())
			*ConfigurationParameter->SOCKS_Password = *SOCKS_Password;
		else 
			ConfigurationParameter->SOCKS_Password->clear();
	}
	ConfigurationParameter->HTTP_SocketTimeout = HTTP_SocketTimeout;
	if (ConfigurationParameter->HTTP_TargetDomain != nullptr && !HTTP_TargetDomain->empty())
		*ConfigurationParameter->HTTP_TargetDomain = *HTTP_TargetDomain;
	if (ConfigurationParameter->HTTP_Version != nullptr && !HTTP_Version->empty())
		*ConfigurationParameter->HTTP_Version = *HTTP_Version;
	if (ConfigurationParameter->HTTP_HeaderField != nullptr)
	{
		if (!HTTP_HeaderField->empty())
			*ConfigurationParameter->HTTP_HeaderField = *HTTP_HeaderField;
		else 
			ConfigurationParameter->HTTP_HeaderField->clear();
	}
	if (ConfigurationParameter->HTTP_ProxyAuthorization != nullptr)
	{
		if (!HTTP_ProxyAuthorization->empty())
			*ConfigurationParameter->HTTP_ProxyAuthorization = *HTTP_ProxyAuthorization;
		else 
			ConfigurationParameter->HTTP_ProxyAuthorization->clear();
	}

	return;
}

//ConfigurationTable class MonitorItemReset function
void ConfigurationTable::MonitorItemReset(
	void)
{
//[Base] block
	Version = 0;
	FileRefreshTime = DEFAULT_FILEREFRESH_TIME;

//[Log] block
	PrintLogLevel = DEFAULT_LOG_LEVEL;
	LogMaxSize = DEFAULT_LOG_MAXSIZE;

//[Listen] block
	IPFilterType = 0;
	IPFilterLevel = 0;
	AcceptType = false;
	AcceptTypeList->clear();
	AcceptTypeList->shrink_to_fit();

//[DNS] block
	DirectRequest = false;
	HostsDefaultTTL = DEFAULT_HOSTS_TTL;

//[Local DNS] block
	LocalProtocol_Network = 0;
	LocalProtocol_Transport = 0;
	LocalForce = false;

//[Values] block
#if defined(ENABLE_PCAP)
	DNSTarget.IPv4.HopLimitData.TTL = 0;
	DNSTarget.IPv6.HopLimitData.HopLimit = 0;
	DNSTarget.Alternate_IPv4.HopLimitData.TTL = 0;
	DNSTarget.Alternate_IPv6.HopLimitData.HopLimit = 0;
#endif
#if defined(PLATFORM_WIN)
	SocketTimeout_Reliable = DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	SocketTimeout_Unreliable = DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	SocketTimeout_Reliable.tv_sec = DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	SocketTimeout_Reliable.tv_usec = 0;
	SocketTimeout_Unreliable.tv_sec = DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
	SocketTimeout_Unreliable.tv_usec = 0;
#endif
	ReceiveWaiting = 0;
#if defined(ENABLE_PCAP)
	ICMP_Speed = 0;
	DomainTest_Speed = DEFAULT_DOMAINTEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
#endif
	MultiRequestTimes = 0;

//[Switches] block
	DomainCaseConversion = false;
#if defined(ENABLE_PCAP)
	HeaderCheck_IPv4 = false;
	HeaderCheck_TCP = false;
#endif
	HeaderCheck_DNS = false;

//[Proxy] block
#if defined(PLATFORM_WIN)
	SOCKS_SocketTimeout_Reliable = DEFAULT_SOCKS_RELIABLE_SOCKET_TIMEOUT;
	SOCKS_SocketTimeout_Unreliable = DEFAULT_SOCKS_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	SOCKS_SocketTimeout_Reliable.tv_sec = DEFAULT_SOCKS_RELIABLE_SOCKET_TIMEOUT;
	SOCKS_SocketTimeout_Reliable.tv_usec = 0;
	SOCKS_SocketTimeout_Unreliable.tv_sec = DEFAULT_SOCKS_UNRELIABLE_SOCKET_TIMEOUT;
	SOCKS_SocketTimeout_Unreliable.tv_usec = 0;
#endif
	memset(&SOCKS_TargetServer, 0, sizeof(ADDRESS_UNION_DATA));
	if (SOCKS_TargetDomain != nullptr)
		SOCKS_TargetDomain->clear();
	SOCKS_TargetDomain_Port = 0;
	if (SOCKS_Username != nullptr)
		SOCKS_Username->clear();
	if (SOCKS_Password != nullptr)
		SOCKS_Password->clear();
#if defined(PLATFORM_WIN)
	HTTP_SocketTimeout = DEFAULT_HTTP_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	HTTP_SocketTimeout.tv_sec = DEFAULT_HTTP_SOCKET_TIMEOUT;
	HTTP_SocketTimeout.tv_usec = 0;
#endif
	HTTP_TargetDomain->clear();
	HTTP_Version->clear();
	HTTP_HeaderField->clear();
	HTTP_ProxyAuthorization->clear();

	return;
}

//GlobalStatus class constructor
GlobalStatus::GlobalStatus(
	void)
{
	memset(this, 0, sizeof(GLOBAL_STATUS));
	try {
		LocalListeningSocket = new std::vector<SYSTEM_SOCKET>();
		RamdomEngine = new std::default_random_engine();
		Path_Global = new std::vector<std::wstring>();
		Path_ErrorLog = new std::wstring();
		FileList_Hosts = new std::vector<std::wstring>();
		FileList_IPFilter = new std::vector<std::wstring>();
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		sPath_Global = new std::vector<std::string>();
		sPath_ErrorLog = new std::string();
		sFileList_Hosts = new std::vector<std::string>();
		sFileList_IPFilter = new std::vector<std::string>();
	#endif
		LocalAddress_Response[0] = new char[PACKET_MAXSIZE]();
		LocalAddress_Response[1U] = new char[PACKET_MAXSIZE]();
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		LocalAddress_ResponsePTR[0] = new std::vector<std::string>();
		LocalAddress_ResponsePTR[1U] = new std::vector<std::string>();
	#endif
	}
	catch (std::bad_alloc)
	{
		delete LocalListeningSocket;
		delete RamdomEngine;
		delete Path_Global;
		delete Path_ErrorLog;
		delete FileList_Hosts;
		delete FileList_IPFilter;
		LocalListeningSocket = nullptr;
		RamdomEngine = nullptr;
		Path_Global = nullptr;
		Path_ErrorLog = nullptr;
		FileList_Hosts = nullptr;
		FileList_IPFilter = nullptr;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		delete sPath_Global;
		delete sPath_ErrorLog;
		delete sFileList_Hosts;
		delete sFileList_IPFilter;
		sPath_Global = nullptr;
		sPath_ErrorLog = nullptr;
		sFileList_Hosts = nullptr;
		sFileList_IPFilter = nullptr;
	#endif
		delete[] LocalAddress_Response[0];
		delete[] LocalAddress_Response[1U];
		LocalAddress_Response[0] = nullptr;
		LocalAddress_Response[1U] = nullptr;
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		delete LocalAddress_ResponsePTR[0];
		delete LocalAddress_ResponsePTR[1U];
		LocalAddress_ResponsePTR[0] = nullptr;
		LocalAddress_ResponsePTR[1U] = nullptr;
	#endif

		exit(EXIT_FAILURE);
		return;
	}

	GlobalStatusSetting(this);
	return;
}

//GlobalStatus class constructor settings
void __fastcall GlobalStatusSetting(
	GlobalStatus *GlobalRunningStatusParameter)
{
#if defined(PLATFORM_LINUX)
	GlobalRunningStatusParameter->Daemon = true;
#endif
	std::random_device RamdomDevice;
	GlobalRunningStatusParameter->RamdomEngine->seed(RamdomDevice());
	GlobalRunningStatusParameter->DomainTable = DomainTable_Initialization;
	GlobalRunningStatusParameter->Base64_EncodeTable = Base64_EncodeTable_Initialization;
//	GlobalRunningStatusParameter->Base64_DecodeTable = Base64_DecodeTable_Initialization;
	GlobalRunningStatusParameter->GatewayAvailable_IPv4 = true;
	memset(GlobalRunningStatusParameter->LocalAddress_Response[0], 0, PACKET_MAXSIZE);
	memset(GlobalRunningStatusParameter->LocalAddress_Response[1U], 0, PACKET_MAXSIZE);

	return;
}

//GlobalStatus class destructor
GlobalStatus::~GlobalStatus(
	void)
{
//Close all sockets.
	for (auto SocketIter:*LocalListeningSocket)
	{
		shutdown(SocketIter, SD_BOTH);
		closesocket(SocketIter);
	}

//Close all file handles and WinSock cleanup.
#if defined(PLATFORM_WIN)
	_fcloseall();
	if (Initialization_WinSock)
		WSACleanup();
#elif (defined(PLATFORM_LINUX) && !defined(PLATFORM_OPENWRT))
	fcloseall();
#endif

//Free pointer.
	delete LocalListeningSocket;
	delete RamdomEngine;
	delete Path_Global;
	delete Path_ErrorLog;
	delete FileList_Hosts;
	delete FileList_IPFilter;
	LocalListeningSocket = nullptr;
	RamdomEngine = nullptr;
	Path_Global = nullptr;
	Path_ErrorLog = nullptr;
	FileList_Hosts = nullptr;
	FileList_IPFilter = nullptr;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	delete sPath_Global;
	delete sPath_ErrorLog;
	delete sFileList_Hosts;
	delete sFileList_IPFilter;
	sPath_Global = nullptr;
	sPath_ErrorLog = nullptr;
	sFileList_Hosts = nullptr;
	sFileList_IPFilter = nullptr;
#endif
	delete[] LocalAddress_Response[0];
	delete[] LocalAddress_Response[1U];
	LocalAddress_Response[0] = nullptr;
	LocalAddress_Response[1U] = nullptr;
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	delete LocalAddress_ResponsePTR[0];
	delete LocalAddress_ResponsePTR[1U];
	LocalAddress_ResponsePTR[0] = nullptr;
	LocalAddress_ResponsePTR[1U] = nullptr;
#endif

	return;
}

//AddressRangeTable class constructor
AddressRangeTable::AddressRangeTable(
	void)
{
	memset(this, 0, sizeof(ADDRESS_RANGE_TABLE));
	return;
}

//HostsTable class constructor
HostsTable::HostsTable(
	void)
{
	PermissionType = 0;
	PermissionOperation = false;

	return;
}

//AlternateSwapTable class constructor
AlternateSwapTable::AlternateSwapTable(
	void)
{
	memset(this, 0, sizeof(ALTERNATE_SWAP_TABLE));
	return;
}

//AddressRoutingTable class constructor
AddressRoutingTable::AddressRoutingTable(
	void)
{
	Prefix = 0;
	return;
}

//InputPacketTable class constructor
#if defined(ENABLE_PCAP)
OutputPacketTable::OutputPacketTable(
	void)
{
//Initialization
	memset(&SocketData_Input, 0, sizeof(SOCKET_DATA));
	Protocol_Network = 0;
	Protocol_Transport = 0;
	ClearPortTime = 0;
	ReceiveIndex = 0;

	return;
}
#endif

//DiffernetFileSetIPFilter class constructor
DiffernetFileSetIPFilter::DiffernetFileSetIPFilter(
	void)
{
	FileIndex = 0;
	return;
}

//DiffernetFileSetHosts class constructor
DiffernetFileSetHosts::DiffernetFileSetHosts(
	void)
{
	FileIndex = 0;
	return;
}

#if defined(ENABLE_LIBSODIUM)
//DNSCurveConfigurationTable class constructor
DNSCurveConfigurationTable::DNSCurveConfigurationTable(
	void)
{
//Libsodium initialization
	if (sodium_init() == LIBSODIUM_ERROR)
	{
		exit(EXIT_FAILURE);
		return;
	}

//Class constructor
	memset(this, 0, sizeof(DNSCURVE_CONFIGURATION_TABLE));
	try {
	//DNSCurve Provider Names
		DNSCurveTarget.IPv4.ProviderName = new char[DOMAIN_MAXSIZE]();
		DNSCurveTarget.Alternate_IPv4.ProviderName = new char[DOMAIN_MAXSIZE]();
		DNSCurveTarget.IPv6.ProviderName = new char[DOMAIN_MAXSIZE]();
		DNSCurveTarget.Alternate_IPv6.ProviderName = new char[DOMAIN_MAXSIZE]();

	//DNSCurve Keys
		Client_PublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		Client_SecretKey = (uint8_t *)sodium_malloc(crypto_box_SECRETKEYBYTES);
		DNSCurveTarget.IPv4.PrecomputationKey = (uint8_t *)sodium_malloc(crypto_box_BEFORENMBYTES);
		DNSCurveTarget.Alternate_IPv4.PrecomputationKey = (uint8_t *)sodium_malloc(crypto_box_BEFORENMBYTES);
		DNSCurveTarget.IPv6.PrecomputationKey = (uint8_t *)sodium_malloc(crypto_box_BEFORENMBYTES);
		DNSCurveTarget.Alternate_IPv6.PrecomputationKey = (uint8_t *)sodium_malloc(crypto_box_BEFORENMBYTES);
		DNSCurveTarget.IPv4.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurveTarget.Alternate_IPv4.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurveTarget.IPv6.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurveTarget.Alternate_IPv6.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurveTarget.IPv4.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurveTarget.Alternate_IPv4.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurveTarget.IPv6.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurveTarget.Alternate_IPv6.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();

	//DNSCurve Magic Numbers
		DNSCurveTarget.IPv4.ReceiveMagicNumber = new char[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber = new char[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurveTarget.IPv6.ReceiveMagicNumber = new char[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber = new char[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurveTarget.IPv4.SendMagicNumber = new char[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurveTarget.Alternate_IPv4.SendMagicNumber = new char[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurveTarget.IPv6.SendMagicNumber = new char[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurveTarget.Alternate_IPv6.SendMagicNumber = new char[DNSCURVE_MAGIC_QUERY_LEN]();
	}
	catch (std::bad_alloc)
	{
	//DNSCurve Provider Names
		delete[] DNSCurveTarget.IPv4.ProviderName;
		delete[] DNSCurveTarget.Alternate_IPv4.ProviderName;
		delete[] DNSCurveTarget.IPv6.ProviderName;
		delete[] DNSCurveTarget.Alternate_IPv6.ProviderName;
		DNSCurveTarget.IPv4.ProviderName = nullptr;
		DNSCurveTarget.Alternate_IPv4.ProviderName = nullptr;
		DNSCurveTarget.IPv6.ProviderName = nullptr;
		DNSCurveTarget.Alternate_IPv6.ProviderName = nullptr;

	//DNSCurve Keys
		delete[] Client_PublicKey;
		sodium_free(Client_SecretKey);
		sodium_free(DNSCurveTarget.IPv4.PrecomputationKey);
		sodium_free(DNSCurveTarget.Alternate_IPv4.PrecomputationKey);
		sodium_free(DNSCurveTarget.IPv6.PrecomputationKey);
		sodium_free(DNSCurveTarget.Alternate_IPv6.PrecomputationKey);
		delete[] DNSCurveTarget.IPv4.ServerPublicKey;
		delete[] DNSCurveTarget.Alternate_IPv4.ServerPublicKey;
		delete[] DNSCurveTarget.IPv6.ServerPublicKey;
		delete[] DNSCurveTarget.Alternate_IPv6.ServerPublicKey;
		delete[] DNSCurveTarget.IPv4.ServerFingerprint;
		delete[] DNSCurveTarget.Alternate_IPv4.ServerFingerprint;
		delete[] DNSCurveTarget.IPv6.ServerFingerprint;
		delete[] DNSCurveTarget.Alternate_IPv6.ServerFingerprint;
		Client_PublicKey = nullptr;
		Client_SecretKey = nullptr;
		DNSCurveTarget.IPv4.PrecomputationKey = nullptr;
		DNSCurveTarget.Alternate_IPv4.PrecomputationKey = nullptr;
		DNSCurveTarget.IPv6.PrecomputationKey = nullptr;
		DNSCurveTarget.Alternate_IPv6.PrecomputationKey = nullptr;
		DNSCurveTarget.IPv4.ServerPublicKey = nullptr;
		DNSCurveTarget.Alternate_IPv4.ServerPublicKey = nullptr;
		DNSCurveTarget.IPv6.ServerPublicKey = nullptr;
		DNSCurveTarget.Alternate_IPv6.ServerPublicKey = nullptr;
		DNSCurveTarget.IPv4.ServerFingerprint = nullptr;
		DNSCurveTarget.Alternate_IPv4.ServerFingerprint = nullptr;
		DNSCurveTarget.IPv6.ServerFingerprint = nullptr;
		DNSCurveTarget.Alternate_IPv6.ServerFingerprint = nullptr;

	//DNSCurve Magic Numbers
		delete[] DNSCurveTarget.IPv4.ReceiveMagicNumber;
		delete[] DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber;
		delete[] DNSCurveTarget.IPv6.ReceiveMagicNumber;
		delete[] DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber;
		delete[] DNSCurveTarget.IPv4.SendMagicNumber;
		delete[] DNSCurveTarget.Alternate_IPv4.SendMagicNumber;
		delete[] DNSCurveTarget.IPv6.SendMagicNumber;
		delete[] DNSCurveTarget.Alternate_IPv6.SendMagicNumber;
		DNSCurveTarget.IPv4.ReceiveMagicNumber = nullptr;
		DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber = nullptr;
		DNSCurveTarget.IPv6.ReceiveMagicNumber = nullptr;
		DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber = nullptr;
		DNSCurveTarget.IPv4.SendMagicNumber = nullptr;
		DNSCurveTarget.Alternate_IPv4.SendMagicNumber = nullptr;
		DNSCurveTarget.IPv6.SendMagicNumber = nullptr;
		DNSCurveTarget.Alternate_IPv6.SendMagicNumber = nullptr;

		exit(EXIT_FAILURE);
		return;
	}

	DNSCurveConfigurationTableSetting(this);
	return;
}

//DNSCurveConfigurationTable class constructor settings
void __fastcall DNSCurveConfigurationTableSetting(
	DNSCurveConfigurationTable *DNSCurveConfigurationParameter)
{
//DNSCurve Provider Names
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ProviderName, DOMAIN_MAXSIZE);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ProviderName, DOMAIN_MAXSIZE);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ProviderName, DOMAIN_MAXSIZE);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ProviderName, DOMAIN_MAXSIZE);

//DNSCurve Keys
	sodium_memzero(DNSCurveConfigurationParameter->Client_PublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->Client_SecretKey, crypto_box_SECRETKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);

//DNSCurve Magic Numbers
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);

//Default settings
#if defined(PLATFORM_WIN)
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Reliable = DEFAULT_DNSCURVE_RELIABLE_SOCKET_TIMEOUT;
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Unreliable = DEFAULT_DNSCURVE_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Reliable.tv_sec = DEFAULT_DNSCURVE_RELIABLE_SOCKET_TIMEOUT;
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Unreliable.tv_sec = DEFAULT_DNSCURVE_UNRELIABLE_SOCKET_TIMEOUT;
#endif
	DNSCurveConfigurationParameter->KeyRecheckTime = DEFAULT_DNSCURVE_RECHECK_TIME * SECOND_TO_MILLISECOND;

	return;
}

//DNSCurveConfigurationTable class destructor
DNSCurveConfigurationTable::~DNSCurveConfigurationTable(
	void)
{
//DNSCurve Provider Names
	delete[] DNSCurveTarget.IPv4.ProviderName;
	delete[] DNSCurveTarget.Alternate_IPv4.ProviderName;
	delete[] DNSCurveTarget.IPv6.ProviderName;
	delete[] DNSCurveTarget.Alternate_IPv6.ProviderName;
	DNSCurveTarget.IPv4.ProviderName = nullptr;
	DNSCurveTarget.Alternate_IPv4.ProviderName = nullptr;
	DNSCurveTarget.IPv6.ProviderName = nullptr;
	DNSCurveTarget.Alternate_IPv6.ProviderName = nullptr;

//DNSCurve Keys
	delete[] Client_PublicKey;
	sodium_free(Client_SecretKey);
	sodium_free(DNSCurveTarget.IPv4.PrecomputationKey);
	sodium_free(DNSCurveTarget.Alternate_IPv4.PrecomputationKey);
	sodium_free(DNSCurveTarget.IPv6.PrecomputationKey);
	sodium_free(DNSCurveTarget.Alternate_IPv6.PrecomputationKey);
	delete[] DNSCurveTarget.IPv4.ServerPublicKey;
	delete[] DNSCurveTarget.Alternate_IPv4.ServerPublicKey;
	delete[] DNSCurveTarget.IPv6.ServerPublicKey;
	delete[] DNSCurveTarget.Alternate_IPv6.ServerPublicKey;
	delete[] DNSCurveTarget.IPv4.ServerFingerprint;
	delete[] DNSCurveTarget.Alternate_IPv4.ServerFingerprint;
	delete[] DNSCurveTarget.IPv6.ServerFingerprint;
	delete[] DNSCurveTarget.Alternate_IPv6.ServerFingerprint;
	Client_PublicKey = nullptr;
	Client_SecretKey = nullptr;
	DNSCurveTarget.IPv4.PrecomputationKey = nullptr;
	DNSCurveTarget.Alternate_IPv4.PrecomputationKey = nullptr;
	DNSCurveTarget.IPv6.PrecomputationKey = nullptr;
	DNSCurveTarget.Alternate_IPv6.PrecomputationKey = nullptr;
	DNSCurveTarget.IPv4.ServerPublicKey = nullptr;
	DNSCurveTarget.Alternate_IPv4.ServerPublicKey = nullptr;
	DNSCurveTarget.IPv6.ServerPublicKey = nullptr;
	DNSCurveTarget.Alternate_IPv6.ServerPublicKey = nullptr;
	DNSCurveTarget.IPv4.ServerFingerprint = nullptr;
	DNSCurveTarget.Alternate_IPv4.ServerFingerprint = nullptr;
	DNSCurveTarget.IPv6.ServerFingerprint = nullptr;
	DNSCurveTarget.Alternate_IPv6.ServerFingerprint = nullptr;

//DNSCurve Magic Numbers
	delete[] DNSCurveTarget.IPv4.ReceiveMagicNumber;
	delete[] DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber;
	delete[] DNSCurveTarget.IPv6.ReceiveMagicNumber;
	delete[] DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber;
	delete[] DNSCurveTarget.IPv4.SendMagicNumber;
	delete[] DNSCurveTarget.Alternate_IPv4.SendMagicNumber;
	delete[] DNSCurveTarget.IPv6.SendMagicNumber;
	delete[] DNSCurveTarget.Alternate_IPv6.SendMagicNumber;
	DNSCurveTarget.IPv4.ReceiveMagicNumber = nullptr;
	DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber = nullptr;
	DNSCurveTarget.IPv6.ReceiveMagicNumber = nullptr;
	DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber = nullptr;
	DNSCurveTarget.IPv4.SendMagicNumber = nullptr;
	DNSCurveTarget.Alternate_IPv4.SendMagicNumber = nullptr;
	DNSCurveTarget.IPv6.SendMagicNumber = nullptr;
	DNSCurveTarget.Alternate_IPv6.SendMagicNumber = nullptr;

	return;
}

//DNSCurveConfigurationTable class SetToMonitorItem function
void DNSCurveConfigurationTable::SetToMonitorItem(
	void)
{
//Delete pointers.
	delete[] DNSCurveTarget.IPv4.ProviderName;
	delete[] DNSCurveTarget.Alternate_IPv4.ProviderName;
	delete[] DNSCurveTarget.IPv6.ProviderName;
	delete[] DNSCurveTarget.Alternate_IPv6.ProviderName;

//Reset pointers.
	DNSCurveTarget.IPv4.ProviderName = nullptr;
	DNSCurveTarget.Alternate_IPv4.ProviderName = nullptr;
	DNSCurveTarget.IPv6.ProviderName = nullptr;
	DNSCurveTarget.Alternate_IPv6.ProviderName = nullptr;

	return;
}

//DNSCurveConfigurationTable class MonitorItemToUsing function
void DNSCurveConfigurationTable::MonitorItemToUsing(
	DNSCurveConfigurationTable *DNSCurveConfigurationParameter)
{
//[DNSCurve] block
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Reliable = DNSCurve_SocketTimeout_Reliable;
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Unreliable = DNSCurve_SocketTimeout_Unreliable;
	DNSCurveConfigurationParameter->KeyRecheckTime = KeyRecheckTime;

//DNSCurve Keys
	if (DNSCurveConfigurationParameter->Client_PublicKey != nullptr && !CheckEmptyBuffer(Client_PublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->Client_PublicKey, Client_PublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->Client_PublicKey, crypto_box_PUBLICKEYBYTES, Client_PublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->Client_SecretKey != nullptr && !CheckEmptyBuffer(Client_SecretKey, crypto_box_PUBLICKEYBYTES) && 
		sodium_memcmp(DNSCurveConfigurationParameter->Client_SecretKey, Client_SecretKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->Client_SecretKey, crypto_box_PUBLICKEYBYTES, Client_SecretKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerPublicKey, DNSCurveTarget.IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurveTarget.IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerPublicKey, DNSCurveTarget.Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurveTarget.Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerPublicKey, DNSCurveTarget.IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurveTarget.IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerPublicKey, DNSCurveTarget.Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurveTarget.Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);

//DNSCurve Magic Numbers
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);

	return;
}

//DNSCurveConfigurationTable class MonitorItemReset function
void DNSCurveConfigurationTable::MonitorItemReset(
	void)
{
//[DNSCurve] block
#if defined(PLATFORM_WIN)
	DNSCurve_SocketTimeout_Reliable = DEFAULT_DNSCURVE_RELIABLE_SOCKET_TIMEOUT;
	DNSCurve_SocketTimeout_Unreliable = DEFAULT_DNSCURVE_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	DNSCurve_SocketTimeout_Reliable.tv_sec = DEFAULT_DNSCURVE_RELIABLE_SOCKET_TIMEOUT;
	DNSCurve_SocketTimeout_Reliable.tv_usec = 0;
	DNSCurve_SocketTimeout_Unreliable.tv_sec = DEFAULT_DNSCURVE_UNRELIABLE_SOCKET_TIMEOUT;
	DNSCurve_SocketTimeout_Unreliable.tv_usec = 0;
#endif
	KeyRecheckTime = DEFAULT_DNSCURVE_RECHECK_TIME * SECOND_TO_MILLISECOND;

//DNSCurve Keys
	if (Client_PublicKey != nullptr)
		sodium_memzero(Client_PublicKey, crypto_box_PUBLICKEYBYTES);
	if (Client_SecretKey != nullptr)
		sodium_memzero(Client_SecretKey, crypto_box_SECRETKEYBYTES);
	if (DNSCurveTarget.IPv4.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurveTarget.IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveTarget.Alternate_IPv4.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurveTarget.Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveTarget.IPv6.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurveTarget.IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveTarget.Alternate_IPv6.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurveTarget.Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveTarget.IPv4.ServerPublicKey != nullptr)
		sodium_memzero(DNSCurveTarget.IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.Alternate_IPv4.ServerPublicKey != nullptr)
		sodium_memzero(DNSCurveTarget.Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.IPv6.ServerPublicKey != nullptr)
		sodium_memzero(DNSCurveTarget.IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.Alternate_IPv6.ServerPublicKey != nullptr)
		sodium_memzero(DNSCurveTarget.Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.IPv4.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurveTarget.IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.Alternate_IPv4.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurveTarget.Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.IPv6.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurveTarget.IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.Alternate_IPv6.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurveTarget.Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);

//DNSCurve Magic Numbers
	if (DNSCurveTarget.IPv4.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurveTarget.IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.IPv6.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurveTarget.IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.IPv4.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurveTarget.IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.Alternate_IPv4.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurveTarget.Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.IPv6.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurveTarget.IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.Alternate_IPv6.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurveTarget.Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);

	return;
}
#endif
