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
static const uint8_t DomainTable_Initialization[] = (".-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"); //Preferred name syntax(Section 2.3.1 in RFC 1035)
static const uint8_t Base64_EncodeTable_Initialization[] = 
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

/* ASCII order for BASE 64 decode, -1 in unused character.
static const int8_t Base64_DecodeTable_Initialization[] = 
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
		LocalMachineSubnet_IPv6 = new ADDRESS_PREFIX_BLOCK();
		LocalMachineSubnet_IPv4 = new ADDRESS_PREFIX_BLOCK();
		Target_Server_IPv6_Multiple = new std::vector<DNS_SERVER_DATA>();
		Target_Server_IPv4_Multiple = new std::vector<DNS_SERVER_DATA>();

	//[Data] block
	#if defined(ENABLE_PCAP)
		ICMP_PaddingData = new uint8_t[ICMP_PADDING_MAXSIZE]();
		DomainTest_Data = new uint8_t[DOMAIN_MAXSIZE]();
	#endif
		LocalFQDN_Response = new uint8_t[DOMAIN_MAXSIZE]();
		LocalFQDN_String = new std::string();
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		LocalServer_Response = new uint8_t[DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt)]();
	#endif

	//[Proxy] block
		SOCKS_TargetDomain = new std::string();
		SOCKS_Username = new std::string();
		SOCKS_Password = new std::string();
	#if defined(ENABLE_TLS)
		HTTP_CONNECT_TLS_SNI = new std::wstring();
		sHTTP_CONNECT_TLS_SNI = new std::string();
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			HTTP_CONNECT_TLS_AddressString_IPv4 = new std::string();
			HTTP_CONNECT_TLS_AddressString_IPv6 = new std::string();
		#endif
	#endif
		HTTP_CONNECT_TargetDomain = new std::string();
		HTTP_CONNECT_Version = new std::string();
		HTTP_CONNECT_HeaderField = new std::string();
		HTTP_CONNECT_ProxyAuthorization = new std::string();
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
		delete LocalMachineSubnet_IPv6;
		delete LocalMachineSubnet_IPv4;
		delete Target_Server_IPv6_Multiple;
		delete Target_Server_IPv4_Multiple;
		ListenAddress_IPv6 = nullptr;
		ListenAddress_IPv4 = nullptr;
		LocalMachineSubnet_IPv6 = nullptr;
		LocalMachineSubnet_IPv4 = nullptr;
		Target_Server_IPv6_Multiple = nullptr;
		Target_Server_IPv4_Multiple = nullptr;

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
	#if defined(ENABLE_TLS)
		delete HTTP_CONNECT_TLS_SNI;
		delete sHTTP_CONNECT_TLS_SNI;
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			delete HTTP_CONNECT_TLS_AddressString_IPv4;
			delete HTTP_CONNECT_TLS_AddressString_IPv6;
		#endif
	#endif
		delete HTTP_CONNECT_TargetDomain;
		delete HTTP_CONNECT_Version;
		delete HTTP_CONNECT_HeaderField;
		delete HTTP_CONNECT_ProxyAuthorization;
		SOCKS_TargetDomain = nullptr;
		SOCKS_Username = nullptr;
		SOCKS_Password = nullptr;
	#if defined(ENABLE_TLS)
		HTTP_CONNECT_TLS_SNI = nullptr;
		sHTTP_CONNECT_TLS_SNI = nullptr;
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;
			HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
		#endif
	#endif
		HTTP_CONNECT_TargetDomain = nullptr;
		HTTP_CONNECT_Version = nullptr;
		HTTP_CONNECT_HeaderField = nullptr;
		HTTP_CONNECT_ProxyAuthorization = nullptr;

		exit(EXIT_FAILURE);
		return;
	}

	ConfigurationTableSetting(this);
	return;
}

//ConfigurationTable class constructor settings
void ConfigurationTableSetting(
	CONFIGURATION_TABLE * const ConfigurationParameter)
{
//Initialization
#if defined(ENABLE_PCAP)
	memset(ConfigurationParameter->ICMP_PaddingData, 0, ICMP_PADDING_MAXSIZE);
	memset(ConfigurationParameter->DomainTest_Data, 0, DOMAIN_MAXSIZE);
#endif
	memset(ConfigurationParameter->LocalFQDN_Response, 0, DOMAIN_MAXSIZE);
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	memset(ConfigurationParameter->LocalServer_Response, 0, DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt));
#endif

//Default value settings
	//[Base] block
	ConfigurationParameter->FileRefreshTime = DEFAULT_FILEREFRESH_TIME;
	ConfigurationParameter->LargeBufferSize = DEFAULT_LARGE_BUFFER_SIZE;

	//[Log] block
	ConfigurationParameter->PrintLogLevel = DEFAULT_LOG_LEVEL;
	ConfigurationParameter->LogMaxSize = LOG_READING_MAXSIZE;

	//[Listen] block
#if defined(ENABLE_PCAP)
	ConfigurationParameter->PcapReadingTimeout = DEFAULT_PCAP_CAPTURE_TIMEOUT;
#endif
	ConfigurationParameter->ListenProtocol_Network = LISTEN_PROTOCOL_NETWORK_BOTH;
	ConfigurationParameter->ListenProtocol_Transport = LISTEN_PROTOCOL_TRANSPORT_BOTH;
	ConfigurationParameter->OperationMode = LISTEN_MODE_PROXY;

	//[DNS] block
	ConfigurationParameter->RequestMode_Network = REQUEST_MODE_BOTH;
	ConfigurationParameter->RequestMode_Transport = REQUEST_MODE_UDP;
	ConfigurationParameter->DirectRequest = REQUEST_MODE_DIRECT_NONE;
	ConfigurationParameter->CacheType = CACHE_TYPE_NONE;
	ConfigurationParameter->HostsDefaultTTL = DEFAULT_HOSTS_TTL;

	//[Local DNS] block
	ConfigurationParameter->LocalProtocol_Network = REQUEST_MODE_BOTH;
	ConfigurationParameter->LocalProtocol_Transport = REQUEST_MODE_UDP;

	//[Values] block
	ConfigurationParameter->ThreadPoolBaseNum = DEFAULT_THREAD_POOL_BASENUM;
	ConfigurationParameter->ThreadPoolMaxNum = DEFAULT_THREAD_POOL_MAXNUM;
	ConfigurationParameter->ThreadPoolResetTime = DEFAULT_THREAD_POOL_RESET_TIME;
	ConfigurationParameter->EDNSPayloadSize = EDNS_PACKET_MINSIZE;
#if defined(PLATFORM_WIN)
	ConfigurationParameter->SocketTimeout_Reliable_Once = DEFAULT_RELIABLE_ONCE_SOCKET_TIMEOUT;
	ConfigurationParameter->SocketTimeout_Reliable_Serial = DEFAULT_RELIABLE_SERIAL_SOCKET_TIMEOUT;
	ConfigurationParameter->SocketTimeout_Unreliable_Once = DEFAULT_UNRELIABLE_ONCE_SOCKET_TIMEOUT;
	ConfigurationParameter->SocketTimeout_Unreliable_Serial = DEFAULT_UNRELIABLE_SERIAL_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	ConfigurationParameter->SocketTimeout_Reliable_Once.tv_sec = DEFAULT_RELIABLE_ONCE_SOCKET_TIMEOUT / SECOND_TO_MILLISECOND;
	ConfigurationParameter->SocketTimeout_Reliable_Once.tv_usec = DEFAULT_RELIABLE_ONCE_SOCKET_TIMEOUT % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	ConfigurationParameter->SocketTimeout_Reliable_Serial.tv_sec = DEFAULT_RELIABLE_SERIAL_SOCKET_TIMEOUT / SECOND_TO_MILLISECOND;
	ConfigurationParameter->SocketTimeout_Reliable_Serial.tv_usec = DEFAULT_RELIABLE_SERIAL_SOCKET_TIMEOUT % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	ConfigurationParameter->SocketTimeout_Unreliable_Once.tv_sec = DEFAULT_UNRELIABLE_ONCE_SOCKET_TIMEOUT / SECOND_TO_MILLISECOND;
	ConfigurationParameter->SocketTimeout_Unreliable_Once.tv_usec = DEFAULT_RELIABLE_ONCE_SOCKET_TIMEOUT % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	ConfigurationParameter->SocketTimeout_Unreliable_Serial.tv_sec = DEFAULT_UNRELIABLE_SERIAL_SOCKET_TIMEOUT / SECOND_TO_MILLISECOND;
	ConfigurationParameter->SocketTimeout_Unreliable_Serial.tv_usec = DEFAULT_RELIABLE_SERIAL_SOCKET_TIMEOUT % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#endif
#if defined(ENABLE_PCAP)
	ConfigurationParameter->ICMP_Speed = DEFAULT_ICMP_TEST_TIME * SECOND_TO_MILLISECOND;
	ConfigurationParameter->DomainTest_Speed = DEFAULT_DOMAIN_TEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
#endif
	ConfigurationParameter->AlternateTimes = DEFAULT_ALTERNATE_TIMES;
	ConfigurationParameter->AlternateTimeRange = DEFAULT_ALTERNATE_RANGE_TIME * SECOND_TO_MILLISECOND;
	ConfigurationParameter->AlternateResetTime = DEFAULT_ALTERNATE_RESET_TIME * SECOND_TO_MILLISECOND;

	//[Data] block
#if defined(ENABLE_PCAP)
	#if defined(PLATFORM_WIN)
		ConfigurationParameter->ICMP_ID = htons((uint16_t)GetCurrentProcessId()); //Default ICMP ID is current thread ID.
	#elif defined(PLATFORM_LINUX)
		ConfigurationParameter->ICMP_ID = htons((uint16_t)pthread_self()); //Default ICMP ID is current thread ID.
	#elif defined(PLATFORM_MACOS)
		ConfigurationParameter->ICMP_ID = htons(*(uint16_t *)pthread_self()); //Default ICMP ID is current thread ID.
	#endif
	ConfigurationParameter->ICMP_Sequence = htons(DEFAULT_SEQUENCE);
	#if defined(PLATFORM_WIN)
		ConfigurationParameter->ICMP_PaddingLength = strlen(DEFAULT_ICMP_PADDING_DATA);
		memcpy_s(ConfigurationParameter->ICMP_PaddingData, ICMP_PADDING_MAXSIZE, DEFAULT_ICMP_PADDING_DATA, ConfigurationParameter->ICMP_PaddingLength); //Load default padding data in Windows.
	#elif defined(PLATFORM_LINUX)
		size_t CharData = ICMP_STRING_START_NUM_LINUX;
		for (size_t Index = 0;Index < ICMP_PADDING_LENGTH_LINUX;++Index, ++CharData)
			ConfigurationParameter->ICMP_PaddingData[Index] = CharData;
		ConfigurationParameter->ICMP_PaddingLength = strlen((const char *)ConfigurationParameter->ICMP_PaddingData); //Load default padding data in Linux.
	#elif defined(PLATFORM_MACOS)
		size_t CharData = ICMP_STRING_START_NUM_MAC;
		for (size_t Index = 0;Index < ICMP_PADDING_LENGTH_MAC;++Index, ++CharData)
			ConfigurationParameter->ICMP_PaddingData[Index] = CharData;
		ConfigurationParameter->ICMP_PaddingLength = strlen((const char *)ConfigurationParameter->ICMP_PaddingData); //Load default padding data in macOS.
	#endif
	#if defined(PLATFORM_WIN)
		ConfigurationParameter->DomainTest_ID = htons((uint16_t)GetCurrentProcessId()); //Default DNS ID is current thread ID.
	#elif defined(PLATFORM_LINUX)
		ConfigurationParameter->DomainTest_ID = htons((uint16_t)pthread_self()); //Default DNS ID is current thread ID.
	#elif defined(PLATFORM_MACOS)
		ConfigurationParameter->DomainTest_ID = htons(*(uint16_t *)pthread_self()); //Default DNS ID is current thread ID.
	#endif
#endif

	//[Proxy] block
	ConfigurationParameter->SOCKS_Version = SOCKS_VERSION_5;
	ConfigurationParameter->SOCKS_Protocol_Network = REQUEST_MODE_BOTH;
	ConfigurationParameter->SOCKS_Protocol_Transport = REQUEST_MODE_TCP;
	ConfigurationParameter->HTTP_CONNECT_Protocol = REQUEST_MODE_BOTH;

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
	delete LocalMachineSubnet_IPv6;
	delete LocalMachineSubnet_IPv4;
	delete Target_Server_IPv6_Multiple;
	delete Target_Server_IPv4_Multiple;
	ListenAddress_IPv6 = nullptr;
	ListenAddress_IPv4 = nullptr;
	LocalMachineSubnet_IPv6 = nullptr;
	LocalMachineSubnet_IPv4 = nullptr;
	Target_Server_IPv6_Multiple = nullptr;
	Target_Server_IPv4_Multiple = nullptr;

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
#if defined(ENABLE_TLS)
	delete HTTP_CONNECT_TLS_SNI;
	delete sHTTP_CONNECT_TLS_SNI;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		delete HTTP_CONNECT_TLS_AddressString_IPv4;
		delete HTTP_CONNECT_TLS_AddressString_IPv6;
	#endif
#endif
	delete HTTP_CONNECT_TargetDomain;
	delete HTTP_CONNECT_Version;
	delete HTTP_CONNECT_HeaderField;
	delete HTTP_CONNECT_ProxyAuthorization;
	SOCKS_TargetDomain = nullptr;
	SOCKS_Username = nullptr;
	SOCKS_Password = nullptr;
#if defined(ENABLE_TLS)
	HTTP_CONNECT_TLS_SNI = nullptr;
	sHTTP_CONNECT_TLS_SNI = nullptr;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;
		HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
	#endif
#endif
	HTTP_CONNECT_TargetDomain = nullptr;
	HTTP_CONNECT_Version = nullptr;
	HTTP_CONNECT_HeaderField = nullptr;
	HTTP_CONNECT_ProxyAuthorization = nullptr;

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
	delete LocalMachineSubnet_IPv6;
	delete LocalMachineSubnet_IPv4;
	delete Target_Server_IPv6_Multiple;
	delete Target_Server_IPv4_Multiple;
	ListenAddress_IPv6 = nullptr;
	ListenAddress_IPv4 = nullptr;
	LocalMachineSubnet_IPv6 = nullptr;
	LocalMachineSubnet_IPv4 = nullptr;
	Target_Server_IPv6_Multiple = nullptr;
	Target_Server_IPv4_Multiple = nullptr;

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

	return;
}

//ConfigurationTable class MonitorItemToUsing function
void ConfigurationTable::MonitorItemToUsing(
	ConfigurationTable * const ConfigurationParameter)
{
//[Base] block
	ConfigurationParameter->Version = Version;
	ConfigurationParameter->FileRefreshTime = FileRefreshTime;

//[Log] block
	ConfigurationParameter->PrintLogLevel = PrintLogLevel;
	ConfigurationParameter->LogMaxSize = LogMaxSize;

//[Listen] block
	ConfigurationParameter->IsIPFilterTypePermit = IsIPFilterTypePermit;
	ConfigurationParameter->IPFilterLevel = IPFilterLevel;
	ConfigurationParameter->IsAcceptTypePermit = IsAcceptTypePermit;
	ConfigurationParameter->AcceptTypeList->swap(*AcceptTypeList);

//[DNS] block
	ConfigurationParameter->DirectRequest = DirectRequest;
	ConfigurationParameter->HostsDefaultTTL = HostsDefaultTTL;

//[Local DNS] block
	ConfigurationParameter->LocalProtocol_Network = LocalProtocol_Network;
	ConfigurationParameter->LocalProtocol_Transport = LocalProtocol_Transport;
	ConfigurationParameter->LocalForce = LocalForce;

//[Values] block
	ConfigurationParameter->ThreadPoolResetTime = ThreadPoolResetTime;
#if defined(ENABLE_PCAP)
	ConfigurationParameter->Target_Server_Main_IPv4.HopLimitData_Assign.TTL = Target_Server_Main_IPv4.HopLimitData_Assign.TTL;
	ConfigurationParameter->Target_Server_Main_IPv6.HopLimitData_Assign.HopLimit = Target_Server_Main_IPv6.HopLimitData_Assign.HopLimit;
	ConfigurationParameter->Target_Server_Main_IPv4.HopLimitData_Mark.TTL = Target_Server_Main_IPv4.HopLimitData_Mark.TTL;
	ConfigurationParameter->Target_Server_Main_IPv6.HopLimitData_Mark.HopLimit = Target_Server_Main_IPv6.HopLimitData_Mark.HopLimit;
	ConfigurationParameter->Target_Server_Alternate_IPv4.HopLimitData_Assign.TTL = Target_Server_Alternate_IPv4.HopLimitData_Assign.TTL;
	ConfigurationParameter->Target_Server_Alternate_IPv6.HopLimitData_Assign.HopLimit = Target_Server_Alternate_IPv6.HopLimitData_Assign.HopLimit;
	ConfigurationParameter->Target_Server_Alternate_IPv4.HopLimitData_Mark.TTL = Target_Server_Alternate_IPv4.HopLimitData_Mark.TTL;
	ConfigurationParameter->Target_Server_Alternate_IPv6.HopLimitData_Mark.HopLimit = Target_Server_Alternate_IPv6.HopLimitData_Mark.HopLimit;
#endif
	ConfigurationParameter->SocketTimeout_Reliable_Once = SocketTimeout_Reliable_Once;
	ConfigurationParameter->SocketTimeout_Reliable_Serial = SocketTimeout_Reliable_Serial;
	ConfigurationParameter->SocketTimeout_Unreliable_Once = SocketTimeout_Unreliable_Once;
	ConfigurationParameter->SocketTimeout_Unreliable_Serial = SocketTimeout_Unreliable_Serial;
	ConfigurationParameter->ReceiveWaiting = ReceiveWaiting;
#if defined(ENABLE_PCAP)
	ConfigurationParameter->ICMP_Speed = ICMP_Speed;
	ConfigurationParameter->DomainTest_Speed = DomainTest_Speed;
#endif
	ConfigurationParameter->MultipleRequestTimes = MultipleRequestTimes;

//[Switches] block
	ConfigurationParameter->DomainCaseConversion = DomainCaseConversion;
#if defined(ENABLE_PCAP)
	ConfigurationParameter->HeaderCheck_IPv4 = HeaderCheck_IPv4;
	ConfigurationParameter->HeaderCheck_TCP = HeaderCheck_TCP;
#endif
	ConfigurationParameter->HeaderCheck_DNS = HeaderCheck_DNS;

//[Proxy] block
	if (ConfigurationParameter->SOCKS_TargetDomain != nullptr && !SOCKS_TargetDomain->empty() && SOCKS_TargetDomain_Port > 0)
	{
	//Reset old items.
		memset(&ConfigurationParameter->SOCKS_TargetServer, 0, sizeof(ConfigurationParameter->SOCKS_TargetServer));

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
		memcpy_s(&ConfigurationParameter->SOCKS_TargetServer, sizeof(ConfigurationParameter->SOCKS_TargetServer), &SOCKS_TargetServer, sizeof(ConfigurationParameter->SOCKS_TargetServer));
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
	if (ConfigurationParameter->HTTP_CONNECT_TargetDomain != nullptr && !HTTP_CONNECT_TargetDomain->empty())
		*ConfigurationParameter->HTTP_CONNECT_TargetDomain = *HTTP_CONNECT_TargetDomain;
#if defined(ENABLE_TLS)
	ConfigurationParameter->HTTP_CONNECT_TLS_Version = HTTP_CONNECT_TLS_Version;
	ConfigurationParameter->HTTP_CONNECT_TLS_Validation = HTTP_CONNECT_TLS_Validation;
#endif
	if (ConfigurationParameter->HTTP_CONNECT_Version != nullptr && !HTTP_CONNECT_Version->empty())
		*ConfigurationParameter->HTTP_CONNECT_Version = *HTTP_CONNECT_Version;
	if (ConfigurationParameter->HTTP_CONNECT_HeaderField != nullptr)
	{
		if (!HTTP_CONNECT_HeaderField->empty())
			*ConfigurationParameter->HTTP_CONNECT_HeaderField = *HTTP_CONNECT_HeaderField;
		else 
			ConfigurationParameter->HTTP_CONNECT_HeaderField->clear();
	}
	if (ConfigurationParameter->HTTP_CONNECT_ProxyAuthorization != nullptr)
	{
		if (!HTTP_CONNECT_ProxyAuthorization->empty())
			*ConfigurationParameter->HTTP_CONNECT_ProxyAuthorization = *HTTP_CONNECT_ProxyAuthorization;
		else 
			ConfigurationParameter->HTTP_CONNECT_ProxyAuthorization->clear();
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
	LogMaxSize = LOG_READING_MAXSIZE;

//[Listen] block
	IsIPFilterTypePermit = false;
	IPFilterLevel = 0;
	IsAcceptTypePermit = false;
	AcceptTypeList->clear();
	AcceptTypeList->shrink_to_fit();

//[DNS] block
	DirectRequest = false;
	HostsDefaultTTL = DEFAULT_HOSTS_TTL;

//[Local DNS] block
	LocalProtocol_Network = REQUEST_MODE_BOTH;
	LocalProtocol_Transport = REQUEST_MODE_UDP;
	LocalForce = false;

//[Values] block
	ThreadPoolResetTime = DEFAULT_THREAD_POOL_RESET_TIME;
#if defined(ENABLE_PCAP)
	Target_Server_Main_IPv4.HopLimitData_Assign.TTL = 0;
	Target_Server_Main_IPv6.HopLimitData_Assign.HopLimit = 0;
	Target_Server_Main_IPv4.HopLimitData_Mark.TTL = 0;
	Target_Server_Main_IPv6.HopLimitData_Mark.HopLimit = 0;
	Target_Server_Alternate_IPv4.HopLimitData_Assign.TTL = 0;
	Target_Server_Alternate_IPv6.HopLimitData_Assign.HopLimit = 0;
	Target_Server_Alternate_IPv4.HopLimitData_Mark.TTL = 0;
	Target_Server_Alternate_IPv6.HopLimitData_Mark.HopLimit = 0;
#endif
#if defined(PLATFORM_WIN)
	SocketTimeout_Reliable_Once = DEFAULT_RELIABLE_ONCE_SOCKET_TIMEOUT;
	SocketTimeout_Reliable_Serial = DEFAULT_RELIABLE_SERIAL_SOCKET_TIMEOUT;
	SocketTimeout_Unreliable_Once = DEFAULT_UNRELIABLE_ONCE_SOCKET_TIMEOUT;
	SocketTimeout_Unreliable_Serial = DEFAULT_UNRELIABLE_SERIAL_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	SocketTimeout_Reliable_Once.tv_sec = DEFAULT_RELIABLE_ONCE_SOCKET_TIMEOUT / SECOND_TO_MILLISECOND;
	SocketTimeout_Reliable_Once.tv_usec = DEFAULT_RELIABLE_ONCE_SOCKET_TIMEOUT % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	SocketTimeout_Reliable_Serial.tv_sec = DEFAULT_RELIABLE_SERIAL_SOCKET_TIMEOUT / SECOND_TO_MILLISECOND;
	SocketTimeout_Reliable_Serial.tv_usec = DEFAULT_RELIABLE_SERIAL_SOCKET_TIMEOUT % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	SocketTimeout_Unreliable_Once.tv_sec = DEFAULT_UNRELIABLE_ONCE_SOCKET_TIMEOUT / SECOND_TO_MILLISECOND;
	SocketTimeout_Unreliable_Once.tv_usec = DEFAULT_UNRELIABLE_ONCE_SOCKET_TIMEOUT % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	SocketTimeout_Unreliable_Serial.tv_sec = DEFAULT_UNRELIABLE_SERIAL_SOCKET_TIMEOUT / SECOND_TO_MILLISECOND;
	SocketTimeout_Unreliable_Serial.tv_usec = DEFAULT_RELIABLE_SERIAL_SOCKET_TIMEOUT % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#endif
	ReceiveWaiting = 0;
#if defined(ENABLE_PCAP)
	ICMP_Speed = DEFAULT_ICMP_TEST_TIME * SECOND_TO_MILLISECOND;
	DomainTest_Speed = DEFAULT_DOMAIN_TEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
#endif
	MultipleRequestTimes = 0;

//[Switches] block
	DomainCaseConversion = false;
#if defined(ENABLE_PCAP)
	HeaderCheck_IPv4 = false;
	HeaderCheck_TCP = false;
#endif
	HeaderCheck_DNS = false;

//[Proxy] block
	memset(&SOCKS_TargetServer, 0, sizeof(SOCKS_TargetServer));
	if (SOCKS_TargetDomain != nullptr)
		SOCKS_TargetDomain->clear();
	SOCKS_TargetDomain_Port = 0;
	if (SOCKS_Username != nullptr)
		SOCKS_Username->clear();
	if (SOCKS_Password != nullptr)
		SOCKS_Password->clear();
	if (HTTP_CONNECT_TargetDomain != nullptr)
		HTTP_CONNECT_TargetDomain->clear();
#if defined(ENABLE_TLS)
	HTTP_CONNECT_TLS_Version = TLS_VERSION_AUTO;
	HTTP_CONNECT_TLS_Validation = false;
#endif
	if (HTTP_CONNECT_Version != nullptr)
		HTTP_CONNECT_Version->clear();
	if (HTTP_CONNECT_HeaderField != nullptr)
		HTTP_CONNECT_HeaderField->clear();
	if (HTTP_CONNECT_ProxyAuthorization != nullptr)
		HTTP_CONNECT_ProxyAuthorization->clear();

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
		ThreadRunningNum = new std::atomic<size_t>();
		ThreadRunningFreeNum = new std::atomic<size_t>();
		Path_Global = new std::vector<std::wstring>();
		Path_ErrorLog = new std::wstring();
		FileList_Hosts = new std::vector<std::wstring>();
		FileList_IPFilter = new std::vector<std::wstring>();
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		sPath_Global = new std::vector<std::string>();
		sPath_ErrorLog = new std::string();
		sFileList_Hosts = new std::vector<std::string>();
		sFileList_IPFilter = new std::vector<std::string>();
	#endif
		LocalAddress_Response[NETWORK_LAYER_IPV6] = new uint8_t[PACKET_MAXSIZE]();
		LocalAddress_Response[NETWORK_LAYER_IPV4] = new uint8_t[PACKET_MAXSIZE]();
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		LocalAddress_ResponsePTR[NETWORK_LAYER_IPV6] = new std::vector<std::string>();
		LocalAddress_ResponsePTR[NETWORK_LAYER_IPV4] = new std::vector<std::string>();
	#endif
	}
	catch (std::bad_alloc)
	{
		delete LocalListeningSocket;
		delete RamdomEngine;
		delete ThreadRunningNum;
		delete ThreadRunningFreeNum;
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
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		delete sPath_Global;
		delete sPath_ErrorLog;
		delete sFileList_Hosts;
		delete sFileList_IPFilter;
		sPath_Global = nullptr;
		sPath_ErrorLog = nullptr;
		sFileList_Hosts = nullptr;
		sFileList_IPFilter = nullptr;
	#endif
		delete[] LocalAddress_Response[NETWORK_LAYER_IPV6];
		delete[] LocalAddress_Response[NETWORK_LAYER_IPV4];
		LocalAddress_Response[NETWORK_LAYER_IPV6] = nullptr;
		LocalAddress_Response[NETWORK_LAYER_IPV4] = nullptr;
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		delete LocalAddress_ResponsePTR[NETWORK_LAYER_IPV6];
		delete LocalAddress_ResponsePTR[NETWORK_LAYER_IPV4];
		LocalAddress_ResponsePTR[NETWORK_LAYER_IPV6] = nullptr;
		LocalAddress_ResponsePTR[NETWORK_LAYER_IPV4] = nullptr;
	#endif

		exit(EXIT_FAILURE);
		return;
	}

	GlobalStatusSetting(this);
	return;
}

//GlobalStatus class constructor settings
void GlobalStatusSetting(
	GLOBAL_STATUS * const GlobalRunningStatusParameter)
{
#if defined(PLATFORM_LINUX)
	GlobalRunningStatusParameter->IsDaemon = true;
#endif
	std::random_device RamdomDevice;
	GlobalRunningStatusParameter->RamdomEngine->seed(RamdomDevice());
	GlobalRunningStatusParameter->DomainTable = (uint8_t *)DomainTable_Initialization;
	GlobalRunningStatusParameter->Base64_EncodeTable = (uint8_t *)Base64_EncodeTable_Initialization;
//	GlobalRunningStatusParameter->Base64_DecodeTable = (uint8_t *)Base64_DecodeTable_Initialization;
	GlobalRunningStatusParameter->GatewayAvailable_IPv4 = true;
	memset(GlobalRunningStatusParameter->LocalAddress_Response[NETWORK_LAYER_IPV6], 0, PACKET_MAXSIZE);
	memset(GlobalRunningStatusParameter->LocalAddress_Response[NETWORK_LAYER_IPV4], 0, PACKET_MAXSIZE);

	return;
}

//GlobalStatus class destructor
GlobalStatus::~GlobalStatus(
	void)
{
//Close all sockets.
	for (const auto &SocketIter:*LocalListeningSocket)
		SocketSetting(SocketIter, SOCKET_SETTING_CLOSE, false, nullptr);

//Close all file handles and WinSock cleanup.
#if defined(PLATFORM_WIN)
	_fcloseall();
	if (IsWinSockInitialized)
		WSACleanup();
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	#if defined(ENABLE_TLS)
		#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0 //OpenSSL version brfore 1.1.0
			if (IsOpenSSLInitialized)
				OpenSSL_Library_Init(false);
		#endif
	#endif
#endif
#if (defined(PLATFORM_LINUX) && !defined(PLATFORM_OPENWRT))
	fcloseall();
#endif

//Delete and reset pointers.
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
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	delete sPath_Global;
	delete sPath_ErrorLog;
	delete sFileList_Hosts;
	delete sFileList_IPFilter;
	sPath_Global = nullptr;
	sPath_ErrorLog = nullptr;
	sFileList_Hosts = nullptr;
	sFileList_IPFilter = nullptr;
#endif
	delete[] LocalAddress_Response[NETWORK_LAYER_IPV6];
	delete[] LocalAddress_Response[NETWORK_LAYER_IPV4];
	LocalAddress_Response[NETWORK_LAYER_IPV6] = nullptr;
	LocalAddress_Response[NETWORK_LAYER_IPV4] = nullptr;
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	delete LocalAddress_ResponsePTR[NETWORK_LAYER_IPV6];
	delete LocalAddress_ResponsePTR[NETWORK_LAYER_IPV4];
	LocalAddress_ResponsePTR[NETWORK_LAYER_IPV6] = nullptr;
	LocalAddress_ResponsePTR[NETWORK_LAYER_IPV4] = nullptr;
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
	IsStringMatching = false;
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
	memset(&SocketData_Input, 0, sizeof(SocketData_Input));
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
	//[DNSCurve Addresses] block
		DNSCurve_Target_Server_Main_IPv4.ProviderName = new uint8_t[DOMAIN_MAXSIZE]();
		DNSCurve_Target_Server_Alternate_IPv4.ProviderName = new uint8_t[DOMAIN_MAXSIZE]();
		DNSCurve_Target_Server_Main_IPv6.ProviderName = new uint8_t[DOMAIN_MAXSIZE]();
		DNSCurve_Target_Server_Alternate_IPv6.ProviderName = new uint8_t[DOMAIN_MAXSIZE]();

	//[DNSCurve Keys] block
		Client_PublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		Client_SecretKey = (uint8_t *)sodium_malloc(crypto_box_SECRETKEYBYTES);
		DNSCurve_Target_Server_Main_IPv4.PrecomputationKey = (uint8_t *)sodium_malloc(crypto_box_BEFORENMBYTES);
		DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey = (uint8_t *)sodium_malloc(crypto_box_BEFORENMBYTES);
		DNSCurve_Target_Server_Main_IPv6.PrecomputationKey = (uint8_t *)sodium_malloc(crypto_box_BEFORENMBYTES);
		DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey = (uint8_t *)sodium_malloc(crypto_box_BEFORENMBYTES);
		DNSCurve_Target_Server_Main_IPv4.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Main_IPv6.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Main_IPv4.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Main_IPv6.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();

	//[DNSCurve Magic Number] block
		DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Main_IPv4.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Main_IPv6.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
	}
	catch (std::bad_alloc)
	{
	//[DNSCurve Addresses] block
		delete[] DNSCurve_Target_Server_Main_IPv4.ProviderName;
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ProviderName;
		delete[] DNSCurve_Target_Server_Main_IPv6.ProviderName;
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ProviderName;
		DNSCurve_Target_Server_Main_IPv4.ProviderName = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.ProviderName = nullptr;
		DNSCurve_Target_Server_Main_IPv6.ProviderName = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.ProviderName = nullptr;

	//[DNSCurve Keys] block
		delete[] Client_PublicKey;
		sodium_free(Client_SecretKey);
		sodium_free(DNSCurve_Target_Server_Main_IPv4.PrecomputationKey);
		sodium_free(DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey);
		sodium_free(DNSCurve_Target_Server_Main_IPv6.PrecomputationKey);
		sodium_free(DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey);
		delete[] DNSCurve_Target_Server_Main_IPv4.ServerPublicKey;
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey;
		delete[] DNSCurve_Target_Server_Main_IPv6.ServerPublicKey;
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey;
		delete[] DNSCurve_Target_Server_Main_IPv4.ServerFingerprint;
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint;
		delete[] DNSCurve_Target_Server_Main_IPv6.ServerFingerprint;
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint;
		Client_PublicKey = nullptr;
		Client_SecretKey = nullptr;
		DNSCurve_Target_Server_Main_IPv4.PrecomputationKey = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey = nullptr;
		DNSCurve_Target_Server_Main_IPv6.PrecomputationKey = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey = nullptr;
		DNSCurve_Target_Server_Main_IPv4.ServerPublicKey = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey = nullptr;
		DNSCurve_Target_Server_Main_IPv6.ServerPublicKey = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey = nullptr;
		DNSCurve_Target_Server_Main_IPv4.ServerFingerprint = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint = nullptr;
		DNSCurve_Target_Server_Main_IPv6.ServerFingerprint = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint = nullptr;

	//[DNSCurve Magic Number] block
		delete[] DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber;
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber;
		delete[] DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber;
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber;
		delete[] DNSCurve_Target_Server_Main_IPv4.SendMagicNumber;
		delete[] DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber;
		delete[] DNSCurve_Target_Server_Main_IPv6.SendMagicNumber;
		delete[] DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber;
		DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber = nullptr;
		DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber = nullptr;
		DNSCurve_Target_Server_Main_IPv4.SendMagicNumber = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = nullptr;
		DNSCurve_Target_Server_Main_IPv6.SendMagicNumber = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = nullptr;

		exit(EXIT_FAILURE);
		return;
	}

	DNSCurveConfigurationTableSetting(this);
	return;
}

//DNSCurveConfigurationTable class constructor settings
void DNSCurveConfigurationTableSetting(
	DNSCURVE_CONFIGURATION_TABLE * const DNSCurveConfigurationParameter)
{
//[DNSCurve Addresses] block
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ProviderName, DOMAIN_MAXSIZE);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ProviderName, DOMAIN_MAXSIZE);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ProviderName, DOMAIN_MAXSIZE);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ProviderName, DOMAIN_MAXSIZE);

//[DNSCurve Keys] block
	sodium_memzero(DNSCurveConfigurationParameter->Client_PublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->Client_SecretKey, crypto_box_SECRETKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);

//[DNSCurve Magic Number] block
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);

//Default settings
	//[DNSCurve] block
	DNSCurveConfigurationParameter->DNSCurveProtocol_Network = REQUEST_MODE_BOTH;
	DNSCurveConfigurationParameter->DNSCurveProtocol_Transport = REQUEST_MODE_UDP;
	DNSCurveConfigurationParameter->DNSCurvePayloadSize = EDNS_PACKET_MINSIZE;
#if defined(PLATFORM_WIN)
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Reliable = DEFAULT_DNSCURVE_RELIABLE_SOCKET_TIMEOUT;
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Unreliable = DEFAULT_DNSCURVE_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
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
//[DNSCurve Addresses] block
	delete[] DNSCurve_Target_Server_Main_IPv4.ProviderName;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.ProviderName;
	delete[] DNSCurve_Target_Server_Main_IPv6.ProviderName;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.ProviderName;
	DNSCurve_Target_Server_Main_IPv4.ProviderName = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.ProviderName = nullptr;
	DNSCurve_Target_Server_Main_IPv6.ProviderName = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.ProviderName = nullptr;

//[DNSCurve Keys] block
	delete[] Client_PublicKey;
	sodium_free(Client_SecretKey);
	sodium_free(DNSCurve_Target_Server_Main_IPv4.PrecomputationKey);
	sodium_free(DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey);
	sodium_free(DNSCurve_Target_Server_Main_IPv6.PrecomputationKey);
	sodium_free(DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey);
	delete[] DNSCurve_Target_Server_Main_IPv4.ServerPublicKey;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey;
	delete[] DNSCurve_Target_Server_Main_IPv6.ServerPublicKey;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey;
	delete[] DNSCurve_Target_Server_Main_IPv4.ServerFingerprint;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint;
	delete[] DNSCurve_Target_Server_Main_IPv6.ServerFingerprint;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint;
	Client_PublicKey = nullptr;
	Client_SecretKey = nullptr;
	DNSCurve_Target_Server_Main_IPv4.PrecomputationKey = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey = nullptr;
	DNSCurve_Target_Server_Main_IPv6.PrecomputationKey = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey = nullptr;
	DNSCurve_Target_Server_Main_IPv4.ServerPublicKey = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey = nullptr;
	DNSCurve_Target_Server_Main_IPv6.ServerPublicKey = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey = nullptr;
	DNSCurve_Target_Server_Main_IPv4.ServerFingerprint = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint = nullptr;
	DNSCurve_Target_Server_Main_IPv6.ServerFingerprint = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint = nullptr;

//[DNSCurve Magic Number] block
	delete[] DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber;
	delete[] DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber;
	delete[] DNSCurve_Target_Server_Main_IPv4.SendMagicNumber;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber;
	delete[] DNSCurve_Target_Server_Main_IPv6.SendMagicNumber;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber;
	DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber = nullptr;
	DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber = nullptr;
	DNSCurve_Target_Server_Main_IPv4.SendMagicNumber = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = nullptr;
	DNSCurve_Target_Server_Main_IPv6.SendMagicNumber = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = nullptr;

	return;
}

//DNSCurveConfigurationTable class SetToMonitorItem function
void DNSCurveConfigurationTable::SetToMonitorItem(
	void)
{
//Delete and reset pointers.
	delete[] DNSCurve_Target_Server_Main_IPv4.ProviderName;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.ProviderName;
	delete[] DNSCurve_Target_Server_Main_IPv6.ProviderName;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.ProviderName;
	DNSCurve_Target_Server_Main_IPv4.ProviderName = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.ProviderName = nullptr;
	DNSCurve_Target_Server_Main_IPv6.ProviderName = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.ProviderName = nullptr;

	return;
}

//DNSCurveConfigurationTable class MonitorItemToUsing function
void DNSCurveConfigurationTable::MonitorItemToUsing(
	DNSCurveConfigurationTable * const DNSCurveConfigurationParameter)
{
//[DNSCurve] block
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Reliable = DNSCurve_SocketTimeout_Reliable;
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Unreliable = DNSCurve_SocketTimeout_Unreliable;
	DNSCurveConfigurationParameter->KeyRecheckTime = KeyRecheckTime;

//[DNSCurve Keys] block
	if (DNSCurveConfigurationParameter->Client_PublicKey != nullptr && !CheckEmptyBuffer(Client_PublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->Client_PublicKey, Client_PublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->Client_PublicKey, crypto_box_PUBLICKEYBYTES, Client_PublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->Client_SecretKey != nullptr && !CheckEmptyBuffer(Client_SecretKey, crypto_box_PUBLICKEYBYTES) && 
		sodium_memcmp(DNSCurveConfigurationParameter->Client_SecretKey, Client_SecretKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->Client_SecretKey, crypto_box_PUBLICKEYBYTES, Client_SecretKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);

//[DNSCurve Magic Number] block
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);

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
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	DNSCurve_SocketTimeout_Reliable.tv_sec = DEFAULT_DNSCURVE_RELIABLE_SOCKET_TIMEOUT;
	DNSCurve_SocketTimeout_Reliable.tv_usec = 0;
	DNSCurve_SocketTimeout_Unreliable.tv_sec = DEFAULT_DNSCURVE_UNRELIABLE_SOCKET_TIMEOUT;
	DNSCurve_SocketTimeout_Unreliable.tv_usec = 0;
#endif
	KeyRecheckTime = DEFAULT_DNSCURVE_RECHECK_TIME * SECOND_TO_MILLISECOND;

//[DNSCurve Keys] block
	if (Client_PublicKey != nullptr)
		sodium_memzero(Client_PublicKey, crypto_box_PUBLICKEYBYTES);
	if (Client_SecretKey != nullptr)
		sodium_memzero(Client_SecretKey, crypto_box_SECRETKEYBYTES);
	if (DNSCurve_Target_Server_Main_IPv4.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurve_Target_Server_Main_IPv6.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurve_Target_Server_Main_IPv4.ServerPublicKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Main_IPv6.ServerPublicKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Main_IPv4.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Main_IPv6.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);

//[DNSCurve Magic Number] block
	if (DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Main_IPv4.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Main_IPv6.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);

	return;
}
#endif

#if defined(ENABLE_TLS)
#if defined(PLATFORM_WIN)
//SSPIHandleTable class constructor
SSPIHandleTable::SSPIHandleTable(
	void)
{
	memset(&ClientCredentials, 0, sizeof(ClientCredentials));
	memset(&ContextHandle, 0, sizeof(ContextHandle));
	InputFlags = 0;
	memset(&StreamSizes, 0, sizeof(StreamSizes));
	LastReturnValue = 0;

	return;
}

//SSPIHandleTable class destructor
SSPIHandleTable::~SSPIHandleTable(
	void)
{
	FreeCredentialsHandle(&ClientCredentials);
	DeleteSecurityContext(&ContextHandle);

	return;
}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//SSPIHandleTable class constructor
OpenSSLContextTable::OpenSSLContextTable(
	void)
{
	MethodContext = nullptr;
	SessionBIO = nullptr;
	SessionData = nullptr;

	return;
}

//OpenSSLContextTable class destructor
OpenSSLContextTable::~OpenSSLContextTable(
	void)
{
	if (SessionBIO != nullptr)
		BIO_free_all(SessionBIO);
	if (MethodContext != nullptr)
		SSL_CTX_free(MethodContext);

	return;
}
#endif
#endif
