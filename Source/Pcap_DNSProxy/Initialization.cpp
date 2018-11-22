// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2018 Chengr28
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

//Preferred name syntax(Section 2.3.1 in RFC 1035)
static const uint8_t DomainTable_Normal[] = "0123456789abcdefghijklmnopqrstuvwxyz.-";
static const uint8_t DomainTable_Upper[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-";

#if !defined(ENABLE_LIBSODIUM)
//RFC domain and Base64 encoding table
static const uint8_t Base64_EncodeTable_Initialization[] = 
{
	('A'), ('B'), ('C'), ('D'), ('E'), ('F'), ('G'), ('H'), 
	('I'), ('J'), ('K'), ('L'), ('M'), ('N'), ('O'), ('P'), 
	('Q'), ('R'), ('S'), ('T'), ('U'), ('V'), ('W'), ('X'), 
	('Y'), ('Z'), ('a'), ('b'), ('c'), ('d'), ('e'), ('f'), 
	('g'), ('h'), ('i'), ('j'), ('k'), ('l'), ('m'), ('n'), 
	('o'), ('p'), ('q'), ('r'), ('s'), ('t'), ('u'), ('v'), 
	('w'), ('x'), ('y'), ('z'), ('0'), ('1'), ('2'), ('3'), 
	('4'), ('5'), ('6'), ('7'), ('8'), ('9'), ('+'), ('/')
};

//RFC domain and Base64 decoding table
static const int8_t Base64_DecodeTable_Initialization[] = 
{
	('+'), (','), ('-'), ('.'), ('/'), ('0'), ('1'), ('2'), 
	62,  -1,  -1,  -1,  63,  52,  53,  54, 
	('3'), ('4'), ('5'), ('6'), ('7'), ('8'), ('9'), (':'), 
	55,  56,  57,  58,  59,  60,  61,  -1, 
	(';'), ('<'), ('='), ('>'), ('?'), ('@'), ('A'), ('B'), 
	-1,  -1,  -1,  -1,  -1,  -1,   0,  1, 
	('C'), ('D'), ('E'), ('F'), ('G'), ('H'), ('I'), ('J'), 
	2,   3,   4,   5,   6,   7,   8,   9, 
	('K'), ('L'), ('M'), ('N'), ('O'), ('P'), ('Q'), ('R'), 
	10,  11,  12,  13,  14,  15,  16,  17, 
	('S'), ('T'), ('U'), ('V'), ('W'), ('X'), ('Y'), ('Z'), 
	18,  19,  20,  21,  22,  23,  24,  25, 
	('['), ('\\'), (']'), ('^'), ('_'), ('`'), ('a'), ('b'), 
	-1,  -1,  -1,  -1,  -1,  -1,  26,  27, 
	('c'), ('d'), ('e'), ('f'), ('g'), ('h'), ('i'), ('j'), 
	28,  29,  30,  31,  32,  33,  34,  35, 
	('k'), ('l'), ('m'), ('n'), ('o'), ('p'), ('q'), ('r'), 
	36,  37,  38,  39,  40,  41,  42,  43, 
	('s'), ('t'), ('u'), ('v'), ('w'), ('x'), ('y'), ('z'), 
	44,  45,  46,  47,  48,  49,  50,  51
};
#endif

//ConfigurationTable class constructor
ConfigurationTable::ConfigurationTable(
	void)
{
//Libraries initialization
#if defined(ENABLE_LIBSODIUM)
//Libsodium Random Number Generator/RNG initialization
//No need to set a custom RNG, please visit https://download.libsodium.org/doc/advanced/custom_rng.html.
//	randombytes_set_implementation(&randombytes_salsa20_implementation);
//	randombytes_stir();

//Libsodium main initialization
//randombytes_set_implementation function should only be called once, before sodium_init().
	if (sodium_init() == LIBSODIUM_ERROR)
	{
		exit(EXIT_FAILURE);
//		return;
	}
#endif

//Class constructor
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
		Local_FQDN_String = new std::string();
		Local_FQDN_Response = new uint8_t[DOMAIN_MAXSIZE]();
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		LocalServer_Response = new uint8_t[PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES]();
	#endif

	//[Proxy] block
		SOCKS_TargetDomain = new std::string();
	#if defined(ENABLE_LIBSODIUM)
		SOCKS_Username = reinterpret_cast<uint8_t *>(sodium_malloc(SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES));
		SOCKS_Password = reinterpret_cast<uint8_t *>(sodium_malloc(SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES));
	#else
		SOCKS_Username = new uint8_t[SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES]();
		SOCKS_Password = new uint8_t[SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES]();
	#endif
	#if defined(ENABLE_TLS)
		HTTP_CONNECT_TLS_SNI = new std::wstring();
		HTTP_CONNECT_TLS_SNI_MBS = new std::string();
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		HTTP_CONNECT_TLS_AddressString_IPv6 = new std::string();
		HTTP_CONNECT_TLS_AddressString_IPv4 = new std::string();
	#endif
	#endif
		HTTP_CONNECT_TargetDomain = new std::string();
		HTTP_CONNECT_HeaderField = new std::vector<std::string>();
	#if defined(ENABLE_LIBSODIUM)
		HTTP_CONNECT_ProxyAuthorization = reinterpret_cast<uint8_t *>(sodium_malloc(HTTP_AUTHORIZATION_MAXSIZE + MEMORY_RESERVED_BYTES));
	#else
		HTTP_CONNECT_ProxyAuthorization = new uint8_t[HTTP_AUTHORIZATION_MAXSIZE + MEMORY_RESERVED_BYTES]();
	#endif
	}
	catch (std::bad_alloc &)
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
		delete Local_FQDN_String;
		delete[] Local_FQDN_Response;
		Local_FQDN_String = nullptr;
		Local_FQDN_Response = nullptr;
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		delete[] LocalServer_Response;
		LocalServer_Response = nullptr;
	#endif

	//[Proxy] block
		delete SOCKS_TargetDomain;
	#if defined(ENABLE_LIBSODIUM)
		sodium_free(SOCKS_Username);
		sodium_free(SOCKS_Password);
	#else
		delete[] SOCKS_Username;
		delete[] SOCKS_Password;
	#endif
	#if defined(ENABLE_TLS)
		delete HTTP_CONNECT_TLS_SNI;
		delete HTTP_CONNECT_TLS_SNI_MBS;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		delete HTTP_CONNECT_TLS_AddressString_IPv6;
		delete HTTP_CONNECT_TLS_AddressString_IPv4;
	#endif
	#endif
		delete HTTP_CONNECT_TargetDomain;
		delete HTTP_CONNECT_HeaderField;
	#if defined(ENABLE_LIBSODIUM)
		sodium_free(HTTP_CONNECT_ProxyAuthorization);
	#else
		delete[] HTTP_CONNECT_ProxyAuthorization;
	#endif
		SOCKS_TargetDomain = nullptr;
		SOCKS_Username = nullptr;
		SOCKS_Password = nullptr;
	#if defined(ENABLE_TLS)
		HTTP_CONNECT_TLS_SNI = nullptr;
		HTTP_CONNECT_TLS_SNI_MBS = nullptr;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
		HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;
	#endif
	#endif
		HTTP_CONNECT_TargetDomain = nullptr;
		HTTP_CONNECT_HeaderField = nullptr;
		HTTP_CONNECT_ProxyAuthorization = nullptr;

	//Exit process.
		exit(EXIT_FAILURE);
//		return;
	}

//ConfigurationTable settings
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
	memset(ConfigurationParameter->Local_FQDN_Response, 0, DOMAIN_MAXSIZE);
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	memset(ConfigurationParameter->LocalServer_Response, 0, PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
#endif
#if defined(ENABLE_LIBSODIUM)
	sodium_memzero(ConfigurationParameter->SOCKS_Username, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
	sodium_memzero(ConfigurationParameter->SOCKS_Password, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
	sodium_memzero(ConfigurationParameter->HTTP_CONNECT_ProxyAuthorization, HTTP_AUTHORIZATION_MAXSIZE + MEMORY_RESERVED_BYTES);
#else
	memset(ConfigurationParameter->SOCKS_Username, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
	memset(ConfigurationParameter->SOCKS_Password, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
	memset(ConfigurationParameter->HTTP_CONNECT_ProxyAuthorization, 0, HTTP_AUTHORIZATION_MAXSIZE + MEMORY_RESERVED_BYTES);
#endif

//Default value settings
	//[Base] block
	ConfigurationParameter->FileRefreshTime = DEFAULT_FILE_REFRESH_TIME;
	ConfigurationParameter->LargeBufferSize = DEFAULT_LARGE_BUFFER_SIZE;

	//[Log] block
	ConfigurationParameter->PrintLogLevel = DEFAULT_LOG_LEVEL;
	ConfigurationParameter->LogMaxSize = DEFAULT_LOG_READING_MAXSIZE;

	//[Listen] block
	ConfigurationParameter->IsProcessUnique = true;
#if defined(ENABLE_PCAP)
	ConfigurationParameter->PcapReadingTimeout = DEFAULT_PCAP_CAPTURE_TIMEOUT;
#endif
	ConfigurationParameter->ListenProtocol_Network = LISTEN_PROTOCOL_NETWORK::BOTH;
	ConfigurationParameter->ListenProtocol_Transport = LISTEN_PROTOCOL_TRANSPORT::BOTH;
	ConfigurationParameter->OperationMode = LISTEN_MODE::PRIVATE;

	//[DNS] block
	ConfigurationParameter->RequestMode_Network = REQUEST_MODE_NETWORK::BOTH;
	ConfigurationParameter->RequestMode_Transport = REQUEST_MODE_TRANSPORT::UDP;
	ConfigurationParameter->DirectRequest_Protocol = REQUEST_MODE_DIRECT::NONE;
	ConfigurationParameter->DNS_CacheType = DNS_CACHE_TYPE::BOTH;
	ConfigurationParameter->DNS_CacheParameter = DEFAULT_DOMAIN_CACHE_PARAMETER;
	ConfigurationParameter->HostsDefaultTTL = DEFAULT_HOSTS_TTL;

	//[Local DNS] block
	ConfigurationParameter->LocalProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
	ConfigurationParameter->LocalProtocol_Transport = REQUEST_MODE_TRANSPORT::UDP;

	//[Values] block
	ConfigurationParameter->ThreadPoolMaxNum = DEFAULT_THREAD_POOL_MAXNUM;
	ConfigurationParameter->ThreadPoolResetTime = DEFAULT_THREAD_POOL_RESET_TIME;
	ConfigurationParameter->EDNS_PayloadSize = EDNS_PACKET_MINSIZE;
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
	ConfigurationParameter->DomainTest_Protocol = REQUEST_MODE_TEST::BOTH;
	ConfigurationParameter->DomainTest_Speed = DEFAULT_DOMAIN_TEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
#endif
	ConfigurationParameter->AlternateTimes = DEFAULT_ALTERNATE_TIMES;
	ConfigurationParameter->AlternateTimeRange = DEFAULT_ALTERNATE_RANGE_TIME * SECOND_TO_MILLISECOND;
	ConfigurationParameter->AlternateResetTime = DEFAULT_ALTERNATE_RESET_TIME * SECOND_TO_MILLISECOND;

	//[Data] block
#if defined(ENABLE_PCAP)
#if defined(PLATFORM_WIN)
	ConfigurationParameter->ICMP_PaddingLength = strlen(DEFAULT_ICMP_PADDING_DATA);
	memcpy_s(ConfigurationParameter->ICMP_PaddingData, ICMP_PADDING_MAXSIZE, DEFAULT_ICMP_PADDING_DATA, ConfigurationParameter->ICMP_PaddingLength); //Load default padding data(Windows).
#elif defined(PLATFORM_LINUX)
	for (size_t Index = 0, CharData = ICMP_STRING_START_NUM_LINUX;Index < ICMP_PADDING_LENGTH_LINUX;++Index, ++CharData)
		ConfigurationParameter->ICMP_PaddingData[Index] = CharData;
	ConfigurationParameter->ICMP_PaddingLength = strlen(reinterpret_cast<const char *>(ConfigurationParameter->ICMP_PaddingData)); //Load default padding data(Linux).
#elif defined(PLATFORM_MACOS)
	for (size_t Index = 0, CharData = ICMP_STRING_START_NUM_MACOS;Index < ICMP_PADDING_LENGTH_MACOS;++Index, ++CharData)
		ConfigurationParameter->ICMP_PaddingData[Index] = CharData;
	ConfigurationParameter->ICMP_PaddingLength = strlen(reinterpret_cast<const char *>(ConfigurationParameter->ICMP_PaddingData)); //Load default padding data(macOS).
#endif
#endif

	//[Proxy] block
	ConfigurationParameter->SOCKS_Version = SOCKS_VERSION_5;
	ConfigurationParameter->SOCKS_Protocol_Network = REQUEST_MODE_NETWORK::BOTH;
	ConfigurationParameter->SOCKS_Protocol_Transport = REQUEST_MODE_TRANSPORT::TCP;
	ConfigurationParameter->HTTP_CONNECT_Protocol = REQUEST_MODE_NETWORK::BOTH;
	ConfigurationParameter->HTTP_CONNECT_Version = HTTP_VERSION_SELECTION::VERSION_AUTO;

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
	delete Local_FQDN_String;
	delete[] Local_FQDN_Response;
	Local_FQDN_String = nullptr;
	Local_FQDN_Response = nullptr;
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	delete[] LocalServer_Response;
	LocalServer_Response = nullptr;
#endif

//[Proxy] block
	delete SOCKS_TargetDomain;
#if defined(ENABLE_LIBSODIUM)
	sodium_free(SOCKS_Username);
	sodium_free(SOCKS_Password);
#else
	delete[] SOCKS_Username;
	delete[] SOCKS_Password;
#endif
#if defined(ENABLE_TLS)
	delete HTTP_CONNECT_TLS_SNI;
	delete HTTP_CONNECT_TLS_SNI_MBS;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	delete HTTP_CONNECT_TLS_AddressString_IPv6;
	delete HTTP_CONNECT_TLS_AddressString_IPv4;
#endif
#endif
	delete HTTP_CONNECT_TargetDomain;
	delete HTTP_CONNECT_HeaderField;
#if defined(ENABLE_LIBSODIUM)
	sodium_free(HTTP_CONNECT_ProxyAuthorization);
#else
	delete[] HTTP_CONNECT_ProxyAuthorization;
#endif
	SOCKS_TargetDomain = nullptr;
	SOCKS_Username = nullptr;
	SOCKS_Password = nullptr;
#if defined(ENABLE_TLS)
	HTTP_CONNECT_TLS_SNI = nullptr;
	HTTP_CONNECT_TLS_SNI_MBS = nullptr;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
	HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;
#endif
#endif
	HTTP_CONNECT_TargetDomain = nullptr;
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
	delete Local_FQDN_String;
	delete[] Local_FQDN_Response;
	Local_FQDN_String = nullptr;
	Local_FQDN_Response = nullptr;
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
	ConfigurationParameter->Version_Major = Version_Major;
	ConfigurationParameter->Version_Minor = Version_Minor;
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
	ConfigurationParameter->DirectRequest_Protocol = DirectRequest_Protocol;
	ConfigurationParameter->HostsDefaultTTL = HostsDefaultTTL;

//[Local DNS] block
	ConfigurationParameter->LocalProtocol_Network = LocalProtocol_Network;
	ConfigurationParameter->LocalProtocol_Transport = LocalProtocol_Transport;

//[Values] block
	ConfigurationParameter->ThreadPoolResetTime = ThreadPoolResetTime;
#if defined(ENABLE_PCAP)
	ConfigurationParameter->Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad = Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad;
	ConfigurationParameter->Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad = Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad;
	ConfigurationParameter->Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark = Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark;
	ConfigurationParameter->Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark = Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark;
	ConfigurationParameter->Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad = Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad;
	ConfigurationParameter->Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad = Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad;
	ConfigurationParameter->Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark = Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark;
	ConfigurationParameter->Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark = Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark;
#endif
	ConfigurationParameter->SocketTimeout_Reliable_Once = SocketTimeout_Reliable_Once;
	ConfigurationParameter->SocketTimeout_Reliable_Serial = SocketTimeout_Reliable_Serial;
	ConfigurationParameter->SocketTimeout_Unreliable_Once = SocketTimeout_Unreliable_Once;
	ConfigurationParameter->SocketTimeout_Unreliable_Serial = SocketTimeout_Unreliable_Serial;
	ConfigurationParameter->ReceiveWaiting = ReceiveWaiting;
#if defined(ENABLE_PCAP)
	ConfigurationParameter->ICMP_Speed = ICMP_Speed;
	ConfigurationParameter->DomainTest_Protocol = DomainTest_Protocol;
	ConfigurationParameter->DomainTest_Speed = DomainTest_Speed;
#endif
	ConfigurationParameter->MultipleRequestTimes = MultipleRequestTimes;

//[Switches] block
	ConfigurationParameter->DomainCaseConversion = DomainCaseConversion;
#if defined(ENABLE_PCAP)
	ConfigurationParameter->PacketCheck_TCP = PacketCheck_TCP;
#endif
	ConfigurationParameter->PacketCheck_DNS = PacketCheck_DNS;
	ConfigurationParameter->DataCheck_RRSetTTL = DataCheck_RRSetTTL;

//[Proxy] block
	if (ConfigurationParameter->SOCKS_TargetDomain != nullptr && !SOCKS_TargetDomain->empty() && SOCKS_TargetDomain_Port > 0)
	{
	//Reset old items.
		memset(&ConfigurationParameter->SOCKS_TargetServer, 0, sizeof(ConfigurationParameter->SOCKS_TargetServer));

	//Copy new items.
		*ConfigurationParameter->SOCKS_TargetDomain = *SOCKS_TargetDomain;
		ConfigurationParameter->SOCKS_TargetDomain_Port = SOCKS_TargetDomain_Port;
	}
	else if (SOCKS_TargetServer.Storage.ss_family != 0)
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
		if (SOCKS_UsernameLength > 0)
		{
			memcpy_s(ConfigurationParameter->SOCKS_Username, SOCKS_USERNAME_PASSWORD_MAXNUM, SOCKS_Username, SOCKS_UsernameLength);
			ConfigurationParameter->SOCKS_UsernameLength = SOCKS_UsernameLength;
		}
		else {
		#if defined(ENABLE_LIBSODIUM)
			sodium_memzero(ConfigurationParameter->SOCKS_Username, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
		#else
			memset(ConfigurationParameter->SOCKS_Username, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
		#endif
			ConfigurationParameter->SOCKS_UsernameLength = 0;
		}
	}
	if (ConfigurationParameter->SOCKS_Password != nullptr)
	{
		if (SOCKS_PasswordLength > 0)
		{
			memcpy_s(ConfigurationParameter->SOCKS_Password, SOCKS_USERNAME_PASSWORD_MAXNUM, SOCKS_Password, SOCKS_PasswordLength);
			ConfigurationParameter->SOCKS_PasswordLength = SOCKS_PasswordLength;
		}
		else {
		#if defined(ENABLE_LIBSODIUM)
			sodium_memzero(ConfigurationParameter->SOCKS_Password, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
		#else
			memset(ConfigurationParameter->SOCKS_Password, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
		#endif
			ConfigurationParameter->SOCKS_PasswordLength = 0;
		}
	}
	if (ConfigurationParameter->HTTP_CONNECT_TargetDomain != nullptr && !HTTP_CONNECT_TargetDomain->empty())
		*ConfigurationParameter->HTTP_CONNECT_TargetDomain = *HTTP_CONNECT_TargetDomain;
#if defined(ENABLE_TLS)
	ConfigurationParameter->HTTP_CONNECT_TLS_Version = HTTP_CONNECT_TLS_Version;
	ConfigurationParameter->HTTP_CONNECT_TLS_Validation = HTTP_CONNECT_TLS_Validation;
#endif
	if (ConfigurationParameter->HTTP_CONNECT_HeaderField != nullptr)
	{
		if (!HTTP_CONNECT_HeaderField->empty())
			*ConfigurationParameter->HTTP_CONNECT_HeaderField = *HTTP_CONNECT_HeaderField;
		else 
			ConfigurationParameter->HTTP_CONNECT_HeaderField->clear();
	}
	if (ConfigurationParameter->HTTP_CONNECT_ProxyAuthorization != nullptr)
	{
		if (HTTP_CONNECT_ProxyAuthorizationLength > 0)
		{
			memcpy_s(ConfigurationParameter->HTTP_CONNECT_ProxyAuthorization, HTTP_AUTHORIZATION_MAXSIZE, HTTP_CONNECT_ProxyAuthorization, HTTP_CONNECT_ProxyAuthorizationLength);
			ConfigurationParameter->HTTP_CONNECT_ProxyAuthorizationLength = HTTP_CONNECT_ProxyAuthorizationLength;
		}
		else {
		#if defined(ENABLE_LIBSODIUM)
			sodium_memzero(ConfigurationParameter->HTTP_CONNECT_ProxyAuthorization, HTTP_AUTHORIZATION_MAXSIZE + MEMORY_RESERVED_BYTES);
		#else
			memset(ConfigurationParameter->HTTP_CONNECT_ProxyAuthorization, 0, HTTP_AUTHORIZATION_MAXSIZE + MEMORY_RESERVED_BYTES);
		#endif
			ConfigurationParameter->HTTP_CONNECT_ProxyAuthorizationLength = 0;
		}
	}

	return;
}

//ConfigurationTable class MonitorItemReset function
void ConfigurationTable::MonitorItemReset(
	void)
{
//[Base] block
	Version_Major = 0;
	Version_Minor = 0;
	FileRefreshTime = DEFAULT_FILE_REFRESH_TIME;

//[Log] block
	PrintLogLevel = DEFAULT_LOG_LEVEL;
	LogMaxSize = DEFAULT_LOG_READING_MAXSIZE;

//[Listen] block
	IsIPFilterTypePermit = false;
	IPFilterLevel = 0;
	IsAcceptTypePermit = false;
	AcceptTypeList->clear();
	AcceptTypeList->shrink_to_fit();

//[DNS] block
	DirectRequest_Protocol = REQUEST_MODE_DIRECT::NONE;
	HostsDefaultTTL = DEFAULT_HOSTS_TTL;

//[Local DNS] block
	LocalProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
	LocalProtocol_Transport = REQUEST_MODE_TRANSPORT::UDP;

//[Values] block
	ThreadPoolResetTime = DEFAULT_THREAD_POOL_RESET_TIME;
#if defined(ENABLE_PCAP)
	Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad = 0;
	Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad = 0;
	Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark = 0;
	Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark = 0;
	Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad = 0;
	Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad = 0;
	Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark = 0;
	Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark = 0;
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
	DomainTest_Protocol = REQUEST_MODE_TEST::UDP;
	DomainTest_Speed = DEFAULT_DOMAIN_TEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
#endif
	MultipleRequestTimes = 0;

//[Switches] block
	DomainCaseConversion = false;
#if defined(ENABLE_PCAP)
	PacketCheck_TCP = false;
#endif
	PacketCheck_DNS = false;
	DataCheck_RRSetTTL = false;

//[Proxy] block
	memset(&SOCKS_TargetServer, 0, sizeof(SOCKS_TargetServer));
	if (SOCKS_TargetDomain != nullptr)
		SOCKS_TargetDomain->clear();
	SOCKS_TargetDomain_Port = 0;
	if (SOCKS_Username != nullptr)
	#if defined(ENABLE_LIBSODIUM)
		sodium_memzero(SOCKS_Username, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
	#else
		memset(SOCKS_Username, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
	#endif
	SOCKS_UsernameLength = 0;
	if (SOCKS_Password != nullptr)
	#if defined(ENABLE_LIBSODIUM)
		sodium_memzero(SOCKS_Password, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
	#else
		memset(SOCKS_Password, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + MEMORY_RESERVED_BYTES);
	#endif
	SOCKS_PasswordLength = 0;
	if (HTTP_CONNECT_TargetDomain != nullptr)
		HTTP_CONNECT_TargetDomain->clear();
#if defined(ENABLE_TLS)
	HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::VERSION_AUTO;
	HTTP_CONNECT_TLS_Validation = false;
#endif
	if (HTTP_CONNECT_HeaderField != nullptr)
		HTTP_CONNECT_HeaderField->clear();
	if (HTTP_CONNECT_ProxyAuthorization != nullptr)
	#if defined(ENABLE_LIBSODIUM)
		sodium_memzero(HTTP_CONNECT_ProxyAuthorization, HTTP_AUTHORIZATION_MAXSIZE + MEMORY_RESERVED_BYTES);
	#else
		memset(HTTP_CONNECT_ProxyAuthorization, 0, HTTP_AUTHORIZATION_MAXSIZE + MEMORY_RESERVED_BYTES);
	#endif
	HTTP_CONNECT_ProxyAuthorizationLength = 0;

	return;
}

//GlobalStatus class constructor
GlobalStatus::GlobalStatus(
	void)
{
//Class constructor
	memset(this, 0, sizeof(GLOBAL_STATUS));
	try {
		LocalListeningSocket = new std::vector<SYSTEM_SOCKET>();
		RandomEngine = new std::default_random_engine();
		ThreadRunningNum = new std::atomic<size_t>();
		ThreadRunningFreeNum = new std::atomic<size_t>();
		Path_Global = new std::vector<std::wstring>();
		Path_ErrorLog = new std::wstring();
		FileList_Hosts = new std::vector<std::wstring>();
		FileList_IPFilter = new std::vector<std::wstring>();
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		Path_Global_MBS = new std::vector<std::string>();
		Path_ErrorLog_MBS = new std::string();
		FileList_Hosts_MBS = new std::vector<std::string>();
		FileList_IPFilter_MBS = new std::vector<std::string>();
	#endif
		LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6] = new uint8_t[PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES]();
		LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4] = new uint8_t[PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES]();
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6] = new std::vector<std::string>();
		LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4] = new std::vector<std::string>();
	#endif
	}
	catch (std::bad_alloc &)
	{
		delete LocalListeningSocket;
		delete RandomEngine;
		delete ThreadRunningNum;
		delete ThreadRunningFreeNum;
		delete Path_Global;
		delete Path_ErrorLog;
		delete FileList_Hosts;
		delete FileList_IPFilter;
		LocalListeningSocket = nullptr;
		RandomEngine = nullptr;
		ThreadRunningNum = nullptr;
		ThreadRunningFreeNum = nullptr;
		Path_Global = nullptr;
		Path_ErrorLog = nullptr;
		FileList_Hosts = nullptr;
		FileList_IPFilter = nullptr;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		delete Path_Global_MBS;
		delete Path_ErrorLog_MBS;
		delete FileList_Hosts_MBS;
		delete FileList_IPFilter_MBS;
		Path_Global_MBS = nullptr;
		Path_ErrorLog_MBS = nullptr;
		FileList_Hosts_MBS = nullptr;
		FileList_IPFilter_MBS = nullptr;
	#endif
		delete[] LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6];
		delete[] LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4];
		LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6] = nullptr;
		LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4] = nullptr;
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		delete LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6];
		delete LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4];
		LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6] = nullptr;
		LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4] = nullptr;
	#endif

	//Exit process.
		exit(EXIT_FAILURE);
//		return;
	}

//GlobalStatus settings
	GlobalStatusSetting(this);

//Libraries initialization
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
#if defined(ENABLE_TLS)
//OpenSSL main initialization
	if (!GlobalRunningStatus.IsInitialized_OpenSSL)
	{
		OpenSSL_LibraryInit(true);
		GlobalRunningStatus.IsInitialized_OpenSSL = true;
	}
#endif
#endif

	return;
}

//GlobalStatus class constructor settings
void GlobalStatusSetting(
	GLOBAL_STATUS * const GlobalRunningStatusParameter)
{
#if defined(PLATFORM_LINUX)
	GlobalRunningStatusParameter->IsDaemon = true;
#endif
	std::random_device RandomDevice;
	GlobalRunningStatusParameter->RandomEngine->seed(RandomDevice());
	GlobalRunningStatusParameter->DomainTable_Normal = const_cast<uint8_t *>(DomainTable_Normal);
	GlobalRunningStatusParameter->DomainTable_Upper = const_cast<uint8_t *>(DomainTable_Upper);
#if !defined(ENABLE_LIBSODIUM)
	GlobalRunningStatusParameter->Base64_EncodeTable = const_cast<uint8_t *>(Base64_EncodeTable_Initialization);
	GlobalRunningStatusParameter->Base64_DecodeTable = const_cast<int8_t *>(Base64_DecodeTable_Initialization);
#endif
	GlobalRunningStatusParameter->GatewayAvailable_IPv4 = true;
	memset(GlobalRunningStatusParameter->LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6], 0, PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
	memset(GlobalRunningStatusParameter->LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4], 0, PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);

	return;
}

//GlobalStatus class destructor
GlobalStatus::~GlobalStatus(
	void)
{
//Close all sockets.
	for (auto &SocketItem:*LocalListeningSocket)
		SocketSetting(SocketItem, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

#if defined(PLATFORM_WIN)
//WinSock cleanup
	if (IsInitialized_WinSock)
	{
		WSACleanup();
		IsInitialized_WinSock = false;
	}

//Mutex handle cleanup
	if (Initialized_MutexHandle != nullptr)
	{
		ReleaseMutex(Initialized_MutexHandle);
		CloseHandle(Initialized_MutexHandle);
		Initialized_MutexHandle = nullptr;
	}

//Close all file handles.
	_fcloseall();
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//Mutex handle cleanup
	if (Initialized_MutexHandle != 0 && Initialized_MutexHandle != RETURN_ERROR)
	{
		flock(Initialized_MutexHandle, LOCK_UN);
		close(Initialized_MutexHandle);
		Initialized_MutexHandle = 0;
	}

//Free all OpenSSL libraries.
#if defined(ENABLE_TLS)
	if (IsInitialized_OpenSSL)
	{
		OpenSSL_LibraryInit(false);
		IsInitialized_OpenSSL = false;
	}
#endif

//Close all file handles.
#if (defined(PLATFORM_LINUX) && !defined(PLATFORM_OPENWRT))
	fcloseall();
#endif
#endif

//Delete and reset pointers.
	delete LocalListeningSocket;
	delete RandomEngine;
	delete Path_Global;
	delete Path_ErrorLog;
	delete FileList_Hosts;
	delete FileList_IPFilter;
	LocalListeningSocket = nullptr;
	RandomEngine = nullptr;
	Path_Global = nullptr;
	Path_ErrorLog = nullptr;
	FileList_Hosts = nullptr;
	FileList_IPFilter = nullptr;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	delete Path_Global_MBS;
	delete Path_ErrorLog_MBS;
	delete FileList_Hosts_MBS;
	delete FileList_IPFilter_MBS;
	Path_Global_MBS = nullptr;
	Path_ErrorLog_MBS = nullptr;
	FileList_Hosts_MBS = nullptr;
	FileList_IPFilter_MBS = nullptr;
#endif
	delete[] LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6];
	delete[] LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4];
	LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6] = nullptr;
	LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4] = nullptr;
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	delete LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6];
	delete LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4];
	LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6] = nullptr;
	LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4] = nullptr;
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
	PermissionType = HOSTS_TYPE::NONE;
	PermissionOperation = false;
	IsStringMatching = false;

	return;
}

//AddressRoutingTable class constructor
AddressRoutingTable::AddressRoutingTable(
	void)
{
	Prefix = 0;
	return;
}

//AlternateSwapTable class constructor
AlternateSwapTable::AlternateSwapTable(
	void)
{
	TimeoutTimes.fill(0);
	IsSwapped.fill(false);

	return;
}

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


//SocketValueTable class SocketValueInit function
bool SocketValueTable::SocketValueInit(
	const uint16_t SocketNetwork, 
	const uint16_t SocketType, 
	const uint16_t SocketTransport, 
	const uint16_t SocketPort, 
	const void * const SocketAddress, 
	ssize_t * const ErrorCode)
{
//Initialization
	SOCKET_DATA ValueItem;
	memset(&ValueItem, 0, sizeof(ValueItem));

//IPv6
	if (SocketNetwork == AF_INET6)
	{
		ValueItem.Socket = socket(AF_INET6, SocketType, SocketTransport);
		if (!SocketSetting(ValueItem.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr))
		{
			if (ErrorCode != nullptr)
				*ErrorCode = WSAGetLastError();
		}
		else {
			ValueItem.AddrLen = sizeof(sockaddr_in6);
			ValueItem.SockAddr.ss_family = AF_INET6;
			reinterpret_cast<sockaddr_in6 *>(&ValueItem.SockAddr)->sin6_port = hton16(SocketPort);
			if (SocketAddress != nullptr)
				memcpy_s(&reinterpret_cast<sockaddr_in6 *>(&ValueItem.SockAddr)->sin6_addr, sizeof(reinterpret_cast<const sockaddr_in6 *>(&ValueItem.SockAddr)->sin6_addr), SocketAddress, sizeof(in6_addr));

		//Add item to list.
			ValueSet.push_back(ValueItem);
			return true;
		}
	}
//IPv4
	else if (SocketNetwork == AF_INET)
	{
		ValueItem.Socket = socket(AF_INET, SocketType, SocketTransport);
		if (!SocketSetting(ValueItem.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr))
		{
			if (ErrorCode != nullptr)
				*ErrorCode = WSAGetLastError();
		}
		else {
			ValueItem.AddrLen = sizeof(sockaddr_in);
			ValueItem.SockAddr.ss_family = AF_INET;
			reinterpret_cast<sockaddr_in *>(&ValueItem.SockAddr)->sin_port = hton16(SocketPort);
			if (SocketAddress != nullptr)
				memcpy_s(&reinterpret_cast<sockaddr_in *>(&ValueItem.SockAddr)->sin_addr, sizeof(reinterpret_cast<const sockaddr_in *>(&ValueItem.SockAddr)->sin_addr), SocketAddress, sizeof(in_addr));

		//Add item to list.
			ValueSet.push_back(ValueItem);
			return true;
		}
	}

	return false;
}

//SocketValueTable class ClearAllSocket function
void SocketValueTable::ClearAllSocket(
	const bool IsPrintError)
{
//Close all sockets and clear list.
	if (!ValueSet.empty())
	{
		for (auto &SocketItem:ValueSet)
			SocketSetting(SocketItem.Socket, SOCKET_SETTING_TYPE::CLOSE, IsPrintError, nullptr);

		ValueSet.clear();
		ValueSet.shrink_to_fit();
	}

	return;
}

//SocketValueTable class destructor
SocketValueTable::~SocketValueTable(
	void)
{
//Close all sockets.
	for (auto &SocketItem:ValueSet)
		SocketSetting(SocketItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

	return;
}

#if defined(ENABLE_PCAP)
//EventTable_SocketSend class constructor
EventTable_SocketSend::EventTable_SocketSend(
	void)
{
	Protocol = 0;
	memset(&SocketTimeout, 0, sizeof(SocketTimeout));
	memset(&IntervalTimeout, 0, sizeof(IntervalTimeout));
	EventBase = nullptr;
	EventList = nullptr;
	SocketValue = nullptr;
	SendBuffer = nullptr;
	RecvBuffer = nullptr;
	SendSize = 0;
	RecvSize = 0;
	TotalSleepTime = 0;
	OnceTimes = 0;
	RetestTimes = 0;
	FileModifiedTime = 0;
	PacketSequence = 0;

	return;
}

//EventTable_SocketSend class destructor
EventTable_SocketSend::~EventTable_SocketSend(
	void)
{
//Free all event items.
	for (auto &EventItem:*EventList)
	{
		if (EventItem != nullptr)
		{
			event_free(EventItem);
			EventItem = nullptr;
		}
	}

//Free event base.
	if (EventBase != nullptr)
	{
		event_base_free(EventBase);
		EventBase = nullptr;
	}

	return;
}

//EventTable_TransmissionOnce class constructor
EventTable_TransmissionOnce::EventTable_TransmissionOnce(
	void)
{
	Protocol_Network = 0;
	Protocol_Transport = nullptr;
	SocketTimeout = nullptr;
	memset(&IntervalTimeout, 0, sizeof(IntervalTimeout));
	EventBase = nullptr;
	EventList = nullptr;
	EventBufferList = nullptr;
	SocketValue = nullptr;
	SendBuffer = nullptr;
	RecvBuffer = nullptr;
	SendSize = 0;
	SendLen = nullptr;
	SendTimes = nullptr;
	RecvSize = 0;
	TotalSleepTime = 0;
	OnceTimes = 0;
	RetestTimes = 0;
	FileModifiedTime = 0;

	return;
}

//EventTable_TransmissionOnce class destructor
EventTable_TransmissionOnce::~EventTable_TransmissionOnce(
	void)
{
//Free all bufferevent items.
	for (auto &EventBufferItem:*EventBufferList)
	{
		if (EventBufferItem != nullptr)
		{
			bufferevent_free(EventBufferItem);
			EventBufferItem = nullptr;
		}
	}

//Free all event items.
	for (auto &EventItem:*EventList)
	{
		if (EventItem != nullptr)
		{
			event_free(EventItem);
			EventItem = nullptr;
		}
	}

//Free event base.
	if (EventBase != nullptr)
	{
		event_base_free(EventBase);
		EventBase = nullptr;
	}

	return;
}
#endif

//SocketSelectingOnceTable class constructor
SocketSelectingOnceTable::SocketSelectingOnceTable(
	void)
{
	RecvLen = 0;
	IsPacketDone = false;

	return;
}

#if defined(ENABLE_PCAP)
//CaptureDeviceTable class constructor
CaptureDeviceTable::CaptureDeviceTable(
	void)
{
	memset(this, 0, sizeof(CAPTURE_DEVICE_TABLE));
	try {
		DeviceName = new std::string();
	}
	catch (std::bad_alloc &)
	{
		delete DeviceName;
		DeviceName = nullptr;

	//Exit process.
		exit(EXIT_FAILURE);
//		return;
	}

	return;
}

//CaptureDeviceTable class destructor
CaptureDeviceTable::~CaptureDeviceTable(
	void)
{
	delete DeviceName;
	DeviceName = nullptr;
	if (DeviceHandle != nullptr)
	{
		pcap_close(DeviceHandle);
		DeviceHandle = nullptr;
	}
	if (!CheckEmptyBuffer(&BPF_Code, sizeof(BPF_Code)))
	{
		pcap_freecode(&BPF_Code);
		memset(&BPF_Code, 0, sizeof(BPF_Code));
	}

	return;
}

//InputPacketTable class constructor
OutputPacketTable::OutputPacketTable(
	void)
{
//Initialization
	memset(&SocketData_Input, 0, sizeof(SocketData_Input));
	SocketData_Input.Socket = INVALID_SOCKET;
	ReceiveIndex = 0;
	Protocol_Network = 0;
	Protocol_Transport = 0;
	ClearPortTime = 0;
	EDNS_Length = 0;

	return;
}
#endif

#if defined(ENABLE_LIBSODIUM)
//DNSCurveConfigurationTable class constructor
DNSCurveConfigurationTable::DNSCurveConfigurationTable(
	void)
{
//Class constructor
	memset(this, 0, sizeof(DNSCURVE_CONFIGURATION_TABLE));
	try {
	//[DNSCurve Database] block
		DatabaseName = new std::wstring();
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		DatabaseName_MBS = new std::string();
	#endif
		Database_Target_Server_Main_IPv6 = new std::string();
		Database_Target_Server_Alternate_IPv6 = new std::string();
		Database_Target_Server_Main_IPv4 = new std::string();
		Database_Target_Server_Alternate_IPv4 = new std::string();
		Database_LineData = new std::vector<std::vector<std::string>>();

	//[DNSCurve Addresses] block
		DNSCurve_Target_Server_Main_IPv6.ProviderName = new uint8_t[DOMAIN_MAXSIZE]();
		DNSCurve_Target_Server_Alternate_IPv6.ProviderName = new uint8_t[DOMAIN_MAXSIZE]();
		DNSCurve_Target_Server_Main_IPv4.ProviderName = new uint8_t[DOMAIN_MAXSIZE]();
		DNSCurve_Target_Server_Alternate_IPv4.ProviderName = new uint8_t[DOMAIN_MAXSIZE]();

	//[DNSCurve Keys] block
		Client_PublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		Client_SecretKey = reinterpret_cast<uint8_t *>(sodium_malloc(crypto_box_SECRETKEYBYTES));
		DNSCurve_Target_Server_Main_IPv6.PrecomputationKey = reinterpret_cast<uint8_t *>(sodium_malloc(crypto_box_BEFORENMBYTES));
		DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey = reinterpret_cast<uint8_t *>(sodium_malloc(crypto_box_BEFORENMBYTES));
		DNSCurve_Target_Server_Main_IPv4.PrecomputationKey = reinterpret_cast<uint8_t *>(sodium_malloc(crypto_box_BEFORENMBYTES));
		DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey = reinterpret_cast<uint8_t *>(sodium_malloc(crypto_box_BEFORENMBYTES));
		DNSCurve_Target_Server_Main_IPv6.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Main_IPv4.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Main_IPv6.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Main_IPv4.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint = new uint8_t[crypto_box_PUBLICKEYBYTES]();

	//[DNSCurve Magic Number] block
		DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Main_IPv4.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Main_IPv6.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
	}
	catch (std::bad_alloc &)
	{
	//[DNSCurve Database] block
		delete DatabaseName;
		DatabaseName = nullptr;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		delete DatabaseName_MBS;
		DatabaseName_MBS = nullptr;
	#endif
		delete Database_Target_Server_Main_IPv6;
		delete Database_Target_Server_Alternate_IPv6;
		delete Database_Target_Server_Main_IPv4;
		delete Database_Target_Server_Alternate_IPv4;
		delete Database_LineData;
		Database_Target_Server_Main_IPv6 = nullptr;
		Database_Target_Server_Alternate_IPv6 = nullptr;
		Database_Target_Server_Main_IPv4 = nullptr;
		Database_Target_Server_Alternate_IPv4 = nullptr;
		Database_LineData = nullptr;

	//[DNSCurve Addresses] block
		delete[] DNSCurve_Target_Server_Main_IPv6.ProviderName;
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ProviderName;
		delete[] DNSCurve_Target_Server_Main_IPv4.ProviderName;
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ProviderName;
		DNSCurve_Target_Server_Main_IPv6.ProviderName = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.ProviderName = nullptr;
		DNSCurve_Target_Server_Main_IPv4.ProviderName = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.ProviderName = nullptr;

	//[DNSCurve Keys] block
		delete[] Client_PublicKey;
		sodium_free(Client_SecretKey);
		sodium_free(DNSCurve_Target_Server_Main_IPv6.PrecomputationKey);
		sodium_free(DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey);
		sodium_free(DNSCurve_Target_Server_Main_IPv4.PrecomputationKey);
		sodium_free(DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey);
		delete[] DNSCurve_Target_Server_Main_IPv6.ServerPublicKey;
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey;
		delete[] DNSCurve_Target_Server_Main_IPv4.ServerPublicKey;
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey;
		delete[] DNSCurve_Target_Server_Main_IPv6.ServerFingerprint;
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint;
		delete[] DNSCurve_Target_Server_Main_IPv4.ServerFingerprint;
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint;
		Client_PublicKey = nullptr;
		Client_SecretKey = nullptr;
		DNSCurve_Target_Server_Main_IPv6.PrecomputationKey = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey = nullptr;
		DNSCurve_Target_Server_Main_IPv4.PrecomputationKey = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey = nullptr;
		DNSCurve_Target_Server_Main_IPv6.ServerPublicKey = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey = nullptr;
		DNSCurve_Target_Server_Main_IPv4.ServerPublicKey = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey = nullptr;
		DNSCurve_Target_Server_Main_IPv6.ServerFingerprint = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint = nullptr;
		DNSCurve_Target_Server_Main_IPv4.ServerFingerprint = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint = nullptr;

	//[DNSCurve Magic Number] block
		delete[] DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber;
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber;
		delete[] DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber;
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber;
		delete[] DNSCurve_Target_Server_Main_IPv6.SendMagicNumber;
		delete[] DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber;
		delete[] DNSCurve_Target_Server_Main_IPv4.SendMagicNumber;
		delete[] DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber;
		DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber = nullptr;
		DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber = nullptr;
		DNSCurve_Target_Server_Main_IPv6.SendMagicNumber = nullptr;
		DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = nullptr;
		DNSCurve_Target_Server_Main_IPv4.SendMagicNumber = nullptr;
		DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = nullptr;

	//Exit process.
		exit(EXIT_FAILURE);
//		return;
	}

//DNSCurveConfigurationTable settings
	DNSCurveConfigurationTableSetting(this);
	return;
}

//DNSCurveConfigurationTable class constructor settings
void DNSCurveConfigurationTableSetting(
	DNSCURVE_CONFIGURATION_TABLE * const DNSCurveConfigurationParameter)
{
//[DNSCurve Addresses] block
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ProviderName, 0, DOMAIN_MAXSIZE);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ProviderName, 0, DOMAIN_MAXSIZE);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ProviderName, 0, DOMAIN_MAXSIZE);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ProviderName, 0, DOMAIN_MAXSIZE);

//[DNSCurve Keys] block
	memset(DNSCurveConfigurationParameter->Client_PublicKey, 0, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->Client_SecretKey, crypto_box_SECRETKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);

//[DNSCurve Magic Number] block
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);

//Default settings
	//[DNSCurve] block
	DNSCurveConfigurationParameter->DNSCurveProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
	DNSCurveConfigurationParameter->DNSCurveProtocol_Transport = REQUEST_MODE_TRANSPORT::UDP;
	DNSCurveConfigurationParameter->DNSCurvePayloadSize = EDNS_PACKET_MINSIZE;
#if defined(PLATFORM_WIN)
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Reliable = DNSCURVE_DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Unreliable = DNSCURVE_DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Reliable.tv_sec = DNSCURVE_DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	DNSCurveConfigurationParameter->DNSCurve_SocketTimeout_Unreliable.tv_sec = DNSCURVE_DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
#endif
	DNSCurveConfigurationParameter->KeyRecheckTime = DNSCURVE_DEFAULT_RECHECK_TIME * SECOND_TO_MILLISECOND;

	return;
}

//DNSCurveConfigurationTable class destructor
DNSCurveConfigurationTable::~DNSCurveConfigurationTable(
	void)
{
//[DNSCurve Database] block
	delete DatabaseName;
	DatabaseName = nullptr;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	delete DatabaseName_MBS;
	DatabaseName_MBS = nullptr;
#endif
	delete Database_Target_Server_Main_IPv6;
	delete Database_Target_Server_Alternate_IPv6;
	delete Database_Target_Server_Main_IPv4;
	delete Database_Target_Server_Alternate_IPv4;
	delete Database_LineData;
	Database_Target_Server_Main_IPv6 = nullptr;
	Database_Target_Server_Alternate_IPv6 = nullptr;
	Database_Target_Server_Main_IPv4 = nullptr;
	Database_Target_Server_Alternate_IPv4 = nullptr;
	Database_LineData = nullptr;

//[DNSCurve Addresses] block
	delete[] DNSCurve_Target_Server_Main_IPv6.ProviderName;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.ProviderName;
	delete[] DNSCurve_Target_Server_Main_IPv4.ProviderName;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.ProviderName;
	DNSCurve_Target_Server_Main_IPv6.ProviderName = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.ProviderName = nullptr;
	DNSCurve_Target_Server_Main_IPv4.ProviderName = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.ProviderName = nullptr;

//[DNSCurve Keys] block
	delete[] Client_PublicKey;
	sodium_free(Client_SecretKey);
	sodium_free(DNSCurve_Target_Server_Main_IPv6.PrecomputationKey);
	sodium_free(DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey);
	sodium_free(DNSCurve_Target_Server_Main_IPv4.PrecomputationKey);
	sodium_free(DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey);
	delete[] DNSCurve_Target_Server_Main_IPv6.ServerPublicKey;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey;
	delete[] DNSCurve_Target_Server_Main_IPv4.ServerPublicKey;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey;
	delete[] DNSCurve_Target_Server_Main_IPv6.ServerFingerprint;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint;
	delete[] DNSCurve_Target_Server_Main_IPv4.ServerFingerprint;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint;
	Client_PublicKey = nullptr;
	Client_SecretKey = nullptr;
	DNSCurve_Target_Server_Main_IPv6.PrecomputationKey = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey = nullptr;
	DNSCurve_Target_Server_Main_IPv4.PrecomputationKey = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey = nullptr;
	DNSCurve_Target_Server_Main_IPv6.ServerPublicKey = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey = nullptr;
	DNSCurve_Target_Server_Main_IPv4.ServerPublicKey = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey = nullptr;
	DNSCurve_Target_Server_Main_IPv6.ServerFingerprint = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint = nullptr;
	DNSCurve_Target_Server_Main_IPv4.ServerFingerprint = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint = nullptr;

//[DNSCurve Magic Number] block
	delete[] DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber;
	delete[] DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber;
	delete[] DNSCurve_Target_Server_Main_IPv6.SendMagicNumber;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber;
	delete[] DNSCurve_Target_Server_Main_IPv4.SendMagicNumber;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber;
	DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber = nullptr;
	DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber = nullptr;
	DNSCurve_Target_Server_Main_IPv6.SendMagicNumber = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = nullptr;
	DNSCurve_Target_Server_Main_IPv4.SendMagicNumber = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = nullptr;

	return;
}

//DNSCurveConfigurationTable class SetToMonitorItem function
void DNSCurveConfigurationTable::SetToMonitorItem(
	void)
{
//Delete and reset pointers.
	delete DatabaseName;
	DatabaseName = nullptr;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	delete DatabaseName_MBS;
	DatabaseName_MBS = nullptr;
#endif
	delete Database_Target_Server_Main_IPv6;
	delete Database_Target_Server_Alternate_IPv6;
	delete Database_Target_Server_Main_IPv4;
	delete Database_Target_Server_Alternate_IPv4;
	Database_Target_Server_Main_IPv6 = nullptr;
	Database_Target_Server_Alternate_IPv6 = nullptr;
	Database_Target_Server_Main_IPv4 = nullptr;
	Database_Target_Server_Alternate_IPv4 = nullptr;
	delete[] DNSCurve_Target_Server_Main_IPv6.ProviderName;
	delete[] DNSCurve_Target_Server_Alternate_IPv6.ProviderName;
	delete[] DNSCurve_Target_Server_Main_IPv4.ProviderName;
	delete[] DNSCurve_Target_Server_Alternate_IPv4.ProviderName;
	DNSCurve_Target_Server_Main_IPv6.ProviderName = nullptr;
	DNSCurve_Target_Server_Alternate_IPv6.ProviderName = nullptr;
	DNSCurve_Target_Server_Main_IPv4.ProviderName = nullptr;
	DNSCurve_Target_Server_Alternate_IPv4.ProviderName = nullptr;

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
	if (DNSCurveConfigurationParameter->Client_SecretKey != nullptr && sodium_is_zero(Client_SecretKey, crypto_box_PUBLICKEYBYTES) == 0 && 
		sodium_memcmp(DNSCurveConfigurationParameter->Client_SecretKey, Client_SecretKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->Client_SecretKey, crypto_box_PUBLICKEYBYTES, Client_SecretKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.PrecomputationKey != nullptr && 
		sodium_is_zero(DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) == 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey != nullptr && 
		sodium_is_zero(DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) == 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.PrecomputationKey != nullptr && 
		sodium_is_zero(DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) == 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey != nullptr && 
		sodium_is_zero(DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) == 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES, DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);

//[DNSCurve Magic Number] block
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);

	return;
}

//DNSCurveConfigurationTable class MonitorItemReset function
void DNSCurveConfigurationTable::MonitorItemReset(
	void)
{
//[DNSCurve] block
#if defined(PLATFORM_WIN)
	DNSCurve_SocketTimeout_Reliable = DNSCURVE_DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	DNSCurve_SocketTimeout_Unreliable = DNSCURVE_DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	DNSCurve_SocketTimeout_Reliable.tv_sec = DNSCURVE_DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	DNSCurve_SocketTimeout_Reliable.tv_usec = 0;
	DNSCurve_SocketTimeout_Unreliable.tv_sec = DNSCURVE_DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
	DNSCurve_SocketTimeout_Unreliable.tv_usec = 0;
#endif
	KeyRecheckTime = DNSCURVE_DEFAULT_RECHECK_TIME * SECOND_TO_MILLISECOND;

//[DNSCurve database] block
	if (Database_LineData != nullptr)
	{
		Database_LineData->clear();
		Database_LineData->shrink_to_fit();
	}

//[DNSCurve Keys] block
	if (Client_PublicKey != nullptr)
		memset(Client_PublicKey, 0, crypto_box_PUBLICKEYBYTES);
	if (Client_SecretKey != nullptr)
		sodium_memzero(Client_SecretKey, crypto_box_SECRETKEYBYTES);
	if (DNSCurve_Target_Server_Main_IPv6.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurve_Target_Server_Main_IPv4.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurve_Target_Server_Main_IPv6.ServerPublicKey != nullptr)
		memset(DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey != nullptr)
		memset(DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Main_IPv4.ServerPublicKey != nullptr)
		memset(DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey != nullptr)
		memset(DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Main_IPv6.ServerFingerprint != nullptr)
		memset(DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint != nullptr)
		memset(DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Main_IPv4.ServerFingerprint != nullptr)
		memset(DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint != nullptr)
		memset(DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);

//[DNSCurve Magic Number] block
	if (DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber != nullptr)
		memset(DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber != nullptr)
		memset(DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber != nullptr)
		memset(DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber != nullptr)
		memset(DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Main_IPv6.SendMagicNumber != nullptr)
		memset(DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber != nullptr)
		memset(DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Main_IPv4.SendMagicNumber != nullptr)
		memset(DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber != nullptr)
		memset(DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);

	return;
}

//DNSCurveSocketSelectingTable class constructor
DNSCurveSocketSelectingTable::DNSCurveSocketSelectingTable(
	void)
{
	ServerType = DNSCURVE_SERVER_TYPE::NONE;
	PrecomputationKey = nullptr;
	ReceiveMagicNumber = nullptr;
	SendBuffer = nullptr;
	SendSize = 0;
	RecvLen = 0;
	IsPacketDone = false;

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
	Protocol_Network = 0;
	Protocol_Transport = 0;
	Socket = INVALID_SOCKET;

	return;
}

//OpenSSLContextTable class destructor
OpenSSLContextTable::~OpenSSLContextTable(
	void)
{
//Free all sessions.
	if (SessionBIO != nullptr)
	{
		BIO_free_all(SessionBIO);
		SessionBIO = nullptr;
	}

//Free all method context.
	if (MethodContext != nullptr)
	{
		SSL_CTX_free(MethodContext);
		MethodContext = nullptr;
	}

//Close all sockets.
	if (SocketSetting(Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
		SocketSetting(Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

	return;
}
#endif
#endif
