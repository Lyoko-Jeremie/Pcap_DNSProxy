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


#include "Initialization.h"

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
	#if !defined(PLATFORM_MACX)
		LocalServer_Response = new char[DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt)]();
	#endif

	//[Proxy] block
		SOCKS_TargetDomain = new char[DOMAIN_MAXSIZE]();
		SOCKS_Username = new char[SOCKS_USERNAME_PASSWORD_MAXNUM + 1U]();
		SOCKS_Password = new char[SOCKS_USERNAME_PASSWORD_MAXNUM + 1U]();
	}
	catch (std::bad_alloc)
	{
	//[Listen] block
	#if defined(ENABLE_PCAP)
		delete PcapDevicesBlacklist;
	#endif
		delete ListenPort;
		delete AcceptTypeList;

	//[Addresses] block
		delete ListenAddress_IPv6;
		delete ListenAddress_IPv4;
		delete LocalhostSubnet.IPv6;
		delete LocalhostSubnet.IPv4;
		delete DNSTarget.IPv6_Multi;
		delete DNSTarget.IPv4_Multi;

	//[Data] block
	#if defined(ENABLE_PCAP)
		delete[] ICMP_PaddingData;
		delete[] DomainTest_Data;
	#endif
		delete[] LocalFQDN_Response;
		delete LocalFQDN_String;
	#if !defined(PLATFORM_MACX)
		delete[] LocalServer_Response;
	#endif

	//[Proxy] block
		delete[] SOCKS_TargetDomain;
		delete[] SOCKS_Username;
		delete[] SOCKS_Password;

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
#if !defined(PLATFORM_MACX)
	memset(ConfigurationParameter->LocalServer_Response, 0, DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt));
#endif
	memset(ConfigurationParameter->SOCKS_TargetDomain, 0, DOMAIN_MAXSIZE);
	memset(ConfigurationParameter->SOCKS_Username, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + 1U);
	memset(ConfigurationParameter->SOCKS_Password, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + 1U);

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
	ConfigurationParameter->SOCKS_SocketTimeout_Reliable = DEFAULT_SOCKS_RELIABLE_SOCKET_TIMEOUT;
	ConfigurationParameter->SOCKS_SocketTimeout_Unreliable = DEFAULT_SOCKS_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	ConfigurationParameter->SocketTimeout_Reliable.tv_sec = DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	ConfigurationParameter->SocketTimeout_Unreliable.tv_sec = DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
	ConfigurationParameter->SOCKS_SocketTimeout_Reliable.tv_sec = DEFAULT_SOCKS_RELIABLE_SOCKET_TIMEOUT;
	ConfigurationParameter->SOCKS_SocketTimeout_Unreliable.tv_sec = DEFAULT_SOCKS_UNRELIABLE_SOCKET_TIMEOUT;
#endif
	ConfigurationParameter->AlternateTimes = DEFAULT_ALTERNATE_TIMES;
	ConfigurationParameter->AlternateTimeRange = DEFAULT_ALTERNATE_RANGE * SECOND_TO_MILLISECOND;
	ConfigurationParameter->AlternateResetTime = DEFAULT_ALTERNATE_RESET_TIME * SECOND_TO_MILLISECOND;
#if defined(ENABLE_PCAP)
	#if defined(PLATFORM_MACX)
		ConfigurationParameter->ICMP_ID = htons(*(PUINT16)pthread_self());
	#else
		ConfigurationParameter->ICMP_ID = htons((uint16_t)GetCurrentProcessId()); //Default ICMP ID is current process ID.
	#endif
		ConfigurationParameter->ICMP_Sequence = htons(DEFAULT_SEQUENCE);
		ConfigurationParameter->DomainTest_Speed = DEFAULT_DOMAINTEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
	#if defined(PLATFORM_MACX)
		ConfigurationParameter->DomainTest_ID = htons(*(PUINT16)pthread_self());
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

	return;
}

//ConfigurationTable class destructor
ConfigurationTable::~ConfigurationTable(
	void)
{
//Delete all pointers.
//[Listen] block
#if defined(ENABLE_PCAP)
	delete PcapDevicesBlacklist;
#endif
	delete ListenPort;
	delete AcceptTypeList;

//[Addresses] block
	delete ListenAddress_IPv6;
	delete ListenAddress_IPv4;
	delete LocalhostSubnet.IPv6;
	delete LocalhostSubnet.IPv4;
	delete DNSTarget.IPv6_Multi;
	delete DNSTarget.IPv4_Multi;

//[Data] block
#if defined(ENABLE_PCAP)
	delete[] ICMP_PaddingData;
	delete[] DomainTest_Data;
#endif
	delete[] LocalFQDN_Response;
	delete LocalFQDN_String;
#if !defined(PLATFORM_MACX)
	delete[] LocalServer_Response;
#endif

//[Proxy] block
	delete[] SOCKS_TargetDomain;
	delete[] SOCKS_Username;
	delete[] SOCKS_Password;

	return;
}

//ConfigurationTable class SetToMonitorItem function
void ConfigurationTable::SetToMonitorItem(
	void)
{
//[Listen] block
#if defined(ENABLE_PCAP)
	delete PcapDevicesBlacklist;
#endif
	delete ListenPort;

//[Addresses] block
	delete ListenAddress_IPv6;
	delete ListenAddress_IPv4;
	delete LocalhostSubnet.IPv6;
	delete LocalhostSubnet.IPv4;
	delete DNSTarget.IPv6_Multi;
	delete DNSTarget.IPv4_Multi;

//[Data] block
#if defined(ENABLE_PCAP)
	delete[] ICMP_PaddingData;
	delete[] DomainTest_Data;
#endif
	delete[] LocalFQDN_Response;
	delete LocalFQDN_String;
#if !defined(PLATFORM_MACX)
	delete[] LocalServer_Response;
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
#if !defined(PLATFORM_MACX)
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
	ConfigurationParameter->PrintError = PrintError;
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

//[Values] block
#if defined(ENABLE_PCAP)
	ConfigurationParameter->DNSTarget.IPv4.HopLimitData.TTL = DNSTarget.IPv4.HopLimitData.TTL;
	ConfigurationParameter->DNSTarget.IPv6.HopLimitData.HopLimit = DNSTarget.IPv6.HopLimitData.HopLimit;
	ConfigurationParameter->DNSTarget.Alternate_IPv4.HopLimitData.TTL = DNSTarget.Alternate_IPv4.HopLimitData.TTL;
	ConfigurationParameter->DNSTarget.Alternate_IPv6.HopLimitData.HopLimit = DNSTarget.Alternate_IPv6.HopLimitData.HopLimit;
#endif
	ConfigurationParameter->SocketTimeout_Reliable = SocketTimeout_Reliable;
	ConfigurationParameter->SocketTimeout_Unreliable = SocketTimeout_Unreliable;
	ConfigurationParameter->SOCKS_SocketTimeout_Reliable = SOCKS_SocketTimeout_Reliable;
	ConfigurationParameter->SOCKS_SocketTimeout_Unreliable = SOCKS_SocketTimeout_Unreliable;
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
	if (ConfigurationParameter->SOCKS_TargetDomain != nullptr && SOCKS_TargetDomain_Length > 0 && SOCKS_TargetDomain_Port > 0)
	{
	//Reset old item.
		memset(&ConfigurationParameter->SOCKS_TargetServer, 0, sizeof(ADDRESS_UNION_DATA));

	//Copy new item.
		memcpy_s(ConfigurationParameter->SOCKS_TargetDomain, DOMAIN_MAXSIZE, SOCKS_TargetDomain, SOCKS_TargetDomain_Length);
		ConfigurationParameter->SOCKS_TargetDomain_Length = SOCKS_TargetDomain_Length;
		ConfigurationParameter->SOCKS_TargetDomain_Port = SOCKS_TargetDomain_Port;
	}
	else if (SOCKS_TargetServer.Storage.ss_family > 0)
	{
	//Reset old item.
		if (ConfigurationParameter->SOCKS_TargetDomain != nullptr)
			memset(ConfigurationParameter->SOCKS_TargetDomain, 0, DOMAIN_MAXSIZE);
		ConfigurationParameter->SOCKS_TargetDomain_Length = 0;
		ConfigurationParameter->SOCKS_TargetDomain_Port = 0;

	//Copy new item.
		memcpy_s(&ConfigurationParameter->SOCKS_TargetServer, sizeof(ADDRESS_UNION_DATA), &SOCKS_TargetServer, sizeof(ADDRESS_UNION_DATA));
	}
	if (ConfigurationParameter->SOCKS_Username != nullptr)
	{
		if (SOCKS_Username_Length > 0)
		{
			ConfigurationParameter->SOCKS_Username_Length = SOCKS_Username_Length;
			memcpy_s(ConfigurationParameter->SOCKS_Username, SOCKS_USERNAME_PASSWORD_MAXNUM + 1U, SOCKS_Username, ConfigurationParameter->SOCKS_Username_Length);
		}
		else {
			ConfigurationParameter->SOCKS_Username_Length = 0;
			memset(ConfigurationParameter->SOCKS_Username, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + 1U);
		}
	}
	if (ConfigurationParameter->SOCKS_Password != nullptr)
	{
		if (SOCKS_Password_Length > 0)
		{
			ConfigurationParameter->SOCKS_Password_Length = SOCKS_Password_Length;
			memcpy_s(ConfigurationParameter->SOCKS_Password, SOCKS_USERNAME_PASSWORD_MAXNUM + 1U, SOCKS_Password, ConfigurationParameter->SOCKS_Password_Length);
		}
		else {
			ConfigurationParameter->SOCKS_Password_Length = 0;
			memset(ConfigurationParameter->SOCKS_Password, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + 1U);
		}
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
	PrintError = true;
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
	SOCKS_SocketTimeout_Reliable = DEFAULT_SOCKS_RELIABLE_SOCKET_TIMEOUT;
	SOCKS_SocketTimeout_Unreliable = DEFAULT_SOCKS_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	SocketTimeout_Reliable.tv_sec = DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	SocketTimeout_Reliable.tv_usec = 0;
	SocketTimeout_Unreliable.tv_sec = DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
	SocketTimeout_Unreliable.tv_usec = 0;
	SOCKS_SocketTimeout_Reliable.tv_sec = DEFAULT_SOCKS_RELIABLE_SOCKET_TIMEOUT;
	SOCKS_SocketTimeout_Reliable.tv_usec = 0;
	SOCKS_SocketTimeout_Unreliable.tv_sec = DEFAULT_SOCKS_UNRELIABLE_SOCKET_TIMEOUT;
	SOCKS_SocketTimeout_Unreliable.tv_usec = 0;
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
	memset(&SOCKS_TargetServer, 0, sizeof(ADDRESS_UNION_DATA));
	if (SOCKS_TargetDomain != nullptr)
		memset(SOCKS_TargetDomain, 0, DOMAIN_MAXSIZE);
	SOCKS_TargetDomain_Length = 0;
	SOCKS_TargetDomain_Port = 0;
	if (SOCKS_Username != nullptr)
	{
		memset(SOCKS_Username, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + 1U);
		SOCKS_Username_Length = 0;
	}
	if (SOCKS_Password != nullptr)
	{
		memset(SOCKS_Password, 0, SOCKS_USERNAME_PASSWORD_MAXNUM + 1U);
		SOCKS_Password_Length = 0;
	}

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
		DomainTable = new char[strlen(RFC_DOMAIN_TABLE) + 1U]();
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
	#if !defined(PLATFORM_MACX)
		LocalAddress_ResponsePTR[0] = new std::vector<std::string>();
		LocalAddress_ResponsePTR[1U] = new std::vector<std::string>();
	#endif
	}
	catch (std::bad_alloc)
	{
		delete LocalListeningSocket;
		delete RamdomEngine;
		delete[] DomainTable;
		delete Path_Global;
		delete Path_ErrorLog;
		delete FileList_Hosts;
		delete FileList_IPFilter;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		delete sPath_Global;
		delete sPath_ErrorLog;
		delete sFileList_Hosts;
		delete sFileList_IPFilter;
	#endif
		delete[] LocalAddress_Response[0];
		delete[] LocalAddress_Response[1U];
	#if !defined(PLATFORM_MACX)
		delete LocalAddress_ResponsePTR[0];
		delete LocalAddress_ResponsePTR[1U];
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
	memset(GlobalRunningStatusParameter->DomainTable, 0, strlen(RFC_DOMAIN_TABLE) + 1U);
	strncpy_s(GlobalRunningStatusParameter->DomainTable, strlen(RFC_DOMAIN_TABLE) + 1U, RFC_DOMAIN_TABLE, strlen(RFC_DOMAIN_TABLE));
	GlobalRunningStatusParameter->GatewayAvailable_IPv4 = true;
	memset(GlobalRunningStatusParameter->LocalAddress_Response[0], 0, PACKET_MAXSIZE);
	memset(GlobalRunningStatusParameter->LocalAddress_Response[1U], 0, PACKET_MAXSIZE);

//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	GetFunctionPointer(FUNCTION_GETTICKCOUNT64);
	GetFunctionPointer(FUNCTION_INET_NTOP);
	GetFunctionPointer(FUNCTION_INET_PTON);
#endif

	return;
}

//GlobalStatus class destructor
GlobalStatus::~GlobalStatus(
	void)
{
//Close all sockets.
	if (LocalListeningSocket != nullptr)
	{
		for (auto SocketIter:*LocalListeningSocket)
		{
			shutdown(SocketIter, SD_BOTH);
			closesocket(SocketIter);
		}
	}

//Free libraries.
//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	if (FunctionLibrary_GetTickCount64 != nullptr)
		FreeLibrary(FunctionLibrary_GetTickCount64);
	if (FunctionLibrary_InetNtop != nullptr)
		FreeLibrary(FunctionLibrary_InetNtop);
	if (FunctionLibrary_InetPton != nullptr)
		FreeLibrary(FunctionLibrary_InetPton);
#endif

//Free pointer.
	delete LocalListeningSocket;
	delete RamdomEngine;
	delete[] DomainTable;
	delete Path_Global;
	delete Path_ErrorLog;
	delete FileList_Hosts;
	delete FileList_IPFilter;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	delete sPath_Global;
	delete sPath_ErrorLog;
	delete sFileList_Hosts;
	delete sFileList_IPFilter;
#endif
	delete[] LocalAddress_Response[0];
	delete[] LocalAddress_Response[1U];
#if !defined(PLATFORM_MACX)
	delete LocalAddress_ResponsePTR[0];
	delete LocalAddress_ResponsePTR[1U];
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
	Type_Hosts = 0;
	Length = 0;
	Type_Operation = false;

	return;
}

//AlternateSwapTable class constructor
AlternateSwapTable::AlternateSwapTable(
	void)
{
	memset(this, 0, sizeof(ALTERNATE_SWAP_TABLE));
	return;
}

//AddressRoutingTable_IPv6 class constructor
AddressRoutingTable_IPv6::AddressRoutingTable_IPv6(
	void)
{
	Prefix = 0;
	return;
}

//AddressRoutingTable_IPv4 class constructor
AddressRoutingTable_IPv4::AddressRoutingTable_IPv4(
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

//DiffernetIPFilterFileSet class constructor
DiffernetIPFilterFileSet::DiffernetIPFilterFileSet(
	void)
{
	FileIndex = 0;
	return;
}

//DiffernetHostsFileSet class constructor
DiffernetHostsFileSet::DiffernetHostsFileSet(
	void)
{
	FileIndex = 0;
	return;
}

//DNSCurveConfigurationTable class constructor
#if defined(ENABLE_LIBSODIUM)
DNSCurveConfigurationTable::DNSCurveConfigurationTable(
	void)
{
	memset(this, 0, sizeof(DNSCURVE_CONFIGURATION_TABLE));
	try {
	//DNSCurve Provider Names
		DNSCurveTarget.IPv4.ProviderName = new char[DOMAIN_MAXSIZE]();
		DNSCurveTarget.Alternate_IPv4.ProviderName = new char[DOMAIN_MAXSIZE]();
		DNSCurveTarget.IPv6.ProviderName = new char[DOMAIN_MAXSIZE]();
		DNSCurveTarget.Alternate_IPv6.ProviderName = new char[DOMAIN_MAXSIZE]();

	//DNSCurve Keys
		Client_PublicKey = new uint8_t[crypto_box_PUBLICKEYBYTES]();
		Client_SecretKey = new uint8_t[crypto_box_SECRETKEYBYTES]();
		DNSCurveTarget.IPv4.PrecomputationKey = new uint8_t[crypto_box_BEFORENMBYTES]();
		DNSCurveTarget.Alternate_IPv4.PrecomputationKey = new uint8_t[crypto_box_BEFORENMBYTES]();
		DNSCurveTarget.IPv6.PrecomputationKey = new uint8_t[crypto_box_BEFORENMBYTES]();
		DNSCurveTarget.Alternate_IPv6.PrecomputationKey = new uint8_t[crypto_box_BEFORENMBYTES]();
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

	//DNSCurve Keys
		delete[] Client_PublicKey;
		delete[] Client_SecretKey;
		delete[] DNSCurveTarget.IPv4.PrecomputationKey;
		delete[] DNSCurveTarget.Alternate_IPv4.PrecomputationKey;
		delete[] DNSCurveTarget.IPv6.PrecomputationKey;
		delete[] DNSCurveTarget.Alternate_IPv6.PrecomputationKey;
		delete[] DNSCurveTarget.IPv4.ServerPublicKey;
		delete[] DNSCurveTarget.Alternate_IPv4.ServerPublicKey;
		delete[] DNSCurveTarget.IPv6.ServerPublicKey;
		delete[] DNSCurveTarget.Alternate_IPv6.ServerPublicKey;
		delete[] DNSCurveTarget.IPv4.ServerFingerprint;
		delete[] DNSCurveTarget.Alternate_IPv4.ServerFingerprint;
		delete[] DNSCurveTarget.IPv6.ServerFingerprint;
		delete[] DNSCurveTarget.Alternate_IPv6.ServerFingerprint;

	//DNSCurve Magic Numbers
		delete[] DNSCurveTarget.IPv4.ReceiveMagicNumber;
		delete[] DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber;
		delete[] DNSCurveTarget.IPv6.ReceiveMagicNumber;
		delete[] DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber;
		delete[] DNSCurveTarget.IPv4.SendMagicNumber;
		delete[] DNSCurveTarget.Alternate_IPv4.SendMagicNumber;
		delete[] DNSCurveTarget.IPv6.SendMagicNumber;
		delete[] DNSCurveTarget.Alternate_IPv6.SendMagicNumber;

		exit(EXIT_FAILURE);
		return;
	}

//Initialization
//DNSCurve Provider Names
	memset(DNSCurveTarget.IPv4.ProviderName, 0, DOMAIN_MAXSIZE);
	memset(DNSCurveTarget.Alternate_IPv4.ProviderName, 0, DOMAIN_MAXSIZE);
	memset(DNSCurveTarget.IPv6.ProviderName, 0, DOMAIN_MAXSIZE);
	memset(DNSCurveTarget.Alternate_IPv6.ProviderName, 0, DOMAIN_MAXSIZE);

//DNSCurve Keys
	memset(Client_PublicKey, 0, crypto_box_PUBLICKEYBYTES);
	memset(Client_SecretKey, 0, crypto_box_SECRETKEYBYTES);
	memset(DNSCurveTarget.IPv4.PrecomputationKey, 0, crypto_box_BEFORENMBYTES);
	memset(DNSCurveTarget.Alternate_IPv4.PrecomputationKey, 0, crypto_box_BEFORENMBYTES);
	memset(DNSCurveTarget.IPv6.PrecomputationKey, 0, crypto_box_BEFORENMBYTES);
	memset(DNSCurveTarget.Alternate_IPv6.PrecomputationKey, 0, crypto_box_BEFORENMBYTES);
	memset(DNSCurveTarget.IPv4.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.Alternate_IPv4.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.IPv6.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.Alternate_IPv6.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.IPv4.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.Alternate_IPv4.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.IPv6.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.Alternate_IPv6.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);

//DNSCurve Magic Numbers
	memset(DNSCurveTarget.IPv4.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveTarget.IPv6.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveTarget.IPv4.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveTarget.Alternate_IPv4.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveTarget.IPv6.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	memset(DNSCurveTarget.Alternate_IPv6.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);

//Default settings
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

//DNSCurve Keys
	delete[] Client_PublicKey;
	delete[] Client_SecretKey;
	delete[] DNSCurveTarget.IPv4.PrecomputationKey;
	delete[] DNSCurveTarget.Alternate_IPv4.PrecomputationKey;
	delete[] DNSCurveTarget.IPv6.PrecomputationKey;
	delete[] DNSCurveTarget.Alternate_IPv6.PrecomputationKey;
	delete[] DNSCurveTarget.IPv4.ServerPublicKey;
	delete[] DNSCurveTarget.Alternate_IPv4.ServerPublicKey;
	delete[] DNSCurveTarget.IPv6.ServerPublicKey;
	delete[] DNSCurveTarget.Alternate_IPv6.ServerPublicKey;
	delete[] DNSCurveTarget.IPv4.ServerFingerprint;
	delete[] DNSCurveTarget.Alternate_IPv4.ServerFingerprint;
	delete[] DNSCurveTarget.IPv6.ServerFingerprint;
	delete[] DNSCurveTarget.Alternate_IPv6.ServerFingerprint;

//DNSCurve Magic Numbers
	delete[] DNSCurveTarget.IPv4.ReceiveMagicNumber;
	delete[] DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber;
	delete[] DNSCurveTarget.IPv6.ReceiveMagicNumber;
	delete[] DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber;
	delete[] DNSCurveTarget.IPv4.SendMagicNumber;
	delete[] DNSCurveTarget.Alternate_IPv4.SendMagicNumber;
	delete[] DNSCurveTarget.IPv6.SendMagicNumber;
	delete[] DNSCurveTarget.Alternate_IPv6.SendMagicNumber;

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
	if (DNSCurveConfigurationParameter->Client_PublicKey != nullptr && !CheckEmptyBuffer(Client_PublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->Client_PublicKey, Client_PublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) != EXIT_SUCCESS)
			memcpy_s(DNSCurveConfigurationParameter->Client_PublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES, Client_PublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->Client_SecretKey != nullptr && !CheckEmptyBuffer(Client_SecretKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->Client_SecretKey, Client_SecretKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) != EXIT_SUCCESS)
			memcpy_s(DNSCurveConfigurationParameter->Client_SecretKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES, Client_SecretKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv4.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES, DNSCurveTarget.IPv4.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv4.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES, DNSCurveTarget.Alternate_IPv4.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv6.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES, DNSCurveTarget.IPv6.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv6.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES, DNSCurveTarget.Alternate_IPv6.PrecomputationKey, sizeof(uint8_t) * crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv4.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerPublicKey, DNSCurveTarget.IPv4.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) != EXIT_SUCCESS)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES, DNSCurveTarget.IPv4.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv4.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerPublicKey, DNSCurveTarget.Alternate_IPv4.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) != EXIT_SUCCESS)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES, DNSCurveTarget.Alternate_IPv4.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv6.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerPublicKey, DNSCurveTarget.IPv6.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) != EXIT_SUCCESS)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES, DNSCurveTarget.IPv6.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerPublicKey != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv6.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) && 
		memcmp(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerPublicKey, DNSCurveTarget.Alternate_IPv6.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES) != EXIT_SUCCESS)
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES, DNSCurveTarget.Alternate_IPv6.ServerPublicKey, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv4.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv4.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES, DNSCurveTarget.IPv4.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv4.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv4.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES, DNSCurveTarget.Alternate_IPv4.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.IPv6.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.IPv6.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES, DNSCurveTarget.IPv6.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerFingerprint != nullptr && 
		!CheckEmptyBuffer(DNSCurveTarget.Alternate_IPv6.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurveTarget.Alternate_IPv6.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES, DNSCurveTarget.Alternate_IPv6.ServerFingerprint, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);

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
		memset(Client_PublicKey, 0, crypto_box_PUBLICKEYBYTES);
	if (Client_SecretKey != nullptr)
		memset(Client_SecretKey, 0, crypto_box_SECRETKEYBYTES);
	if (DNSCurveTarget.IPv4.PrecomputationKey != nullptr)
		memset(DNSCurveTarget.IPv4.PrecomputationKey, 0, crypto_box_BEFORENMBYTES);
	if (DNSCurveTarget.Alternate_IPv4.PrecomputationKey != nullptr)
		memset(DNSCurveTarget.Alternate_IPv4.PrecomputationKey, 0, crypto_box_BEFORENMBYTES);
	if (DNSCurveTarget.IPv6.PrecomputationKey != nullptr)
		memset(DNSCurveTarget.IPv6.PrecomputationKey, 0, crypto_box_BEFORENMBYTES);
	if (DNSCurveTarget.Alternate_IPv6.PrecomputationKey != nullptr)
		memset(DNSCurveTarget.Alternate_IPv6.PrecomputationKey, 0, crypto_box_BEFORENMBYTES);
	if (DNSCurveTarget.IPv4.ServerPublicKey != nullptr)
		memset(DNSCurveTarget.IPv4.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.Alternate_IPv4.ServerPublicKey != nullptr)
		memset(DNSCurveTarget.Alternate_IPv4.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.IPv6.ServerPublicKey != nullptr)
		memset(DNSCurveTarget.IPv6.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.Alternate_IPv6.ServerPublicKey != nullptr)
		memset(DNSCurveTarget.Alternate_IPv6.ServerPublicKey, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.IPv4.ServerFingerprint != nullptr)
		memset(DNSCurveTarget.IPv4.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.Alternate_IPv4.ServerFingerprint != nullptr)
		memset(DNSCurveTarget.Alternate_IPv4.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.IPv6.ServerFingerprint != nullptr)
		memset(DNSCurveTarget.IPv6.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveTarget.Alternate_IPv6.ServerFingerprint != nullptr)
		memset(DNSCurveTarget.Alternate_IPv6.ServerFingerprint, 0, crypto_box_PUBLICKEYBYTES);

//DNSCurve Magic Numbers
	if (DNSCurveTarget.IPv4.ReceiveMagicNumber != nullptr)
		memset(DNSCurveTarget.IPv4.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber != nullptr)
		memset(DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.IPv6.ReceiveMagicNumber != nullptr)
		memset(DNSCurveTarget.IPv6.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber != nullptr)
		memset(DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.IPv4.SendMagicNumber != nullptr)
		memset(DNSCurveTarget.IPv4.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.Alternate_IPv4.SendMagicNumber != nullptr)
		memset(DNSCurveTarget.Alternate_IPv4.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.IPv6.SendMagicNumber != nullptr)
		memset(DNSCurveTarget.IPv6.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurveTarget.Alternate_IPv6.SendMagicNumber != nullptr)
		memset(DNSCurveTarget.Alternate_IPv6.SendMagicNumber, 0, DNSCURVE_MAGIC_QUERY_LEN);

	return;
}
#endif
