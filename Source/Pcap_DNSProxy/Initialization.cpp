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

//Configuration class constructor
ConfigurationTable::ConfigurationTable(void)
{
	memset(this, 0, sizeof(CONFIGURATION_TABLE));
	try {
	//[Listen] block
		ListenPort = new std::vector<uint16_t>();
	//[Addresses] block
		ListenAddress_IPv6 = new std::vector<sockaddr_storage>();
		ListenAddress_IPv4 = new std::vector<sockaddr_storage>();
		LocalhostSubnet.IPv6 = new ADDRESS_PREFIX_BLOCK();
		LocalhostSubnet.IPv4 = new ADDRESS_PREFIX_BLOCK();
		DNSTarget.IPv6_Multi = new std::vector<DNS_SERVER_DATA>();
		DNSTarget.IPv4_Multi = new std::vector<DNS_SERVER_DATA>();
	//[Data] block(A part)
	#if defined(ENABLE_PCAP)
		ICMP_PaddingData = new char[ICMP_PADDING_MAXSIZE]();
		DomainTest_Data = new char[DOMAIN_MAXSIZE]();
	#endif
	//[Data] block(B part)
		LocalFQDN_Response = new char[DOMAIN_MAXSIZE]();
		LocalFQDN_String = new std::string();
	#if !defined(PLATFORM_MACX)
		LocalServer_Response = new char[DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt)]();
	#endif
		LocalAddress_Response[0] = new char[PACKET_MAXSIZE]();
		LocalAddress_Response[1U] = new char[PACKET_MAXSIZE]();
	#if !defined(PLATFORM_MACX)
		LocalAddress_ResponsePTR[0] = new std::vector<std::string>();
		LocalAddress_ResponsePTR[1U] = new std::vector<std::string>();
	#endif
	//Global block
		LocalSocket = new std::vector<SYSTEM_SOCKET>();
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
		DomainTable = new char[strlen(RFC_DOMAIN_TABLE) + 1U]();
		AcceptTypeList = new std::vector<uint16_t>();
	}
	catch (std::bad_alloc)
	{
	//[Listen] block
		delete ListenPort;
	//[Addresses] block
		delete ListenAddress_IPv6;
		delete ListenAddress_IPv4;
		delete LocalhostSubnet.IPv6;
		delete LocalhostSubnet.IPv4;
		delete DNSTarget.IPv6_Multi;
		delete DNSTarget.IPv4_Multi;
	//[Data] block(A part)
	#if defined(ENABLE_PCAP)
		delete[] ICMP_PaddingData;
		delete[] DomainTest_Data;
	#endif
	//[Data] block(B part)
		delete[] LocalFQDN_Response;
		delete LocalFQDN_String;
	#if !defined(PLATFORM_MACX)
		delete[] LocalServer_Response;
	#endif
		delete[] LocalAddress_Response[0];
		delete[] LocalAddress_Response[1U];
	#if !defined(PLATFORM_MACX)
		delete LocalAddress_ResponsePTR[0];
		delete LocalAddress_ResponsePTR[1U];
	#endif
	//Global block
		delete LocalSocket;
		delete RamdomEngine;
		delete Path_Global;
		delete Path_ErrorLog;
		delete FileList_Hosts;
		delete FileList_IPFilter;
		delete[] DomainTable;
		delete AcceptTypeList;

		exit(EXIT_FAILURE);
		return;
	}

//Initialization
	BufferQueueSize = DEFAULT_BUFFER_QUEUE;
	//[Data] block(A part)
#if defined(ENABLE_PCAP)
	memset(ICMP_PaddingData, 0, ICMP_PADDING_MAXSIZE);
	memset(DomainTest_Data, 0, DOMAIN_MAXSIZE);
#endif
	//[Data] block(B part)
	memset(LocalFQDN_Response, 0, DOMAIN_MAXSIZE);
#if !defined(PLATFORM_MACX)
	memset(LocalServer_Response, 0, DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt));
#endif
	memset(LocalAddress_Response[0], 0, PACKET_MAXSIZE);
	memset(LocalAddress_Response[1U], 0, PACKET_MAXSIZE);
	//Global block
	memset(DomainTable, 0, strlen(RFC_DOMAIN_TABLE) + 1U);

//Default settings
	strncpy_s(DomainTable, strlen(RFC_DOMAIN_TABLE) + 1U, RFC_DOMAIN_TABLE, strlen(RFC_DOMAIN_TABLE));
	std::random_device RamdomDevice;
	RamdomEngine->seed(RamdomDevice());

//Default values
	FileRefreshTime = DEFAULT_FILEREFRESH_TIME * SECOND_TO_MILLISECOND;
	LogMaxSize = DEFAULT_LOG_MAXSIZE;
	HostsDefaultTTL = DEFAULT_HOSTS_TTL;
	AlternateTimes = DEFAULT_ALTERNATE_TIMES;
	AlternateTimeRange = DEFAULT_ALTERNATE_RANGE * SECOND_TO_MILLISECOND;
	AlternateResetTime = DEFAULT_ALTERNATE_RESET_TIME * SECOND_TO_MILLISECOND;
#if defined(PLATFORM_WIN)
	SocketTimeout_Reliable = DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	SocketTimeout_Unreliable = DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	SocketTimeout_Reliable.tv_sec = DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	SocketTimeout_Unreliable.tv_sec = DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
#endif
#if defined(PLATFORM_MACX)
	Console = true;
#endif
#if defined(ENABLE_PCAP)
	PcapReadingTimeout = DEFAULT_PCAP_CAPTURE_TIMEOUT;
	#if defined(PLATFORM_MACX)
		ICMP_ID = htons(*(uint16_t *)pthread_self());
	#else
		ICMP_ID = htons((uint16_t)GetCurrentProcessId()); //Default ICMP ID is current process ID.
	#endif
		ICMP_Sequence = htons(DEFAULT_SEQUENCE);
		DomainTest_Speed = DEFAULT_DOMAINTEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
	#if defined(PLATFORM_MACX)
		DomainTest_ID = htons(*(uint16_t *)pthread_self());
	#else
		DomainTest_ID = htons((uint16_t)GetCurrentProcessId()); //Default DNS ID is current process ID.
	#endif
	#if defined(PLATFORM_WIN)
		ICMP_PaddingLength = strlen(DEFAULT_PADDINGDATA) + 1U;
		memcpy_s(ICMP_PaddingData, ICMP_PADDING_MAXSIZE, DEFAULT_PADDINGDATA, Parameter.ICMP_PaddingLength - 1U); //Load default padding data.
	#elif defined(PLATFORM_LINUX)
		size_t CharData = ICMP_STRING_START_NUM_LINUX;
		for (size_t Index = 0;Index < ICMP_PADDING_LENGTH_LINUX;++Index, ++CharData)
			ICMP_PaddingData[Index] = CharData;
		ICMP_PaddingLength = strlen(ICMP_PaddingData) + 1U;
	#elif defined(PLATFORM_MACX)
		size_t CharData = ICMP_STRING_START_NUM_MAC;
		for (size_t Index = 0;Index < ICMP_PADDING_LENGTH_MAC;++Index, ++CharData)
			ICMP_PaddingData[Index] = CharData;
		ICMP_PaddingLength = strlen(ICMP_PaddingData) + 1U;
	#endif
#endif

//Default status
	GatewayAvailable_IPv4 = true;

	return;
}

//Configuration class destructor
ConfigurationTable::~ConfigurationTable(void)
{
//[Listen] block
	delete ListenPort;
//[Addresses] block
	delete ListenAddress_IPv6;
	delete ListenAddress_IPv4;
	delete LocalhostSubnet.IPv6;
	delete LocalhostSubnet.IPv4;
	delete DNSTarget.IPv6_Multi;
	delete DNSTarget.IPv4_Multi;
//[Data] block(A part)
#if defined(ENABLE_PCAP)
	delete[] ICMP_PaddingData;
	delete[] DomainTest_Data;
#endif
//[Data] block(B part)
	delete[] LocalFQDN_Response;
	delete LocalFQDN_String;
#if !defined(PLATFORM_MACX)
	delete[] LocalServer_Response;
#endif
	delete[] LocalAddress_Response[0];
	delete[] LocalAddress_Response[1U];
#if !defined(PLATFORM_MACX)
	delete LocalAddress_ResponsePTR[0];
	delete LocalAddress_ResponsePTR[1U];
#endif
//Global block
	delete LocalSocket;
	delete RamdomEngine;
	delete Path_Global;
	delete Path_ErrorLog;
	delete FileList_Hosts;
	delete FileList_IPFilter;
	delete[] DomainTable;
	delete AcceptTypeList;

	return;
}

//Address Range class constructor
AddressRangeTable::AddressRangeTable(void)
{
	memset(this, 0, sizeof(ADDRESS_RANGE_TABLE));
	return;
}

//HostsTable class constructor
HostsTable::HostsTable(void)
{
	Type_Hosts = 0;
	Length = 0;
	Type_Operation = false;

	return;
}

//AlternateSwapTable class constructor
AlternateSwapTable::AlternateSwapTable(void)
{
	memset(this, 0, sizeof(ALTERNATE_SWAP_TABLE));
	return;
}

//AddressRoutingTable_IPv6 class constructor
AddressRoutingTable_IPv6::AddressRoutingTable_IPv6(void)
{
	Prefix = 0;
	return;
}

//AddressRoutingTable_IPv4 class constructor
AddressRoutingTable_IPv4::AddressRoutingTable_IPv4(void)
{
	Prefix = 0;
	return;
}

//InputPacketTable class constructor
#if defined(ENABLE_PCAP)
OutputPacketTable::OutputPacketTable(void)
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

//Differnet IPFilter File Set class constructor
DiffernetIPFilterFileSet::DiffernetIPFilterFileSet(void)
{
	FileIndex = 0;
	return;
}

//Differnet Hosts File Set class constructor
DiffernetHostsFileSet::DiffernetHostsFileSet(void)
{
	FileIndex = 0;
	return;
}

//DNSCurveConfiguration class constructor
#if defined(ENABLE_LIBSODIUM)
DNSCurveConfigurationTable::DNSCurveConfigurationTable(void)
{
	memset(this, 0, sizeof(DNSCURVE_CONFIGURATON_TABLE));
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
	memset(Client_PublicKey, 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(Client_SecretKey, 0, sizeof(uint8_t) * crypto_box_SECRETKEYBYTES);
	memset(DNSCurveTarget.IPv4.PrecomputationKey, 0, sizeof(uint8_t) * crypto_box_BEFORENMBYTES);
	memset(DNSCurveTarget.Alternate_IPv4.PrecomputationKey, 0, sizeof(uint8_t) * crypto_box_BEFORENMBYTES);
	memset(DNSCurveTarget.IPv6.PrecomputationKey, 0, sizeof(uint8_t) * crypto_box_BEFORENMBYTES);
	memset(DNSCurveTarget.Alternate_IPv6.PrecomputationKey, 0, sizeof(uint8_t) * crypto_box_BEFORENMBYTES);
	memset(DNSCurveTarget.IPv4.ServerPublicKey, 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.Alternate_IPv4.ServerPublicKey, 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.IPv6.ServerPublicKey, 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.Alternate_IPv6.ServerPublicKey, 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.IPv4.ServerFingerprint, 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.Alternate_IPv4.ServerFingerprint, 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.IPv6.ServerFingerprint, 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
	memset(DNSCurveTarget.Alternate_IPv6.ServerFingerprint, 0, sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES);
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
	KeyRecheckTime = DEFAULT_DNSCURVE_RECHECK_TIME * SECOND_TO_MILLISECOND;

	return;
}

//DNSCurveConfiguration class destructor
DNSCurveConfigurationTable::~DNSCurveConfigurationTable(void)
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
#endif
