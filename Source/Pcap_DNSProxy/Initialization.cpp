// This code is part of Pcap_DNSProxy
// A local DNS server base on WinPcap and LibPcap.
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
		DNSTarget.IPv6_Multi = new std::vector<DNS_SERVER_DATA>();
		DNSTarget.IPv4_Multi = new std::vector<DNS_SERVER_DATA>();
	//[Data] block(A part)
		ICMPPaddingData = new char[ICMP_PADDING_MAXSIZE]();
		DomainTestData = new char[DOMAIN_MAXSIZE]();
	//[Data] block(B part)
		LocalFQDN = new char[DOMAIN_MAXSIZE]();
		LocalFQDNString = new std::string();
		LocalServerResponse = new char[DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt)]();
		LocalAddress[0] = new char[PACKET_MAXSIZE]();
		LocalAddress[1U] = new char[PACKET_MAXSIZE]();
		LocalAddressPTR[0] = new std::vector<std::string>();
		LocalAddressPTR[1U] = new std::vector<std::string>();
	//Global block
		LocalSocket = new std::vector<SYSTEM_SOCKET>();
		RamdomEngine = new std::default_random_engine();
		Path = new std::vector<std::wstring>();
		HostsFileList = new std::vector<std::wstring>();
		IPFilterFileList = new std::vector<std::wstring>();
		ErrorLogPath = new std::wstring();
		RunningLogPath = new std::wstring();
		RunningLogWriteQueue = new std::vector<RUNNING_LOG_DATA>();
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
		delete DNSTarget.IPv6_Multi;
		delete DNSTarget.IPv4_Multi;
	//[Data] block(A part)
		delete[] ICMPPaddingData;
		delete[] DomainTestData;
	//[Data] block(B part)
		delete[] LocalFQDN;
		delete LocalFQDNString;
		delete[] LocalServerResponse;
		delete[] LocalAddress[0];
		delete[] LocalAddress[1U];
		delete LocalAddressPTR[0];
		delete LocalAddressPTR[1U];
	//Global block
		delete LocalSocket;
		delete RamdomEngine;
		delete Path;
		delete HostsFileList;
		delete IPFilterFileList;
		delete ErrorLogPath;
		delete RunningLogPath;
		delete RunningLogWriteQueue;
		delete[] DomainTable;
		delete AcceptTypeList;

		exit(EXIT_FAILURE);
		return;
	}

//Initialization
	//[Data] block(A part)
	memset(ICMPPaddingData, 0, ICMP_PADDING_MAXSIZE);
	memset(DomainTestData, 0, DOMAIN_MAXSIZE);
	//[Data] block(B part)
	memset(LocalFQDN, 0, DOMAIN_MAXSIZE);
	memset(LocalServerResponse, 0, DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt));
	memset(LocalAddress[0], 0, PACKET_MAXSIZE);
	memset(LocalAddress[1U], 0, PACKET_MAXSIZE);
	//Global block
	memset(DomainTable, 0, strlen(RFC_DOMAIN_TABLE) + 1U);

//Default values
	strncpy_s(DomainTable, strlen(RFC_DOMAIN_TABLE) + 1U, RFC_DOMAIN_TABLE, strlen(RFC_DOMAIN_TABLE));
	std::random_device RamdomDevice;
	RamdomEngine->seed(RamdomDevice());

//Default settings
	LogMaxSize = DEFAULT_LOG_MAXSIZE;
	GatewayAvailable_IPv4 = true;
#if defined(PLATFORM_WIN)
	ReliableSocketTimeout = DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	UnreliableSocketTimeout = DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
#elif defined(PLATFORM_LINUX)
	ReliableSocketTimeout.tv_sec = DEFAULT_RELIABLE_SOCKET_TIMEOUT;
	UnreliableSocketTimeout.tv_sec = DEFAULT_UNRELIABLE_SOCKET_TIMEOUT;
#endif
	ICMPID = htons((uint16_t)GetCurrentProcessId()); //Default ICMP ID is current process ID.
	ICMPSequence = htons(DEFAULT_SEQUENCE);
	DomainTestSpeed = DEFAULT_DOMAINTEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
	DomainTestID = htons((uint16_t)GetCurrentProcessId()); //Default DNS ID is current process ID.
	//Load default padding data from Microsoft Windows Ping.
	ICMPPaddingDataLength = strlen(DEFAULT_PADDINGDATA) + 1U;
	memcpy_s(ICMPPaddingData, ICMP_PADDING_MAXSIZE, DEFAULT_PADDINGDATA, Parameter.ICMPPaddingDataLength - 1U);
	HostsDefaultTTL = DEFAULT_HOSTS_TTL;

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
	delete DNSTarget.IPv6_Multi;
	delete DNSTarget.IPv4_Multi;
//[Data] block(A part)
	delete[] ICMPPaddingData;
	delete[] DomainTestData;
//[Data] block(B part)
	delete[] LocalFQDN;
	delete LocalFQDNString;
	delete[] LocalServerResponse;
	delete[] LocalAddress[0];
	delete[] LocalAddress[1U];
	delete LocalAddressPTR[0];
	delete LocalAddressPTR[1U];
//Global block
	delete LocalSocket;
	delete RamdomEngine;
	delete Path;
	delete HostsFileList;
	delete IPFilterFileList;
	delete ErrorLogPath;
	delete RunningLogPath;
	delete RunningLogWriteQueue;
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
	FileIndex = 0;
	Type = 0;
	Protocol = 0;
	Length = 0;

	return;
}

//AlternateSwapTable class constructor
AlternateSwapTable::AlternateSwapTable(void)
{
	memset(this, 0, sizeof(ALTERNATE_SWAP_TABLE));
	return;
}

//Blacklist of results class constructor
ResultBlacklistTable::ResultBlacklistTable(void)
{
	FileIndex = 0;
	return;
}

//Address Hosts class constructor
AddressHostsTable::AddressHostsTable(void)
{
	FileIndex = 0;
	memset(&TargetAddress, 0, sizeof(sockaddr_storage));

	return;
}

//AddressRoutingTable_IPv6 class constructor
AddressRoutingTable_IPv6::AddressRoutingTable_IPv6(void)
{
	FileIndex = 0;
	Prefix = 0;

	return;
}

//AddressRoutingTable_IPv4 class constructor
AddressRoutingTable_IPv4::AddressRoutingTable_IPv4(void)
{
	FileIndex = 0;
	Prefix = 0;

	return;
}

//PortTable class constructor
PortTable::PortTable(void)
{
//Initialization
	memset(&SystemData, 0, sizeof(SOCKET_DATA));
	NetworkLayer = 0;
	TransportLayer = 0;
	ClearPortTime = 0;

	return;
}

//DNSCurveConfiguration class constructor
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
