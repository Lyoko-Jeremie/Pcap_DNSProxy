// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
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


#include "Pcap_DNSProxy.h"

ConfigurationTable Parameter;
time_t StartTime, RunningLogStartTime;
std::vector<std::wstring> ConfigFileList;
std::vector<FileData> IPFilterFileList, HostsFileList;
PortTable PortList;
AlternateSwapTable AlternateSwapList;
DNSCurveConfigurationTable DNSCurveParameter;
std::vector<HostsTable> HostsList[2U], *HostsListUsing = &HostsList[0], *HostsListModificating = &HostsList[1U];
std::vector<AddressRange> AddressRangeList[2U], *AddressRangeUsing = &AddressRangeList[0], *AddressRangeModificating = &AddressRangeList[1U];
std::vector<ResultBlacklistTable> ResultBlacklistList[2U], *ResultBlacklistUsing = &ResultBlacklistList[0], *ResultBlacklistModificating = &ResultBlacklistList[1U];
std::vector<AddressPrefixBlock> LocalRoutingList[2U], *LocalRoutingListUsing = &LocalRoutingList[0], *LocalRoutingListModificating = &LocalRoutingList[1U];
std::deque<DNSCacheData> DNSCacheList;
std::mutex ErrLogLock, RunningLogLock, CaptureLock, PortListLock, LocalAddressLock[QUEUE_PARTNUM / 2U], HostsListLock, DNSCacheListLock, AddressRangeLock, ResultBlacklistLock, LocalRoutingListLock;

//Configuration class constructor
ConfigurationTable::ConfigurationTable(void)
{
	memset(this, 0, sizeof(ConfigurationTable));
	try {
	//[Addresses] block
		DNSTarget.IPv4_Multi = new std::vector<DNSServerData>();
		DNSTarget.IPv6_Multi = new std::vector<DNSServerData>();
	//[Data] block(A part)
		ICMPPaddingData = new char[ICMP_PADDING_MAXSIZE]();
		DomainTestData = new char[DOMAIN_MAXSIZE]();
	//[Data] block(B part)
		LocalFQDN = new char[DOMAIN_MAXSIZE]();
		LocalFQDNString = new std::string();
		LocalServerResponse = new char[DOMAIN_MAXSIZE + sizeof(dns_ptr_record) + sizeof(dns_opt_record)]();
		LocalAddress[0] = new char[PACKET_MAXSIZE]();
		LocalAddress[1U] = new char[PACKET_MAXSIZE]();
		LocalAddressPTR[0] = new std::vector<std::string>();
		LocalAddressPTR[1U] = new std::vector<std::string>();
	//Global block
		RamdomEngine = new std::default_random_engine();
		Path = new std::vector<std::wstring>();
		HostsFileList = new std::vector<std::wstring>();
		IPFilterFileList = new std::vector<std::wstring>();
		ErrorLogPath = new std::wstring();
		RunningLogPath = new std::wstring();
		DomainTable = new char[strlen(RFC_DOMAIN_TABLE) + 1U]();
		AcceptTypeList = new std::vector<uint16_t>();
	}
	catch (std::bad_alloc)
	{
	//[Addresses] block
		delete DNSTarget.IPv4_Multi;
		delete DNSTarget.IPv6_Multi;
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
		delete RamdomEngine;
		delete Path;
		delete HostsFileList;
		delete IPFilterFileList;
		delete ErrorLogPath;
		delete RunningLogPath;
		delete[] DomainTable;
		delete AcceptTypeList;
		memset(this, 0, sizeof(ConfigurationTable));

//		WSACleanup();
//		TerminateService();
		exit(EXIT_FAILURE);
		return;
	}

//Initialization
	strncpy_s(DomainTable, strlen(RFC_DOMAIN_TABLE) + 1U, RFC_DOMAIN_TABLE, strlen(RFC_DOMAIN_TABLE));
	std::random_device RamdomDevice;
	RamdomEngine->seed(RamdomDevice());

	return;
}

//Configuration class destructor
ConfigurationTable::~ConfigurationTable(void)
{
//[Addresses] block
	delete DNSTarget.IPv4_Multi;
	delete DNSTarget.IPv6_Multi;
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
	delete RamdomEngine;
	delete Path;
	delete HostsFileList;
	delete IPFilterFileList;
	delete ErrorLogPath;
	delete RunningLogPath;
	delete[] DomainTable;
	delete AcceptTypeList;
	memset(this, 0, sizeof(ConfigurationTable));

	return;
}

//HostsTable class constructor
HostsTable::HostsTable(void)
{
	memset(this, 0, sizeof(HostsTable) - sizeof(std::shared_ptr<char>) - sizeof(std::regex) - sizeof(std::string));
	return;
}

//AddressRange class constructor
AddressRange::AddressRange(void)
{
	memset(this, 0, sizeof(AddressRange));
	return;
}

//PortTable class constructor
PortTable::PortTable(void)
{
	memset(this, 0, sizeof(PortTable) - sizeof(SendData));
	try {
		RecvData = new SOCKET_DATA[QUEUE_MAXLEN * QUEUE_PARTNUM]();
	}
	catch (std::bad_alloc)
	{
		memset(this, 0, sizeof(PortTable) - sizeof(SendData));

//		WSACleanup();
//		TerminateService();
		exit(EXIT_FAILURE);
		return;
	}

	return;
}

//PortTable class destructor
PortTable::~PortTable(void)
{
	delete[] RecvData;
	memset(this, 0, sizeof(PortTable) - sizeof(SendData));

	return;
}

//AlternateSwapTable class constructor
AlternateSwapTable::AlternateSwapTable(void)
{
	memset(this, 0, sizeof(AlternateSwapTable));
	try {
		PcapAlternateTimeout = new size_t[QUEUE_MAXLEN * QUEUE_PARTNUM]();
	}
	catch (std::bad_alloc)
	{
		memset(this, 0, sizeof(AlternateSwapTable));

//		WSACleanup();
//		TerminateService();
		exit(EXIT_FAILURE);
		return;
	}

	return;
}

//AlternateSwapTable class destructor
AlternateSwapTable::~AlternateSwapTable(void)
{
	delete[] PcapAlternateTimeout;
	memset(this, 0, sizeof(AlternateSwapTable));

	return;
}

//DNSCurveConfiguration class constructor
DNSCurveConfigurationTable::DNSCurveConfigurationTable(void)
{
	memset(this, 0, sizeof(DNSCurveConfigurationTable));
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
		memset(this, 0, sizeof(DNSCurveConfigurationTable));

//		WSACleanup();
//		TerminateService();
		exit(EXIT_FAILURE);
		return;
	}

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
	memset(this, 0, sizeof(DNSCurveConfigurationTable));

	return;
}
