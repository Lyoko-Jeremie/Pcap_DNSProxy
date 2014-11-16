// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
// Copyright (C) 2012-2014 Chengr28
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

Configuration Parameter;
PortTable PortList;
std::vector<uint16_t> AcceptTypeList;
std::vector<HostsTable> HostsList[2U], *HostsListUsing = &HostsList[0], *HostsListModificating = &HostsList[1U];
std::deque<DNSCacheData> DNSCacheList;
std::vector<AddressRange> AddressRangeList[2U], *AddressRangeUsing = &AddressRangeList[0], *AddressRangeModificating = &AddressRangeList[1U];
std::vector<ResultBlacklistTable> ResultBlacklistList[2U], *ResultBlacklistUsing = &ResultBlacklistList[0], *ResultBlacklistModificating = &ResultBlacklistList[1U];
std::mutex ErrLogLock, RunningLogLock, CaptureLock, PortListLock, LocalAddressLock[QUEUE_PARTNUM / 2U], HostsListLock, DNSCacheListLock, AddressRangeLock, ResultBlacklistLock;
AlternateSwapTable AlternateSwapList;
DNSCurveConfiguration DNSCurveParameter;

//Configuration class constructor
Configuration::Configuration(void)
{
	memset(this, 0, sizeof(Configuration));
	Path = nullptr, ErrorLogPath = nullptr, RunningLogPath = nullptr;
	DomainTable = nullptr;
	DNSTarget.IPv4_Multi = nullptr, DNSTarget.IPv6_Multi = nullptr;
	DomainTestOptions.DomainTestData = nullptr, ICMPOptions.PaddingData = nullptr, LocalServerOptions.LocalFQDN = nullptr;
	LocalAddressOptions.LocalAddress[0] = nullptr, LocalAddressOptions.LocalAddress[1U] = nullptr;
	try {
		Path = new std::wstring();
		ErrorLogPath = new std::wstring();
		RunningLogPath = new std::wstring();
		DomainTable = new char[strlen(RFC_DOMAIN_TABLE) + 1U]();

		DNSTarget.IPv4_Multi = new std::vector<DNSServerData>();
		DNSTarget.IPv6_Multi = new std::vector<DNSServerData>();

		DomainTestOptions.DomainTestData = new char[DOMAIN_MAXSIZE]();
		ICMPOptions.PaddingData = new char[ICMP_PADDING_MAXSIZE](); 
		LocalServerOptions.LocalFQDN = new char[DOMAIN_MAXSIZE]();
		LocalServerOptions.LocalPTRResponse = new char[DOMAIN_MAXSIZE + sizeof(dns_ptr_record) + sizeof(dns_edns0_label)]();

		LocalAddressOptions.LocalAddress[0] = new char[PACKET_MAXSIZE]();
		LocalAddressOptions.LocalAddress[1U] = new char[PACKET_MAXSIZE]();
	}
	catch (std::bad_alloc)
	{
	//Paths.
		delete Path;
		delete ErrorLogPath;
		delete RunningLogPath;
		delete[] DomainTable;
	//Multi requesting
		delete DNSTarget.IPv4_Multi;
		delete DNSTarget.IPv6_Multi;
	//Domain test data, padding data and localhost server name
		delete[] DomainTestOptions.DomainTestData;
		delete[] ICMPOptions.PaddingData;
		delete[] LocalServerOptions.LocalFQDN;
		delete[] LocalServerOptions.LocalPTRResponse;
	//Local address response packets
		delete[] LocalAddressOptions.LocalAddress[0];
		delete[] LocalAddressOptions.LocalAddress[1U];
	//Reset pointer.
		Path = nullptr, ErrorLogPath = nullptr, RunningLogPath = nullptr;
		DomainTable = nullptr;
		DNSTarget.IPv4_Multi = nullptr, DNSTarget.IPv6_Multi = nullptr;
		DomainTestOptions.DomainTestData = nullptr, ICMPOptions.PaddingData = nullptr, LocalServerOptions.LocalFQDN = nullptr, LocalServerOptions.LocalPTRResponse = nullptr;
		LocalAddressOptions.LocalAddress[0] = nullptr, LocalAddressOptions.LocalAddress[1U] = nullptr;

		WSACleanup();
		TerminateService();
		return;
	}

//Initialization
	// Old version(2014-07-22)
	//timeval ReliableSocketTimeout = {RELIABLE_SOCKET_TIMEOUT, 0}, UnreliableSocketTimeout = {UNRELIABLE_SOCKET_TIMEOUT, 0};
	ReliableSocketTimeout = RELIABLE_SOCKET_TIMEOUT, UnreliableSocketTimeout = UNRELIABLE_SOCKET_TIMEOUT;
	strncpy_s(DomainTable, strlen(RFC_DOMAIN_TABLE) + 1U, RFC_DOMAIN_TABLE, strlen(RFC_DOMAIN_TABLE));

	return;
}

//Configuration class destructor
Configuration::~Configuration(void)
{
//Paths.
	delete Path;
	delete ErrorLogPath;
	delete RunningLogPath;
	delete[] DomainTable;
//Multi requesting
	delete DNSTarget.IPv4_Multi;
	delete DNSTarget.IPv6_Multi;
//Domain test data, padding data and localhost server name
	delete[] DomainTestOptions.DomainTestData;
	delete[] ICMPOptions.PaddingData;
	delete[] LocalServerOptions.LocalFQDN;
	delete[] LocalServerOptions.LocalPTRResponse;
//Local address response packets
	delete[] LocalAddressOptions.LocalAddress[0];
	delete[] LocalAddressOptions.LocalAddress[1U];
//Reset pointer.
	Path = nullptr, ErrorLogPath = nullptr, RunningLogPath = nullptr;
	DomainTable = nullptr;
	DNSTarget.IPv4_Multi = nullptr, DNSTarget.IPv6_Multi = nullptr;
	DomainTestOptions.DomainTestData = nullptr, ICMPOptions.PaddingData = nullptr, LocalServerOptions.LocalFQDN = nullptr, LocalServerOptions.LocalPTRResponse = nullptr;
	LocalAddressOptions.LocalAddress[0] = nullptr, LocalAddressOptions.LocalAddress[1U] = nullptr;

	return;
}

//HostsTable class constructor
HostsTable::HostsTable(void)
{
	memset(this, 0, sizeof(HostsTable) - sizeof(HostsTable::Response) - sizeof(HostsTable::Pattern) - sizeof(HostsTable::PatternString));
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
	memset((PSTR)this + sizeof(SendData), 0, sizeof(PortTable) - sizeof(SendData));
	RecvData = nullptr;
	try {
		RecvData = new SOCKET_DATA[QUEUE_MAXLEN * QUEUE_PARTNUM]();
	}
	catch (std::bad_alloc)
	{
		RecvData = nullptr;
		WSACleanup();
		TerminateService();

		return;
	}

	return;
}

//PortTable class destructor
PortTable::~PortTable(void)
{
	delete[] RecvData;
	RecvData = nullptr;

	return;
}

//AlternateSwapTable class constructor
AlternateSwapTable::AlternateSwapTable(void)
{
	memset(this, 0, sizeof(AlternateSwapTable));
	PcapAlternateTimeout = nullptr;
	try {
		PcapAlternateTimeout = new size_t[QUEUE_MAXLEN * QUEUE_PARTNUM]();
	}
	catch (std::bad_alloc)
	{
		PcapAlternateTimeout = nullptr;
		WSACleanup();
		TerminateService();

		return;
	}

	return;
}

//AlternateSwapTable class destructor
AlternateSwapTable::~AlternateSwapTable(void)
{
	delete[] PcapAlternateTimeout;
	PcapAlternateTimeout = nullptr;

	return;
}

//DNSCurveConfiguration class constructor
DNSCurveConfiguration::DNSCurveConfiguration(void)
{
	memset(this, 0, sizeof(DNSCurveConfiguration));
	DNSCurveTarget.IPv4.ProviderName = nullptr, DNSCurveTarget.Alternate_IPv4.ProviderName = nullptr, DNSCurveTarget.IPv6.ProviderName = nullptr, DNSCurveTarget.Alternate_IPv6.ProviderName = nullptr;
	Client_PublicKey = nullptr, Client_SecretKey = nullptr;
	DNSCurveTarget.IPv4.PrecomputationKey = nullptr, DNSCurveTarget.Alternate_IPv4.PrecomputationKey = nullptr, DNSCurveTarget.IPv6.PrecomputationKey = nullptr, DNSCurveTarget.Alternate_IPv6.PrecomputationKey = nullptr;
	DNSCurveTarget.IPv4.ServerPublicKey = nullptr, DNSCurveTarget.Alternate_IPv4.ServerPublicKey = nullptr, DNSCurveTarget.IPv6.ServerPublicKey = nullptr, DNSCurveTarget.Alternate_IPv6.ServerPublicKey = nullptr;
	DNSCurveTarget.IPv4.ServerFingerprint = nullptr, DNSCurveTarget.Alternate_IPv4.ServerFingerprint = nullptr, DNSCurveTarget.IPv6.ServerFingerprint = nullptr, DNSCurveTarget.Alternate_IPv6.ServerFingerprint = nullptr;
	DNSCurveTarget.IPv4.SendMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv4.SendMagicNumber = nullptr, DNSCurveTarget.IPv6.SendMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv6.SendMagicNumber = nullptr;
	DNSCurveTarget.IPv4.ReceiveMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber = nullptr, DNSCurveTarget.IPv6.ReceiveMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber = nullptr;
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
	//Reset pointers.
		DNSCurveTarget.IPv4.ProviderName = nullptr, DNSCurveTarget.Alternate_IPv4.ProviderName = nullptr, DNSCurveTarget.IPv6.ProviderName = nullptr, DNSCurveTarget.Alternate_IPv6.ProviderName = nullptr;
		Client_PublicKey = nullptr, Client_SecretKey = nullptr;
		DNSCurveTarget.IPv4.PrecomputationKey = nullptr, DNSCurveTarget.Alternate_IPv4.PrecomputationKey = nullptr, DNSCurveTarget.IPv6.PrecomputationKey = nullptr, DNSCurveTarget.Alternate_IPv6.PrecomputationKey = nullptr;
		DNSCurveTarget.IPv4.ServerPublicKey = nullptr, DNSCurveTarget.Alternate_IPv4.ServerPublicKey = nullptr, DNSCurveTarget.IPv6.ServerPublicKey = nullptr, DNSCurveTarget.Alternate_IPv6.ServerPublicKey = nullptr;
		DNSCurveTarget.IPv4.ServerFingerprint = nullptr, DNSCurveTarget.Alternate_IPv4.ServerFingerprint = nullptr, DNSCurveTarget.IPv6.ServerFingerprint = nullptr, DNSCurveTarget.Alternate_IPv6.ServerFingerprint = nullptr;
		DNSCurveTarget.IPv4.SendMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv4.SendMagicNumber = nullptr, DNSCurveTarget.IPv6.SendMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv6.SendMagicNumber = nullptr;
		DNSCurveTarget.IPv4.ReceiveMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber = nullptr, DNSCurveTarget.IPv6.ReceiveMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber = nullptr;

		WSACleanup();
		TerminateService();
		return;
	}

	return;
}

//DNSCurveConfiguration class destructor
DNSCurveConfiguration::~DNSCurveConfiguration(void)
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
//Reset pointers.
	DNSCurveTarget.IPv4.ProviderName = nullptr, DNSCurveTarget.Alternate_IPv4.ProviderName = nullptr, DNSCurveTarget.IPv6.ProviderName = nullptr, DNSCurveTarget.Alternate_IPv6.ProviderName = nullptr;
	Client_PublicKey = nullptr, Client_SecretKey = nullptr;
	DNSCurveTarget.IPv4.PrecomputationKey = nullptr, DNSCurveTarget.Alternate_IPv4.PrecomputationKey = nullptr, DNSCurveTarget.IPv6.PrecomputationKey = nullptr, DNSCurveTarget.Alternate_IPv6.PrecomputationKey = nullptr;
	DNSCurveTarget.IPv4.ServerPublicKey = nullptr, DNSCurveTarget.Alternate_IPv4.ServerPublicKey = nullptr, DNSCurveTarget.IPv6.ServerPublicKey = nullptr, DNSCurveTarget.Alternate_IPv6.ServerPublicKey = nullptr;
	DNSCurveTarget.IPv4.ServerFingerprint = nullptr, DNSCurveTarget.Alternate_IPv4.ServerFingerprint = nullptr, DNSCurveTarget.IPv6.ServerFingerprint = nullptr, DNSCurveTarget.Alternate_IPv6.ServerFingerprint = nullptr;
	DNSCurveTarget.IPv4.SendMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv4.SendMagicNumber = nullptr, DNSCurveTarget.IPv6.SendMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv6.SendMagicNumber = nullptr;
	DNSCurveTarget.IPv4.ReceiveMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv4.ReceiveMagicNumber = nullptr, DNSCurveTarget.IPv6.ReceiveMagicNumber = nullptr, DNSCurveTarget.Alternate_IPv6.ReceiveMagicNumber = nullptr;

	return;
}
