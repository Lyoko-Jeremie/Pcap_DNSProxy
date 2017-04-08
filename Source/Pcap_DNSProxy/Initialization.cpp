// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2017 Chengr28
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
static const uint8_t DomainTable_Initialization[] = (".-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

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
		Local_FQDN_String = new std::string();
		Local_FQDN_Response = new uint8_t[DOMAIN_MAXSIZE]();
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		LocalServer_Response = new uint8_t[DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt)]();
	#endif

	//[Proxy] block
		SOCKS_TargetDomain = new std::string();
		SOCKS_Username = new std::string();
		SOCKS_Password = new std::string();
	#if defined(ENABLE_TLS)
		HTTP_CONNECT_TLS_SNI = new std::wstring();
		MBS_HTTP_CONNECT_TLS_SNI = new std::string();
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		HTTP_CONNECT_TLS_AddressString_IPv6 = new std::string();
		HTTP_CONNECT_TLS_AddressString_IPv4 = new std::string();
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
		delete SOCKS_Username;
		delete SOCKS_Password;
	#if defined(ENABLE_TLS)
		delete HTTP_CONNECT_TLS_SNI;
		delete MBS_HTTP_CONNECT_TLS_SNI;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		delete HTTP_CONNECT_TLS_AddressString_IPv6;
		delete HTTP_CONNECT_TLS_AddressString_IPv4;
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
		MBS_HTTP_CONNECT_TLS_SNI = nullptr;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
		HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;
	#endif
	#endif
		HTTP_CONNECT_TargetDomain = nullptr;
		HTTP_CONNECT_Version = nullptr;
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

//ConfigurationTable class copy constructor
ConfigurationTable::ConfigurationTable(
	const ConfigurationTable &Reference)
{
//Check itself.
	if (this == &Reference)
		return;
	
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
		LocalServer_Response = new uint8_t[DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt)]();
	#endif

	//[Proxy] block
		SOCKS_TargetDomain = new std::string();
		SOCKS_Username = new std::string();
		SOCKS_Password = new std::string();
	#if defined(ENABLE_TLS)
		HTTP_CONNECT_TLS_SNI = new std::wstring();
		MBS_HTTP_CONNECT_TLS_SNI = new std::string();
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		HTTP_CONNECT_TLS_AddressString_IPv6 = new std::string();
		HTTP_CONNECT_TLS_AddressString_IPv4 = new std::string();
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
		delete SOCKS_Username;
		delete SOCKS_Password;
	#if defined(ENABLE_TLS)
		delete HTTP_CONNECT_TLS_SNI;
		delete MBS_HTTP_CONNECT_TLS_SNI;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		delete HTTP_CONNECT_TLS_AddressString_IPv6;
		delete HTTP_CONNECT_TLS_AddressString_IPv4;
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
		MBS_HTTP_CONNECT_TLS_SNI = nullptr;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
		HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;
	#endif
	#endif
		HTTP_CONNECT_TargetDomain = nullptr;
		HTTP_CONNECT_Version = nullptr;
		HTTP_CONNECT_HeaderField = nullptr;
		HTTP_CONNECT_ProxyAuthorization = nullptr;

	//Exit process.
		exit(EXIT_FAILURE);
//		return;
	}

//ConfigurationTable settings
	ConfigurationTableSetting(this);

//Copy constructor
	//[Base] block
	Version_Major = Reference.Version_Major;
	Version_Minor = Reference.Version_Minor;
	FileRefreshTime = Reference.FileRefreshTime;
	LargeBufferSize = Reference.LargeBufferSize;
	//[Log] block
	PrintLogLevel = Reference.PrintLogLevel;
	LogMaxSize = Reference.LogMaxSize;
	//[Listen] block
#if defined(ENABLE_PCAP)
	IsPcapCapture = Reference.IsPcapCapture;
	if (Reference.PcapDevicesBlacklist != nullptr)
	{
		*PcapDevicesBlacklist = *Reference.PcapDevicesBlacklist;
	}
	else {
		delete PcapDevicesBlacklist;
		PcapDevicesBlacklist = nullptr;
	}
	PcapReadingTimeout = Reference.PcapReadingTimeout;
#endif
	OperationMode = Reference.OperationMode;
	ListenProtocol_Network = Reference.ListenProtocol_Network;
	ListenProtocol_Transport = Reference.ListenProtocol_Transport;
	if (Reference.ListenPort != nullptr)
	{
		*ListenPort = *Reference.ListenPort;
	}
	else {
		delete ListenPort;
		ListenPort = nullptr;
	}
	IsIPFilterTypePermit = Reference.IsIPFilterTypePermit;
	IPFilterLevel = Reference.IPFilterLevel;
	IsAcceptTypePermit = Reference.IsAcceptTypePermit;
	if (Reference.AcceptTypeList != nullptr)
	{
		*AcceptTypeList = *Reference.AcceptTypeList;
	}
	else {
		delete AcceptTypeList;
		AcceptTypeList = nullptr;
	}

	//[DNS] block
	RequestMode_Network = Reference.RequestMode_Network;
	RequestMode_Transport = Reference.RequestMode_Transport;
	DirectRequest = Reference.DirectRequest;
	DNS_CacheType = Reference.DNS_CacheType;
	DNS_CacheParameter = Reference.DNS_CacheParameter;
	HostsDefaultTTL = Reference.HostsDefaultTTL;

	//[Local DNS] block
	LocalProtocol_Network = Reference.LocalProtocol_Network;
	LocalProtocol_Transport = Reference.LocalProtocol_Transport;
	IsLocalForce = Reference.IsLocalForce;
	IsLocalMain = Reference.IsLocalMain;
	IsLocalHosts = Reference.IsLocalHosts;
	IsLocalRouting = Reference.IsLocalRouting;

	//[Addresses] block
	if (Reference.ListenAddress_IPv6 != nullptr)
	{
		*ListenAddress_IPv6 = *Reference.ListenAddress_IPv6;
	}
	else {
		delete ListenAddress_IPv6;
		ListenAddress_IPv6 = nullptr;
	}
	if (Reference.ListenAddress_IPv4 != nullptr)
	{
		*ListenAddress_IPv4 = *Reference.ListenAddress_IPv4;
	}
	else {
		delete ListenAddress_IPv4;
		ListenAddress_IPv4 = nullptr;
	}
	if (Reference.LocalMachineSubnet_IPv6 != nullptr)
	{
		*LocalMachineSubnet_IPv6 = *Reference.LocalMachineSubnet_IPv6;
	}
	else {
		delete LocalMachineSubnet_IPv6;
		LocalMachineSubnet_IPv6 = nullptr;
	}
	if (Reference.LocalMachineSubnet_IPv4 != nullptr)
	{
		*LocalMachineSubnet_IPv4 = *Reference.LocalMachineSubnet_IPv4;
	}
	else {
		delete LocalMachineSubnet_IPv4;
		LocalMachineSubnet_IPv4 = nullptr;
	}
	Target_Server_Main_IPv6 = Reference.Target_Server_Main_IPv6;
	Target_Server_Alternate_IPv6 = Reference.Target_Server_Alternate_IPv6;
	Target_Server_Main_IPv4 = Reference.Target_Server_Main_IPv4;
	Target_Server_Alternate_IPv4 = Reference.Target_Server_Alternate_IPv4;
	Target_Server_Local_Main_IPv6 = Reference.Target_Server_Local_Main_IPv6;
	Target_Server_Local_Alternate_IPv6 = Reference.Target_Server_Local_Alternate_IPv6;
	Target_Server_Local_Main_IPv4 = Reference.Target_Server_Local_Main_IPv4;
	Target_Server_Local_Alternate_IPv4 = Reference.Target_Server_Local_Alternate_IPv4;
	if (Reference.Target_Server_IPv6_Multiple != nullptr)
	{
		*Target_Server_IPv6_Multiple = *Reference.Target_Server_IPv6_Multiple;
	}
	else {
		delete Target_Server_IPv6_Multiple;
		Target_Server_IPv6_Multiple = nullptr;
	}
	if (Reference.Target_Server_IPv4_Multiple != nullptr)
	{
		*Target_Server_IPv4_Multiple = *Reference.Target_Server_IPv4_Multiple;
	}
	else {
		delete Target_Server_IPv4_Multiple;
		Target_Server_IPv4_Multiple = nullptr;
	}

	//[Values] block
	ThreadPoolBaseNum = Reference.ThreadPoolBaseNum;
	ThreadPoolMaxNum = Reference.ThreadPoolMaxNum;
	ThreadPoolResetTime = Reference.ThreadPoolResetTime;
	QueueResetTime = Reference.QueueResetTime;
	EDNS_PayloadSize = Reference.EDNS_PayloadSize;
	PacketHopLimits_IPv6_Begin = Reference.PacketHopLimits_IPv6_Begin;
	PacketHopLimits_IPv6_End = Reference.PacketHopLimits_IPv6_End;
	PacketHopLimits_IPv4_Begin = Reference.PacketHopLimits_IPv4_Begin;
	PacketHopLimits_IPv4_End = Reference.PacketHopLimits_IPv4_End;
#if defined(ENABLE_PCAP)
	HopLimitsFluctuation = Reference.HopLimitsFluctuation;
#endif
	SocketTimeout_Reliable_Once = Reference.SocketTimeout_Reliable_Once;
	SocketTimeout_Reliable_Serial = Reference.SocketTimeout_Reliable_Serial;
	SocketTimeout_Unreliable_Once = Reference.SocketTimeout_Unreliable_Once;
	SocketTimeout_Unreliable_Serial = Reference.SocketTimeout_Unreliable_Serial;
	TCP_FastOpen = Reference.TCP_FastOpen;
	ReceiveWaiting = Reference.ReceiveWaiting;
	AlternateTimes = Reference.AlternateTimes;
	AlternateTimeRange = Reference.AlternateTimeRange;
	AlternateResetTime = Reference.AlternateResetTime;
	MultipleRequestTimes = Reference.MultipleRequestTimes;

	//[Switches] block
	DomainCaseConversion = Reference.DomainCaseConversion;
	CompressionPointerMutation = Reference.CompressionPointerMutation;
	CPM_PointerToHeader = Reference.CPM_PointerToHeader;
	CPM_PointerToRR = Reference.CPM_PointerToRR;
	CPM_PointerToAdditional = Reference.CPM_PointerToAdditional;
	EDNS_Label = Reference.EDNS_Label;
	EDNS_Switch_Local = Reference.EDNS_Switch_Local;
	EDNS_Switch_SOCKS = Reference.EDNS_Switch_SOCKS;
	EDNS_Switch_HTTP_CONNECT = Reference.EDNS_Switch_HTTP_CONNECT;
	EDNS_Switch_Direct = Reference.EDNS_Switch_Direct;
#if defined(ENABLE_LIBSODIUM)
	EDNS_Switch_DNSCurve = Reference.EDNS_Switch_DNSCurve;
#endif
	EDNS_Switch_TCP = Reference.EDNS_Switch_TCP;
	EDNS_Switch_UDP = Reference.EDNS_Switch_UDP;
	EDNS_ClientSubnet_Relay = Reference.EDNS_ClientSubnet_Relay;
	DNSSEC_Request = Reference.DNSSEC_Request;
	DNSSEC_Validation = Reference.DNSSEC_Validation;
	DNSSEC_ForceValidation = Reference.DNSSEC_ForceValidation;
	AlternateMultipleRequest = Reference.AlternateMultipleRequest;
	DoNotFragment = Reference.DoNotFragment;
#if defined(ENABLE_PCAP)
	HeaderCheck_IPv4 = Reference.HeaderCheck_IPv4;
	HeaderCheck_TCP = Reference.HeaderCheck_TCP;
#endif
	HeaderCheck_DNS = Reference.HeaderCheck_DNS;
	DataCheck_Blacklist = Reference.DataCheck_Blacklist;
	DataCheck_Strict_RR_TTL = Reference.DataCheck_Strict_RR_TTL;

	//[Data] block
#if defined(ENABLE_PCAP)
	ICMP_ID = Reference.ICMP_ID;
	ICMP_Sequence = Reference.ICMP_Sequence;
	ICMP_Speed = Reference.ICMP_Speed;
	if (Reference.ICMP_PaddingData != nullptr)
	{
		memcpy_s(ICMP_PaddingData, ICMP_PADDING_MAXSIZE, Reference.ICMP_PaddingData, ICMP_PADDING_MAXSIZE);
	}
	else {
		delete[] ICMP_PaddingData;
		ICMP_PaddingData = nullptr;
	}
	ICMP_PaddingLength = Reference.ICMP_PaddingLength;
	if (Reference.DomainTest_Data != nullptr)
	{
		memcpy_s(DomainTest_Data, DOMAIN_MAXSIZE, Reference.DomainTest_Data, DOMAIN_MAXSIZE);
	}
	else {
		delete[] DomainTest_Data;
		DomainTest_Data = nullptr;
	}
	DomainTest_ID = Reference.DomainTest_ID;
	DomainTest_Speed = Reference.DomainTest_Speed;
#endif
	if (Reference.Local_FQDN_String != nullptr)
	{
		*Local_FQDN_String = *Reference.Local_FQDN_String;
	}
	else {
		delete Local_FQDN_String;
		Local_FQDN_String = nullptr;
	}
	memcpy_s(Local_FQDN_Response, DOMAIN_MAXSIZE, Reference.Local_FQDN_Response, DOMAIN_MAXSIZE);
	Local_FQDN_Length = Reference.Local_FQDN_Length;
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	memcpy_s(LocalServer_Response, DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt), Reference.LocalServer_Response, DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt));
	LocalServer_Length = Reference.LocalServer_Length;
#endif

	//[Proxy] block
	SOCKS_Proxy = Reference.SOCKS_Proxy;
	SOCKS_Version = Reference.SOCKS_Version;
	SOCKS_Protocol_Network = Reference.SOCKS_Protocol_Network;
	SOCKS_Protocol_Transport = Reference.SOCKS_Protocol_Transport;
	SOCKS_UDP_NoHandshake = Reference.SOCKS_UDP_NoHandshake;
	SOCKS_Only = Reference.SOCKS_Only;
	SOCKS_Address_IPv6 = Reference.SOCKS_Address_IPv6;
	SOCKS_Address_IPv4 = Reference.SOCKS_Address_IPv4;
	SOCKS_TargetServer = Reference.SOCKS_TargetServer;
	if (Reference.SOCKS_TargetDomain != nullptr)
	{
		*SOCKS_TargetDomain = *Reference.SOCKS_TargetDomain;
	}
	else {
		delete SOCKS_TargetDomain;
		SOCKS_TargetDomain = nullptr;
	}
	SOCKS_TargetDomain_Port = Reference.SOCKS_TargetDomain_Port;
	if (Reference.SOCKS_Username != nullptr)
	{
		*SOCKS_Username = *Reference.SOCKS_Username;
	}
	else {
		delete SOCKS_Username;
		SOCKS_Username = nullptr;
	}
	if (Reference.SOCKS_Password != nullptr)
	{
		*SOCKS_Password = *Reference.SOCKS_Password;
	}
	else {
		delete SOCKS_Password;
		SOCKS_Password = nullptr;
	}
	HTTP_CONNECT_Proxy = Reference.HTTP_CONNECT_Proxy;
	HTTP_CONNECT_Protocol = Reference.HTTP_CONNECT_Protocol;
	HTTP_CONNECT_Only = Reference.HTTP_CONNECT_Only;
	HTTP_CONNECT_Address_IPv6 = Reference.HTTP_CONNECT_Address_IPv6;
	HTTP_CONNECT_Address_IPv4 = Reference.HTTP_CONNECT_Address_IPv4;
#if defined(ENABLE_TLS)
	HTTP_CONNECT_TLS_Handshake = Reference.HTTP_CONNECT_TLS_Handshake;
	HTTP_CONNECT_TLS_Version = Reference.HTTP_CONNECT_TLS_Version;
	HTTP_CONNECT_TLS_Validation = Reference.HTTP_CONNECT_TLS_Validation;
	if (Reference.HTTP_CONNECT_TLS_SNI != nullptr)
	{
		*HTTP_CONNECT_TLS_SNI = *Reference.HTTP_CONNECT_TLS_SNI;
	}
	else {
		delete HTTP_CONNECT_TLS_SNI;
		HTTP_CONNECT_TLS_SNI = nullptr;
	}
	if (Reference.MBS_HTTP_CONNECT_TLS_SNI != nullptr)
	{
		*MBS_HTTP_CONNECT_TLS_SNI = *Reference.MBS_HTTP_CONNECT_TLS_SNI;
	}
	else {
		delete MBS_HTTP_CONNECT_TLS_SNI;
		MBS_HTTP_CONNECT_TLS_SNI = nullptr;
	}
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (Reference.HTTP_CONNECT_TLS_AddressString_IPv6 != nullptr)
	{
		*HTTP_CONNECT_TLS_AddressString_IPv6 = *Reference.HTTP_CONNECT_TLS_AddressString_IPv6;
	}
	else {
		delete HTTP_CONNECT_TLS_AddressString_IPv6;
		HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
	}
	if (Reference.HTTP_CONNECT_TLS_AddressString_IPv4 != nullptr)
	{
		*HTTP_CONNECT_TLS_AddressString_IPv4 = *Reference.HTTP_CONNECT_TLS_AddressString_IPv4;
	}
	else {
		delete HTTP_CONNECT_TLS_AddressString_IPv4;
		HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;
	}
#endif
#endif
	if (Reference.HTTP_CONNECT_TargetDomain != nullptr)
	{
		*HTTP_CONNECT_TargetDomain = *Reference.HTTP_CONNECT_TargetDomain;
	}
	else {
		delete HTTP_CONNECT_TargetDomain;
		HTTP_CONNECT_TargetDomain = nullptr;
	}
	if (Reference.HTTP_CONNECT_Version != nullptr)
	{
		*HTTP_CONNECT_Version = *Reference.HTTP_CONNECT_Version;
	}
	else {
		delete HTTP_CONNECT_Version;
		HTTP_CONNECT_Version = nullptr;
	}
	if (Reference.HTTP_CONNECT_HeaderField != nullptr)
	{
		*HTTP_CONNECT_HeaderField = *Reference.HTTP_CONNECT_HeaderField;
	}
	else {
		delete HTTP_CONNECT_HeaderField;
		HTTP_CONNECT_HeaderField = nullptr;
	}
	if (Reference.HTTP_CONNECT_ProxyAuthorization != nullptr)
	{
		*HTTP_CONNECT_ProxyAuthorization = *Reference.HTTP_CONNECT_ProxyAuthorization;
	}
	else {
		delete HTTP_CONNECT_ProxyAuthorization;
		HTTP_CONNECT_ProxyAuthorization = nullptr;
	}

	//[DNSCurve/DNSCrypt] block
#if defined(ENABLE_LIBSODIUM)
	IsDNSCurve = Reference.IsDNSCurve;
#endif

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
	memset(ConfigurationParameter->LocalServer_Response, 0, DOMAIN_MAXSIZE + sizeof(dns_record_ptr) + sizeof(dns_record_opt));
#endif

//Default value settings
	//[Base] block
	ConfigurationParameter->FileRefreshTime = DEFAULT_FILE_REFRESH_TIME;
	ConfigurationParameter->LargeBufferSize = DEFAULT_LARGE_BUFFER_SIZE;

	//[Log] block
	ConfigurationParameter->PrintLogLevel = DEFAULT_LOG_LEVEL;
	ConfigurationParameter->LogMaxSize = LOG_READING_MAXSIZE;

	//[Listen] block
#if defined(ENABLE_PCAP)
	ConfigurationParameter->PcapReadingTimeout = DEFAULT_PCAP_CAPTURE_TIMEOUT;
#endif
	ConfigurationParameter->ListenProtocol_Network = LISTEN_PROTOCOL_NETWORK::BOTH;
	ConfigurationParameter->ListenProtocol_Transport = LISTEN_PROTOCOL_TRANSPORT::BOTH;
	ConfigurationParameter->OperationMode = LISTEN_MODE::PRIVATE;

	//[DNS] block
	ConfigurationParameter->RequestMode_Network = REQUEST_MODE_NETWORK::BOTH;
	ConfigurationParameter->RequestMode_Transport = REQUEST_MODE_TRANSPORT::UDP;
	ConfigurationParameter->DirectRequest = REQUEST_MODE_DIRECT::NONE;
	ConfigurationParameter->DNS_CacheType = DNS_CACHE_TYPE::NONE;
	ConfigurationParameter->HostsDefaultTTL = DEFAULT_HOSTS_TTL;

	//[Local DNS] block
	ConfigurationParameter->LocalProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
	ConfigurationParameter->LocalProtocol_Transport = REQUEST_MODE_TRANSPORT::UDP;

	//[Values] block
	ConfigurationParameter->ThreadPoolBaseNum = DEFAULT_THREAD_POOL_BASENUM;
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
	ConfigurationParameter->DomainTest_Speed = DEFAULT_DOMAIN_TEST_INTERVAL_TIME * SECOND_TO_MILLISECOND;
#endif
	ConfigurationParameter->AlternateTimes = DEFAULT_ALTERNATE_TIMES;
	ConfigurationParameter->AlternateTimeRange = DEFAULT_ALTERNATE_RANGE_TIME * SECOND_TO_MILLISECOND;
	ConfigurationParameter->AlternateResetTime = DEFAULT_ALTERNATE_RESET_TIME * SECOND_TO_MILLISECOND;

	//[Data] block
#if defined(ENABLE_PCAP)
#if defined(PLATFORM_WIN)
	ConfigurationParameter->ICMP_ID = htons(static_cast<uint16_t>(GetCurrentProcessId())); //Default ICMP ID is current thread ID.
#elif defined(PLATFORM_LINUX)
	ConfigurationParameter->ICMP_ID = htons(static_cast<uint16_t>(pthread_self())); //Default ICMP ID is current thread ID.
#elif defined(PLATFORM_MACOS)
	ConfigurationParameter->ICMP_ID = htons(*reinterpret_cast<uint16_t *>(pthread_self())); //Default ICMP ID is current thread ID.
#endif
ConfigurationParameter->ICMP_Sequence = htons(DEFAULT_SEQUENCE);
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
#if defined(PLATFORM_WIN)
	ConfigurationParameter->DomainTest_ID = htons(static_cast<uint16_t>(GetCurrentProcessId())); //Default DNS ID is current thread ID.
#elif defined(PLATFORM_LINUX)
	ConfigurationParameter->DomainTest_ID = htons(static_cast<uint16_t>(pthread_self())); //Default DNS ID is current thread ID.
#elif defined(PLATFORM_MACOS)
	ConfigurationParameter->DomainTest_ID = htons(*reinterpret_cast<uint16_t *>(pthread_self())); //Default DNS ID is current thread ID.
#endif
#endif

	//[Proxy] block
	ConfigurationParameter->SOCKS_Version = SOCKS_VERSION_5;
	ConfigurationParameter->SOCKS_Protocol_Network = REQUEST_MODE_NETWORK::BOTH;
	ConfigurationParameter->SOCKS_Protocol_Transport = REQUEST_MODE_TRANSPORT::TCP;
	ConfigurationParameter->HTTP_CONNECT_Protocol = REQUEST_MODE_NETWORK::BOTH;

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
	delete SOCKS_Username;
	delete SOCKS_Password;
#if defined(ENABLE_TLS)
	delete HTTP_CONNECT_TLS_SNI;
	delete MBS_HTTP_CONNECT_TLS_SNI;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	delete HTTP_CONNECT_TLS_AddressString_IPv6;
	delete HTTP_CONNECT_TLS_AddressString_IPv4;
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
	MBS_HTTP_CONNECT_TLS_SNI = nullptr;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	HTTP_CONNECT_TLS_AddressString_IPv6 = nullptr;
	HTTP_CONNECT_TLS_AddressString_IPv4 = nullptr;
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
	ConfigurationParameter->DirectRequest = DirectRequest;
	ConfigurationParameter->HostsDefaultTTL = HostsDefaultTTL;

//[Local DNS] block
	ConfigurationParameter->LocalProtocol_Network = LocalProtocol_Network;
	ConfigurationParameter->LocalProtocol_Transport = LocalProtocol_Transport;
	ConfigurationParameter->IsLocalForce = IsLocalForce;

//[Values] block
	ConfigurationParameter->ThreadPoolResetTime = ThreadPoolResetTime;
#if defined(ENABLE_PCAP)
	ConfigurationParameter->Target_Server_Main_IPv6.HopLimitsData_Assign.HopLimit = Target_Server_Main_IPv6.HopLimitsData_Assign.HopLimit;
	ConfigurationParameter->Target_Server_Main_IPv4.HopLimitsData_Assign.TTL = Target_Server_Main_IPv4.HopLimitsData_Assign.TTL;
	ConfigurationParameter->Target_Server_Main_IPv6.HopLimitsData_Mark.HopLimit = Target_Server_Main_IPv6.HopLimitsData_Mark.HopLimit;
	ConfigurationParameter->Target_Server_Main_IPv4.HopLimitsData_Mark.TTL = Target_Server_Main_IPv4.HopLimitsData_Mark.TTL;
	ConfigurationParameter->Target_Server_Alternate_IPv6.HopLimitsData_Assign.HopLimit = Target_Server_Alternate_IPv6.HopLimitsData_Assign.HopLimit;
	ConfigurationParameter->Target_Server_Alternate_IPv4.HopLimitsData_Assign.TTL = Target_Server_Alternate_IPv4.HopLimitsData_Assign.TTL;
	ConfigurationParameter->Target_Server_Alternate_IPv6.HopLimitsData_Mark.HopLimit = Target_Server_Alternate_IPv6.HopLimitsData_Mark.HopLimit;
	ConfigurationParameter->Target_Server_Alternate_IPv4.HopLimitsData_Mark.TTL = Target_Server_Alternate_IPv4.HopLimitsData_Mark.TTL;
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
	ConfigurationParameter->DataCheck_Strict_RR_TTL = DataCheck_Strict_RR_TTL;

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
	Version_Major = 0;
	Version_Minor = 0;
	FileRefreshTime = DEFAULT_FILE_REFRESH_TIME;

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
	DirectRequest = REQUEST_MODE_DIRECT::NONE;
	HostsDefaultTTL = DEFAULT_HOSTS_TTL;

//[Local DNS] block
	LocalProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
	LocalProtocol_Transport = REQUEST_MODE_TRANSPORT::UDP;
	IsLocalForce = false;

//[Values] block
	ThreadPoolResetTime = DEFAULT_THREAD_POOL_RESET_TIME;
#if defined(ENABLE_PCAP)
	Target_Server_Main_IPv6.HopLimitsData_Assign.HopLimit = 0;
	Target_Server_Main_IPv4.HopLimitsData_Assign.TTL = 0;
	Target_Server_Main_IPv6.HopLimitsData_Mark.HopLimit = 0;
	Target_Server_Main_IPv4.HopLimitsData_Mark.TTL = 0;
	Target_Server_Alternate_IPv6.HopLimitsData_Assign.HopLimit = 0;
	Target_Server_Alternate_IPv4.HopLimitsData_Assign.TTL = 0;
	Target_Server_Alternate_IPv6.HopLimitsData_Mark.HopLimit = 0;
	Target_Server_Alternate_IPv4.HopLimitsData_Mark.TTL = 0;
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
	DataCheck_Strict_RR_TTL = false;

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
	HTTP_CONNECT_TLS_Version = TLS_VERSION_SELECTION::AUTO;
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
		MBS_Path_Global = new std::vector<std::string>();
		MBS_Path_ErrorLog = new std::string();
		MBS_FileList_Hosts = new std::vector<std::string>();
		MBS_FileList_IPFilter = new std::vector<std::string>();
	#endif
		LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6] = new uint8_t[PACKET_MAXSIZE]();
		LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4] = new uint8_t[PACKET_MAXSIZE]();
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6] = new std::vector<std::string>();
		LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4] = new std::vector<std::string>();
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
		delete MBS_Path_Global;
		delete MBS_Path_ErrorLog;
		delete MBS_FileList_Hosts;
		delete MBS_FileList_IPFilter;
		MBS_Path_Global = nullptr;
		MBS_Path_ErrorLog = nullptr;
		MBS_FileList_Hosts = nullptr;
		MBS_FileList_IPFilter = nullptr;
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
	return;
}

//GlobalStatus class copy constructor
GlobalStatus::GlobalStatus(
	const GlobalStatus &Reference)
{
//Check itself.
	if (this == &Reference)
		return;

//Class constructor
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
		MBS_Path_Global = new std::vector<std::string>();
		MBS_Path_ErrorLog = new std::string();
		MBS_FileList_Hosts = new std::vector<std::string>();
		MBS_FileList_IPFilter = new std::vector<std::string>();
	#endif
		LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6] = new uint8_t[PACKET_MAXSIZE]();
		LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4] = new uint8_t[PACKET_MAXSIZE]();
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6] = new std::vector<std::string>();
		LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4] = new std::vector<std::string>();
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
		delete MBS_Path_Global;
		delete MBS_Path_ErrorLog;
		delete MBS_FileList_Hosts;
		delete MBS_FileList_IPFilter;
		MBS_Path_Global = nullptr;
		MBS_Path_ErrorLog = nullptr;
		MBS_FileList_Hosts = nullptr;
		MBS_FileList_IPFilter = nullptr;
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

//Copy constructor
#if defined(PLATFORM_WIN)
	IsInitialized_WinSock = Reference.IsInitialized_WinSock;
	Initialized_MutexHandle = Reference.Initialized_MutexHandle;
	Initialized_MutexSecurityAttributes = Reference.Initialized_MutexSecurityAttributes;
	Initialized_MutexSecurityDescriptor = Reference.Initialized_MutexSecurityDescriptor;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
#if defined(ENABLE_TLS)
	IsInitialized_OpenSSL = Reference.IsInitialized_OpenSSL;
#endif
	Initialized_MutexHandle = Reference.Initialized_MutexHandle;
#endif
	StartupTime = Reference.StartupTime;
#if defined(PLATFORM_WIN)
	IsConsole = Reference.IsConsole;
#elif defined(PLATFORM_LINUX)
	IsDaemon = Reference.IsDaemon;
#endif
	GatewayAvailable_IPv6 = Reference.GatewayAvailable_IPv6;
	GatewayAvailable_IPv4 = Reference.GatewayAvailable_IPv4;
	LocalAddress_Length[NETWORK_LAYER_TYPE_IPV6] = Reference.LocalAddress_Length[NETWORK_LAYER_TYPE_IPV6];
	LocalAddress_Length[NETWORK_LAYER_TYPE_IPV4] = Reference.LocalAddress_Length[NETWORK_LAYER_TYPE_IPV4];
	if (Reference.LocalListeningSocket != nullptr)
	{
		*LocalListeningSocket = *Reference.LocalListeningSocket;
	}
	else {
		delete LocalListeningSocket;
		LocalListeningSocket = nullptr;
	}
	if (Reference.RamdomEngine != nullptr)
	{
		*RamdomEngine = *Reference.RamdomEngine;
	}
	else {
		delete RamdomEngine;
		RamdomEngine = nullptr;
	}
	ThreadRunningNum->store(*Reference.ThreadRunningNum);
	ThreadRunningFreeNum->store(*Reference.ThreadRunningFreeNum);
	if (Reference.Path_Global != nullptr)
	{
		*Path_Global = *Reference.Path_Global;
	}
	else {
		delete Path_Global;
		Path_Global = nullptr;
	}
	if (Reference.Path_ErrorLog != nullptr)
	{
		*Path_ErrorLog = *Reference.Path_ErrorLog;
	}
	else {
		delete Path_ErrorLog;
		Path_ErrorLog = nullptr;
	}
	if (Reference.FileList_Hosts != nullptr)
	{
		*FileList_Hosts = *Reference.FileList_Hosts;
	}
	else {
		delete FileList_Hosts;
		FileList_Hosts = nullptr;
	}
	if (Reference.FileList_IPFilter != nullptr)
	{
		*FileList_IPFilter = *Reference.FileList_IPFilter;
	}
	else {
		delete FileList_IPFilter;
		FileList_IPFilter = nullptr;
	}
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (Reference.MBS_Path_Global != nullptr)
	{
		*MBS_Path_Global = *Reference.MBS_Path_Global;
	}
	else {
		delete MBS_Path_Global;
		MBS_Path_Global = nullptr;
	}
	if (Reference.MBS_Path_ErrorLog != nullptr)
	{
		*MBS_Path_ErrorLog = *Reference.MBS_Path_ErrorLog;
	}
	else {
		delete MBS_Path_ErrorLog;
		MBS_Path_ErrorLog = nullptr;
	}
	if (Reference.MBS_FileList_Hosts != nullptr)
	{
		*MBS_FileList_Hosts = *Reference.MBS_FileList_Hosts;
	}
	else {
		delete MBS_FileList_Hosts;
		MBS_FileList_Hosts = nullptr;
	}
	if (Reference.MBS_FileList_IPFilter != nullptr)
	{
		*MBS_FileList_IPFilter = *Reference.MBS_FileList_IPFilter;
	}
	else {
		delete MBS_FileList_IPFilter;
		MBS_FileList_IPFilter = nullptr;
	}
#endif
	memcpy_s(LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6], PACKET_MAXSIZE, Reference.LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6], PACKET_MAXSIZE);
	memcpy_s(LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4], PACKET_MAXSIZE, Reference.LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4], PACKET_MAXSIZE);
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	if (Reference.LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6] != nullptr)
	{
		*LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6] = *Reference.LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6];
	}
	else {
		delete LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6];
		LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV6] = nullptr;
	}
	if (Reference.LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4] != nullptr)
	{
		*LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4] = *Reference.LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4];
	}
	else {
		delete LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4];
		LocalAddress_PointerResponse[NETWORK_LAYER_TYPE_IPV4] = nullptr;
	}
#endif
	ConfigFileModifiedTime = Reference.ConfigFileModifiedTime;

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
	GlobalRunningStatusParameter->DomainTable = const_cast<uint8_t *>(DomainTable_Initialization);
	GlobalRunningStatusParameter->Base64_EncodeTable = const_cast<uint8_t *>(Base64_EncodeTable_Initialization);
	GlobalRunningStatusParameter->Base64_DecodeTable = const_cast<int8_t *>(Base64_DecodeTable_Initialization);
	GlobalRunningStatusParameter->GatewayAvailable_IPv4 = true;
	memset(GlobalRunningStatusParameter->LocalAddress_Response[NETWORK_LAYER_TYPE_IPV6], 0, PACKET_MAXSIZE);
	memset(GlobalRunningStatusParameter->LocalAddress_Response[NETWORK_LAYER_TYPE_IPV4], 0, PACKET_MAXSIZE);

	return;
}

//GlobalStatus class destructor
GlobalStatus::~GlobalStatus(
	void)
{
//Close all sockets.
	for (const auto &SocketIter:*LocalListeningSocket)
		SocketSetting(SocketIter, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

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

//Free all OpenSSL libraries
#if defined(ENABLE_TLS)
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0 //OpenSSL version brfore 1.1.0
	if (IsInitialized_OpenSSL)
	{
		OpenSSL_Library_Init(false);
		IsInitialized_OpenSSL = false;
	}
#endif
#endif

//Close all file handles.
#if (defined(PLATFORM_LINUX) && !defined(PLATFORM_OPENWRT))
	fcloseall();
#endif
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
	delete MBS_Path_Global;
	delete MBS_Path_ErrorLog;
	delete MBS_FileList_Hosts;
	delete MBS_FileList_IPFilter;
	MBS_Path_Global = nullptr;
	MBS_Path_ErrorLog = nullptr;
	MBS_FileList_Hosts = nullptr;
	MBS_FileList_IPFilter = nullptr;
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
	IsStringMatching = false;
	PermissionOperation = false;

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
	memset(this, 0, sizeof(ALTERNATE_SWAP_TABLE));
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

//SocketSelectingOnceTable class constructor
SocketSelectingOnceTable::SocketSelectingOnceTable(
	void)
{
	RecvLen = 0;
	IsPacketDone = false;

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

#if defined(ENABLE_LIBSODIUM)
//DNSCurveConfigurationTable class constructor
DNSCurveConfigurationTable::DNSCurveConfigurationTable(
	void)
{
//Libsodium initialization
	if (sodium_init() == LIBSODIUM_ERROR)
	{
		exit(EXIT_FAILURE);
//		return;
	}

//Class constructor
	memset(this, 0, sizeof(DNSCURVE_CONFIGURATION_TABLE));
	try {
	//[DNSCurve Database] block
		DatabaseName = new std::wstring();
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		MBS_DatabaseName = new std::string();
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
	catch (std::bad_alloc)
	{
	//[DNSCurve Database] block
		delete DatabaseName;
		DatabaseName = nullptr;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		delete MBS_DatabaseName;
		MBS_DatabaseName = nullptr;
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

//DNSCurveConfigurationTable class copy constructor
DNSCurveConfigurationTable::DNSCurveConfigurationTable(
	const DNSCurveConfigurationTable &Reference)
{
//Check itself.
	if (this == &Reference)
		return;

//Class constructor
	memset(this, 0, sizeof(DNSCURVE_CONFIGURATION_TABLE));
	try {
	//[DNSCurve Database] block
		DatabaseName = new std::wstring();
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		MBS_DatabaseName = new std::string();
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
		DNSCurve_Target_Server_Main_IPv6.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Main_IPv4.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
		DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = new uint8_t[DNSCURVE_MAGIC_QUERY_LEN]();
	}
	catch (std::bad_alloc)
	{
	//[DNSCurve Database] block
		delete DatabaseName;
		DatabaseName = nullptr;
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		delete MBS_DatabaseName;
		MBS_DatabaseName = nullptr;
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

//Copy constructor
	//[DNSCurve] block
	DNSCurvePayloadSize = Reference.DNSCurvePayloadSize;
	DNSCurveProtocol_Network = Reference.DNSCurveProtocol_Network;
	DNSCurveProtocol_Transport = Reference.DNSCurveProtocol_Transport;
	IsEncryption = Reference.IsEncryption;
	IsEncryptionOnly = Reference.IsEncryptionOnly;
	IsClientEphemeralKey = Reference.IsClientEphemeralKey;
	DNSCurve_SocketTimeout_Reliable = Reference.DNSCurve_SocketTimeout_Reliable;
	DNSCurve_SocketTimeout_Unreliable = Reference.DNSCurve_SocketTimeout_Unreliable;
	KeyRecheckTime = Reference.KeyRecheckTime;

	//[DNSCurve Database] block
	if (Reference.DatabaseName != nullptr)
	{
		*DatabaseName = *Reference.DatabaseName;
	}
	else {
		delete DatabaseName;
		DatabaseName = nullptr;
	}
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (Reference.MBS_DatabaseName != nullptr)
	{
		*MBS_DatabaseName = *Reference.MBS_DatabaseName;
	}
	else {
		delete MBS_DatabaseName;
		MBS_DatabaseName = nullptr;
	}
#endif
	if (Reference.Database_Target_Server_Main_IPv6 != nullptr)
	{
		*Database_Target_Server_Main_IPv6 = *Reference.Database_Target_Server_Main_IPv6;
	}
	else {
		delete Database_Target_Server_Main_IPv6;
		Database_Target_Server_Main_IPv6 = nullptr;
	}
	if (Reference.Database_Target_Server_Alternate_IPv6 != nullptr)
	{
		*Database_Target_Server_Alternate_IPv6 = *Reference.Database_Target_Server_Alternate_IPv6;
	}
	else {
		delete Database_Target_Server_Alternate_IPv6;
		Database_Target_Server_Alternate_IPv6 = nullptr;
	}
	if (Reference.Database_Target_Server_Main_IPv4 != nullptr)
	{
		*Database_Target_Server_Main_IPv4 = *Reference.Database_Target_Server_Main_IPv4;
	}
	else {
		delete Database_Target_Server_Main_IPv4;
		Database_Target_Server_Main_IPv4 = nullptr;
	}
	if (Reference.Database_Target_Server_Alternate_IPv4 != nullptr)
	{
		*Database_Target_Server_Alternate_IPv4 = *Reference.Database_Target_Server_Alternate_IPv4;
	}
	else {
		delete Database_Target_Server_Alternate_IPv4;
		Database_Target_Server_Alternate_IPv4 = nullptr;
	}
	if (Reference.Database_LineData != nullptr)
	{
		*Database_LineData = *Reference.Database_LineData;
	}
	else {
		delete Database_LineData;
		Database_LineData = nullptr;
	}

	//[DNSCurve Addresses] block
	DNSCurve_Target_Server_Main_IPv6.AddressData = Reference.DNSCurve_Target_Server_Main_IPv6.AddressData;
	DNSCurve_Target_Server_Alternate_IPv6.AddressData = Reference.DNSCurve_Target_Server_Alternate_IPv6.AddressData;
	DNSCurve_Target_Server_Main_IPv4.AddressData = Reference.DNSCurve_Target_Server_Main_IPv4.AddressData;
	DNSCurve_Target_Server_Alternate_IPv4.AddressData = Reference.DNSCurve_Target_Server_Alternate_IPv4.AddressData;
	if (Reference.DNSCurve_Target_Server_Main_IPv6.ProviderName != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv6.ProviderName, DOMAIN_MAXSIZE, Reference.DNSCurve_Target_Server_Main_IPv6.ProviderName, DOMAIN_MAXSIZE);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv6.ProviderName;
		DNSCurve_Target_Server_Main_IPv6.ProviderName = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv6.ProviderName != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv6.ProviderName, DOMAIN_MAXSIZE, Reference.DNSCurve_Target_Server_Alternate_IPv6.ProviderName, DOMAIN_MAXSIZE);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ProviderName;
		DNSCurve_Target_Server_Alternate_IPv6.ProviderName = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Main_IPv4.ProviderName != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv4.ProviderName, DOMAIN_MAXSIZE, Reference.DNSCurve_Target_Server_Main_IPv4.ProviderName, DOMAIN_MAXSIZE);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv4.ProviderName;
		DNSCurve_Target_Server_Main_IPv4.ProviderName = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv4.ProviderName != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv4.ProviderName, DOMAIN_MAXSIZE, Reference.DNSCurve_Target_Server_Alternate_IPv4.ProviderName, DOMAIN_MAXSIZE);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ProviderName;
		DNSCurve_Target_Server_Alternate_IPv4.ProviderName = nullptr;
	}

	//[DNSCurve Keys] block
	if (Reference.Client_PublicKey != nullptr)
	{
		memcpy_s(Client_PublicKey, crypto_box_PUBLICKEYBYTES, Reference.Client_PublicKey, crypto_box_PUBLICKEYBYTES);
	}
	else {
		delete[] Client_PublicKey;
		Client_PublicKey = nullptr;
	}
	if (Reference.Client_SecretKey != nullptr)
	{
		memcpy_s(Client_SecretKey, crypto_box_SECRETKEYBYTES, Reference.Client_SecretKey, crypto_box_PUBLICKEYBYTES);
	}
	else {
		delete[] Client_SecretKey;
		Client_SecretKey = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES, Reference.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv6.PrecomputationKey;
		DNSCurve_Target_Server_Main_IPv6.PrecomputationKey = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES, Reference.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey;
		DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES, Reference.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv4.PrecomputationKey;
		DNSCurve_Target_Server_Main_IPv4.PrecomputationKey = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES, Reference.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey;
		DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Main_IPv6.ServerPublicKey != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES, Reference.DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv6.ServerPublicKey;
		DNSCurve_Target_Server_Main_IPv6.ServerPublicKey = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES, Reference.DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey;
		DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Main_IPv4.ServerPublicKey != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES, Reference.DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv4.ServerPublicKey;
		DNSCurve_Target_Server_Main_IPv4.ServerPublicKey = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES, Reference.DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey;
		DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES, Reference.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv6.ServerFingerprint;
		DNSCurve_Target_Server_Main_IPv6.ServerFingerprint = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES, Reference.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint;
		DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES, Reference.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv4.ServerFingerprint;
		DNSCurve_Target_Server_Main_IPv4.ServerFingerprint = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES, Reference.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint;
		DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint = nullptr;
	}

	//[DNSCurve Magic Number] block
	if (Reference.DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Reference.DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber;
		DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Reference.DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber;
		DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Reference.DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber;
		DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Reference.DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber;
		DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Reference.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv6.SendMagicNumber;
		DNSCurve_Target_Server_Main_IPv6.SendMagicNumber = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Reference.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber;
		DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Reference.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	}
	else {
		delete[] DNSCurve_Target_Server_Main_IPv4.SendMagicNumber;
		DNSCurve_Target_Server_Main_IPv4.SendMagicNumber = nullptr;
	}
	if (Reference.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber != nullptr)
	{
		memcpy_s(DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN, Reference.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	}
	else {
		delete[] DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber;
		DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber = nullptr;
	}

	return;
}

//DNSCurveConfigurationTable class constructor settings
void DNSCurveConfigurationTableSetting(
	DNSCURVE_CONFIGURATION_TABLE * const DNSCurveConfigurationParameter)
{
//[DNSCurve Addresses] block
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ProviderName, DOMAIN_MAXSIZE);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ProviderName, DOMAIN_MAXSIZE);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ProviderName, DOMAIN_MAXSIZE);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ProviderName, DOMAIN_MAXSIZE);

//[DNSCurve Keys] block
	sodium_memzero(DNSCurveConfigurationParameter->Client_PublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->Client_SecretKey, crypto_box_SECRETKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);

//[DNSCurve Magic Number] block
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	sodium_memzero(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	
//Default settings
	//[DNSCurve] block
	DNSCurveConfigurationParameter->DNSCurveProtocol_Network = REQUEST_MODE_NETWORK::BOTH;
	DNSCurveConfigurationParameter->DNSCurveProtocol_Transport = REQUEST_MODE_TRANSPORT::UDP;
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
//[DNSCurve Database] block
	delete DatabaseName;
	DatabaseName = nullptr;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	delete MBS_DatabaseName;
	MBS_DatabaseName = nullptr;
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
	if (DNSCurveConfigurationParameter->Client_SecretKey != nullptr && !CheckEmptyBuffer(Client_SecretKey, crypto_box_PUBLICKEYBYTES) && 
		sodium_memcmp(DNSCurveConfigurationParameter->Client_SecretKey, Client_SecretKey, crypto_box_PUBLICKEYBYTES) != 0)
			memcpy_s(DNSCurveConfigurationParameter->Client_SecretKey, crypto_box_PUBLICKEYBYTES, Client_SecretKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES))
			memcpy_s(DNSCurveConfigurationParameter->DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES, DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES);
	if (DNSCurveConfigurationParameter->DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey != nullptr && 
		!CheckEmptyBuffer(DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES))
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
	DNSCurve_SocketTimeout_Reliable = DEFAULT_DNSCURVE_RELIABLE_SOCKET_TIMEOUT;
	DNSCurve_SocketTimeout_Unreliable = DEFAULT_DNSCURVE_UNRELIABLE_SOCKET_TIMEOUT;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	DNSCurve_SocketTimeout_Reliable.tv_sec = DEFAULT_DNSCURVE_RELIABLE_SOCKET_TIMEOUT;
	DNSCurve_SocketTimeout_Reliable.tv_usec = 0;
	DNSCurve_SocketTimeout_Unreliable.tv_sec = DEFAULT_DNSCURVE_UNRELIABLE_SOCKET_TIMEOUT;
	DNSCurve_SocketTimeout_Unreliable.tv_usec = 0;
#endif
	KeyRecheckTime = DEFAULT_DNSCURVE_RECHECK_TIME * SECOND_TO_MILLISECOND;

//[DNSCurve database] block
	if (Database_LineData != nullptr)
	{
		Database_LineData->clear();
		Database_LineData->shrink_to_fit();
	}

//[DNSCurve Keys] block
	if (Client_PublicKey != nullptr)
		sodium_memzero(Client_PublicKey, crypto_box_PUBLICKEYBYTES);
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
		sodium_memzero(DNSCurve_Target_Server_Main_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv6.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Main_IPv4.ServerPublicKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv4.ServerPublicKey, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Main_IPv6.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Main_IPv4.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);
	if (DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES);

//[DNSCurve Magic Number] block
	if (DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv6.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv4.ReceiveMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Main_IPv6.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Main_IPv4.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);
	if (DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber != nullptr)
		sodium_memzero(DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN);

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
	Protocol = 0;

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
