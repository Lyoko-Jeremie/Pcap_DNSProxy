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

extern ConfigurationTable Parameter;
extern PortTable PortList;
extern AlternateSwapTable AlternateSwapList;
extern DNSCurveConfigurationTable DNSCurveParameter;
extern std::vector<HostsTable> *HostsListUsing;
extern std::deque<DNSCacheData> DNSCacheList;
extern std::mutex LocalAddressLock[QUEUE_PARTNUM / 2U], HostsListLock, DNSCacheListLock;

/* Old version(2014-09-13)
static const std::regex IPv4PrivateB(".(1[6-9]|2[0-9]|3[01]).172.in-addr.arpa", std::regex_constants::extended);
static const std::regex IPv6ULA(".f.[cd].([0-9]|[a-f]).([0-9]|[a-f]).ip6.arpa", std::regex_constants::extended);
static const std::regex IPv6LUC(".f.f.([89]|[ab]).([0-9]|[a-f]).ip6.arpa", std::regex_constants::extended);
*/
//Independent request process
size_t __fastcall EnterRequestProcess(const PSTR OriginalSend, const size_t Length, const SOCKET_DATA TargetData, const uint16_t Protocol, const size_t ListIndex)
{
//Initialization(Send buffer part)
	std::shared_ptr<char> SendBuffer, RecvBuffer;
	if (Parameter.CompressionPointerMutation)
	{
		if (Parameter.CPMPointerToAdditional)
		{
			std::shared_ptr<char> SendBufferTemp(new char[Length + 2U + sizeof(dns_aaaa_record)]());
			SendBufferTemp.swap(SendBuffer);
		}
		else if (Parameter.CPMPointerToRR)
		{
			std::shared_ptr<char> SendBufferTemp(new char[Length + 2U]());
			SendBufferTemp.swap(SendBuffer);
		}
		else { //Pointer to header
			std::shared_ptr<char> SendBufferTemp(new char[Length + 1U]());
			SendBufferTemp.swap(SendBuffer);
		}
	}
	else {
		std::shared_ptr<char> SendBufferTemp(new char[Length]());
		SendBufferTemp.swap(SendBuffer);
	}
	memcpy(SendBuffer.get(), OriginalSend, Length);

//Initialization(Receive buffer part)
	size_t DataLength = 0;
	if (Parameter.RequestMode == REQUEST_TCPMODE || Parameter.DNSCurve && DNSCurveParameter.DNSCurveMode == DNSCURVE_REQUEST_TCPMODE || Protocol == IPPROTO_TCP) //TCP
	{
		std::shared_ptr<char> TCPRecvBuffer(new char[LARGE_PACKET_MAXSIZE]());
		RecvBuffer.swap(TCPRecvBuffer);
	}
	else { //UDP
		std::shared_ptr<char> UDPRecvBuffer(new char[PACKET_MAXSIZE]());
		RecvBuffer.swap(UDPRecvBuffer);
	}

//Check hosts.
	auto LocalRequest = false;
	auto pdns_hdr = (dns_hdr *)SendBuffer.get();
	if (pdns_hdr->Questions == htons(U16_NUM_ONE))
	{
		if (Protocol == IPPROTO_TCP) //TCP
			DataLength = CheckHosts(SendBuffer.get(), Length, RecvBuffer.get(), LARGE_PACKET_MAXSIZE - sizeof(uint16_t), LocalRequest);
		else //UDP
			DataLength = CheckHosts(SendBuffer.get(), Length, RecvBuffer.get(), PACKET_MAXSIZE, LocalRequest);

	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE)
		{
			SendToRequester(RecvBuffer.get(), DataLength, Protocol, TargetData);
			return EXIT_SUCCESS;
		}
	}
	else { //No any Question Resource Records
		memcpy(RecvBuffer.get(), SendBuffer.get(), Length);
		pdns_hdr = (dns_hdr *)RecvBuffer.get();
//		pdns_hdr->Flags = htons(DNS_SQR_FE);
		pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8001); //Set 10000000000000001, DNS_SQR_FE

		SendToRequester(RecvBuffer.get(), Length, Protocol, TargetData);
		return EXIT_FAILURE;
	}

//Local server requesting
	if (LocalRequest || Parameter.LocalMain)
	{
		DataLength = LocalRequestProcess(SendBuffer.get(), Length, RecvBuffer.get(), Protocol, TargetData);
		if (!Parameter.LocalMain || DataLength == EXIT_SUCCESS)
		{
		//Fin TCP request connection.
			if (Protocol == IPPROTO_TCP && TargetData.Socket != INVALID_SOCKET)
				closesocket(TargetData.Socket);

			return EXIT_SUCCESS;
		}
	}

	size_t SendLength = Length;
//Compression Pointer Mutation
	if (Parameter.CompressionPointerMutation && pdns_hdr->Additional == 0)
	{
		SendLength = MakeCompressionPointerMutation(SendBuffer.get(), Length);
		if (SendLength < Length)
			SendLength = Length;
	}

//Hosts Only requesting
	if (Parameter.HostsOnly)
	{
		DirectRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, TargetData);
	//Fin TCP request connection.
		if (Protocol == IPPROTO_TCP && TargetData.Socket != INVALID_SOCKET)
			closesocket(TargetData.Socket);

		return EXIT_SUCCESS;
	}

//DNSCurve requesting
	if (Parameter.DNSCurve)
	{
		if (DNSCurveParameter.IsEncryption && 
		//Send Length check
			(SendLength > DNSCurveParameter.DNSCurvePayloadSize + crypto_box_BOXZEROBYTES - (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES) || 
		//Receive Size check(TCP Mode)
			(Parameter.RequestMode == REQUEST_TCPMODE || DNSCurveParameter.DNSCurveMode == DNSCURVE_REQUEST_TCPMODE || Protocol == IPPROTO_TCP) && DNSCurveParameter.DNSCurvePayloadSize >= LARGE_PACKET_MAXSIZE && 
			crypto_box_ZEROBYTES + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES + SendLength >= LARGE_PACKET_MAXSIZE - sizeof(uint16_t) ||
		//Receive Size check(UDP Mode)
			Parameter.RequestMode != REQUEST_TCPMODE && DNSCurveParameter.DNSCurveMode != DNSCURVE_REQUEST_TCPMODE && Protocol != IPPROTO_TCP && DNSCurveParameter.DNSCurvePayloadSize >= PACKET_MAXSIZE &&
			crypto_box_ZEROBYTES + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES + SendLength >= PACKET_MAXSIZE))
				goto SkipDNSCurve;

	//DNSCurve requesting
		if (DNSCurveRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, TargetData) == EXIT_SUCCESS)
			return EXIT_SUCCESS;

	//DNSCurve Encryption Only mode
		if (DNSCurveParameter.IsEncryptionOnly)
		{
		//Fin TCP request connection.
			if (Protocol == IPPROTO_TCP && TargetData.Socket != INVALID_SOCKET)
				closesocket(TargetData.Socket);

			return EXIT_SUCCESS;
		}
	}
	SkipDNSCurve: 

//TCP requesting
	if (Parameter.RequestMode == REQUEST_TCPMODE && TCPRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, TargetData) == EXIT_SUCCESS)
		return EXIT_SUCCESS;

//IPv6 tunnels support
	if (((Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL || LocalRequest && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family != NULL) && TargetData.AddrLen == sizeof(sockaddr_in6) || //IPv6
		(Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL /* || !Local && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == NULL */ ) && TargetData.AddrLen == sizeof(sockaddr_in)) && //IPv4 is empty.
		Parameter.Tunnel_IPv6)
	{
		DirectRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, TargetData);
	//Fin TCP request connection.
		if (Protocol == IPPROTO_TCP && TargetData.Socket != INVALID_SOCKET)
			closesocket(TargetData.Socket);

		return EXIT_SUCCESS;
	}

	RecvBuffer.reset();
//Pcap Capture check
	if (!Parameter.PcapCapture)
		return EXIT_SUCCESS;

//UDP requesting
	if (Protocol == IPPROTO_UDP && SendLength <= Parameter.EDNS0PayloadSize || Protocol == IPPROTO_TCP)
	{
		UDPRequestProcess(SendBuffer.get(), SendLength, Protocol, TargetData, ListIndex);
		return EXIT_SUCCESS;
	}
	else { //UDP Truncated retry TCP protocol failed.
//		pdns_hdr->Flags = htons(DNS_SQR_NETC);
		pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8200); //Set 1000001000000000, DNS_SQR_NETC
		sendto(TargetData.Socket, SendBuffer.get(), (int)SendLength, NULL, (PSOCKADDR)&TargetData.SockAddr, TargetData.AddrLen);
	}

	return EXIT_FAILURE;
}

//Check hosts from list
inline size_t __fastcall CheckHosts(PSTR OriginalRequest, const size_t Length, PSTR Result, const size_t ResultSize, bool &IsLocal)
{
//Initilization
	auto pdns_hdr = (dns_hdr *)OriginalRequest;
	std::string Domain;
	if (pdns_hdr->Questions == htons(U16_NUM_ONE) && CheckDNSQueryNameLength(OriginalRequest + sizeof(dns_hdr)) + 1U < DOMAIN_MAXSIZE)
	{
		if (DNSQueryToChar(OriginalRequest + sizeof(dns_hdr), Result) > DOMAIN_MINSIZE)
		{
		//Domain Case Conversion
			CaseConvert(false, Result, strlen(Result));

		//Copy domain string.
			Domain = Result;
			memset(Result, 0, ResultSize);
		}
		else {
			memset(Result, 0, ResultSize);
			return EXIT_FAILURE;
		}
	}
	else {
		return EXIT_FAILURE;
	}

//Response
	memcpy(Result, OriginalRequest, Length);
	pdns_hdr = (dns_hdr *)Result;
	auto pdns_qry = (dns_qry *)(Result + DNS_PACKET_QUERY_LOCATE(Result));

//Check Classes.
	if (pdns_qry->Classes != htons(DNS_CLASS_IN))
	{
		memset(Result, 0, ResultSize);
		return FALSE;
	}

//Check Accept Types list.
	if (Parameter.AcceptType) //Permit
	{
		for (auto AcceptTypeIter = Parameter.AcceptTypeList->begin();AcceptTypeIter != Parameter.AcceptTypeList->end();AcceptTypeIter++)
		{
			if (AcceptTypeIter + 1U == Parameter.AcceptTypeList->end()) //Last
			{
				if (*AcceptTypeIter != pdns_qry->Type)
				{
//					pdns_hdr->Flags = htons(DNS_SQR_SNH);
					pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8003); //Set 1000000000000011, DNS_SQR_SNH
					return Length;
				}
			}
			else if (*AcceptTypeIter == pdns_qry->Type)
			{
				break;
			}
		}
	}
	else { //Deny
		for (auto AcceptTypeIter:*Parameter.AcceptTypeList)
		{
			if (AcceptTypeIter == pdns_qry->Type)
			{
//				pdns_hdr->Flags = htons(DNS_SQR_SNH);
				pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8003); //Set 1000000000000011, DNS_SQR_SNH
				return Length;
			}
		}
	}

/* Old version(2014-11-15)
//Domain Case Conversion
	for (auto StringIter = Domain.begin();StringIter != Domain.end();StringIter++)
	{
		if (*StringIter > ASCII_AT && *StringIter < ASCII_BRACKETS_LEAD)
			*StringIter += 32U;
	}
*/

//PTR Records
	if (pdns_qry->Type == htons(DNS_RECORD_PTR) && Parameter.LocalServerResponseLength + Length <= ResultSize)
	{
/* Old version(2014-09-13)
	//IPv4 check
		if (Domain.find(LocalAddressPTR[0]) != std::string::npos || //IPv4 Localhost
			Domain.find(".10.in-addr.arpa") != std::string::npos || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
			std::regex_match(Domain, IPv4PrivateB) || //Private class B address(172.16.0.0/16, Section 3 in RFC 1918)
			Domain.find(".168.192.in-addr.arpa") != std::string::npos || //Private class C address(192.168.0.0/24, Section 3 in RFC 1918)
	//IPv6 check
			Domain.find(LocalAddressPTR[1U]) != std::string::npos || //IPv6 Localhost
			std::regex_match(Domain, IPv6ULA) || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
			std::regex_match(Domain, IPv6LUC)) //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
*/
		auto SendPTR = false;

	//IPv6 check
		if (Domain == ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa") || //Loopback address(::1, Section 2.5.3 in RFC 4291)
	//IPv4 check
			Domain.find(".127.in-addr.arpa") != std::string::npos || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
			Domain.find(".254.169.in-addr.arpa") != std::string::npos) //Link-local address(169.254.0.0/16, RFC 3927)
		{
			SendPTR = true;
		}
		else {
		//IPv6 check
			std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[0]);
			for (auto StringIter:*Parameter.LocalAddressPTR[0])
			{
				if (Domain == StringIter)
				{
					SendPTR = true;
					break;
				}
			}
			LocalAddressMutexIPv6.unlock();

		//IPv4 check
			if (!SendPTR)
			{
				std::unique_lock<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[1U]);
				for (auto StringIter:*Parameter.LocalAddressPTR[1U])
				{
					if (Domain == StringIter)
					{
						SendPTR = true;
						break;
					}
				}
			}
		}

	//Send Localhost PTR.
		if (SendPTR)
		{
/* Old version(2014-11-15)
			dns_ptr_record *pdns_rsp = nullptr;

		//EDNS0 Lebal
			if (pdns_hdr->Additional != 0)
			{
				memset(Result + Length - sizeof(dns_opt_record), 0, sizeof(dns_opt_record));

			//Response
				pdns_rsp = (dns_ptr_record *)(Result + Length - sizeof(dns_opt_record));
				pdns_rsp->PTR = htons(DNS_QUERY_PTR);
				pdns_rsp->Classes = htons(DNS_CLASS_IN); //Class IN
				pdns_rsp->TTL = htonl(Parameter.HostsDefaultTTL);
				pdns_rsp->Type = htons(DNS_RECORD_PTR);
				pdns_rsp->Length = htons((uint16_t)Parameter.LocalFQDNLength);
				memcpy(Result + Length - sizeof(dns_opt_record) + sizeof(dns_ptr_record), Parameter.LocalFQDN, Parameter.LocalFQDNLength);

			//EDNS0
				auto EDNS0 = (dns_opt_record *)(Result + Length - sizeof(dns_opt_record) + sizeof(dns_ptr_record) + Parameter.LocalFQDNLength);
				EDNS0->Type = htons(DNS_RECORD_OPT);
				EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				return Length + sizeof(dns_ptr_record) + Parameter.LocalFQDNLength;
			}

		//Response
			pdns_rsp = (dns_ptr_record *)(Result + Length);
			memcpy(Result + Length + sizeof(dns_ptr_record), Parameter.LocalFQDN, Parameter.LocalFQDNLength);
			pdns_rsp->PTR = htons(DNS_QUERY_PTR);
			pdns_rsp->Classes = htons(DNS_CLASS_IN); //Class IN
			pdns_rsp->TTL = htonl(Parameter.HostsDefaultTTL);
			pdns_rsp->Type = htons(DNS_RECORD_PTR);
			pdns_rsp->Length = htons((uint16_t)Parameter.LocalFQDNLength);
			return Length + sizeof(dns_ptr_record) + Parameter.LocalFQDNLength;
*/
//			pdns_hdr->Flags = htons(DNS_SQR_NEA);
			pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8400); //Set 1000100000000000, DNS_SQR_NEA
			pdns_hdr->Answer = htons(U16_NUM_ONE);

		//EDNS0 Label
			if (Parameter.EDNS0Label)
			{
				auto pdns_opt_record = (dns_opt_record *)(Result + Length - sizeof(dns_opt_record));
				if (pdns_hdr->Additional > 0 && pdns_opt_record->Type == htons(DNS_RECORD_OPT))
				{
					memset(Result + Length - sizeof(dns_opt_record), 0, sizeof(dns_opt_record));
					memcpy(Result + Length - sizeof(dns_opt_record), Parameter.LocalServerResponse, Parameter.LocalServerResponseLength);

					return Length - sizeof(dns_opt_record) + Parameter.LocalServerResponseLength;
				}
			}

			memcpy(Result + Length, Parameter.LocalServerResponse, Parameter.LocalServerResponseLength);
			return Length + Parameter.LocalServerResponseLength;
		}
	}

//LocalFQDN check
	if (*Parameter.LocalFQDNString == Domain)
	{
		if (pdns_qry->Type == htons(DNS_RECORD_AAAA))
		{
			std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[0]);
			if (Parameter.LocalAddressLength[0] >= DNS_PACKET_MINSIZE)
			{
				memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
				memcpy(Result + sizeof(uint16_t), Parameter.LocalAddress[0] + sizeof(uint16_t), Parameter.LocalAddressLength[0] - sizeof(uint16_t));
				return Parameter.LocalAddressLength[0];
			}
		}
		else if (pdns_qry->Type == htons(DNS_RECORD_A))
		{
			std::unique_lock<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[1U]);
			if (Parameter.LocalAddressLength[1U] >= DNS_PACKET_MINSIZE)
			{
				memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
				memcpy(Result + sizeof(uint16_t), Parameter.LocalAddress[1U] + sizeof(uint16_t), Parameter.LocalAddressLength[1U] - sizeof(uint16_t));
				return Parameter.LocalAddressLength[1U];
			}
		}
	}

//Main check
	std::unique_lock<std::mutex> HostsListMutex(HostsListLock);
	for (auto HostsTableIter:*HostsListUsing)
	{
		if (std::regex_match(Domain, HostsTableIter.Pattern))
		{
		//Check white list.
			if (HostsTableIter.Type == HOSTS_WHITE)
			{
				break;
			}
		//Check local request.
			else if (HostsTableIter.Type == HOSTS_LOCAL)
			{
				IsLocal = true;
				break;
			}
		//Check banned list.
			else if (HostsTableIter.Type == HOSTS_BANNED)
			{
//				pdns_hdr->Flags = htons(DNS_SQR_SNH);
				pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8003); //Set 1000000000000011, DNS_SQR_SNH
				return Length;
			}
		//Check Hosts.
			else {
			//IPv6
				if (pdns_qry->Type == htons(DNS_RECORD_AAAA) && HostsTableIter.Protocol == AF_INET6)
				{
				//EDNS0 Lebal
					if (pdns_hdr->Additional == htons(U16_NUM_ONE))
					{
						memset(Result + Length - sizeof(dns_opt_record), 0, sizeof(dns_opt_record));
//						pdns_hdr->Flags = htons(DNS_SQR_NE);
						pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8000); //Set 1000000000000000, DNS_SQR_NE
						pdns_hdr->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_aaaa_record)));
						memcpy(Result + Length - sizeof(dns_opt_record), HostsTableIter.Response.get(), HostsTableIter.Length);

					//Hosts load balancing
						if (ntohs(pdns_hdr->Answer) > U16_NUM_ONE)
						{
							std::shared_ptr<dns_aaaa_record> DNS_AAAA_Temp(new dns_aaaa_record());

						//Select a ramdom preferred result.
							std::uniform_int_distribution<int> RamdomDistribution(0, ntohs(pdns_hdr->Answer) - 1U);
							size_t RamdomIndex = RamdomDistribution(*Parameter.RamdomEngine);
							if (RamdomIndex > 0)
							{
								memcpy(DNS_AAAA_Temp.get(), Result + Length - sizeof(dns_opt_record), sizeof(dns_aaaa_record));
								memset(Result + Length - sizeof(dns_opt_record), 0, sizeof(dns_aaaa_record));
								memcpy(Result + Length - sizeof(dns_opt_record), Result + Length - sizeof(dns_opt_record) + sizeof(dns_aaaa_record) * RamdomIndex, sizeof(dns_aaaa_record));
								memset(Result + Length - sizeof(dns_opt_record) + sizeof(dns_aaaa_record) * RamdomIndex, 0, sizeof(dns_aaaa_record));
								memcpy(Result + Length - sizeof(dns_opt_record) + sizeof(dns_aaaa_record) * RamdomIndex, DNS_AAAA_Temp.get(), sizeof(dns_aaaa_record));
							}
						}

					//Different result.
						if (!Parameter.EDNS0Label)
						{
							auto pdns_opt_record = (dns_opt_record *)(Result + Length - sizeof(dns_opt_record) + HostsTableIter.Length);
							pdns_opt_record->Type = htons(DNS_RECORD_OPT);
							pdns_opt_record->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);

						//DNSSEC
							if (Parameter.DNSSECRequest)
								pdns_opt_record->Z_Bits.DO = ~pdns_opt_record->Z_Bits.DO; //Accepts DNSSEC security Resource Records

							return Length + HostsTableIter.Length;
						}
						else {
							return Length - sizeof(dns_opt_record) + HostsTableIter.Length;
						}
					}
					else {
//						pdns_hdr->Flags = htons(DNS_SQR_NE);
						pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8000); //Set 1000000000000000, DNS_SQR_NE
						pdns_hdr->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_aaaa_record)));
						memcpy(Result + Length, HostsTableIter.Response.get(), HostsTableIter.Length);
						
					//Hosts load balancing
						if (ntohs(pdns_hdr->Answer) > U16_NUM_ONE)
						{
							std::shared_ptr<dns_aaaa_record> DNS_AAAA_Temp(new dns_aaaa_record());

						//Select a ramdom preferred result.
							std::uniform_int_distribution<int> RamdomDistribution(0, ntohs(pdns_hdr->Answer) - 1U);
							size_t RamdomIndex = RamdomDistribution(*Parameter.RamdomEngine);
							if (RamdomIndex > 0)
							{
								memcpy(DNS_AAAA_Temp.get(), Result + Length, sizeof(dns_aaaa_record));
								memset(Result + Length, 0, sizeof(dns_aaaa_record));
								memcpy(Result + Length, Result + Length + sizeof(dns_aaaa_record) * RamdomIndex, sizeof(dns_aaaa_record));
								memset(Result + Length + sizeof(dns_aaaa_record) * RamdomIndex, 0, sizeof(dns_aaaa_record));
								memcpy(Result + Length + sizeof(dns_aaaa_record) * RamdomIndex, DNS_AAAA_Temp.get(), sizeof(dns_aaaa_record));
							}
						}

						return Length + HostsTableIter.Length;
					}
				}
				else if (pdns_qry->Type == htons(DNS_RECORD_A) && HostsTableIter.Protocol == AF_INET)
				{
				//EDNS0 Lebal
					if (pdns_hdr->Additional == htons(U16_NUM_ONE))
					{
						memset(Result + Length - sizeof(dns_opt_record), 0, sizeof(dns_opt_record));
//						pdns_hdr->Flags = htons(DNS_SQR_NE);
						pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8000); //Set 1000000000000000, DNS_SQR_NE
						pdns_hdr->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_a_record)));
						memcpy(Result + Length - sizeof(dns_opt_record), HostsTableIter.Response.get(), HostsTableIter.Length);

					//Hosts load balancing
						if (ntohs(pdns_hdr->Answer) > U16_NUM_ONE)
						{
							std::shared_ptr<dns_a_record> DNS_A_Temp(new dns_a_record());

						//Select a ramdom preferred result.
							std::uniform_int_distribution<int> RamdomDistribution(0, ntohs(pdns_hdr->Answer) - 1U);
							size_t RamdomIndex = RamdomDistribution(*Parameter.RamdomEngine);
							if (RamdomIndex > 0)
							{
								memcpy(DNS_A_Temp.get(), Result + Length - sizeof(dns_opt_record), sizeof(dns_a_record));
								memset(Result + Length - sizeof(dns_opt_record), 0, sizeof(dns_a_record));
								memcpy(Result + Length - sizeof(dns_opt_record), Result + Length - sizeof(dns_opt_record) + sizeof(dns_a_record) * RamdomIndex, sizeof(dns_a_record));
								memset(Result + Length - sizeof(dns_opt_record) + sizeof(dns_a_record) * RamdomIndex, 0, sizeof(dns_a_record));
								memcpy(Result + Length - sizeof(dns_opt_record) + sizeof(dns_a_record) * RamdomIndex, DNS_A_Temp.get(), sizeof(dns_a_record));
							}
						}

					//Different result.
						if (!Parameter.EDNS0Label)
						{
							auto pdns_opt_record = (dns_opt_record *)(Result + Length - sizeof(dns_opt_record) + HostsTableIter.Length);
							pdns_opt_record->Type = htons(DNS_RECORD_OPT);
							pdns_opt_record->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);

						//DNSSEC
							if (Parameter.DNSSECRequest)
								pdns_opt_record->Z_Bits.DO = ~pdns_opt_record->Z_Bits.DO; //Accepts DNSSEC security Resource Records

							return Length + HostsTableIter.Length;
						}
						else {
							return Length - sizeof(dns_opt_record) + HostsTableIter.Length;
						}
					}
					else {
//						pdns_hdr->Flags = htons(DNS_SQR_NE);
						pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8000); //Set 1000000000000000, DNS_SQR_NE
						pdns_hdr->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_a_record)));
						memcpy(Result + Length, HostsTableIter.Response.get(), HostsTableIter.Length);

					//Hosts load balancing
						if (ntohs(pdns_hdr->Answer) > U16_NUM_ONE)
						{
							std::shared_ptr<dns_a_record> DNS_A_Temp(new dns_a_record());

						//Select a ramdom preferred result.
							std::uniform_int_distribution<int> RamdomDistribution(0, ntohs(pdns_hdr->Answer) - 1U);
							size_t RamdomIndex = RamdomDistribution(*Parameter.RamdomEngine);
							if (RamdomIndex > 0)
							{
								memcpy(DNS_A_Temp.get(), Result + Length, sizeof(dns_a_record));
								memset(Result + Length, 0, sizeof(dns_a_record));
								memcpy(Result + Length, Result + Length + sizeof(dns_a_record) * RamdomIndex, sizeof(dns_a_record));
								memset(Result + Length + sizeof(dns_a_record) * RamdomIndex, 0, sizeof(dns_a_record));
								memcpy(Result + Length + sizeof(dns_a_record) * RamdomIndex, DNS_A_Temp.get(), sizeof(dns_a_record));
							}
						}

						return Length + HostsTableIter.Length;
					}
				}
			}
		}
	}
	HostsListMutex.unlock();

//Check Cache.
	std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	for (auto DNSCacheIter:DNSCacheList)
	{
		if (Domain == DNSCacheIter.Domain && pdns_qry->Type == DNSCacheIter.Type)
//			(pdns_qry->Type == htons(DNS_RECORD_AAAA) && DNSCacheIter.Protocol == AF_INET6 || 
//			pdns_qry->Type == htons(DNS_RECORD_A) && DNSCacheIter.Protocol == AF_INET))
		{
			memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
			memcpy(Result + sizeof(uint16_t), DNSCacheIter.Response.get(), DNSCacheIter.Length);
			return DNSCacheIter.Length + sizeof(uint16_t);
		}
	}
	DNSCacheListMutex.unlock();

//Domain Case Conversion
	if (Parameter.DomainCaseConversion)
		MakeDomainCaseConversion(OriginalRequest + sizeof(dns_hdr));
	
	memset(Result, 0, ResultSize);
	return EXIT_SUCCESS;
}

//Request Process(Local part)
inline size_t __fastcall LocalRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData)
{
	size_t DataLength = 0;

//TCP Mode
	if (Parameter.RequestMode == REQUEST_TCPMODE)
	{
		if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, true, AlternateSwapList.IsSwap[4U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[4U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[4U]++;
		}
		else { //IPv4
			DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, true, AlternateSwapList.IsSwap[5U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[5U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[5U]++;
		}

	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE && DataLength < LARGE_PACKET_MAXSIZE)
		{
			SendToRequester(OriginalRecv, DataLength, Protocol, TargetData);
			return EXIT_SUCCESS;
		}
	}
		
//UDP Mode(REQUEST_UDPMODE)
	if (Protocol == IPPROTO_TCP) //TCP requesting
	{
		if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, true, AlternateSwapList.IsSwap[6U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[6U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[6U]++;
		}
		else { //IPv4
			DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, true, AlternateSwapList.IsSwap[7U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[7U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[7U]++;
		}
	}
//UDP requesting
	else {
		if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, true, AlternateSwapList.IsSwap[6U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[6U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[6U]++;
		}
		else { //IPv4
			DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, true, AlternateSwapList.IsSwap[7U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[7U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[7U]++;
		}
	}
		
//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && (DataLength < PACKET_MAXSIZE || Protocol == IPPROTO_TCP && DataLength < LARGE_PACKET_MAXSIZE))
	{
		SendToRequester(OriginalRecv, DataLength, Protocol, TargetData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(Direct connections part)
inline size_t __fastcall DirectRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData)
{
	size_t DataLength = 0;

//TCP Mode
	if (Parameter.RequestMode == REQUEST_TCPMODE)
	{
	//Multi requesting.
		if (Parameter.AlternateMultiRequest)
		{
/* Old version(2014-12-09)
		//Initialization
			std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
			std::mutex MultiRequestingLock;
			TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER TCPRequestParameter = {Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, 1U, 0};

		//All server(including Alternate) Multi Request
			if (Parameter.AlternateMultiRequest)
			{
				if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				{
					std::vector<std::thread> MultiRequestingTemp((Parameter.DNSTarget.IPv6_Multi->size() + 2U) * Parameter.MultiRequestTimes);
					MultiRequestingTemp.swap(MultiRequesting);

				//Start threads.
					for (size_t MultiIndex = 0;MultiIndex < Parameter.DNSTarget.IPv6_Multi->size() + 2U;MultiIndex++)
					{
						for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
						{
							std::thread TCPRequestThread(TCPRequestMulti, std::ref(TCPRequestParameter), std::ref(MultiRequestingLock));
							MultiRequesting[MultiIndex * Parameter.MultiRequestTimes + InnerIndex].swap(TCPRequestThread);
						}

						TCPRequestParameter.ServerIndex++;
					}
				}
				else { //IPv4
					std::vector<std::thread> MultiRequestingTemp((Parameter.DNSTarget.IPv4_Multi->size() + 2U) * Parameter.MultiRequestTimes);
					MultiRequestingTemp.swap(MultiRequesting);

				//Start threads.
					for (size_t MultiIndex = 0;MultiIndex < Parameter.DNSTarget.IPv4_Multi->size() + 2U;MultiIndex++)
					{
						for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
						{
							std::thread TCPRequestThread(TCPRequestMulti, std::ref(TCPRequestParameter), std::ref(MultiRequestingLock));
							MultiRequesting[MultiIndex * Parameter.MultiRequestTimes + InnerIndex].swap(TCPRequestThread);
						}

						TCPRequestParameter.ServerIndex++;
					}
				}
			}
			else {
				if (TargetData.AddrLen == sizeof(sockaddr_in6) && AlternateSwapList.IsSwap[0] || //IPv6
					TargetData.AddrLen == sizeof(sockaddr_in) && AlternateSwapList.IsSwap[1U]) //IPv4
						TCPRequestParameter.ServerIndex = 2U;

			//Start threads
				for (size_t MultiIndex = 0;MultiIndex < MultiRequesting.size();MultiIndex++)
				{
					std::thread TCPRequestThread(TCPRequestMulti, std::ref(TCPRequestParameter), std::ref(MultiRequestingLock));
					MultiRequesting[MultiIndex].swap(TCPRequestThread);
				}
			}

		//Waiting for threads finish and send back.
			for (auto MultiRequestingIter = MultiRequesting.begin();MultiRequestingIter != MultiRequesting.end();MultiRequestingIter++)
			{
			//Send response.
				std::unique_lock<std::mutex> TCPMutex(MultiRequestingLock);
				if (TCPRequestParameter.ReturnValue >= DNS_PACKET_MINSIZE && TCPRequestParameter.ReturnValue < LARGE_PACKET_MAXSIZE)
				{
					SendToRequester(Send, SendSize, Recv, TCPRequestParameter.ReturnValue, Protocol, TargetData);
					TCPRequestParameter.ReturnValue = EXIT_FAILURE;
				}
				TCPMutex.unlock();

			//Waiting for all threads.
				if (MultiRequestingIter->joinable())
					MultiRequestingIter->join();

			//Return.
				if (MultiRequestingIter + 1U == MultiRequesting.end() && TCPRequestParameter.ReturnValue == EXIT_FAILURE)
					return EXIT_SUCCESS;
*/
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false);
			else  //IPv4
				DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false);
		}
	//Normal requesting
		else {
			if (Parameter.MultiRequestTimes > 1U)
			{
				if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
					DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[0]);
				else //IPv4
					DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[1U]);
			}
			else {
				if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
					DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false, AlternateSwapList.IsSwap[0]);
				else //IPv4
					DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false, AlternateSwapList.IsSwap[1U]);
			}
		}

	//Check timeout.
		if (DataLength == WSAETIMEDOUT)
		{
			if (TargetData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.IsSwap[0] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[0]++;
			else if (TargetData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.IsSwap[1U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[1U]++;
		}

	//Send response.
		else if (DataLength >= DNS_PACKET_MINSIZE && DataLength < LARGE_PACKET_MAXSIZE)
		{
			SendToRequester(OriginalRecv, DataLength, Protocol, TargetData);
			return EXIT_SUCCESS;
		}
	}

//UDP Mode(REQUEST_UDPMODE)
	//Multi requesting.
	if (Parameter.AlternateMultiRequest)
	{
/* Old version(2014-12-09)
	//Initialization
		std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
		std::mutex MultiRequestingLock;
		TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER UDPRequestParameter = {Send, SendSize, Recv, 0, TargetData, 1U, 0};
		if (Protocol == IPPROTO_TCP) //TCP requesting
			UDPRequestParameter.RecvSize = LARGE_PACKET_MAXSIZE - sizeof(uint16_t);
		else //UDP requesting
			UDPRequestParameter.RecvSize = PACKET_MAXSIZE;

	//All server(including Alternate) Multi Request
		if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			std::vector<std::thread> MultiRequestingTemp((Parameter.DNSTarget.IPv6_Multi->size() + 2U) * Parameter.MultiRequestTimes);
			MultiRequestingTemp.swap(MultiRequesting);

		//Start threads.
			for (size_t MultiIndex = 0;MultiIndex < Parameter.DNSTarget.IPv6_Multi->size() + 2U;MultiIndex++)
			{
				for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
				{
					std::thread UDPRequestThread(UDPCompleteRequestMulti, std::ref(UDPRequestParameter), std::ref(MultiRequestingLock));
					MultiRequesting[MultiIndex * Parameter.MultiRequestTimes + InnerIndex].swap(UDPRequestThread);
				}

				UDPRequestParameter.ServerIndex++;
			}
		}
		else { //IPv4
			std::vector<std::thread> MultiRequestingTemp((Parameter.DNSTarget.IPv4_Multi->size() + 2U) * Parameter.MultiRequestTimes);
			MultiRequestingTemp.swap(MultiRequesting);

		//Start threads.
			for (size_t MultiIndex = 0;MultiIndex < Parameter.DNSTarget.IPv4_Multi->size() + 2U;MultiIndex++)
			{
				for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
				{
					std::thread UDPRequestThread(UDPCompleteRequestMulti, std::ref(UDPRequestParameter), std::ref(MultiRequestingLock));
					MultiRequesting[MultiIndex * Parameter.MultiRequestTimes + InnerIndex].swap(UDPRequestThread);
				}

				UDPRequestParameter.ServerIndex++;
			}
		}
	}
	else {
		if (TargetData.AddrLen == sizeof(sockaddr_in6) && AlternateSwapList.IsSwap[2U] || //IPv6
			TargetData.AddrLen == sizeof(sockaddr_in) && AlternateSwapList.IsSwap[3U]) //IPv4
				UDPRequestParameter.ServerIndex = 2U;

	//Start threads.
		for (size_t MultiIndex = 0;MultiIndex < MultiRequesting.size();MultiIndex++)
		{
			std::thread UDPRequestThread(UDPCompleteRequestMulti, std::ref(UDPRequestParameter), std::ref(MultiRequestingLock));
			MultiRequesting[MultiIndex].swap(UDPRequestThread);
		}
	}

//Waiting for threads finish and send back.
	for (auto MultiRequestingIter = MultiRequesting.begin();MultiRequestingIter != MultiRequesting.end();MultiRequestingIter++)
	{
	//Send response.
		std::unique_lock<std::mutex> UDPMutex(MultiRequestingLock);
		if (UDPRequestParameter.ReturnValue >= DNS_PACKET_MINSIZE && UDPRequestParameter.ReturnValue < LARGE_PACKET_MAXSIZE)
		{
			SendToRequester( /* Send, SendSize, Recv, UDPRequestParameter.ReturnValue, Protocol, TargetData);
			UDPRequestParameter.ReturnValue = EXIT_FAILURE;
		}
		UDPMutex.unlock();

	//Waiting for all threads.
		if (MultiRequestingIter->joinable())
			MultiRequestingIter->join();

	//Return.
		if (MultiRequestingIter + 1U == MultiRequesting.end() && UDPRequestParameter.ReturnValue == EXIT_FAILURE)
			return EXIT_SUCCESS;
	}
*/
		if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			if (Protocol == IPPROTO_TCP) //TCP requesting
				DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false);
			else //UDP requesting
				DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, false);
		}
		else { //IPv4
			if (Protocol == IPPROTO_TCP) //TCP requesting
				DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false);
			else //UDP requesting
				DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, false);
		}
	}
//Normal requesting
	else {
		if (Parameter.MultiRequestTimes > 1U)
		{
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				if (Protocol == IPPROTO_TCP) //TCP requesting
					DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[2U]);
				else //UDP requesting
					DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, AlternateSwapList.IsSwap[2U]);
			}
			else { //IPv4
				if (Protocol == IPPROTO_TCP) //TCP requesting
					DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[3U]);
				else //UDP requesting
					DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, AlternateSwapList.IsSwap[3U]);
			}
		}
		else {
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				if (Protocol == IPPROTO_TCP) //TCP requesting
					DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false, AlternateSwapList.IsSwap[2U]);
				else //UDP requesting
					DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, false, AlternateSwapList.IsSwap[2U]);
			}
			else { //IPv4
				if (Protocol == IPPROTO_TCP) //TCP requesting
					DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false, AlternateSwapList.IsSwap[3U]);
				else //UDP requesting
					DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, false, AlternateSwapList.IsSwap[3U]);
			}
		}
	}

//Check timeout.
	if (DataLength == WSAETIMEDOUT)
	{
		if (TargetData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.IsSwap[2U] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[2U]++;
		else if (TargetData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.IsSwap[3U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[3U]++;
	}

//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && (DataLength < PACKET_MAXSIZE || Protocol == IPPROTO_TCP && DataLength < LARGE_PACKET_MAXSIZE))
	{
		SendToRequester(OriginalRecv, DataLength, Protocol, TargetData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(DNSCurve part)
inline size_t __fastcall DNSCurveRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData)
{
	size_t DataLength = 0;

//TCP requesting
	if (DNSCurveParameter.DNSCurveMode == DNSCURVE_REQUEST_TCPMODE)
	{
	//Multi requesting.
		if (Parameter.AlternateMultiRequest)
		{
/* Old version(2015-01-13)
		//Initialization
			std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
			std::mutex MultiRequestingLock;
			DNSCURVE_REQUEST_MULTITHREAD_PARAMETER DNSCurveRequestParameter = {OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false, DNSCurveParameter.IsEncryption, 0};
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				DNSCurveRequestParameter.Alternate = AlternateSwapList.IsSwap[8U];
			else //IPv4
				DNSCurveRequestParameter.Alternate = AlternateSwapList.IsSwap[9U];

		//Start threads.
			for (size_t MultiIndex = 0;MultiIndex < MultiRequesting.size();MultiIndex++)
			{
				std::thread DNSCurveTCPRequestThread(DNSCurveTCPRequestMulti, std::ref(DNSCurveRequestParameter), std::ref(MultiRequestingLock));
				MultiRequesting[MultiIndex].swap(DNSCurveTCPRequestThread);
			}

		//Waiting for threads finish and send back.
			for (auto MultiRequestingIter = MultiRequesting.begin();MultiRequestingIter != MultiRequesting.end();MultiRequestingIter++)
			{
			//Send response.
				std::unique_lock<std::mutex> DNSCurveMutex(MultiRequestingLock);
				if (DNSCurveRequestParameter.ReturnValue >= DNS_PACKET_MINSIZE && DNSCurveRequestParameter.ReturnValue < PACKET_MAXSIZE)
				{
					SendToRequester(Send, SendSize, OriginalRecv, DNSCurveRequestParameter.ReturnValue, Protocol, TargetData);
					DNSCurveRequestParameter.ReturnValue = EXIT_FAILURE;
				}
				DNSCurveMutex.unlock();

			//Waiting for all threads.
				if (MultiRequestingIter->joinable())
					MultiRequestingIter->join();

			//Return.
				if (MultiRequestingIter + 1U == MultiRequesting.end() && DNSCurveRequestParameter.ReturnValue == EXIT_FAILURE)
					return EXIT_SUCCESS;
			}
*/
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				DataLength = DNSCurveTCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false);
			else  //IPv4
				DataLength = DNSCurveTCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false);
		}
	//Normal requesting
		else {
			if (Parameter.MultiRequestTimes > 1U)
			{
				if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
					DataLength = DNSCurveTCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[8U]);
				else //IPv4
					DataLength = DNSCurveTCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[9U]);
			}
			else {
				if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
					DataLength = DNSCurveTCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[8U]);
				else //IPv4
					DataLength = DNSCurveTCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[9U]);
			}
		}

	//Check timeout.
		if (DataLength == WSAETIMEDOUT)
		{
			if (TargetData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.IsSwap[0] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[8U]++;
			else if (TargetData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.IsSwap[1U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[9U]++;
		}

	//Send response.
		else if (DataLength >= DNS_PACKET_MINSIZE && DataLength < LARGE_PACKET_MAXSIZE)
		{
			SendToRequester(OriginalRecv, DataLength, Protocol, TargetData);
			return EXIT_SUCCESS;
		}
	}

//UDP Mode(REQUEST_UDPMODE)
	//Multi requesting.
	if (Parameter.AlternateMultiRequest)
	{
/* Old version(2015-01-13)
	//Initialization
		std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
		std::mutex MultiRequestingLock;
		DNSCURVE_REQUEST_MULTITHREAD_PARAMETER DNSCurveRequestParameter = {OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, false, DNSCurveParameter.IsEncryption, 0};
		if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			DNSCurveRequestParameter.Alternate = AlternateSwapList.IsSwap[10U];
		else //IPv4
			DNSCurveRequestParameter.Alternate = AlternateSwapList.IsSwap[11U];

	//Start threads.
		for (size_t MultiIndex = 0;MultiIndex < MultiRequesting.size();MultiIndex++)
		{
			std::thread DNSCurveUDPRequestThread(DNSCurveUDPRequestMulti, std::ref(DNSCurveRequestParameter), std::ref(MultiRequestingLock));
			MultiRequesting[MultiIndex].swap(DNSCurveUDPRequestThread);
		}

	//Waiting for threads finish and send back.
		for (auto MultiRequestingIter = MultiRequesting.begin();MultiRequestingIter != MultiRequesting.end();MultiRequestingIter++)
		{
		//Send response.
			std::unique_lock<std::mutex> DNSCurveMutex(MultiRequestingLock);
			if (DNSCurveRequestParameter.ReturnValue >= DNS_PACKET_MINSIZE && DNSCurveRequestParameter.ReturnValue < PACKET_MAXSIZE)
			{
				SendToRequester(Send, SendSize, OriginalRecv, DNSCurveRequestParameter.ReturnValue, Protocol, TargetData);
				DNSCurveRequestParameter.ReturnValue = EXIT_FAILURE;
			}
			DNSCurveMutex.unlock();

		//Waiting for all threads.
			if (MultiRequestingIter->joinable())
				MultiRequestingIter->join();

		//Return.
			if (MultiRequestingIter + 1U == MultiRequesting.end() && DNSCurveRequestParameter.ReturnValue == EXIT_FAILURE)
				return EXIT_SUCCESS;
		}
*/
		if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			if (Protocol == IPPROTO_TCP) //TCP requesting
				DataLength = DNSCurveUDPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false);
			else //UDP requesting
				DataLength = DNSCurveUDPRequestMulti(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, false);
		}
		else { //IPv4
			if (Protocol == IPPROTO_TCP) //TCP requesting
				DataLength = DNSCurveUDPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false);
			else //UDP requesting
				DataLength = DNSCurveUDPRequestMulti(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, false);
		}
	}
	//Normal requesting
	else {
		if (Parameter.MultiRequestTimes > 1U)
		{
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				if (Protocol == IPPROTO_TCP) //TCP requesting
					DataLength = DNSCurveUDPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[10U]);
				else //UDP requesting
					DataLength = DNSCurveUDPRequestMulti(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, AlternateSwapList.IsSwap[10U]);
			}
			else { //IPv4
				if (Protocol == IPPROTO_TCP) //TCP requesting
					DataLength = DNSCurveUDPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[11U]);
				else //UDP requesting
					DataLength = DNSCurveUDPRequestMulti(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, AlternateSwapList.IsSwap[11U]);
			}
		}
		else {
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				if (Protocol == IPPROTO_TCP) //TCP requesting
					DataLength = DNSCurveUDPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[10U]);
				else //UDP requesting
					DataLength = DNSCurveUDPRequest(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, AlternateSwapList.IsSwap[10U]);
			}
			else { //IPv4
				if (Protocol == IPPROTO_TCP) //TCP requesting
					DataLength = DNSCurveUDPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[11U]);
				else //UDP requesting
					DataLength = DNSCurveUDPRequest(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, TargetData, AlternateSwapList.IsSwap[11U]);
			}
		}
	}

//Check timeout.
	if (DataLength == WSAETIMEDOUT)
	{
		if (TargetData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.IsSwap[10U] && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[10U]++;
		else if (TargetData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.IsSwap[11U] && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[11U]++;
	}

//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && (DataLength < PACKET_MAXSIZE || Protocol == IPPROTO_TCP && DataLength < LARGE_PACKET_MAXSIZE))
	{
		SendToRequester(OriginalRecv, DataLength, Protocol, TargetData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(TCP part)
inline size_t __fastcall TCPRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData)
{
	size_t DataLength = 0;

//Multi requesting.
	if (Parameter.AlternateMultiRequest)
	{
/* Old version(2014-12-09)
	//Initialization
		std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
		std::mutex MultiRequestingLock;
		TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER TCPRequestParameter = {Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, 1U, 0};

	//All server(including Alternate) Multi Request
		if (Parameter.AlternateMultiRequest)
		{
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				std::vector<std::thread> MultiRequestingTemp((Parameter.DNSTarget.IPv6_Multi->size() + 2U) * Parameter.MultiRequestTimes);
				MultiRequestingTemp.swap(MultiRequesting);

			//Start threads.
				for (size_t MultiIndex = 0;MultiIndex < Parameter.DNSTarget.IPv6_Multi->size() + 2U;MultiIndex++)
				{
					for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
					{
						std::thread TCPRequestThread(TCPRequestMulti, std::ref(TCPRequestParameter), std::ref(MultiRequestingLock));
						MultiRequesting[MultiIndex * Parameter.MultiRequestTimes + InnerIndex].swap(TCPRequestThread);
					}

					TCPRequestParameter.ServerIndex++;
				}
			}
			else { //IPv4
				std::vector<std::thread> MultiRequestingTemp((Parameter.DNSTarget.IPv4_Multi->size() + 2U) * Parameter.MultiRequestTimes);
				MultiRequestingTemp.swap(MultiRequesting);

			//Start threads.
				for (size_t MultiIndex = 0;MultiIndex < Parameter.DNSTarget.IPv4_Multi->size() + 2U;MultiIndex++)
				{
					for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
					{
						std::thread TCPRequestThread(TCPRequestMulti, std::ref(TCPRequestParameter), std::ref(MultiRequestingLock));
						MultiRequesting[MultiIndex * Parameter.MultiRequestTimes + InnerIndex].swap(TCPRequestThread);
					}

					TCPRequestParameter.ServerIndex++;
				}
			}
		}
		else {
			if (TargetData.AddrLen == sizeof(sockaddr_in6) && AlternateSwapList.IsSwap[0] || //IPv6
				TargetData.AddrLen == sizeof(sockaddr_in) && AlternateSwapList.IsSwap[1U]) //IPv4
					TCPRequestParameter.ServerIndex = 2U;

		//Start threads.
			for (size_t MultiIndex = 0;MultiIndex < MultiRequesting.size();MultiIndex++)
			{
				std::thread TCPRequestThread(TCPRequestMulti, std::ref(TCPRequestParameter), std::ref(MultiRequestingLock));
				MultiRequesting[MultiIndex].swap(TCPRequestThread);
			}
		}

	//Waiting for threads finish and send back.
		for (auto MultiRequestingIter = MultiRequesting.begin();MultiRequestingIter != MultiRequesting.end();MultiRequestingIter++)
		{
		//Send response.
			std::unique_lock<std::mutex> TCPMutex(MultiRequestingLock);
			if (TCPRequestParameter.ReturnValue >= DNS_PACKET_MINSIZE && TCPRequestParameter.ReturnValue < PACKET_MAXSIZE)
			{
				SendToRequester(Send, SendSize, Recv, TCPRequestParameter.ReturnValue, Protocol, TargetData);
				TCPRequestParameter.ReturnValue = EXIT_FAILURE;
			}
			TCPMutex.unlock();

		//Waiting for all threads.
			if (MultiRequestingIter->joinable())
				MultiRequestingIter->join();

		//Return.
			if (MultiRequestingIter + 1U == MultiRequesting.end() && TCPRequestParameter.ReturnValue == EXIT_FAILURE)
				return EXIT_SUCCESS;

		}
*/
		if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false);
		else  //IPv4
			DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false);
	}
//Normal requesting
	else {
		if (Parameter.MultiRequestTimes > 1U)
		{
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[0]);
			else //IPv4
				DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, AlternateSwapList.IsSwap[1U]);
		}
		else {
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false, AlternateSwapList.IsSwap[0]);
			else //IPv4
				DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), TargetData, false, AlternateSwapList.IsSwap[1U]);
		}
	}

//Check timeout.
	if (DataLength == WSAETIMEDOUT)
	{
		if (TargetData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.IsSwap[0] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[0]++;
		else if (TargetData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.IsSwap[1U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[1U]++;
	}

//Send response.
	if (DataLength >= sizeof(uint16_t) + DNS_PACKET_MINSIZE && DataLength < LARGE_PACKET_MAXSIZE)
	{
	//EDNS0 Label
		auto pdns_hdr = (dns_hdr *)OriginalSend;
		if (Protocol == IPPROTO_UDP && pdns_hdr->Additional > 0)
		{
			pdns_hdr = (dns_hdr *)OriginalRecv;
			pdns_hdr->Additional = htons(U16_NUM_ONE);
			auto pdns_opt_record = (dns_opt_record *)(OriginalRecv + DataLength);
			pdns_opt_record->Type = htons(DNS_RECORD_OPT);
			pdns_opt_record->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);

		//DNSSEC
			if (Parameter.DNSSECRequest)
			{
				pdns_hdr->FlagsBits.AD = ~pdns_hdr->FlagsBits.AD; //Local DNSSEC Server validate
				pdns_hdr->FlagsBits.CD = ~pdns_hdr->FlagsBits.CD; //Client validate
				pdns_opt_record->Z_Bits.DO = ~pdns_opt_record->Z_Bits.DO; //Accepts DNSSEC security Resource Records
			}

			DataLength += sizeof(dns_opt_record);
		}

		SendToRequester(OriginalRecv, DataLength, Protocol, TargetData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(UDP part)
inline size_t __fastcall UDPRequestProcess(const PSTR OriginalSend, const size_t SendSize, const uint16_t Protocol, const SOCKET_DATA TargetData, const size_t ListIndex)
{
//Mark requesting data
	PortList.RecvData[ListIndex] = TargetData;
	PortList.SendData[ListIndex].clear();

//Multi requesting.
	if (Parameter.AlternateMultiRequest)
	{
/* Old version(2014-12-09)
	//Initialization
		std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
		UDP_REQUEST_MULTITHREAD_PARAMETER UDPRequestParameter = {Send, SendSize, TargetData, Index, 1U};

	//All server(including Alternate) Multi Request
		if (Parameter.AlternateMultiRequest)
		{
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				std::vector<std::thread> MultiRequestingTemp((Parameter.DNSTarget.IPv6_Multi->size() + 2U) * Parameter.MultiRequestTimes);
				MultiRequestingTemp.swap(MultiRequesting);

			//Start threads.
				for (size_t MultiIndex = 0;MultiIndex < Parameter.DNSTarget.IPv6_Multi->size() + 2U;MultiIndex++)
				{
					for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
					{
						std::thread UDPRequestThread(UDPRequestMulti, UDPRequestParameter);
						MultiRequesting[MultiIndex * Parameter.MultiRequestTimes + InnerIndex].swap(UDPRequestThread);
					}

					UDPRequestParameter.ServerIndex++;
				}
			}
			else { //IPv4
				std::vector<std::thread> MultiRequestingTemp((Parameter.DNSTarget.IPv4_Multi->size() + 2U) * Parameter.MultiRequestTimes);
				MultiRequestingTemp.swap(MultiRequesting);

			//Start threads.
				for (size_t MultiIndex = 0;MultiIndex < Parameter.DNSTarget.IPv4_Multi->size() + 2U;MultiIndex++)
				{
					for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
					{
						std::thread UDPRequestThread(UDPRequestMulti, UDPRequestParameter);
						MultiRequesting[MultiIndex * Parameter.MultiRequestTimes + InnerIndex].swap(UDPRequestThread);
					}

					UDPRequestParameter.ServerIndex++;
				}
			}
		}
		else {
			if (TargetData.AddrLen == sizeof(sockaddr_in6) && AlternateSwapList.IsSwap[2U] || //IPv6
				TargetData.AddrLen == sizeof(sockaddr_in) && AlternateSwapList.IsSwap[3U]) //IPv4
					UDPRequestParameter.ServerIndex = 2U;

		//Start threads.
			for (size_t InnerIndex = 0;InnerIndex < MultiRequesting.size();InnerIndex++)
			{
				std::thread UDPRequestThread(UDPRequestMulti, UDPRequestParameter);
				MultiRequesting[InnerIndex].swap(UDPRequestThread);
			}
		}

	//Waiting for threads finish and send back.
		for (auto MultiRequestingIter = MultiRequesting.begin();MultiRequestingIter != MultiRequesting.end();MultiRequestingIter++)
		{
			if (MultiRequestingIter->joinable())
				MultiRequestingIter->join();
		}
*/
		UDPRequestMulti(OriginalSend, SendSize, TargetData, ListIndex, false);
	}
//Normal requesting
	else {
		if (Parameter.MultiRequestTimes > 1U)
		{
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				UDPRequestMulti(OriginalSend, SendSize, TargetData, ListIndex, AlternateSwapList.IsSwap[2U]);
			else //IPv4
				UDPRequestMulti(OriginalSend, SendSize, TargetData, ListIndex, AlternateSwapList.IsSwap[3U]);
		}
		else {
			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				UDPRequest(OriginalSend, SendSize, TargetData, ListIndex, AlternateSwapList.IsSwap[2U]);
			else //IPv4
				UDPRequest(OriginalSend, SendSize, TargetData, ListIndex, AlternateSwapList.IsSwap[3U]);
		}
	}

//Fin TCP request connection.
	if (Protocol == IPPROTO_TCP && TargetData.Socket != INVALID_SOCKET)
		closesocket(TargetData.Socket);

	return EXIT_SUCCESS;
}

//Send responses to requester
inline size_t __fastcall SendToRequester(PSTR RecvBuffer, const size_t RecvSize, const uint16_t Protocol, const SOCKET_DATA TargetData)
{
//TCP
	if (Protocol == IPPROTO_TCP)
	{
		if (AddLengthToTCPDNSHeader(RecvBuffer, RecvSize, LARGE_PACKET_MAXSIZE) == EXIT_FAILURE)
		{
/* Old version(2014-11-18)
			auto pdns_hdr = (dns_hdr *)SendBuffer;
			pdns_hdr->Flags = htons(DNS_SQR_FE);
			send(TargetData.Socket, SendBuffer, (int)SendSize, NULL);
*/
			closesocket(TargetData.Socket);
			return EXIT_FAILURE;
		}

		send(TargetData.Socket, RecvBuffer, (int)(RecvSize + sizeof(uint16_t)), NULL);
		closesocket(TargetData.Socket);
	}
//UDP
	else {
		sendto(TargetData.Socket, RecvBuffer, (int)RecvSize, NULL, (PSOCKADDR)&TargetData.SockAddr, TargetData.AddrLen);
	}

	return EXIT_SUCCESS;
}

//Mark responses to domains Cache
size_t __fastcall MarkDomainCache(const PSTR Buffer, const size_t Length)
{
//Check conditions.
	auto pdns_hdr = (dns_hdr *)Buffer;
	if (pdns_hdr->Questions != htons(U16_NUM_ONE) || //No any Question Record in responses
		pdns_hdr->Answer == 0 && pdns_hdr->Authority == 0 && pdns_hdr->Additional == 0) //No any Resource Records 
			return EXIT_FAILURE; 

//Initialization(A part)
	DNSCacheData DNSCacheDataTemp;
	memset((PSTR)&DNSCacheDataTemp + sizeof(DNSCacheDataTemp.Domain) + sizeof(DNSCacheDataTemp.Response), 0, sizeof(DNSCacheData) - sizeof(DNSCacheDataTemp.Domain) - sizeof(DNSCacheDataTemp.Response));

//Mark DNS A records and AAAA records only.
	auto pdns_qry = (dns_qry *)(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer));
	uint32_t ResponseTTL = 0;

/* Old version(2015-01-14)
	if (pdns_qry->Type == htons(DNS_RECORD_AAAA))
	{
	//Check TTL.
		if (pdns_hdr->Answer > 0)
		{
			dns_aaaa_record *pdns_aaaa_record = nullptr;
			if (pdns_hdr->Additional > 0) //EDNS0 Label
				pdns_aaaa_record = (dns_aaaa_record *)(Buffer + (Length - sizeof(dns_opt_record) - sizeof(dns_aaaa_record)));
			else
				pdns_aaaa_record = (dns_aaaa_record *)(Buffer + (Length - sizeof(dns_aaaa_record)));
			ResponseTTL = ntohl(pdns_aaaa_record->TTL);
		}

		DNSCacheDataTemp.Protocol = AF_INET6;
	}
	else if (pdns_qry->Type == htons(DNS_RECORD_A))
	{
	//Check TTL.
		if (pdns_hdr->Answer > 0)
		{
			dns_a_record *pdns_a_record = nullptr;
			if (pdns_hdr->Additional > 0) //EDNS0 Label
				pdns_a_record = (dns_a_record *)(Buffer + (Length - sizeof(dns_opt_record) - sizeof(dns_a_record)));
			else
				pdns_a_record = (dns_a_record *)(Buffer + (Length - sizeof(dns_a_record)));
			ResponseTTL = ntohl(pdns_a_record->TTL);
		}

		DNSCacheDataTemp.Protocol = AF_INET;
	}
	else {
		return EXIT_FAILURE;
	}
*/
	DNSCacheDataTemp.Type = pdns_qry->Type;
	if (DNSCacheDataTemp.Type == htons(DNS_RECORD_AAAA) || DNSCacheDataTemp.Type != htons(DNS_RECORD_A))
	{
		size_t DataLength = DNS_PACKET_RR_LOCATE(Buffer);
		dns_standard_record *pdns_standard_record = nullptr;
		size_t TTLCount = 0;

	//Scan all results.
		for (size_t Index = 0;Index < (size_t)(ntohs(pdns_hdr->Answer) + ntohs(pdns_hdr->Authority) + ntohs(pdns_hdr->Additional));Index++)
		{
		//Resource Records Name(domain)
			DataLength += CheckDNSQueryNameLength(Buffer + DataLength) + 1U;
		//Length check
			if (DataLength > Length)
				break;

		//Standard Resource Records
			pdns_standard_record = (dns_standard_record *)(Buffer + DataLength);
			DataLength += sizeof(dns_standard_record);
		//Length check
			if (DataLength > Length)
				break;

		//Resource Records Data
			if (pdns_standard_record->Classes == htons(DNS_CLASS_IN) && pdns_standard_record->TTL > 0 &&
				(pdns_standard_record->Type == htons(DNS_RECORD_AAAA) && pdns_standard_record->Length == htons(sizeof(in6_addr)) ||
				pdns_standard_record->Type == htons(DNS_RECORD_A) && pdns_standard_record->Length == htons(sizeof(in_addr))))
			{
				ResponseTTL += ntohl(pdns_standard_record->TTL);
				TTLCount++;
			}

			DataLength += ntohs(pdns_standard_record->Length);
		//Length check
			if (DataLength > Length)
				break;
		}

		if (TTLCount > 0)
			ResponseTTL = ResponseTTL / (uint32_t)TTLCount + ResponseTTL % (uint32_t)TTLCount;
	}

//Set cache TTL.
	if (ResponseTTL == 0) //No any A or AAAA answers.
	{
		if (Parameter.CacheType == CACHE_TIMER)
			ResponseTTL = (uint32_t)(Parameter.CacheParameter / SECOND_TO_MILLISECOND);
		else //CACHE_QUEUE
			ResponseTTL = Parameter.HostsDefaultTTL;
	}
	else {
		if (Parameter.CacheType == CACHE_TIMER)
		{
			if (ResponseTTL * SECOND_TO_MILLISECOND < Parameter.CacheParameter)
				ResponseTTL = (uint32_t)(Parameter.CacheParameter / SECOND_TO_MILLISECOND - ResponseTTL + STANDARD_TIMEOUT / SECOND_TO_MILLISECOND);
		}
		else { //CACHE_QUEUE
			if (ResponseTTL < Parameter.HostsDefaultTTL)
				ResponseTTL = Parameter.HostsDefaultTTL - ResponseTTL + STANDARD_TIMEOUT / SECOND_TO_MILLISECOND;
		}
	}

//Initialization(B part)
	if (Length <= DOMAIN_MAXSIZE)
	{
		std::shared_ptr<char> DNSCacheDataBufferTemp(new char[DOMAIN_MAXSIZE]());
		DNSCacheDataTemp.Response.swap(DNSCacheDataBufferTemp);
	}
	else {
		std::shared_ptr<char> DNSCacheDataBufferTemp(new char[Length]());
		DNSCacheDataTemp.Response.swap(DNSCacheDataBufferTemp);
	}

//Mark.
	if (DNSQueryToChar(Buffer + sizeof(dns_hdr), DNSCacheDataTemp.Response.get()) > DOMAIN_MINSIZE)
	{
	//Domain Case Conversion
		CaseConvert(false, DNSCacheDataTemp.Response.get(), strlen(DNSCacheDataTemp.Response.get()));
		DNSCacheDataTemp.Domain = DNSCacheDataTemp.Response.get();
		memset(DNSCacheDataTemp.Response.get(), 0, DOMAIN_MAXSIZE);
		memcpy(DNSCacheDataTemp.Response.get(), Buffer + sizeof(uint16_t), Length - sizeof(uint16_t));
		DNSCacheDataTemp.Length = Length - sizeof(uint16_t);

	//Minimum supported system of GetTickCount64() is Windows Vista.
	#ifdef _WIN64
		DNSCacheDataTemp.ClearTime = GetTickCount64() + ResponseTTL * SECOND_TO_MILLISECOND;
	#else //x86
		DNSCacheDataTemp.ClearTime = GetTickCount() + ResponseTTL * SECOND_TO_MILLISECOND;
	#endif

	//Check repeating items, delete dueue rear and add new item to deque front.
		std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
		for (auto DNSCacheDataIter = DNSCacheList.begin();DNSCacheDataIter != DNSCacheList.end();DNSCacheDataIter++)
		{
			if (DNSCacheDataTemp.Domain == DNSCacheDataIter->Domain && DNSCacheDataTemp.Type == DNSCacheDataIter->Type)
			{
				DNSCacheList.erase(DNSCacheDataIter);
				break;
			}
		}

		if (Parameter.CacheType == CACHE_QUEUE)
		{
			while (DNSCacheList.size() > Parameter.CacheParameter)
				DNSCacheList.pop_front();
		}

		DNSCacheList.push_back(DNSCacheDataTemp);
		DNSCacheList.shrink_to_fit();
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}
