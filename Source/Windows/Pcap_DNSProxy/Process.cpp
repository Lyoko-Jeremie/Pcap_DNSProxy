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

/* Only respond localhost addresses(2014-09-13)
static const std::regex IPv4PrivateB(".(1[6-9]|2[0-9]|3[01]).172.in-addr.arpa", std::regex_constants::extended);
static const std::regex IPv6ULA(".f.[cd].([0-9]|[a-f]).([0-9]|[a-f]).ip6.arpa", std::regex_constants::extended);
static const std::regex IPv6LUC(".f.f.([89]|[ab]).([0-9]|[a-f]).ip6.arpa", std::regex_constants::extended);
*/
extern Configuration Parameter;
extern PortTable PortList;
extern std::vector<uint16_t> AcceptTypeList;
extern std::vector<HostsTable> *HostsListUsing;
extern std::deque<DNSCacheData> DNSCacheList;
extern std::mutex LocalAddressLock[QUEUE_PARTNUM / 2U], HostsListLock, DNSCacheListLock;
extern AlternateSwapTable AlternateSwapList;
extern DNSCurveConfiguration DNSCurveParameter;

//Independent request process
size_t __fastcall RequestProcess(const PSTR Send, const size_t Length, const SOCKET_DATA FunctionData, const uint16_t Protocol, const size_t Index)
{
//Initialization(A part)
	std::shared_ptr<char> SendBuffer, RecvBuffer;
	if (Parameter.CompressionPointerMutation)
	{
		std::shared_ptr<char> SendBufferTemp(new char[Length + 1U]());
		SendBufferTemp.swap(SendBuffer);
	}
	else {
		std::shared_ptr<char> SendBufferTemp(new char[Length]());
		SendBufferTemp.swap(SendBuffer);
	}
	memcpy(SendBuffer.get(), Send, Length);

//Check requesting.
	auto pdns_hdr = (dns_hdr *)SendBuffer.get();
	if (ntohs(pdns_hdr->Questions) != 1U || pdns_hdr->Answer != 0 || ntohs(pdns_hdr->Additional) > 1U || pdns_hdr->Authority != 0)
	{
	//Fin TCP request connection.
		if (Protocol == IPPROTO_TCP && FunctionData.Socket != INVALID_SOCKET)
			closesocket(FunctionData.Socket);

		return EXIT_FAILURE;
	}

//Initialization(B part)
	size_t DataLength = 0;
	if (Parameter.RquestMode == REQUEST_TCPMODE || Parameter.DNSCurve && DNSCurveParameter.DNSCurveMode == DNSCURVE_REQUEST_TCPMODE || Protocol == IPPROTO_TCP) //TCP
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
	if (ntohs(pdns_hdr->Questions) > 0)
	{
		if (Protocol == IPPROTO_TCP) //TCP
			DataLength = CheckHosts(SendBuffer.get(), Length, RecvBuffer.get(), LARGE_PACKET_MAXSIZE - sizeof(uint16_t), LocalRequest);
		else //UDP
			DataLength = CheckHosts(SendBuffer.get(), Length, RecvBuffer.get(), PACKET_MAXSIZE, LocalRequest);

	//Send response.
		if (DataLength > sizeof(dns_hdr) + 1U + sizeof(dns_qry))
		{
			SendToRequester( /* SendBuffer.get(), Length, */ RecvBuffer.get(), DataLength, Protocol, FunctionData);
			return EXIT_SUCCESS;
		}
	}
	else { //Not any questions
		memcpy(RecvBuffer.get(), SendBuffer.get(), Length);
		pdns_hdr = (dns_hdr *)RecvBuffer.get();
		pdns_hdr->Flags = htons(DNS_SQR_FE);

		SendToRequester( /* SendBuffer.get(), Length, */ RecvBuffer.get(), Length, Protocol, FunctionData);
		return EXIT_FAILURE;
	}

//Local server requesting
	if (LocalRequest || Parameter.LocalMain)
	{
		DataLength = LocalRequestProcess(SendBuffer.get(), Length, RecvBuffer.get(), Protocol, FunctionData);
		if (!Parameter.LocalMain || DataLength == EXIT_SUCCESS)
		{
		//Fin TCP request connection.
			if (Protocol == IPPROTO_TCP && FunctionData.Socket != INVALID_SOCKET)
				closesocket(FunctionData.Socket);

			return EXIT_SUCCESS;
		}
	}

	size_t SendLength = Length;
//Compression Pointer Mutation
	if (Parameter.CompressionPointerMutation && pdns_hdr->Additional == 0)
	{
		SendLength++;
		MakeCompressionPointerMutation(SendBuffer.get(), Length);
	}

//Hosts Only requesting
	if (Parameter.HostsOnly)
	{
		DirectRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, FunctionData);
	//Fin TCP request connection.
		if (Protocol == IPPROTO_TCP && FunctionData.Socket != INVALID_SOCKET)
			closesocket(FunctionData.Socket);

		return EXIT_SUCCESS;
	}

//DNSCurve requesting
	if (Parameter.DNSCurve)
	{
	//DNSCurve requesting
		if (DNSCurveRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, FunctionData) == EXIT_SUCCESS)
			return EXIT_SUCCESS;

	//DNSCurve Encryption Only mode
		if (DNSCurveParameter.EncryptionOnly)
		{
		//Fin TCP request connection.
			if (Protocol == IPPROTO_TCP && FunctionData.Socket != INVALID_SOCKET)
				closesocket(FunctionData.Socket);

			return EXIT_SUCCESS;
		}
	}

//TCP requesting
	if (Parameter.RquestMode == REQUEST_TCPMODE && TCPRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, FunctionData) == EXIT_SUCCESS)
		return EXIT_SUCCESS;

//IPv6 tunnels support
	if (((Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL || LocalRequest && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family != NULL) && FunctionData.AddrLen == sizeof(sockaddr_in6) || //IPv6
		(Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL /* || !Local && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == NULL */ ) && FunctionData.AddrLen == sizeof(sockaddr_in)) && //IPv4 is empty.
		Parameter.Tunnel_IPv6)
	{
		DirectRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, FunctionData);
	//Fin TCP request connection.
		if (Protocol == IPPROTO_TCP && FunctionData.Socket != INVALID_SOCKET)
			closesocket(FunctionData.Socket);

		return EXIT_SUCCESS;
	}

	RecvBuffer.reset();
//Pcap Capture check
	if (!Parameter.PcapCapture)
		return EXIT_FAILURE;

//UDP requesting
	if (Protocol == IPPROTO_UDP && SendLength <= Parameter.EDNS0PayloadSize || Protocol == IPPROTO_TCP)
	{
		UDPRequestProcess(SendBuffer.get(), SendLength, Protocol, FunctionData, Index);
	}
	else { //UDP Truncated retry TCP protocol failed.
		pdns_hdr->Flags = htons(DNS_SQR_NETC);
		sendto(FunctionData.Socket, SendBuffer.get(), (int)SendLength, NULL, (PSOCKADDR)&FunctionData.SockAddr, FunctionData.AddrLen);
	}

	return EXIT_FAILURE;
}

//Check hosts from list
inline size_t __fastcall CheckHosts(PSTR Request, const size_t Length, PSTR Result, const size_t ResultSize, bool &Local)
{
//Initilization
	auto pdns_hdr = (dns_hdr *)Request;
	std::string Domain;
	if (pdns_hdr->Questions == htons(U16_NUM_1) && strlen(Request + sizeof(dns_hdr)) < DOMAIN_MAXSIZE)
	{
		if (DNSQueryToChar(Request + sizeof(dns_hdr), Result) > 2U)
		{
		//Domain case conversion
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
	memcpy(Result, Request, Length);
	pdns_hdr = (dns_hdr *)Result;
	auto pdns_qry = (dns_qry *)(Result + sizeof(dns_hdr) + strlen(Result + sizeof(dns_hdr)) + 1U);

//Check Classes.
	if (pdns_qry->Classes != htons(DNS_CLASS_IN))
	{
		memset(Result, 0, ResultSize);
		return FALSE;
	}

//Check Accept Types list.
	if (Parameter.AcceptType) //Permit
	{
		for (auto AcceptTypeIter = AcceptTypeList.begin();AcceptTypeIter != AcceptTypeList.end();AcceptTypeIter++)
		{
			if (AcceptTypeIter + 1U == AcceptTypeList.end()) //Last
			{
				if (*AcceptTypeIter != pdns_qry->Type)
				{
					pdns_hdr->Flags = htons(DNS_SQR_NO_SUCH_NAME);
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
		for (auto AcceptTypeIter:AcceptTypeList)
		{
			if (AcceptTypeIter == pdns_qry->Type)
			{
				pdns_hdr->Flags = htons(DNS_SQR_NO_SUCH_NAME);
				return Length;
			}
		}
	}

/* Old version(2014-11-15)
//Domain case conversion
	for (auto StringIter = Domain.begin();StringIter != Domain.end();StringIter++)
	{
		if (*StringIter > ASCII_AT && *StringIter < ASCII_BRACKETS_LEAD)
			*StringIter += 32U;
	}
*/

//PTR Records
	if (pdns_qry->Type == htons(DNS_PTR_RECORDS) && Parameter.LocalServerOptions.LocalPTRResponseLength + Length <= ResultSize)
	{
/* Only respond localhost addresses(2014-09-13)
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
			for (auto StringIter:Parameter.LocalAddressOptions.LocalAddressPTR[0])
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
				for (auto StringIter:Parameter.LocalAddressOptions.LocalAddressPTR[1U])
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
				memset(Result + Length - sizeof(dns_edns0_label), 0, sizeof(dns_edns0_label));

			//Response
				pdns_rsp = (dns_ptr_record *)(Result + Length - sizeof(dns_edns0_label));
				pdns_rsp->PTR = htons(DNS_QUERY_PTR);
				pdns_rsp->Classes = htons(DNS_CLASS_IN); //Class IN
				pdns_rsp->TTL = htonl(Parameter.HostsDefaultTTL);
				pdns_rsp->Type = htons(DNS_PTR_RECORDS);
				pdns_rsp->Length = htons((uint16_t)Parameter.LocalServerOptions.LocalFQDNLength);
				memcpy(Result + Length - sizeof(dns_edns0_label) + sizeof(dns_ptr_record), Parameter.LocalServerOptions.LocalFQDN, Parameter.LocalServerOptions.LocalFQDNLength);

			//EDNS0
				auto EDNS0 = (dns_edns0_label *)(Result + Length - sizeof(dns_edns0_label) + sizeof(dns_ptr_record) + Parameter.LocalServerOptions.LocalFQDNLength);
				EDNS0->Type = htons(DNS_EDNS0_RECORDS);
				EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				return Length + sizeof(dns_ptr_record) + Parameter.LocalServerOptions.LocalFQDNLength;
			}

		//Response
			pdns_rsp = (dns_ptr_record *)(Result + Length);
			memcpy(Result + Length + sizeof(dns_ptr_record), Parameter.LocalServerOptions.LocalFQDN, Parameter.LocalServerOptions.LocalFQDNLength);
			pdns_rsp->PTR = htons(DNS_QUERY_PTR);
			pdns_rsp->Classes = htons(DNS_CLASS_IN); //Class IN
			pdns_rsp->TTL = htonl(Parameter.HostsDefaultTTL);
			pdns_rsp->Type = htons(DNS_PTR_RECORDS);
			pdns_rsp->Length = htons((uint16_t)Parameter.LocalServerOptions.LocalFQDNLength);
			return Length + sizeof(dns_ptr_record) + Parameter.LocalServerOptions.LocalFQDNLength;
*/
			pdns_hdr->Flags = htons(DNS_SQR_NEA);
			pdns_hdr->Answer = htons(U16_NUM_1);

		//EDNS0 Label
			if (Parameter.EDNS0Label)
			{
				if (pdns_hdr->Additional != 0)
				{
					memset(Result + Length - sizeof(dns_edns0_label), 0, sizeof(dns_edns0_label));
					memcpy(Result + Length - sizeof(dns_edns0_label), Parameter.LocalServerOptions.LocalPTRResponse, Parameter.LocalServerOptions.LocalPTRResponseLength);

					return Length - sizeof(dns_edns0_label) + Parameter.LocalServerOptions.LocalPTRResponseLength;
				}
				else {
					pdns_hdr->Additional = htons(U16_NUM_1);
				}
			}

			memcpy(Result + Length, Parameter.LocalServerOptions.LocalPTRResponse, Parameter.LocalServerOptions.LocalPTRResponseLength);
			return Length + Parameter.LocalServerOptions.LocalPTRResponseLength;
		}
	}

//LocalFQDN check
	if (Parameter.LocalServerOptions.LocalFQDNString == Domain)
	{
		if (pdns_qry->Type == htons(DNS_AAAA_RECORDS)) //IPv6
		{
			std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[0]);
			if (Parameter.LocalAddressOptions.LocalAddressLength[0] > sizeof(dns_hdr) + 1U + sizeof(dns_qry))
			{
				memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
				memcpy(Result + sizeof(uint16_t), Parameter.LocalAddressOptions.LocalAddress[0] + sizeof(uint16_t), Parameter.LocalAddressOptions.LocalAddressLength[0] - sizeof(uint16_t));
				return Parameter.LocalAddressOptions.LocalAddressLength[0];
			}
		}
		else if (pdns_qry->Type == htons(DNS_A_RECORDS)) //IPv4
		{
			std::unique_lock<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[1U]);
			if (Parameter.LocalAddressOptions.LocalAddressLength[1U] > sizeof(dns_hdr) + 1U + sizeof(dns_qry))
			{
				memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
				memcpy(Result + sizeof(uint16_t), Parameter.LocalAddressOptions.LocalAddress[1U] + sizeof(uint16_t), Parameter.LocalAddressOptions.LocalAddressLength[1U] - sizeof(uint16_t));
				return Parameter.LocalAddressOptions.LocalAddressLength[1U];
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
				Local = true;
				break;
			}
		//Check banned list.
			else if (HostsTableIter.Type == HOSTS_BANNED)
			{
				pdns_hdr->Flags = htons(DNS_SQR_NO_SUCH_NAME);
				return Length;
			}
		//Check Hosts.
			else {
			//IPv6
				if (pdns_qry->Type == htons(DNS_AAAA_RECORDS) && HostsTableIter.Protocol == AF_INET6)
				{
				//EDNS0 Lebal
					if (pdns_hdr->Additional == htons(U16_NUM_1))
					{
						memset(Result + Length - sizeof(dns_edns0_label), 0, sizeof(dns_edns0_label));
						pdns_hdr->Flags = htons(DNS_SQR_NE);
						pdns_hdr->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_aaaa_record)));
						memcpy(Result + Length - sizeof(dns_edns0_label), HostsTableIter.Response.get(), HostsTableIter.Length);

						if (!Parameter.EDNS0Label)
						{
							auto pdns_edns0_label = (dns_edns0_label *)(Result + Length - sizeof(dns_edns0_label) + HostsTableIter.Length);
							pdns_edns0_label->Type = htons(DNS_EDNS0_RECORDS);
							pdns_edns0_label->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);

						//DNSSEC
							if (Parameter.DNSSECRequest)
								pdns_edns0_label->Z_Bits.DO = ~pdns_edns0_label->Z_Bits.DO; //Accepts DNSSEC security RRs

							return Length + HostsTableIter.Length;
						}
						else {
							return Length - sizeof(dns_edns0_label) + HostsTableIter.Length;
						}
					}
					else {
						pdns_hdr->Flags = htons(DNS_SQR_NE);
						pdns_hdr->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_aaaa_record)));
						memcpy(Result + Length, HostsTableIter.Response.get(), HostsTableIter.Length);
						return Length + HostsTableIter.Length;
					}
				}
			//IPv4
				else if (pdns_qry->Type == htons(DNS_A_RECORDS) && HostsTableIter.Protocol == AF_INET)
				{
				//EDNS0 Lebal
					if (pdns_hdr->Additional == htons(U16_NUM_1))
					{
						memset(Result + Length - sizeof(dns_edns0_label), 0, sizeof(dns_edns0_label));
						pdns_hdr->Flags = htons(DNS_SQR_NE);
						pdns_hdr->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_a_record)));
						memcpy(Result + Length - sizeof(dns_edns0_label), HostsTableIter.Response.get(), HostsTableIter.Length);

						if (!Parameter.EDNS0Label)
						{
							auto pdns_edns0_label = (dns_edns0_label *)(Result + Length - sizeof(dns_edns0_label) + HostsTableIter.Length);
							pdns_edns0_label->Type = htons(DNS_EDNS0_RECORDS);
							pdns_edns0_label->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);

						//DNSSEC
							if (Parameter.DNSSECRequest)
								pdns_edns0_label->Z_Bits.DO = ~pdns_edns0_label->Z_Bits.DO; //Accepts DNSSEC security RRs

							return Length + HostsTableIter.Length;
						}
						else {
							return Length - sizeof(dns_edns0_label) + HostsTableIter.Length;
						}
					}
					else {
						pdns_hdr->Flags = htons(DNS_SQR_NE);
						pdns_hdr->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_a_record)));
						memcpy(Result + Length, HostsTableIter.Response.get(), HostsTableIter.Length);
						return Length + HostsTableIter.Length;
					}
				}
			}
		}
	}
	HostsListMutex.unlock();

//DNS Cache check
	std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	for (auto DNSCacheIter:DNSCacheList)
	{
		if (Domain == DNSCacheIter.Domain && 
			(pdns_qry->Type == htons(DNS_AAAA_RECORDS) && DNSCacheIter.Protocol == AF_INET6 || //IPv6
			pdns_qry->Type == htons(DNS_A_RECORDS) && DNSCacheIter.Protocol == AF_INET)) //IPv4
		{
			memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
			memcpy(Result + sizeof(uint16_t), DNSCacheIter.Response.get(), DNSCacheIter.Length);
			return DNSCacheIter.Length + sizeof(uint16_t);
		}
	}
	DNSCacheListMutex.unlock();

//Domain case conversion
	if (Parameter.DomainCaseConversion)
		DomainCaseConversion(Request + sizeof(dns_hdr));
	
	memset(Result, 0, ResultSize);
	return EXIT_SUCCESS;
}

//Request Process(Local part)
inline size_t __fastcall LocalRequestProcess(const PSTR Send, const size_t SendSize, PSTR Recv, const uint16_t Protocol, const SOCKET_DATA FunctionData)
{
	size_t DataLength = 0;

//TCP Mode
	if (Parameter.RquestMode == REQUEST_TCPMODE)
	{
		if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			DataLength = TCPRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, true, AlternateSwapList.Swap[4U]);

		//Check timeout.
			if (!AlternateSwapList.Swap[4U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[4U]++;
		}
		else { //IPv4
			DataLength = TCPRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, true, AlternateSwapList.Swap[5U]);

		//Check timeout.
			if (!AlternateSwapList.Swap[5U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[5U]++;
		}

	//Send response.
		if (DataLength > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && DataLength < LARGE_PACKET_MAXSIZE)
		{
			SendToRequester( /* Send, SendSize, */ Recv, DataLength, Protocol, FunctionData);
			return EXIT_SUCCESS;
		}
	}
		
//UDP Mode(REQUEST_UDPMODE)
	if (Protocol == IPPROTO_TCP) //TCP requesting
	{
		if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			DataLength = UDPCompleteRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, true, AlternateSwapList.Swap[6U]);

		//Check timeout.
			if (!AlternateSwapList.Swap[6U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[6U]++;
		}
		else { //IPv4
			DataLength = UDPCompleteRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, true, AlternateSwapList.Swap[7U]);

		//Check timeout.
			if (!AlternateSwapList.Swap[7U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[7U]++;
		}
	}
//UDP requesting
	else {
		if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			DataLength = UDPCompleteRequest(Send, SendSize, Recv, PACKET_MAXSIZE, FunctionData, true, AlternateSwapList.Swap[6U]);

		//Check timeout.
			if (!AlternateSwapList.Swap[6U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[6U]++;
		}
		else { //IPv4
			DataLength = UDPCompleteRequest(Send, SendSize, Recv, PACKET_MAXSIZE, FunctionData, true, AlternateSwapList.Swap[7U]);

		//Check timeout.
			if (!AlternateSwapList.Swap[7U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[7U]++;
		}
	}
		
//Send response.
	if (DataLength > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && (DataLength < PACKET_MAXSIZE || Protocol == IPPROTO_TCP && DataLength < LARGE_PACKET_MAXSIZE))
	{
		SendToRequester( /* Send, SendSize, */ Recv, DataLength, Protocol, FunctionData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(Direct connections part)
inline size_t __fastcall DirectRequestProcess(const PSTR Send, const size_t SendSize, PSTR Recv, const uint16_t Protocol, const SOCKET_DATA FunctionData)
{
	size_t DataLength = 0;

//TCP Mode
	if (Parameter.RquestMode == REQUEST_TCPMODE)
	{
	//Multi requesting.
		if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
		{
		//Initialization
			std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
			std::mutex MultiRequestingLock;
			TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER TCPRequestParameter = {Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, 1U, 0};

		//All server(including Alternate) Multi Request
			if (Parameter.AlternateMultiRequest)
			{
				if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
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
				if (FunctionData.AddrLen == sizeof(sockaddr_in6) && AlternateSwapList.Swap[0] || //IPv6
					FunctionData.AddrLen == sizeof(sockaddr_in) && AlternateSwapList.Swap[1U]) //IPv4
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
				if (TCPRequestParameter.ReturnValue > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && TCPRequestParameter.ReturnValue < LARGE_PACKET_MAXSIZE)
				{
					SendToRequester( /* Send, SendSize, */ Recv, TCPRequestParameter.ReturnValue, Protocol, FunctionData);
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
		}
	//Normal requesting
		else {
			if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				DataLength = TCPRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, false, AlternateSwapList.Swap[0]);
			else //IPv4
				DataLength = TCPRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, false, AlternateSwapList.Swap[1U]);
		}

	//Check timeout.
		if (DataLength == WSAETIMEDOUT)
		{
			if (FunctionData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.Swap[0] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[0]++;
			else if (FunctionData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.Swap[1U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[1U]++;
		}
	//Send response.
		else if (DataLength > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && DataLength < LARGE_PACKET_MAXSIZE)
		{
			SendToRequester( /* Send, SendSize, */ Recv, DataLength, Protocol, FunctionData);
			return EXIT_SUCCESS;
		}
	}

//UDP Mode(REQUEST_UDPMODE)
	//Multi requesting.
	if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
	{
	//Initialization
		std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
		std::mutex MultiRequestingLock;
		TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER UDPRequestParameter = {Send, SendSize, Recv, 0, FunctionData, 1U, 0};
		if (Protocol == IPPROTO_TCP) //TCP requesting
			UDPRequestParameter.RecvSize = LARGE_PACKET_MAXSIZE - sizeof(uint16_t);
		else //UDP requesting
			UDPRequestParameter.RecvSize = PACKET_MAXSIZE;

	//All server(including Alternate) Multi Request
		if (Parameter.AlternateMultiRequest)
		{
			if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
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
			if (FunctionData.AddrLen == sizeof(sockaddr_in6) && AlternateSwapList.Swap[2U] || //IPv6
				FunctionData.AddrLen == sizeof(sockaddr_in) && AlternateSwapList.Swap[3U]) //IPv4
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
			if (UDPRequestParameter.ReturnValue > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && UDPRequestParameter.ReturnValue < LARGE_PACKET_MAXSIZE)
			{
				SendToRequester( /* Send, SendSize, */ Recv, UDPRequestParameter.ReturnValue, Protocol, FunctionData);
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
	}
	//Normal requesting
	else {
		if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			if (Protocol == IPPROTO_TCP) //TCP requesting
				DataLength = UDPCompleteRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, false, AlternateSwapList.Swap[2U]);
			else //UDP requesting
				DataLength = UDPCompleteRequest(Send, SendSize, Recv, PACKET_MAXSIZE, FunctionData, false, AlternateSwapList.Swap[2U]);
		}
		else { //IPv4
			if (Protocol == IPPROTO_TCP) //TCP requesting
				DataLength = UDPCompleteRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, false, AlternateSwapList.Swap[3U]);
			else //UDP requesting
				DataLength = UDPCompleteRequest(Send, SendSize, Recv, PACKET_MAXSIZE, FunctionData, false, AlternateSwapList.Swap[3U]);
		}
	}

//Check timeout.
	if (DataLength == WSAETIMEDOUT)
	{
		if (FunctionData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.Swap[2U] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[2U]++;
		else if (FunctionData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.Swap[3U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[3U]++;
	}

//Send response.
	if (DataLength > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && (DataLength < PACKET_MAXSIZE || Protocol == IPPROTO_TCP && DataLength < LARGE_PACKET_MAXSIZE))
	{
		SendToRequester( /* Send, SendSize, */ Recv, DataLength, Protocol, FunctionData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(DNSCurve part)
inline size_t __fastcall DNSCurveRequestProcess(const PSTR Send, const size_t SendSize, PSTR Recv, const uint16_t Protocol, const SOCKET_DATA FunctionData)
{
	size_t DataLength = 0;

//TCP requesting
	if (DNSCurveParameter.DNSCurveMode == DNSCURVE_REQUEST_TCPMODE)
	{
	//Multi requesting.
		if (Parameter.MultiRequestTimes > 1U)
		{
		//Initialization
			std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
			std::mutex MultiRequestingLock;
			DNSCURVE_REQUEST_MULTITHREAD_PARAMETER DNSCurveRequestParameter = {Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, false, DNSCurveParameter.Encryption, 0};
			if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				DNSCurveRequestParameter.Alternate = AlternateSwapList.Swap[8U];
			else //IPv4
				DNSCurveRequestParameter.Alternate = AlternateSwapList.Swap[9U];

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
				if (DNSCurveRequestParameter.ReturnValue > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && DNSCurveRequestParameter.ReturnValue < PACKET_MAXSIZE)
				{
					SendToRequester( /* Send, SendSize, */ Recv, DNSCurveRequestParameter.ReturnValue, Protocol, FunctionData);
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
		}
	//Normal requesting
		else {
			if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				DataLength = DNSCurveTCPRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, AlternateSwapList.Swap[8U], DNSCurveParameter.Encryption);
			else //IPv4
				DataLength = DNSCurveTCPRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, AlternateSwapList.Swap[9U], DNSCurveParameter.Encryption);
		}

	//Check timeout.
		if (DataLength == WSAETIMEDOUT)
		{
			if (FunctionData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.Swap[8U] && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[8U]++;
			else if (FunctionData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.Swap[9U] && DataLength == WSAETIMEDOUT && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
				AlternateSwapList.TimeoutTimes[9U]++;
		}

	//Send response.
		if (DataLength > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && DataLength < LARGE_PACKET_MAXSIZE)
		{
			SendToRequester( /* Send, SendSize, */ Recv, DataLength, Protocol, FunctionData);
			return EXIT_SUCCESS;
		}
	}

//UDP requesting
	if (Parameter.MultiRequestTimes > 1U) //Multi requesting.
	{
	//Initialization
		std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
		std::mutex MultiRequestingLock;
		DNSCURVE_REQUEST_MULTITHREAD_PARAMETER DNSCurveRequestParameter = {Send, SendSize, Recv, PACKET_MAXSIZE, FunctionData, false, DNSCurveParameter.Encryption, 0};
		if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			DNSCurveRequestParameter.Alternate = AlternateSwapList.Swap[10U];
		else //IPv4
			DNSCurveRequestParameter.Alternate = AlternateSwapList.Swap[11U];

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
			if (DNSCurveRequestParameter.ReturnValue > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && DNSCurveRequestParameter.ReturnValue < PACKET_MAXSIZE)
			{
				SendToRequester( /* Send, SendSize, */ Recv, DNSCurveRequestParameter.ReturnValue, Protocol, FunctionData);
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
	}
	else { //Normal requesting
		if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			DataLength = DNSCurveUDPRequest(Send, SendSize, Recv, PACKET_MAXSIZE, FunctionData, AlternateSwapList.Swap[10U], DNSCurveParameter.Encryption);
		else //IPv4
			DataLength = DNSCurveUDPRequest(Send, SendSize, Recv, PACKET_MAXSIZE, FunctionData, AlternateSwapList.Swap[11U], DNSCurveParameter.Encryption);
	}

//Check timeout.
	if (DataLength == WSAETIMEDOUT)
	{
		if (FunctionData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.Swap[10U] && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[10U]++;
		if (FunctionData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.Swap[11U] && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[11U]++;
	}

//Send response.
	if (DataLength > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && DataLength < PACKET_MAXSIZE)
	{
		SendToRequester( /* Send, SendSize, */ Recv, DataLength, Protocol, FunctionData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(TCP part)
inline size_t __fastcall TCPRequestProcess(const PSTR Send, const size_t SendSize, PSTR Recv, const uint16_t Protocol, const SOCKET_DATA FunctionData)
{
	size_t DataLength = 0;

//Multi requesting.
	if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
	{
	//Initialization
		std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
		std::mutex MultiRequestingLock;
		TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER TCPRequestParameter = {Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, 1U, 0};

	//All server(including Alternate) Multi Request
		if (Parameter.AlternateMultiRequest)
		{
			if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
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
			if (FunctionData.AddrLen == sizeof(sockaddr_in6) && AlternateSwapList.Swap[0] || //IPv6
				FunctionData.AddrLen == sizeof(sockaddr_in) && AlternateSwapList.Swap[1U]) //IPv4
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
			if (TCPRequestParameter.ReturnValue > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && TCPRequestParameter.ReturnValue < PACKET_MAXSIZE)
			{
				SendToRequester( /* Send, SendSize, */ Recv, TCPRequestParameter.ReturnValue, Protocol, FunctionData);
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
	}
//Normal requesting
	else {
		if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			DataLength = TCPRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, false, AlternateSwapList.Swap[0]);
		else //IPv4
			DataLength = TCPRequest(Send, SendSize, Recv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), FunctionData, false, AlternateSwapList.Swap[1U]);
	}

//Check timeout.
	if (DataLength == WSAETIMEDOUT)
	{
		if (FunctionData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.Swap[0] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[0]++;
		else if (FunctionData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.Swap[1U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
			AlternateSwapList.TimeoutTimes[1U]++;
	}

//Send response.
	if (DataLength > sizeof(uint16_t) + sizeof(dns_hdr) + 1U + sizeof(dns_qry) && DataLength < LARGE_PACKET_MAXSIZE)
	{
	//EDNS0 Label
		auto pdns_hdr = (dns_hdr *)Send;
		if (Protocol == IPPROTO_UDP && pdns_hdr->Additional != 0)
		{
			pdns_hdr = (dns_hdr *)Recv;
			pdns_hdr->Additional = htons(U16_NUM_1);
			auto pdns_edns0_label = (dns_edns0_label *)(Recv + DataLength);
			pdns_edns0_label->Type = htons(DNS_EDNS0_RECORDS);
			pdns_edns0_label->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);

		//DNSSEC
			if (Parameter.DNSSECRequest)
				pdns_edns0_label->Z_Bits.DO = ~pdns_edns0_label->Z_Bits.DO; //Accepts DNSSEC security RRs
			DataLength += sizeof(dns_edns0_label);
		}

		SendToRequester( /* Send, SendSize, */ Recv, DataLength, Protocol, FunctionData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(UDP part)
inline size_t __fastcall UDPRequestProcess(const PSTR Send, const size_t SendSize, const uint16_t Protocol, const SOCKET_DATA FunctionData, const size_t Index)
{
//Mark requesting data
	PortList.RecvData[Index] = FunctionData;
	PortList.SendData[Index].clear();

//Multi requesting.
	if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
	{
	//Initialization
		std::vector<std::thread> MultiRequesting(Parameter.MultiRequestTimes);
		UDP_REQUEST_MULTITHREAD_PARAMETER UDPRequestParameter = {Send, SendSize, FunctionData, Index, 1U};

	//All server(including Alternate) Multi Request
		if (Parameter.AlternateMultiRequest)
		{
			if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
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
			if (FunctionData.AddrLen == sizeof(sockaddr_in6) && AlternateSwapList.Swap[2U] || //IPv6
				FunctionData.AddrLen == sizeof(sockaddr_in) && AlternateSwapList.Swap[3U]) //IPv4
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
	}
//Normal requesting
	else {
		if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			UDPRequest(Send, SendSize, FunctionData, Index, AlternateSwapList.Swap[2U]);
		else //IPv4
			UDPRequest(Send, SendSize, FunctionData, Index, AlternateSwapList.Swap[3U]);
	}

//Fin TCP request connection.
	if (Protocol == IPPROTO_TCP && FunctionData.Socket != INVALID_SOCKET)
		closesocket(FunctionData.Socket);

	return EXIT_SUCCESS;
}

//Send responses to requester
inline size_t __fastcall SendToRequester( /* const PSTR SendBuffer, const size_t SendSize, */ PSTR RecvBuffer, const size_t RecvSize, const uint16_t Protocol, const SOCKET_DATA TargetData)
{
//TCP
	if (Protocol == IPPROTO_TCP)
	{
		if (AddLengthToTCPDNSHeader(RecvBuffer, RecvSize, LARGE_PACKET_MAXSIZE) == EXIT_FAILURE)
		{
/*
			auto pdns_hdr = (dns_hdr *)SendBuffer;
			pdns_hdr->Flags = htons(DNS_SQR_SF);
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
//Initialization
	DNSCacheData DNSCacheDataTemp;
	memset((PSTR)&DNSCacheDataTemp + sizeof(DNSCacheDataTemp.Domain) + sizeof(DNSCacheDataTemp.Response), 0, sizeof(DNSCacheData) - sizeof(DNSCacheDataTemp.Domain) - sizeof(DNSCacheDataTemp.Response));
	
//Check conditions.
	auto pdns_hdr = (dns_hdr *)Buffer;
	if (pdns_hdr->Answer == 0 && pdns_hdr->Authority == 0 && pdns_hdr->Additional == 0 || //No any result
		pdns_hdr->Questions == 0) //No any questions
			return EXIT_FAILURE;
	auto pdns_qry = (dns_qry *)(Buffer + sizeof(dns_hdr) + strlen(Buffer + sizeof(dns_hdr)) + 1U);
	if (pdns_qry->Type == htons(DNS_AAAA_RECORDS)) //IPv6
	{
/*	//Check TTL.
		if (pdns_hdr->Answer != 0)
		{
			dns_aaaa_record *pdns_aaaa_record = nullptr;
			if (pdns_hdr->Additional != 0) //EDNS0 Label
				pdns_aaaa_record = (dns_aaaa_record *)(Buffer + (Length - sizeof(dns_edns0_label) - sizeof(dns_aaaa_record)));
			else 
				pdns_aaaa_record = (dns_aaaa_record *)(Buffer + (Length - sizeof(dns_aaaa_record)));
			if (ntohl(pdns_aaaa_record->TTL) >= Parameter.HostsDefaultTTL)
				return EXIT_SUCCESS;
		}
*/
		DNSCacheDataTemp.Protocol = AF_INET6;
	}
	else if (pdns_qry->Type == htons(DNS_A_RECORDS)) //IPv4
	{
/*	//Check TTL.
		if (pdns_hdr->Answer != 0)
		{
			dns_a_record *pdns_a_record = nullptr;
			if (pdns_hdr->Additional != 0) //EDNS0 Label
				pdns_a_record = (dns_a_record *)(Buffer + (Length - sizeof(dns_edns0_label) - sizeof(dns_a_record)));
			else 
				pdns_a_record = (dns_a_record *)(Buffer + (Length - sizeof(dns_a_record)));
			if (ntohl(pdns_a_record->TTL) >= Parameter.HostsDefaultTTL)
				return EXIT_SUCCESS;
		}
*/
		DNSCacheDataTemp.Protocol = AF_INET;
	}
	else {
		return EXIT_FAILURE;
	}

//Mark DNS A records and AAAA records only.
	if (Length <= DOMAIN_MAXSIZE)
	{
		std::shared_ptr<char> DNSCacheDataBufferTemp(new char[DOMAIN_MAXSIZE]());
		DNSCacheDataTemp.Response.swap(DNSCacheDataBufferTemp);
	}
	else {
		std::shared_ptr<char> DNSCacheDataBufferTemp(new char[Length]());
		DNSCacheDataTemp.Response.swap(DNSCacheDataBufferTemp);
	}

//Mark
	if (DNSQueryToChar(Buffer + sizeof(dns_hdr), DNSCacheDataTemp.Response.get()) > 2U)
	{
	//Domain case conversion
/*		for (size_t Index = 0;Index <= strlen(DNSCacheDataTemp.Response.get());Index++)
		{
			if (DNSCacheDataTemp.Response.get()[Index] > ASCII_AT && DNSCacheDataTemp.Response.get()[Index] < ASCII_BRACKETS_LEAD)
				DNSCacheDataTemp.Response.get()[Index] += 32U;
		}
*/
		CaseConvert(false, DNSCacheDataTemp.Response.get(), strlen(DNSCacheDataTemp.Response.get()));

		DNSCacheDataTemp.Domain = DNSCacheDataTemp.Response.get();
		memset(DNSCacheDataTemp.Response.get(), 0, DOMAIN_MAXSIZE);
		memcpy(DNSCacheDataTemp.Response.get(), Buffer + sizeof(uint16_t), Length - sizeof(uint16_t));
		DNSCacheDataTemp.Length = Length - sizeof(uint16_t);

	//Check repeating items, delete dueue rear and add new item to deque front.
		std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
		for (auto DNSCacheDataIter = DNSCacheList.begin();DNSCacheDataIter != DNSCacheList.end();DNSCacheDataIter++)
		{
			if (DNSCacheDataTemp.Protocol == DNSCacheDataIter->Protocol && DNSCacheDataTemp.Domain == DNSCacheDataIter->Domain)
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

	//Minimum supported system of GetTickCount64() is Windows Vista.
	#ifdef _WIN64
		DNSCacheDataTemp.Time = GetTickCount64();
	#else //x86
		DNSCacheDataTemp.Time = GetTickCount();
	#endif

		DNSCacheList.push_back(DNSCacheDataTemp);
		DNSCacheList.shrink_to_fit();
	}
	else {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
