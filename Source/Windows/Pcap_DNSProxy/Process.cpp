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


#include "Process.h"

//Independent request process
size_t __fastcall EnterRequestProcess(const PSTR OriginalSend, const size_t Length, const SOCKET_DATA LocalSocketData, const uint16_t Protocol /* , const size_t ListIndex */ )
{
//Initialization(Send buffer part)
	std::shared_ptr<char> SendBuffer, RecvBuffer;
	if (Parameter.CompressionPointerMutation)
	{
		if (Parameter.CPMPointerToAdditional)
		{
			std::shared_ptr<char> SendBufferTemp(new char[Length + 2U + sizeof(dns_record_aaaa)]());
			memset(SendBufferTemp.get(), 0, Length + 2U + sizeof(dns_record_aaaa));
			SendBufferTemp.swap(SendBuffer);
		}
		else if (Parameter.CPMPointerToRR)
		{
			std::shared_ptr<char> SendBufferTemp(new char[Length + 2U]());
			memset(SendBufferTemp.get(), 0, Length + 2U);
			SendBufferTemp.swap(SendBuffer);
		}
		else { //Pointer to header
			std::shared_ptr<char> SendBufferTemp(new char[Length + 1U]());
			memset(SendBufferTemp.get(), 0, Length + 1U);
			SendBufferTemp.swap(SendBuffer);
		}
	}
	else {
		std::shared_ptr<char> SendBufferTemp(new char[Length]());
		memset(SendBufferTemp.get(), 0, Length);
		SendBufferTemp.swap(SendBuffer);
	}
//	memcpy(SendBuffer.get(), OriginalSend, Length);
	memcpy_s(SendBuffer.get(), Length, OriginalSend, Length);

//Initialization(Receive buffer part)
	size_t DataLength = 0;
	if (Parameter.RequestMode == REQUEST_TCPMODE || Parameter.DNSCurve && DNSCurveParameter.DNSCurveMode == DNSCURVE_REQUEST_TCPMODE || Protocol == IPPROTO_TCP) //TCP
	{
		std::shared_ptr<char> TCPRecvBuffer(new char[LARGE_PACKET_MAXSIZE]());
		memset(TCPRecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
		RecvBuffer.swap(TCPRecvBuffer);
	}
	else { //UDP
		std::shared_ptr<char> UDPRecvBuffer(new char[PACKET_MAXSIZE]());
		memset(UDPRecvBuffer.get(), 0, PACKET_MAXSIZE);
		RecvBuffer.swap(UDPRecvBuffer);
	}

//Check hosts.
	auto IsLocalRequest = false;
	auto DNS_Header = (pdns_hdr)SendBuffer.get();
	if (DNS_Header->Questions == htons(U16_NUM_ONE))
	{
		if (Protocol == IPPROTO_TCP) //TCP
			DataLength = LARGE_PACKET_MAXSIZE - sizeof(uint16_t);
		else //UDP
			DataLength = PACKET_MAXSIZE;
		DataLength = CheckHosts(SendBuffer.get(), Length, RecvBuffer.get(), DataLength, IsLocalRequest);

	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE)
		{
			SendToRequester(RecvBuffer.get(), DataLength, Protocol, LocalSocketData);
			return EXIT_SUCCESS;
		}
	}
	else { //No any Question Resource Records
//		memcpy(RecvBuffer.get(), SendBuffer.get(), Length);
		memcpy_s(RecvBuffer.get(), Length, SendBuffer.get(), Length);
		DNS_Header = (pdns_hdr)RecvBuffer.get();
		DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8001); //Set 10000000000000001, DNS_SQR_FE

		SendToRequester(RecvBuffer.get(), Length, Protocol, LocalSocketData);
		return EXIT_FAILURE;
	}

//Local server requesting
	if ((IsLocalRequest || Parameter.LocalMain) && 
		LocalRequestProcess(SendBuffer.get(), Length, RecvBuffer.get(), Protocol, LocalSocketData) == EXIT_SUCCESS)
	{
	//Fin TCP request connection.
		if (Protocol == IPPROTO_TCP && LocalSocketData.Socket != INVALID_SOCKET)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
		}

		return EXIT_SUCCESS;
	}

	size_t SendLength = Length;
//Compression Pointer Mutation
	if (Parameter.CompressionPointerMutation && DNS_Header->Additional == 0)
	{
		SendLength = MakeCompressionPointerMutation(SendBuffer.get(), Length);
		if (SendLength < Length)
			SendLength = Length;
	}

//Hosts Only requesting
	if (Parameter.HostsOnly && DirectRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, LocalSocketData) == EXIT_SUCCESS)
	{
	//Fin TCP request connection.
		if (Protocol == IPPROTO_TCP && LocalSocketData.Socket != INVALID_SOCKET)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
		}

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
		if (DNSCurveRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, LocalSocketData) == EXIT_SUCCESS)
			return EXIT_SUCCESS;

	//DNSCurve Encryption Only mode
		if (DNSCurveParameter.IsEncryptionOnly)
		{
		//Fin TCP request connection.
			if (Protocol == IPPROTO_TCP && LocalSocketData.Socket != INVALID_SOCKET)
			{
				shutdown(LocalSocketData.Socket, SD_BOTH);
				closesocket(LocalSocketData.Socket);
			}

			return EXIT_SUCCESS;
		}
	}
	SkipDNSCurve: 

//TCP requesting
	if ((Protocol == IPPROTO_TCP || Parameter.RequestMode == REQUEST_TCPMODE) && TCPRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, LocalSocketData) == EXIT_SUCCESS)
		return EXIT_SUCCESS;

//IPv6 tunnels support
	if (Parameter.GatewayAvailable_IPv6 && Parameter.TunnelAvailable_IPv6 && 
		DirectRequestProcess(SendBuffer.get(), SendLength, RecvBuffer.get(), Protocol, LocalSocketData) == EXIT_SUCCESS)
	{
	//Fin TCP request connection.
		if (Protocol == IPPROTO_TCP && LocalSocketData.Socket != INVALID_SOCKET)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
		}

		return EXIT_SUCCESS;
	}

//Pcap Capture check
	if (!Parameter.PcapCapture)
		return EXIT_SUCCESS;
	RecvBuffer.reset();

//UDP requesting
/* Old version(2015-03-08)
	if (Protocol == IPPROTO_UDP && SendLength <= Parameter.EDNS0PayloadSize || Protocol == IPPROTO_TCP)
	{
*/
	UDPRequestProcess(SendBuffer.get(), SendLength, LocalSocketData, Protocol /* , ListIndex */ );
/*		return EXIT_SUCCESS;
	}
	else { //UDP Truncated retry TCP protocol failed.
		DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8200); //Set 1000001000000000, DNS_SQR_NETC
		sendto(LocalSocketData.Socket, SendBuffer.get(), (int)SendLength, 0, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen);
	}
*/
	return EXIT_SUCCESS;
}

//Check hosts from list
size_t __fastcall CheckHosts(PSTR OriginalRequest, const size_t Length, PSTR Result, const size_t ResultSize, bool &IsLocal)
{
//Initilization
	auto DNS_Header = (pdns_hdr)OriginalRequest;
	std::string Domain;
	if (DNS_Header->Questions == htons(U16_NUM_ONE) && CheckDNSQueryNameLength(OriginalRequest + sizeof(dns_hdr)) + 1U < DOMAIN_MAXSIZE)
	{
		if (DNSQueryToChar(OriginalRequest + sizeof(dns_hdr), Result) > DOMAIN_MINSIZE)
		{
		//Domain Case Conversion
//			CaseConvert(false, Result, strlen(Result));
			CaseConvert(false, Result, strnlen_s(Result, ResultSize));

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
//	memcpy(Result, OriginalRequest, Length);
	memcpy_s(Result, ResultSize, OriginalRequest, Length);
	DNS_Header = (pdns_hdr)Result;
	auto DNS_Query = (pdns_qry)(Result + DNS_PACKET_QUERY_LOCATE(Result));

//Check Classes.
	if (DNS_Query->Classes != htons(DNS_CLASS_IN))
	{
		memset(Result, 0, ResultSize);
		return FALSE;
	}

//Check Accept Types list.
	if (Parameter.AcceptType) //Permit
	{
		for (auto AcceptTypeTableIter = Parameter.AcceptTypeList->begin();AcceptTypeTableIter != Parameter.AcceptTypeList->end();AcceptTypeTableIter++)
		{
			if (AcceptTypeTableIter + 1U == Parameter.AcceptTypeList->end()) //Last
			{
				if (*AcceptTypeTableIter != DNS_Query->Type)
				{
					DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8003); //Set 1000000000000011, DNS_SQR_SNH
					return Length;
				}
			}
			else if (*AcceptTypeTableIter == DNS_Query->Type)
			{
				break;
			}
		}
	}
	else { //Deny
		for (auto AcceptTypeTableIter:*Parameter.AcceptTypeList)
		{
			if (AcceptTypeTableIter == DNS_Query->Type)
			{
				DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8003); //Set 1000000000000011, DNS_SQR_SNH
				return Length;
			}
		}
	}

//PTR Records
	if (DNS_Query->Type == htons(DNS_RECORD_PTR) && Parameter.LocalServerResponseLength + Length <= ResultSize)
	{
		auto IsSendPTR = false;

	//IPv6 check
		if (Domain == ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa") || //Loopback address(::1, Section 2.5.3 in RFC 4291)
	//IPv4 check
			Domain.find(".127.in-addr.arpa") != std::string::npos || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
			Domain.find(".254.169.in-addr.arpa") != std::string::npos) //Link-local address(169.254.0.0/16, RFC 3927)
		{
			IsSendPTR = true;
		}
		else {
		//IPv6 check
			std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[0]);
			for (auto StringIter:*Parameter.LocalAddressPTR[0])
			{
				if (Domain == StringIter)
				{
					IsSendPTR = true;
					break;
				}
			}
			LocalAddressMutexIPv6.unlock();

		//IPv4 check
			if (!IsSendPTR)
			{
				std::unique_lock<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[1U]);
				for (auto StringIter:*Parameter.LocalAddressPTR[1U])
				{
					if (Domain == StringIter)
					{
						IsSendPTR = true;
						break;
					}
				}
			}
		}

	//Send Localhost PTR.
		if (IsSendPTR)
		{
			DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8400); //Set 1000100000000000, DNS_SQR_NEA
			DNS_Header->Answer = htons(U16_NUM_ONE);

		//EDNS0 Label
			if (Parameter.EDNS0Label)
			{
				auto DNS_Record_OPT = (pdns_record_opt)(Result + Length - sizeof(dns_record_opt));
				if (DNS_Header->Additional > 0 && DNS_Record_OPT->Type == htons(DNS_RECORD_OPT))
				{
					memset(Result + Length - sizeof(dns_record_opt), 0, sizeof(dns_record_opt));
//					memcpy(Result + Length - sizeof(dns_record_opt), Parameter.LocalServerResponse, Parameter.LocalServerResponseLength);
					memcpy_s(Result + Length - sizeof(dns_record_opt), ResultSize, Parameter.LocalServerResponse, Parameter.LocalServerResponseLength);

					return Length - sizeof(dns_record_opt) + Parameter.LocalServerResponseLength;
				}
			}

//			memcpy(Result + Length, Parameter.LocalServerResponse, Parameter.LocalServerResponseLength);
			memcpy_s(Result + Length, ResultSize, Parameter.LocalServerResponse, Parameter.LocalServerResponseLength);
			return Length + Parameter.LocalServerResponseLength;
		}
	}

//LocalFQDN check
	if (*Parameter.LocalFQDNString == Domain)
	{
		if (DNS_Query->Type == htons(DNS_RECORD_AAAA))
		{
			std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[0]);
			if (Parameter.LocalAddressLength[0] >= DNS_PACKET_MINSIZE)
			{
				memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
//				memcpy(Result + sizeof(uint16_t), Parameter.LocalAddress[0] + sizeof(uint16_t), Parameter.LocalAddressLength[0] - sizeof(uint16_t));
				memcpy_s(Result + sizeof(uint16_t), ResultSize - sizeof(uint16_t), Parameter.LocalAddress[0] + sizeof(uint16_t), Parameter.LocalAddressLength[0] - sizeof(uint16_t));
				return Parameter.LocalAddressLength[0];
			}
		}
		else if (DNS_Query->Type == htons(DNS_RECORD_A))
		{
			std::unique_lock<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[1U]);
			if (Parameter.LocalAddressLength[1U] >= DNS_PACKET_MINSIZE)
			{
				memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
//				memcpy(Result + sizeof(uint16_t), Parameter.LocalAddress[1U] + sizeof(uint16_t), Parameter.LocalAddressLength[1U] - sizeof(uint16_t));
				memcpy_s(Result + sizeof(uint16_t), ResultSize - sizeof(uint16_t), Parameter.LocalAddress[1U] + sizeof(uint16_t), Parameter.LocalAddressLength[1U] - sizeof(uint16_t));
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
				DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8003); //Set 1000000000000011, DNS_SQR_SNH
				return Length;
			}
		//Check Hosts.
			else {
			//IPv6
				if (DNS_Query->Type == htons(DNS_RECORD_AAAA) && HostsTableIter.Protocol == AF_INET6)
				{
				//EDNS0 Lebal
					if (DNS_Header->Additional == htons(U16_NUM_ONE))
					{
						memset(Result + Length - sizeof(dns_record_opt), 0, sizeof(dns_record_opt));
						DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8000); //Set 1000000000000000, DNS_SQR_NE
						DNS_Header->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_record_aaaa)));
//						memcpy(Result + Length - sizeof(dns_record_opt), HostsTableIter.Response.get(), HostsTableIter.Length);
						memcpy_s(Result + Length - sizeof(dns_record_opt), Length, HostsTableIter.Response.get(), HostsTableIter.Length);

					//Hosts load balancing
						if (ntohs(DNS_Header->Answer) > U16_NUM_ONE)
						{
							std::shared_ptr<dns_record_aaaa> DNS_AAAA_Temp(new dns_record_aaaa());
							memset(DNS_AAAA_Temp.get(), 0, sizeof(dns_record_aaaa));

						//Select a ramdom preferred result.
							std::uniform_int_distribution<int> RamdomDistribution(0, ntohs(DNS_Header->Answer) - 1U);
							size_t RamdomIndex = RamdomDistribution(*Parameter.RamdomEngine);
							if (RamdomIndex > 0)
							{
//								memcpy(DNS_AAAA_Temp.get(), Result + Length - sizeof(dns_record_opt), sizeof(dns_record_aaaa));
								memcpy_s(DNS_AAAA_Temp.get(), sizeof(dns_record_aaaa), Result + Length - sizeof(dns_record_opt), sizeof(dns_record_aaaa));
								memset(Result + Length - sizeof(dns_record_opt), 0, sizeof(dns_record_aaaa));
//								memcpy(Result + Length - sizeof(dns_record_opt), Result + Length - sizeof(dns_record_opt) + sizeof(dns_record_aaaa) * RamdomIndex, sizeof(dns_record_aaaa));
								memcpy_s(Result + Length - sizeof(dns_record_opt), ResultSize, Result + Length - sizeof(dns_record_opt) + sizeof(dns_record_aaaa) * RamdomIndex, sizeof(dns_record_aaaa));
								memset(Result + Length - sizeof(dns_record_opt) + sizeof(dns_record_aaaa) * RamdomIndex, 0, sizeof(dns_record_aaaa));
//								memcpy(Result + Length - sizeof(dns_record_opt) + sizeof(dns_record_aaaa) * RamdomIndex, DNS_AAAA_Temp.get(), sizeof(dns_record_aaaa));
								memcpy_s(Result + Length - sizeof(dns_record_opt) + sizeof(dns_record_aaaa) * RamdomIndex, ResultSize, DNS_AAAA_Temp.get(), sizeof(dns_record_aaaa));
							}
						}

					//Different result.
						if (!Parameter.EDNS0Label)
						{
							auto DNS_Record_OPT = (pdns_record_opt)(Result + Length - sizeof(dns_record_opt) + HostsTableIter.Length);
							DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
							DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);

						//DNSSEC
							if (Parameter.DNSSECRequest)
								DNS_Record_OPT->Z_Bits.DO = ~DNS_Record_OPT->Z_Bits.DO; //Accepts DNSSEC security Resource Records

							return Length + HostsTableIter.Length;
						}
						else {
							return Length - sizeof(dns_record_opt) + HostsTableIter.Length;
						}
					}
					else {
						DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8000); //Set 1000000000000000, DNS_SQR_NE
						DNS_Header->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_record_aaaa)));
//						memcpy(Result + Length, HostsTableIter.Response.get(), HostsTableIter.Length);
						memcpy_s(Result + Length, ResultSize, HostsTableIter.Response.get(), HostsTableIter.Length);
						
					//Hosts load balancing
						if (ntohs(DNS_Header->Answer) > U16_NUM_ONE)
						{
							std::shared_ptr<dns_record_aaaa> DNS_AAAA_Temp(new dns_record_aaaa());
							memset(DNS_AAAA_Temp.get(), 0, sizeof(dns_record_aaaa));

						//Select a ramdom preferred result.
							std::uniform_int_distribution<int> RamdomDistribution(0, ntohs(DNS_Header->Answer) - 1U);
							size_t RamdomIndex = RamdomDistribution(*Parameter.RamdomEngine);
							if (RamdomIndex > 0)
							{
//								memcpy(DNS_AAAA_Temp.get(), Result + Length, sizeof(dns_record_aaaa));
								memcpy_s(DNS_AAAA_Temp.get(), sizeof(dns_record_aaaa), Result + Length, sizeof(dns_record_aaaa));
								memset(Result + Length, 0, sizeof(dns_record_aaaa));
//								memcpy(Result + Length, Result + Length + sizeof(dns_record_aaaa) * RamdomIndex, sizeof(dns_record_aaaa));
								memcpy_s(Result + Length, ResultSize, Result + Length + sizeof(dns_record_aaaa) * RamdomIndex, sizeof(dns_record_aaaa));
								memset(Result + Length + sizeof(dns_record_aaaa) * RamdomIndex, 0, sizeof(dns_record_aaaa));
//								memcpy(Result + Length + sizeof(dns_record_aaaa) * RamdomIndex, DNS_AAAA_Temp.get(), sizeof(dns_record_aaaa));
								memcpy_s(Result + Length + sizeof(dns_record_aaaa) * RamdomIndex, ResultSize, DNS_AAAA_Temp.get(), sizeof(dns_record_aaaa));
							}
						}

						return Length + HostsTableIter.Length;
					}
				}
				else if (DNS_Query->Type == htons(DNS_RECORD_A) && HostsTableIter.Protocol == AF_INET)
				{
				//EDNS0 Lebal
					if (DNS_Header->Additional == htons(U16_NUM_ONE))
					{
						memset(Result + Length - sizeof(dns_record_opt), 0, sizeof(dns_record_opt));
						DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8000); //Set 1000000000000000, DNS_SQR_NE
						DNS_Header->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_record_a)));
//						memcpy(Result + Length - sizeof(dns_record_opt), HostsTableIter.Response.get(), HostsTableIter.Length);
						memcpy_s(Result + Length - sizeof(dns_record_opt), ResultSize, HostsTableIter.Response.get(), HostsTableIter.Length);

					//Hosts load balancing
						if (ntohs(DNS_Header->Answer) > U16_NUM_ONE)
						{
							std::shared_ptr<dns_record_a> DNS_A_Temp(new dns_record_a());
							memset(DNS_A_Temp.get(), 0, sizeof(dns_record_a));

						//Select a ramdom preferred result.
							std::uniform_int_distribution<int> RamdomDistribution(0, ntohs(DNS_Header->Answer) - 1U);
							size_t RamdomIndex = RamdomDistribution(*Parameter.RamdomEngine);
							if (RamdomIndex > 0)
							{
//								memcpy(DNS_A_Temp.get(), Result + Length - sizeof(dns_record_opt), sizeof(dns_record_a));
								memcpy_s(DNS_A_Temp.get(), sizeof(dns_record_a), Result + Length - sizeof(dns_record_opt), sizeof(dns_record_a));
								memset(Result + Length - sizeof(dns_record_opt), 0, sizeof(dns_record_a));
//								memcpy(Result + Length - sizeof(dns_record_opt), Result + Length - sizeof(dns_record_opt) + sizeof(dns_record_a) * RamdomIndex, sizeof(dns_record_a));
								memcpy_s(Result + Length - sizeof(dns_record_opt), ResultSize, Result + Length - sizeof(dns_record_opt) + sizeof(dns_record_a) * RamdomIndex, sizeof(dns_record_a));
								memset(Result + Length - sizeof(dns_record_opt) + sizeof(dns_record_a) * RamdomIndex, 0, sizeof(dns_record_a));
//								memcpy(Result + Length - sizeof(dns_record_opt) + sizeof(dns_record_a) * RamdomIndex, DNS_A_Temp.get(), sizeof(dns_record_a));
								memcpy_s(Result + Length - sizeof(dns_record_opt) + sizeof(dns_record_a) * RamdomIndex, ResultSize, DNS_A_Temp.get(), sizeof(dns_record_a));
							}
						}

					//Different result.
						if (!Parameter.EDNS0Label)
						{
							auto DNS_Record_OPT = (pdns_record_opt)(Result + Length - sizeof(dns_record_opt) + HostsTableIter.Length);
							DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
							DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);

						//DNSSEC
							if (Parameter.DNSSECRequest)
								DNS_Record_OPT->Z_Bits.DO = ~DNS_Record_OPT->Z_Bits.DO; //Accepts DNSSEC security Resource Records

							return Length + HostsTableIter.Length;
						}
						else {
							return Length - sizeof(dns_record_opt) + HostsTableIter.Length;
						}
					}
					else {
						DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8000); //Set 1000000000000000, DNS_SQR_NE
						DNS_Header->Answer = htons((uint16_t)(HostsTableIter.Length / sizeof(dns_record_a)));
//						memcpy(Result + Length, HostsTableIter.Response.get(), HostsTableIter.Length);
						memcpy_s(Result + Length, ResultSize, HostsTableIter.Response.get(), HostsTableIter.Length);

					//Hosts load balancing
						if (ntohs(DNS_Header->Answer) > U16_NUM_ONE)
						{
							std::shared_ptr<dns_record_a> DNS_A_Temp(new dns_record_a());
							memset(DNS_A_Temp.get(), 0, sizeof(dns_record_a));

						//Select a ramdom preferred result.
							std::uniform_int_distribution<int> RamdomDistribution(0, ntohs(DNS_Header->Answer) - 1U);
							size_t RamdomIndex = RamdomDistribution(*Parameter.RamdomEngine);
							if (RamdomIndex > 0)
							{
//								memcpy(DNS_A_Temp.get(), Result + Length, sizeof(dns_record_a));
								memcpy_s(DNS_A_Temp.get(), sizeof(dns_record_a), Result + Length, sizeof(dns_record_a));
								memset(Result + Length, 0, sizeof(dns_record_a));
//								memcpy(Result + Length, Result + Length + sizeof(dns_record_a) * RamdomIndex, sizeof(dns_record_a));
								memcpy_s(Result + Length, ResultSize, Result + Length + sizeof(dns_record_a) * RamdomIndex, sizeof(dns_record_a));
								memset(Result + Length + sizeof(dns_record_a) * RamdomIndex, 0, sizeof(dns_record_a));
//								memcpy(Result + Length + sizeof(dns_record_a) * RamdomIndex, DNS_A_Temp.get(), sizeof(dns_record_a));
								memcpy_s(Result + Length + sizeof(dns_record_a) * RamdomIndex, ResultSize, DNS_A_Temp.get(), sizeof(dns_record_a));
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
	for (auto DNSCacheDataIter:DNSCacheList)
	{
		if (Domain == DNSCacheDataIter.Domain && DNS_Query->Type == DNSCacheDataIter.RecordType)
//			(DNS_Query->Type == htons(DNS_RECORD_AAAA) && DNSCacheDataIter.Protocol == AF_INET6 || 
//			DNS_Query->Type == htons(DNS_RECORD_A) && DNSCacheDataIter.Protocol == AF_INET))
		{
			memset(Result + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
//			memcpy(Result + sizeof(uint16_t), DNSCacheDataIter.Response.get(), DNSCacheDataIter.Length);
			memcpy_s(Result + sizeof(uint16_t), ResultSize - sizeof(uint16_t), DNSCacheDataIter.Response.get(), DNSCacheDataIter.Length);

			return DNSCacheDataIter.Length + sizeof(uint16_t);
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
size_t __fastcall LocalRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA LocalSocketData)
{
	size_t DataLength = 0;

//TCP Mode
	if (Parameter.RequestMode == REQUEST_TCPMODE)
	{
/* Old version(2015-03-05)
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), true, AlternateSwapList.IsSwap[4U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[4U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0)
				AlternateSwapList.TimeoutTimes[4U]++;
		}
		else { //IPv4
			DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), true, AlternateSwapList.IsSwap[5U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[5U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0)
				AlternateSwapList.TimeoutTimes[5U]++;
		}
*/
		DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), true);

	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE && DataLength < LARGE_PACKET_MAXSIZE)
		{
			SendToRequester(OriginalRecv, DataLength, Protocol, LocalSocketData);
			return EXIT_SUCCESS;
		}
	}
		
//UDP Mode(REQUEST_UDPMODE)
	if (Protocol == IPPROTO_TCP) //TCP requesting
	{
/* Old version(2015-03-05)
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), true, AlternateSwapList.IsSwap[6U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[6U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0)
				AlternateSwapList.TimeoutTimes[6U]++;
		}
		else { //IPv4
			DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), true, AlternateSwapList.IsSwap[7U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[7U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0)
				AlternateSwapList.TimeoutTimes[7U]++;
		}
*/
		DataLength = LARGE_PACKET_MAXSIZE - sizeof(uint16_t);
	}
//UDP requesting
	else {
/* Old version(2015-03-05)
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, true, AlternateSwapList.IsSwap[6U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[6U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0)
				AlternateSwapList.TimeoutTimes[6U]++;
		}
		else { //IPv4
			DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, true, AlternateSwapList.IsSwap[7U]);

		//Check timeout.
			if (!AlternateSwapList.IsSwap[7U] && DataLength == WSAETIMEDOUT && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0)
				AlternateSwapList.TimeoutTimes[7U]++;
		}
*/
		DataLength = PACKET_MAXSIZE;
	}

	DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, DataLength, true);

//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && (DataLength < PACKET_MAXSIZE || Protocol == IPPROTO_TCP && DataLength < LARGE_PACKET_MAXSIZE))
	{
		SendToRequester(OriginalRecv, DataLength, Protocol, LocalSocketData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(Direct connections part)
size_t __fastcall DirectRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA LocalSocketData)
{
	size_t DataLength = 0;

//TCP Mode
	if (Parameter.RequestMode == REQUEST_TCPMODE)
	{
	//Multi requesting.
		if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
		{
			DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t));
		}
	//Normal requesting
		else {
/* Old version(2015-03-05)
			if (Parameter.MultiRequestTimes > 1U)
			{
				if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
					DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), AlternateSwapList.IsSwap[0]);
				else //IPv4
					DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), AlternateSwapList.IsSwap[1U]);

				DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t));
			}
			else {
				if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
					DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), false, AlternateSwapList.IsSwap[0]);
				else //IPv4
					DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), false, AlternateSwapList.IsSwap[1U]);
			}
*/
			DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), false);
		}

/* Old version(2015-03-05)
	//Check timeout.
		if (DataLength == WSAETIMEDOUT)
		{
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.IsSwap[0] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
				AlternateSwapList.TimeoutTimes[0]++;
			else if (LocalSocketData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.IsSwap[1U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
				AlternateSwapList.TimeoutTimes[1U]++;
		}
*/
	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE && DataLength < LARGE_PACKET_MAXSIZE)
		{
			SendToRequester(OriginalRecv, DataLength, Protocol, LocalSocketData);
			return EXIT_SUCCESS;
		}
	}

//UDP Mode(REQUEST_UDPMODE)
	if (Protocol == IPPROTO_TCP) //TCP requesting
		DataLength = LARGE_PACKET_MAXSIZE - sizeof(uint16_t);
	else //UDP requesting
		DataLength = PACKET_MAXSIZE;

//Multi requesting.
	if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
	{
		DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, DataLength);
	}
//Normal requesting
	else {
/* Old version(2015-03-05)
		if (Parameter.MultiRequestTimes > 1U)
		{
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				if (Protocol == IPPROTO_TCP) //TCP requesting
					DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), AlternateSwapList.IsSwap[2U]);
				else //UDP requesting
					DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, AlternateSwapList.IsSwap[2U]);
			}
			else { //IPv4
				if (Protocol == IPPROTO_TCP) //TCP requesting
					DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), AlternateSwapList.IsSwap[3U]);
				else //UDP requesting
					DataLength = UDPCompleteRequestMulti(OriginalSend, SendSize, OriginalRecv, PACKET_MAXSIZE, AlternateSwapList.IsSwap[3U]);
			}
		}
		else {
			if (Protocol == IPPROTO_TCP) //TCP requesting
				DataLength = LARGE_PACKET_MAXSIZE - sizeof(uint16_t);
			else //UDP requesting
				DataLength = PACKET_MAXSIZE;
		}
*/
		DataLength = UDPCompleteRequest(OriginalSend, SendSize, OriginalRecv, DataLength, false);
	}

/* Old version(2015-03-05)
//Check timeout.
	if (DataLength == WSAETIMEDOUT)
	{
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.IsSwap[2U] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
			AlternateSwapList.TimeoutTimes[2U]++;
		else if (LocalSocketData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.IsSwap[3U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
			AlternateSwapList.TimeoutTimes[3U]++;
	}
*/
//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && (DataLength < PACKET_MAXSIZE || Protocol == IPPROTO_TCP && DataLength < LARGE_PACKET_MAXSIZE))
	{
		SendToRequester(OriginalRecv, DataLength, Protocol, LocalSocketData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(DNSCurve part)
size_t __fastcall DNSCurveRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA LocalSocketData)
{
	size_t DataLength = 0;

//TCP requesting
	if (Protocol == IPPROTO_TCP || DNSCurveParameter.DNSCurveMode == DNSCURVE_REQUEST_TCPMODE)
	{
	//Multi requesting.
		if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
			DataLength = DNSCurveTCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t));
	//Normal requesting
		else 
			DataLength = DNSCurveTCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t));

/* Old version(2015-03-05)
	//Check timeout.
		if (DataLength == WSAETIMEDOUT)
		{
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.IsSwap[0] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
				AlternateSwapList.TimeoutTimes[8U]++;
			else if (LocalSocketData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.IsSwap[1U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
				AlternateSwapList.TimeoutTimes[9U]++;
		}
*/
	//Send response.
		if (DataLength >= DNS_PACKET_MINSIZE && DataLength < LARGE_PACKET_MAXSIZE)
		{
			SendToRequester(OriginalRecv, DataLength, Protocol, LocalSocketData);
			return EXIT_SUCCESS;
		}
	}

//UDP Mode(REQUEST_UDPMODE)
	if (Protocol == IPPROTO_TCP) //TCP requesting
		DataLength = LARGE_PACKET_MAXSIZE - sizeof(uint16_t);
	else //UDP requesting
		DataLength = PACKET_MAXSIZE;

//Multi requesting.
	if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
		DataLength = DNSCurveUDPRequestMulti(OriginalSend, SendSize, OriginalRecv, DataLength);
	//Normal requesting
	else 
		DataLength = DNSCurveUDPRequest(OriginalSend, SendSize, OriginalRecv, DataLength);

/* Old version(2015-03-05)
//Check timeout.
	if (DataLength == WSAETIMEDOUT)
	{
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.IsSwap[10U] && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
			AlternateSwapList.TimeoutTimes[10U]++;
		else if (LocalSocketData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.IsSwap[11U] && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
			AlternateSwapList.TimeoutTimes[11U]++;
	}
*/
//Send response.
	if (DataLength >= DNS_PACKET_MINSIZE && (DataLength < PACKET_MAXSIZE || Protocol == IPPROTO_TCP && DataLength < LARGE_PACKET_MAXSIZE))
	{
		SendToRequester(OriginalRecv, DataLength, Protocol, LocalSocketData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(TCP part)
size_t __fastcall TCPRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA LocalSocketData)
{
	size_t DataLength = 0;

//Multi requesting.
	if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
	{
		DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t));
	}
//Normal requesting
	else {
/* Old version(2015-03-05)
		if (Parameter.MultiRequestTimes > 1U)
		{
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), AlternateSwapList.IsSwap[0]);
			else //IPv4
				DataLength = TCPRequestMulti(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), AlternateSwapList.IsSwap[1U]);
		}
		else {
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), false, AlternateSwapList.IsSwap[0]);
			else //IPv4
				DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), false, AlternateSwapList.IsSwap[1U]);
		}
*/
		DataLength = TCPRequest(OriginalSend, SendSize, OriginalRecv, LARGE_PACKET_MAXSIZE - sizeof(uint16_t), false);
	}

/* Old version(2015-03-05)
//Check timeout.
	if (DataLength == WSAETIMEDOUT)
	{
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6) && !AlternateSwapList.IsSwap[0] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
			AlternateSwapList.TimeoutTimes[0]++;
		else if (LocalSocketData.AddrLen == sizeof(sockaddr_in) && !AlternateSwapList.IsSwap[1U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
			AlternateSwapList.TimeoutTimes[1U]++;
	}
*/
//Send response.
	if (DataLength >= sizeof(uint16_t) + DNS_PACKET_MINSIZE && DataLength < LARGE_PACKET_MAXSIZE)
	{
	//EDNS0 Label
		auto DNS_Header = (pdns_hdr)OriginalSend;
		if (Protocol == IPPROTO_UDP && DNS_Header->Additional > 0)
		{
			DNS_Header = (pdns_hdr)OriginalRecv;
			DNS_Header->Additional = htons(U16_NUM_ONE);
			auto DNS_Record_OPT = (pdns_record_opt)(OriginalRecv + DataLength);
			DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
			DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);

		//DNSSEC
			if (Parameter.DNSSECRequest)
			{
				DNS_Header->FlagsBits.AD = ~DNS_Header->FlagsBits.AD; //Local DNSSEC Server validate
				DNS_Header->FlagsBits.CD = ~DNS_Header->FlagsBits.CD; //Client validate
				DNS_Record_OPT->Z_Bits.DO = ~DNS_Record_OPT->Z_Bits.DO; //Accepts DNSSEC security Resource Records
			}

			DataLength += sizeof(dns_record_opt);
		}

		SendToRequester(OriginalRecv, DataLength, Protocol, LocalSocketData);
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

//Request Process(UDP part)
size_t __fastcall UDPRequestProcess(const PSTR OriginalSend, const size_t SendSize, const SOCKET_DATA LocalSocketData, const uint16_t Protocol /* , const size_t ListIndex */ )
{
/* Old version(2015-03-18)
//Mark requesting data
	PortList.RecvData[ListIndex] = LocalSocketData;
	PortList.SendData[ListIndex].clear();
*/

//Multi requesting.
	if (Parameter.AlternateMultiRequest || Parameter.MultiRequestTimes > 1U)
	{
		UDPRequestMulti(OriginalSend, SendSize, &LocalSocketData, Protocol /* , ListIndex */ );
	}
//Normal requesting
	else {
/* Old version(2015-03-05)
		if (Parameter.MultiRequestTimes > 1U)
		{
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				UDPRequestMulti(OriginalSend, SendSize, ListIndex, AlternateSwapList.IsSwap[2U]);
			else //IPv4
				UDPRequestMulti(OriginalSend, SendSize, ListIndex, AlternateSwapList.IsSwap[3U]);
		}
		else {
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				UDPRequest(OriginalSend, SendSize, ListIndex, AlternateSwapList.IsSwap[2U]);
			else //IPv4
				UDPRequest(OriginalSend, SendSize, ListIndex, AlternateSwapList.IsSwap[3U]);
		}
*/
		UDPRequest(OriginalSend, SendSize, &LocalSocketData, Protocol /* , ListIndex */ );
	}

//Fin TCP request connection.
	if (Protocol == IPPROTO_TCP && LocalSocketData.Socket != INVALID_SOCKET)
	{
		shutdown(LocalSocketData.Socket, SD_BOTH);
		closesocket(LocalSocketData.Socket);
	}

	return EXIT_SUCCESS;
}

//Send responses to requester
size_t __fastcall SendToRequester(PSTR RecvBuffer, const size_t RecvSize, const uint16_t Protocol, const SOCKET_DATA LocalSocketData)
{
//TCP
	if (Protocol == IPPROTO_TCP)
	{
		if (AddLengthToTCPDNSHeader(RecvBuffer, RecvSize, LARGE_PACKET_MAXSIZE) == EXIT_FAILURE)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
			return EXIT_FAILURE;
		}

		send(LocalSocketData.Socket, RecvBuffer, (int)(RecvSize + sizeof(uint16_t)), 0);
		shutdown(LocalSocketData.Socket, SD_BOTH);
		closesocket(LocalSocketData.Socket);
	}
//UDP
	else {
		sendto(LocalSocketData.Socket, RecvBuffer, (int)RecvSize, 0, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen);
	}

	return EXIT_SUCCESS;
}

//Mark responses to domains Cache
size_t __fastcall MarkDomainCache(const PSTR Buffer, const size_t Length)
{
//Check conditions.
	auto DNS_Header = (pdns_hdr)Buffer;
	if (DNS_Header->Questions != htons(U16_NUM_ONE) || //No any Question Record in responses
		DNS_Header->Answer == 0 && DNS_Header->Authority == 0 && DNS_Header->Additional == 0) //No any Resource Records 
			return EXIT_FAILURE; 

//Initialization(A part)
	DNSCACHE_DATA DNSCacheDataTemp;
	DNSCacheDataTemp.Length = 0;
	DNSCacheDataTemp.ClearCacheTime = 0;
	auto DNS_Query = (pdns_qry)(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer));
	DNSCacheDataTemp.RecordType = DNS_Query->Type;
	uint32_t ResponseTTL = 0;

//Mark DNS A records and AAAA records only.
	if (DNSCacheDataTemp.RecordType == htons(DNS_RECORD_AAAA) || DNSCacheDataTemp.RecordType == htons(DNS_RECORD_A))
	{
		size_t DataLength = DNS_PACKET_RR_LOCATE(Buffer);
		pdns_record_standard DNS_Record_Standard = nullptr;
		size_t TTLCount = 0;

	//Scan all results.
		for (size_t Index = 0;Index < (size_t)(ntohs(DNS_Header->Answer) + ntohs(DNS_Header->Authority) + ntohs(DNS_Header->Additional));Index++)
		{
		//Resource Records Name(domain)
			DataLength += CheckDNSQueryNameLength(Buffer + DataLength) + 1U;
		//Length check
			if (DataLength > Length)
				break;

		//Standard Resource Records
			DNS_Record_Standard = (pdns_record_standard)(Buffer + DataLength);
			DataLength += sizeof(dns_record_standard);
		//Length check
			if (DataLength > Length)
				break;

		//Resource Records Data
			if (DNS_Record_Standard->Classes == htons(DNS_CLASS_IN) && DNS_Record_Standard->TTL > 0 && 
				(DNS_Record_Standard->Type == htons(DNS_RECORD_AAAA) && DNS_Record_Standard->Length == htons(sizeof(in6_addr)) || 
				DNS_Record_Standard->Type == htons(DNS_RECORD_A) && DNS_Record_Standard->Length == htons(sizeof(in_addr))))
			{
				ResponseTTL += ntohl(DNS_Record_Standard->TTL);
				TTLCount++;
			}

			DataLength += ntohs(DNS_Record_Standard->Length);
		//Length check
			if (DataLength > Length)
				break;
		}

		if (TTLCount > 0)
			ResponseTTL = ResponseTTL / (uint32_t)TTLCount + ResponseTTL % (uint32_t)TTLCount;
	}

//Set cache TTL(Not any A or AAAA answers).
	if (ResponseTTL == 0)
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
		memset(DNSCacheDataBufferTemp.get(), 0, DOMAIN_MAXSIZE);
		DNSCacheDataTemp.Response.swap(DNSCacheDataBufferTemp);
	}
	else {
		std::shared_ptr<char> DNSCacheDataBufferTemp(new char[Length]());
		memset(DNSCacheDataBufferTemp.get(), 0, Length);
		DNSCacheDataTemp.Response.swap(DNSCacheDataBufferTemp);
	}

//Mark to global list.
	if (DNSQueryToChar(Buffer + sizeof(dns_hdr), DNSCacheDataTemp.Response.get()) > DOMAIN_MINSIZE)
	{
	//Domain Case Conversion
//		CaseConvert(false, DNSCacheDataTemp.Response.get(), strlen(DNSCacheDataTemp.Response.get()));
		CaseConvert(false, DNSCacheDataTemp.Response.get(), strnlen_s(DNSCacheDataTemp.Response.get(), DOMAIN_MAXSIZE));
		DNSCacheDataTemp.Domain = DNSCacheDataTemp.Response.get();
		memset(DNSCacheDataTemp.Response.get(), 0, DOMAIN_MAXSIZE);
//		memcpy(DNSCacheDataTemp.Response.get(), Buffer + sizeof(uint16_t), Length - sizeof(uint16_t));
		memcpy_s(DNSCacheDataTemp.Response.get(), PACKET_MAXSIZE, Buffer + sizeof(uint16_t), Length - sizeof(uint16_t));
		DNSCacheDataTemp.Length = Length - sizeof(uint16_t);

	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
	#ifdef _WIN64
		DNSCacheDataTemp.ClearCacheTime = GetTickCount64() + ResponseTTL * SECOND_TO_MILLISECOND;
	#else //x86
		if (Parameter.GetTickCount64PTR != nullptr)
			DNSCacheDataTemp.ClearCacheTime = (size_t)((*Parameter.GetTickCount64PTR)() + ResponseTTL * SECOND_TO_MILLISECOND);
		else 
			DNSCacheDataTemp.ClearCacheTime = GetTickCount() + ResponseTTL * SECOND_TO_MILLISECOND;
	#endif

		std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	//Check repeating items, delete duque rear and add new item to deque front.
		for (auto DNSCacheDataIter = DNSCacheList.begin();DNSCacheDataIter != DNSCacheList.end();DNSCacheDataIter++)
		{
			if (DNSCacheDataTemp.Domain == DNSCacheDataIter->Domain && DNSCacheDataTemp.RecordType == DNSCacheDataIter->RecordType)
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
		else { //CACHE_TIMER
		//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
		#ifdef _WIN64
			while (!DNSCacheList.empty() && GetTickCount64() >= DNSCacheList.front().ClearCacheTime)
		#else //x86
			while (!DNSCacheList.empty() && (Parameter.GetTickCount64PTR != nullptr && (*Parameter.GetTickCount64PTR)() >= DNSCacheList.front().ClearCacheTime || 
				GetTickCount() >= DNSCacheList.front().ClearCacheTime))
		#endif
				DNSCacheList.pop_front();
		}

		DNSCacheList.push_back(DNSCacheDataTemp);
		DNSCacheList.shrink_to_fit();
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}
