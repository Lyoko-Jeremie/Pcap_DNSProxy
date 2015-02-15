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


#include "Main.h"

extern ConfigurationTable Parameter;
extern PortTable PortList;
extern AlternateSwapTable AlternateSwapList;
extern std::mutex PortListLock;

//Get TTL(IPv4)/Hop Limits(IPv6) with normal DNS request
size_t __fastcall DomainTestRequest(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE]()), DNSQuery(new char[PACKET_MAXSIZE]());
	std::shared_ptr<SOCKET_DATA> TargetData(new SOCKET_DATA());

//Set request protocol.
	if (Protocol == AF_INET6) //IPv6
		TargetData->AddrLen = sizeof(sockaddr_in6);
	else //IPv4
		TargetData->AddrLen = sizeof(sockaddr_in);

//Make a DNS request with Doamin Test packet.
	auto DNS_Header = (pdns_hdr)Buffer.get();
	DNS_Header->ID = Parameter.DomainTestID;
	DNS_Header->Flags = htons(DNS_STANDARD);
	DNS_Header->Questions = htons(U16_NUM_ONE);
	size_t DataLength = 0;

//Convert domain.
	pdns_qry DNS_Query = nullptr;
	if (Parameter.DomainTestData != nullptr)
	{
		DataLength = CharToDNSQuery(Parameter.DomainTestData, DNSQuery.get());
		if (DataLength > 2U && DataLength < PACKET_MAXSIZE - sizeof(dns_hdr))
		{
			memcpy(Buffer.get() + sizeof(dns_hdr), DNSQuery.get(), DataLength);
			DNS_Query = (pdns_qry)(Buffer.get() + sizeof(dns_hdr) + DataLength);
			DNS_Query->Classes = htons(DNS_CLASS_IN);
			if (Protocol == AF_INET6) //IPv6
				DNS_Query->Type = htons(DNS_RECORD_AAAA);
			else //IPv4
				DNS_Query->Type = htons(DNS_RECORD_A);
			DNSQuery.reset();
			DataLength += sizeof(dns_qry);

		//EDNS0 Label
			if (Parameter.EDNS0Label) //No additional
			{
				auto DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + sizeof(dns_hdr) + DataLength);
				DNS_Header->Additional = htons(U16_NUM_ONE);
				DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
				DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				DataLength += sizeof(dns_record_opt);
			}
		}
		else {
			return EXIT_FAILURE;
		}
	}
	DataLength += sizeof(dns_hdr);

//Send requesting.
	size_t Times = 0;
	auto IsIsReTest = false;

/* Old version(2014-12-09)
	UDP_REQUEST_MULTITHREAD_PARAMETER UDPRequestParameter = {Buffer.get(), 0, *TargetData, QUEUE_MAXLEN * QUEUE_PARTNUM, 3U};
	for (;;)
	{
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			IsReTest = false;
			if (Protocol == AF_INET6) //IPv6
			{
				if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0 || //IPv6 Main
					Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0) //IPv6 Alternate
						IsReTest = true;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv6_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
						{
							IsReTest = true;
							break;
						}
					}
				}
			}
			else { //IPv4
				if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0 || //IPv4 Main
					Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0) //IPv4 Alternate
						IsReTest = true;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv4_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
						{
							IsReTest = true;
							break;
						}
					}
				}
			}

			if (IsReTest)
			{
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND); //5 seconds between every sending.
				continue;
			}

			Sleep((DWORD)Parameter.DomainTestSpeed);
		}
		else {
		//Main
			if (Parameter.DomainTestData == nullptr) //Make ramdom domain request.
			{
				memset(Buffer.get() + sizeof(dns_hdr), 0, PACKET_MAXSIZE - sizeof(dns_hdr));
				MakeRamdomDomain(DNSQuery.get());
				DataLength = CharToDNSQuery(DNSQuery.get(), Buffer.get() + sizeof(dns_hdr));
				memset(DNSQuery.get(), 0, DOMAIN_MAXSIZE);
				
				DNS_Query = (pdns_qry)(Buffer.get() + sizeof(dns_hdr) + DataLength);
				DNS_Query->Classes = htons(DNS_CLASS_IN);
				if (Protocol == AF_INET6) //IPv6
					DNS_Query->Type = htons(DNS_RECORD_AAAA);
				else //IPv4
					DNS_Query->Type = htons(DNS_RECORD_A);
				DataLength += sizeof(dns_hdr) + sizeof(dns_qry);

			//EDNS0 Label
				if (Parameter.EDNS0Label) //No additional
				{
					DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + DataLength);
					DNS_Header->Additional = htons(U16_NUM_ONE);
					DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
					DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					DataLength += sizeof(dns_record_opt);
				}
			}
			UDPRequest(Buffer.get(), DataLength, *TargetData, QUEUE_MAXLEN * QUEUE_PARTNUM, false);

		//Alternate
			if (Parameter.DomainTestData == nullptr) //Make ramdom domain request.
			{
				memset(Buffer.get() + sizeof(dns_hdr), 0, PACKET_MAXSIZE - sizeof(dns_hdr));
				MakeRamdomDomain(DNSQuery.get());
				DataLength = CharToDNSQuery(DNSQuery.get(), Buffer.get() + sizeof(dns_hdr));
				memset(DNSQuery.get(), 0, DOMAIN_MAXSIZE);
				
				DNS_Query = (pdns_qry)(Buffer.get() + sizeof(dns_hdr) + DataLength);
				DNS_Query->Classes = htons(DNS_CLASS_IN);
				if (Protocol == AF_INET6)
					DNS_Query->Type = htons(DNS_RECORD_AAAA);
				else 
					DNS_Query->Type = htons(DNS_RECORD_A);
				DataLength += sizeof(dns_hdr) + sizeof(dns_qry);

			//EDNS0 Label
				if (Parameter.EDNS0Label) //No additional
				{
					DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + DataLength);
					DNS_Header->Additional = htons(U16_NUM_ONE);
					DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
					DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					DataLength += sizeof(dns_record_opt);
				}
			}
			UDPRequest(Buffer.get(), DataLength, *TargetData, QUEUE_MAXLEN * QUEUE_PARTNUM, true);

		//Other(Multi)
			if (Protocol == AF_INET6 && Parameter.DNSTarget.IPv6_Multi != nullptr) //IPv6
			{
				for (size_t Index = 0;Index < Parameter.DNSTarget.IPv6_Multi->size();Index++)
				{
					if (Parameter.DomainTestData == nullptr) //Make ramdom domain request.
					{
						memset(Buffer.get() + sizeof(dns_hdr), 0, PACKET_MAXSIZE - sizeof(dns_hdr));
						MakeRamdomDomain(DNSQuery.get());
						DataLength = CharToDNSQuery(DNSQuery.get(), Buffer.get() + sizeof(dns_hdr));
						memset(DNSQuery.get(), 0, DOMAIN_MAXSIZE);
				
						DNS_Query = (pdns_qry)(Buffer.get() + sizeof(dns_hdr) + DataLength);
						DNS_Query->Classes = htons(DNS_CLASS_IN);
						DNS_Query->Type = htons(DNS_RECORD_AAAA);
						DataLength += sizeof(dns_hdr) + sizeof(dns_qry);

					//EDNS0 Label
						if (Parameter.EDNS0Label) //No additional
						{
							DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + DataLength);
							DNS_Header->Additional = htons(U16_NUM_ONE);
							DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
							DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
							DataLength += sizeof(dns_record_opt);
						}
					}

					UDPRequestParameter.ServerIndex = Index + 3U;
					UDPRequestParameter.Length = DataLength;
					UDPRequestMulti(UDPRequestParameter);
				}
			}
			else if (Parameter.DNSTarget.IPv4_Multi != nullptr) //IPv4
			{
				for (size_t Index = 0;Index < Parameter.DNSTarget.IPv4_Multi->size();Index++)
				{
					if (Parameter.DomainTestData == nullptr) //Make ramdom domain request.
					{
						memset(Buffer.get() + sizeof(dns_hdr), 0, PACKET_MAXSIZE - sizeof(dns_hdr));
						MakeRamdomDomain(DNSQuery.get());
						DataLength = CharToDNSQuery(DNSQuery.get(), Buffer.get() + sizeof(dns_hdr));
						memset(DNSQuery.get(), 0, DOMAIN_MAXSIZE);
				
						DNS_Query = (pdns_qry)(Buffer.get() + sizeof(dns_hdr) + DataLength);
						DNS_Query->Classes = htons(DNS_CLASS_IN);
						DNS_Query->Type = htons(DNS_RECORD_A);
						DataLength += sizeof(dns_hdr) + sizeof(dns_qry);

					//EDNS0 Label
						if (Parameter.EDNS0Label) //No additional
						{
							DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + DataLength);
							DNS_Header->Additional = htons(U16_NUM_ONE);
							DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
							DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
							DataLength += sizeof(dns_record_opt);
						}
					}

					UDPRequestParameter.ServerIndex = Index + 3U;
					UDPRequestParameter.Length = DataLength;
					UDPRequestMulti(UDPRequestParameter);
				}
			}

		//Repeat
			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			Times++;
		}
	}
*/
	for (;;)
	{
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			IsIsReTest = false;
			if (Protocol == AF_INET6) //IPv6
			{
				if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0) //Alternate
						IsIsReTest = true;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv6_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
						{
							IsIsReTest = true;
							break;
						}
					}
				}
			}
			else { //IPv4
				if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0) //Alternate
						IsIsReTest = true;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv4_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
						{
							IsIsReTest = true;
							break;
						}
					}
				}
			}

		//Test again.
			if (IsIsReTest)
			{
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}
			else {
				Sleep((DWORD)Parameter.DomainTestSpeed);
			}
		}
		else {
		//Make ramdom domain request.
			if (Parameter.DomainTestData == nullptr)
			{
				memset(Buffer.get() + sizeof(dns_hdr), 0, PACKET_MAXSIZE - sizeof(dns_hdr));
				MakeRamdomDomain(DNSQuery.get());
				DataLength = CharToDNSQuery(DNSQuery.get(), Buffer.get() + sizeof(dns_hdr));
				memset(DNSQuery.get(), 0, DOMAIN_MAXSIZE);

				DNS_Query = (pdns_qry)(Buffer.get() + sizeof(dns_hdr) + DataLength);
				DNS_Query->Classes = htons(DNS_CLASS_IN);
				if (Protocol == AF_INET6) //IPv6
					DNS_Query->Type = htons(DNS_RECORD_AAAA);
				else //IPv4
					DNS_Query->Type = htons(DNS_RECORD_A);
				DataLength += sizeof(dns_qry);

			//EDNS0 Label
				if (Parameter.EDNS0Label) //No additional
				{
					auto DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + sizeof(dns_hdr) + DataLength);
					DNS_Header->Additional = htons(U16_NUM_ONE);
					DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
					DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					DataLength += sizeof(dns_record_opt);
				}

				DataLength += sizeof(dns_hdr);
			}

		//Send.
			UDPRequestMulti(Buffer.get(), (int)DataLength, QUEUE_MAXLEN * QUEUE_PARTNUM, false);

		//Repeat.
			Times++;
			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
		}
	}

	PrintError(LOG_ERROR_SYSTEM, L"Domain Test module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Internet Control Message Protocol/ICMP Echo(Ping) request
size_t __fastcall ICMPEcho(void)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[sizeof(icmp_hdr) + Parameter.ICMPPaddingDataLength - 1U]());
	std::vector<sockaddr_storage> SockAddr;
	std::shared_ptr<sockaddr_storage> SockAddrTemp(new sockaddr_storage());

//Make a ICMP request echo packet.
	auto ICMP_Header = (picmp_hdr)Buffer.get();
	ICMP_Header->Type = ICMP_TYPE_REQUEST; //Echo(Ping) request type
	ICMP_Header->ID = Parameter.ICMPID;
	ICMP_Header->Sequence = Parameter.ICMPSequence;
	memcpy(Buffer.get() + sizeof(icmp_hdr), Parameter.ICMPPaddingData, Parameter.ICMPPaddingDataLength - 1U);
	ICMP_Header->Checksum = GetChecksum((PUINT16)Buffer.get(), sizeof(icmp_hdr) + Parameter.ICMPPaddingDataLength - 1U);
	SYSTEM_SOCKET ICMPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	//Main and Alternate
	SockAddrTemp->ss_family = AF_INET;
	((PSOCKADDR_IN)SockAddrTemp.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
	SockAddr.push_back(*SockAddrTemp);
	memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));
	if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
	{
		SockAddrTemp->ss_family = AF_INET;
		((PSOCKADDR_IN)SockAddrTemp.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
		SockAddr.push_back(*SockAddrTemp);
		memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));
	}

	//Other(Multi)
	if (Parameter.DNSTarget.IPv4_Multi != nullptr)
	{
		for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
		{
			SockAddrTemp->ss_family = AF_INET;
			((PSOCKADDR_IN)SockAddrTemp.get())->sin_addr = DNSServerDataIter.AddressData.IPv4.sin_addr;
			SockAddr.push_back(*SockAddrTemp);
			memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));
		}
	}

//Socket check
	if (ICMPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"ICMP Echo(Ping) request error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(ICMPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set ICMP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(ICMPSocket);

		return EXIT_FAILURE;
	}

//Send requesting.
	size_t Times = 0;
	auto IsReTest = false;
	for (;;)
	{
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			IsReTest = false;
			if (Parameter.DNSTarget.IPv4_Multi != nullptr) //Other(Multi)
			{
				for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
				{
					if (DNSServerDataIter.HopLimitData.TTL == 0)
					{
						IsReTest = true;
						break;
					}
				}
			}

			if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0 || //Main
				Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0 || //Alternate
				IsReTest) //Other(Multi)
			{
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}

			Sleep((DWORD)Parameter.ICMPSpeed);
		}

	//Send.
		for (auto HostsTableIter:SockAddr)
		{
			sendto(ICMPSocket, Buffer.get(), (int)(sizeof(icmp_hdr) + Parameter.ICMPPaddingDataLength - 1U), 0, (PSOCKADDR)&HostsTableIter, sizeof(sockaddr_in));

		//Increase Sequence.
			if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE))
			{
				if (ICMP_Header->Sequence == U16_MAXNUM)
					ICMP_Header->Sequence = htons(DEFAULT_SEQUENCE);
				else 
					ICMP_Header->Sequence = htons(ntohs(ICMP_Header->Sequence) + 1U);

				ICMP_Header->Checksum = 0;
				ICMP_Header->Checksum = GetChecksum((PUINT16)Buffer.get(), sizeof(icmp_hdr) + Parameter.ICMPPaddingDataLength - 1U);
			}
		}

	//Repeat.
		Times++;
		Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
	}

	closesocket(ICMPSocket);
	PrintError(LOG_ERROR_SYSTEM, L"ICMP Test module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Internet Control Message Protocol Echo version 6/ICMPv6 Echo(Ping) request
size_t __fastcall ICMPv6Echo(void)
{
//Initialization
	std::vector<std::shared_ptr<char>> Buffer;
	if (Parameter.DNSTarget.IPv6_Multi == nullptr)
	{
		std::vector<std::shared_ptr<char>> BufferTemp(2U);
		BufferTemp.swap(Buffer);
	}
	else {
		std::vector<std::shared_ptr<char>> BufferTemp(Parameter.DNSTarget.IPv6_Multi->size() + 2U);
		BufferTemp.swap(Buffer);
	}

//Make a ICMPv6 request echo packet.
	picmpv6_hdr ICMPv6_Header = nullptr;
	for (auto StringIter = Buffer.begin();StringIter != Buffer.end();StringIter++)
	{
		std::shared_ptr<char> BufferTemp(new char[sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U]());

		ICMPv6_Header = (picmpv6_hdr)BufferTemp.get();
		ICMPv6_Header->Type = ICMPV6_REQUEST;
		ICMPv6_Header->Code = 0;
		ICMPv6_Header->ID = Parameter.ICMPID;
		ICMPv6_Header->Sequence = Parameter.ICMPSequence;
		memcpy(BufferTemp.get() + sizeof(icmpv6_hdr), Parameter.ICMPPaddingData, Parameter.ICMPPaddingDataLength - 1U);
		BufferTemp.swap(*StringIter);
	}

//Get localhost IPv6 address.
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	auto LocalAddressTableIter = GetLocalAddressList(AF_INET6);
	if (LocalAddressTableIter == nullptr)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Get localhost addresses", 0, nullptr, 0);
		return EXIT_FAILURE;
	}
	else {
		if (LocalAddressTableIter->ai_family == AF_INET6 && LocalAddressTableIter->ai_addrlen == sizeof(sockaddr_in6))
			memcpy(SockAddr.get(), LocalAddressTableIter->ai_addr, sizeof(sockaddr_in6));
		freeaddrinfo(LocalAddressTableIter);
	}

//ICMP Sequence increase and calculate checksum.
	ICMPv6_Header = (picmpv6_hdr)Buffer.front().get();
	ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer.front().get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
	if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0)
	{
		Buffer.erase(Buffer.begin() + 1U);
	}
	else {
		ICMPv6_Header = (picmpv6_hdr)Buffer[1U].get();
		if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE))
			ICMPv6_Header->Sequence = htons(ntohs(Parameter.ICMPSequence) + 1U);
		ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer[1U].get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
	}

	//Multi requesting part.
	size_t Index = 0;
	for (Index = 2U;(SSIZE_T)Index < (SSIZE_T)(Buffer.size() - 2U);Index++)
	{
		ICMPv6_Header = (picmpv6_hdr)Buffer[Index].get();
		if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE))
			ICMPv6_Header->Sequence = htons((uint16_t)(ntohs(Parameter.ICMPSequence) + Index));
		ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer[Index].get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, Parameter.DNSTarget.IPv6_Multi->at(Index).AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
	}

//Socket check
	SYSTEM_SOCKET ICMPv6Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (ICMPv6Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"ICMPv6 Echo(Ping) request error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(ICMPv6Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set ICMPv6 socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(ICMPv6Socket);

		return EXIT_FAILURE;
	}

//Send requesting.
	size_t Times = 0;
	auto IsReTest = false;
	for (;;)
	{
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			IsReTest = false;
			if (Parameter.DNSTarget.IPv6_Multi != nullptr)
			{
				for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi) //Other(Multi)
				{
					if (DNSServerDataIter.HopLimitData.TTL == 0)
					{
						IsReTest = true;
						break;
					}
				}
			}

			if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0 || //IPv6 Main
				Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0 || //IPv6 Alternate
				IsReTest) //Other(Multi)
			{
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}

			Sleep((DWORD)Parameter.ICMPSpeed);
		}

	//Send.
		//Main
		sendto(ICMPv6Socket, Buffer.front().get(), (int)(sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U), 0, (PSOCKADDR)&Parameter.DNSTarget.IPv6.AddressData.IPv6, sizeof(sockaddr_in6));
		if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE)) //Increase Sequence.
		{
			ICMPv6_Header = (picmpv6_hdr)Buffer.front().get();
			if (ICMPv6_Header->Sequence == U16_MAXNUM)
				ICMPv6_Header->Sequence = htons(DEFAULT_SEQUENCE);
			else 
				ICMPv6_Header->Sequence = htons(ntohs(ICMPv6_Header->Sequence) + 1U);
			ICMPv6_Header->Checksum = 0;
			ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer.front().get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
		}

		//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
			sendto(ICMPv6Socket, Buffer[1U].get(), (int)(sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U), 0, (PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6, sizeof(sockaddr_in6));
			if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE)) //Increase Sequence.
			{
				ICMPv6_Header = (picmpv6_hdr)Buffer[1U].get();
				if (ICMPv6_Header->Sequence == U16_MAXNUM)
					ICMPv6_Header->Sequence = htons(DEFAULT_SEQUENCE);
				else 
					ICMPv6_Header->Sequence = htons(ntohs(ICMPv6_Header->Sequence) + 1U);
				ICMPv6_Header->Checksum = 0;
				ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer[1U].get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
			}
		}

		//Other(Multi)
		if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			Index = 2U;
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				sendto(ICMPv6Socket, Buffer[Index].get(), (int)(sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U), 0, (PSOCKADDR)&DNSServerDataIter.AddressData.IPv6, sizeof(sockaddr_in6));
				if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE)) //Increase Sequence.
				{
					ICMPv6_Header = (picmpv6_hdr)Buffer[Index].get();
					if (ICMPv6_Header->Sequence == U16_MAXNUM)
						ICMPv6_Header->Sequence = htons(DEFAULT_SEQUENCE);
					else 
						ICMPv6_Header->Sequence = htons(ntohs(ICMPv6_Header->Sequence) + 1U);
					ICMPv6_Header->Checksum = 0;
					ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer[Index].get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, DNSServerDataIter.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
				}

				Index++;
			}
		}

	//Repeat.
		Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
		Times++;
	}

	closesocket(ICMPv6Socket);
	PrintError(LOG_ERROR_SYSTEM, L"ICMPv6 Test module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Transmission and reception of TCP protocol(Independent)
size_t __fastcall TCPRequest(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsLocal, const bool IsAlternate)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[sizeof(uint16_t) + SendSize]());
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	SYSTEM_SOCKET TCPSocket = 0;
	int AddrLen = 0;
	memcpy(SendBuffer.get(), OriginalSend, SendSize);

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	size_t DataLength = AddLengthToTCPDNSHeader(SendBuffer.get(), SendSize, sizeof(uint16_t) + SendSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket initialization
	if (Parameter.GatewayAvailable_IPv6 && (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 || IsLocal && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0)) //IPv6
	{
		if (IsAlternate) //Alternate
		{
			if (IsLocal && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0) //Local
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port;
				SockAddr->ss_family = AF_INET6;
			}
			else if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0) //Main
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				SockAddr->ss_family = AF_INET6;
			}
		}

		if (SockAddr->ss_family == 0)
		{
			if (IsLocal && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0) //Local
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port;
			}
			else if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0) //Main
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
			}
			else {
				return FALSE;
			}

			SockAddr->ss_family = AF_INET6;
		}

		TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.GatewayAvailable_IPv4 && (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 || IsLocal && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == 0)) //IPv4
	{
		if (IsAlternate) //Alternate
		{
			if (IsLocal && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0) //Local
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port;
				SockAddr->ss_family = AF_INET;
			}
			else if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0) //Main
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				SockAddr->ss_family = AF_INET;
			}
		}
		
		if (SockAddr->ss_family == 0)
		{
			if (IsLocal && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0) //Local
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port;
			}
			else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //Main
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}
			else {
				return FALSE;
			}

			SockAddr->ss_family = AF_INET;
		}

		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (TCPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}
/*
//TCP KeepAlive Mode
	BOOL bKeepAlive = TRUE;
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_KEEPALIVE, (PSTR)&bKeepAlive, sizeof(bKeepAlive)) == SOCKET_ERROR)
	{
		closesocket(TCPSocket);
		return EXIT_FAILURE;
	}

	tcp_keepalive alive_in = {0};
	tcp_keepalive alive_out = {0};
	alive_in.keepalivetime = STANDARD_TIMEOUT;
	alive_in.keepaliveinterval = Parameter.ReliableSocketTimeout;
	alive_in.onoff = TRUE;
	ULONG ulBytesReturn = 0;
	if (WSAIoctl(TCPSocket, SIO_KEEPALIVE_VALS, &alive_in, sizeof(alive_in), &alive_out, sizeof(alive_out), &ulBytesReturn, nullptr, nullptr) == SOCKET_ERROR)
	{
		closesocket(TCPSocket);
		return EXIT_FAILURE;
	}
*/
//Set Non-blocking Mode
	ULONG SocketMode = 1U;
	if (ioctlsocket(TCPSocket, FIONBIO, &SocketMode) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

/* Old version(2014-12-08)
//Set socket timeout.
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSocket);

		return EXIT_FAILURE;
	}
*/
//Connect to server.
	if (connect(TCPSocket, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
	{
		if (!IsAlternate && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}

/* Old version(2014-12-08)
//Send requesting.
	if (send(TCPSocket, SendBuffer.get(), (int)DataLength, 0) == SOCKET_ERROR) //Connection is RESET or other errors when sending.
	{
		if (!Alternate && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}
	SendBuffer.reset();

//Receive result.
	SSIZE_T RecvLen = recv(TCPSocket, Recv, (int)RecvSize, 0) - (SSIZE_T)sizeof(uint16_t);
	if (RecvLen <= 0 || (SSIZE_T)htons(((uint16_t *)Recv)[0]) > RecvLen) //Connection is RESET or other errors(including SOCKET_ERROR) when sending or server fin the connection.
	{
		memset(Recv, 0, RecvSize);
		if (!Alternate && RecvLen == SOCKET_ERROR - (SSIZE_T)sizeof(uint16_t) && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}
	else if (RecvLen < DNS_PACKET_MINSIZE && htons(((uint16_t *)Recv)[0]) >= DNS_PACKET_MINSIZE) //TCP segment of a reassembled PDU
	{
		uint16_t PDULen = htons(((uint16_t *)Recv)[0]);
		memset(Recv, 0, RecvSize);
		RecvLen = recv(TCPSocket, Recv, (int)RecvSize, 0) - (SSIZE_T)sizeof(uint16_t);
		if (RecvLen < (SSIZE_T)PDULen) //Connection is RESET, corrupted packet or sother errors(including SOCKET_ERROR) after sending or finished.
		{
			memset(Recv, 0, RecvSize);
			if (!Alternate && RecvLen == SOCKET_ERROR - (SSIZE_T)sizeof(uint16_t) && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(TCPSocket);
				return WSAETIMEDOUT;
			}
			else {
				closesocket(TCPSocket);
				return EXIT_FAILURE;
			}
		}

		closesocket(TCPSocket);
		if (PDULen >= DNS_PACKET_MINSIZE && PDULen <= RecvSize)
		{
		//Responses question and answers check
			if (Parameter.DNSDataCheck || Parameter.Blacklist)
			{
			//Pointer check
				for (AddrLen = sizeof(dns_tcp_hdr);AddrLen < (int)((DNS_TCP_PACKET_QUERY_LOCATE(Recv));AddrLen++)
				{
					if (*(Recv + AddrLen) == '\xC0')
						break;
				}

			//Last result check
				if (!CheckResponseResult(Recv + sizeof(uint16_t), RecvLen) || 
					AddrLen != (int)((DNS_TCP_PACKET_QUERY_LOCATE(Recv)))
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}
			}

			memmove(Recv, Recv + sizeof(uint16_t), PDULen);
		//Mark DNS Cache.
			if (Parameter.CacheType > 0)
				MarkDomainCache(Recv, PDULen);

			return PDULen;
		}
		else {
			closesocket(TCPSocket);
			memset(Recv, 0, RecvSize);

			return EXIT_FAILURE;
		}
	}
	else if (RecvLen >= DNS_PACKET_MINSIZE)
	{
		closesocket(TCPSocket);
		RecvLen = ntohs(((uint16_t *)Recv)[0]);
		if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && RecvLen <= (SSIZE_T)RecvSize)
		{
		//Responses question and answers check
			if (Parameter.DNSDataCheck || Parameter.Blacklist)
			{
			//Pointer check
				for (AddrLen = sizeof(dns_tcp_hdr);AddrLen < (int)((DNS_TCP_PACKET_QUERY_LOCATE(Recv));AddrLen++)
				{
					if (*(Recv + AddrLen) == '\xC0')
						break;
				}

			//Last result check
				if (!CheckResponseResult(Recv + sizeof(uint16_t), RecvLen) || 
					AddrLen != (int)((DNS_TCP_PACKET_QUERY_LOCATE(Recv)))
				{
					memset(Recv, 0, RecvSize);
					return EXIT_FAILURE;
				}
			}

			memmove(Recv, Recv + sizeof(uint16_t), RecvLen);
		//Mark DNS Cache.
			if (Parameter.CacheType > 0)
				MarkDomainCache(Recv, RecvLen);

			return RecvLen;
		}
		else {
			return EXIT_FAILURE;
		}
	}
	else {
		closesocket(TCPSocket);
		memset(Recv, 0, RecvSize);
	}
*/

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	timeval Timeout = {0};
	FD_ZERO(WriteFDS.get());
	FD_SET(TCPSocket, WriteFDS.get());
	SSIZE_T SelectResult = 0, RecvLen = 0;
	uint16_t PDULen = 0;
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
		Timeout.tv_sec = Parameter.ReliableSocketTimeout / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.ReliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND;
		FD_ZERO(ReadFDS.get());
		FD_SET(TCPSocket, ReadFDS.get());

	//Wait for system calling.
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
		if (SelectResult > 0)
		{
		//Receive.
			if (FD_ISSET(TCPSocket, ReadFDS.get()))
			{
				RecvLen = recv(TCPSocket, OriginalRecv, (int)RecvSize, 0);

			//TCP segment of a reassembled PDU
				if (RecvLen < DNS_PACKET_MINSIZE)
				{
					if (RecvLen > 0 && htons(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE)
					{
						PDULen = htons(((uint16_t *)OriginalRecv)[0]);
						memset(OriginalRecv, 0, RecvSize);
						continue;
					}
				//Invalid packet.
					else {
						break;
					}
				}
				else {
				//Length check.
					if ((SSIZE_T)PDULen > RecvLen)
					{
						break;
					}
				//Receive again.
					else if (PDULen > 0)
					{
						closesocket(TCPSocket);

					//Jump to normal receive process.
						if (PDULen >= DNS_PACKET_MINSIZE)
						{
							RecvLen = (SSIZE_T)PDULen;
							goto JumpFromPDU;
						}

						memset(OriginalRecv, 0, RecvSize);
						return EXIT_FAILURE;
					}
				//First receive.
					else {
					//Length check
						if ((SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]) > RecvLen)
						{
							break;
						}
						else {
							closesocket(TCPSocket);

							RecvLen = (SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]);
							if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
							{
								memmove(OriginalRecv, OriginalRecv + sizeof(uint16_t), RecvLen);

							//Jump here when TCP segment of a reassembled PDU.
								JumpFromPDU: 

							//Responses question and answers check
								if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, IsLocal, nullptr))
								{
									memset(OriginalRecv, 0, RecvSize);
									return EXIT_FAILURE;
								}

							//Mark DNS Cache.
								if (Parameter.CacheType > 0)
									MarkDomainCache(OriginalRecv, RecvLen);

								return RecvLen;
							}
						//Length check
							else {
								break;
							}
						}
					}
				}
			}

		//Send.
			if (FD_ISSET(TCPSocket, WriteFDS.get()))
			{
				send(TCPSocket, SendBuffer.get(), (int)DataLength, 0);
				FD_ZERO(WriteFDS.get());
			}
		}
	//Timeout
		else if (SelectResult == 0)
		{
			closesocket(TCPSocket);
			memset(OriginalRecv, 0, RecvSize);
			return WSAETIMEDOUT;
		}
	//SOCKET_ERROR
		else {
			break;
		}
	}

	closesocket(TCPSocket);
	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}

/* Old version(2014-12-09)
//Transmission and reception of TCP protocol(Multithreading)
size_t __fastcall TCPRequestMulti(TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER &TCPRequestParameter, std::mutex &Mutex)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[sizeof(uint16_t) + TCPRequestParameter.SendSize]()), RecvBuffer(new char[TCPRequestParameter.RecvSize]());
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	SYSTEM_SOCKET TCPSocket = 0;
	int AddrLen = 0;
	memcpy(SendBuffer.get(), TCPRequestParameter.Send, TCPRequestParameter.SendSize);

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	size_t DataLength = AddLengthToTCPDNSHeader(SendBuffer.get(), TCPRequestParameter.SendSize, sizeof(uint16_t) + TCPRequestParameter.SendSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket initialization
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && TCPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in6) || //IPv6
		Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0 && TCPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in)) //Non-IPv4
	{
	//All server(including Alternate) Multi Request
		if (TCPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (TCPRequestParameter.ServerIndex == 1U)
			{
				if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0)
				{
					((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Alternate
			else if (TCPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
				{
					((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv6_Multi != nullptr && Parameter.DNSTarget.IPv6_Multi->size() > TCPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6_Multi->at(TCPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.IPv6_Multi->at(TCPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		SockAddr->ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
	//All server(including Alternate) Multi Request
		if (TCPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (TCPRequestParameter.ServerIndex == 1U)
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}
		//Alternate
			else if (TCPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
				{
					((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv4_Multi != nullptr && Parameter.DNSTarget.IPv4_Multi->size() > TCPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4_Multi->at(TCPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4_Multi->at(TCPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		SockAddr->ss_family = AF_INET;
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (TCPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}
/*
//TCP KeepAlive Mode
	BOOL bKeepAlive = TRUE;
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_KEEPALIVE, (PSTR)&bKeepAlive, sizeof(bKeepAlive)) == SOCKET_ERROR)
	{
		closesocket(TCPSocket);
		return EXIT_FAILURE;
	}

	tcp_keepalive alive_in = {0};
	tcp_keepalive alive_out = {0};
	alive_in.keepalivetime = STANDARD_TIMEOUT;
	alive_in.keepaliveinterval = Parameter.ReliableSocketTimeout;
	alive_in.onoff = TRUE;
	ULONG ulBytesReturn = 0;
	if (WSAIoctl(TCPSocket, SIO_KEEPALIVE_VALS, &alive_in, sizeof(alive_in), &alive_out, sizeof(alive_out), &ulBytesReturn, nullptr, nullptr) == SOCKET_ERROR)
	{
		closesocket(TCPSocket);
		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSocket);

		return EXIT_FAILURE;
	}

//Connect to server.
	if (connect(TCPSocket, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR) //Connection is RESET or other errors when connecting.
	{
		if (TCPRequestParameter.ServerIndex != 2U && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);

			std::unique_lock<std::mutex> TCPMutex(Mutex);
			TCPRequestParameter.ReturnValue = WSAETIMEDOUT;
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}

//Send requesting.
	if (send(TCPSocket, SendBuffer.get(), (int)DataLength, 0) == SOCKET_ERROR) //Connection is RESET or other errors when sending.
	{
		if (TCPRequestParameter.ServerIndex != 2U && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);

			std::unique_lock<std::mutex> TCPMutex(Mutex);
			TCPRequestParameter.ReturnValue = WSAETIMEDOUT;
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}
	SendBuffer.reset();

//Receive result.
	SSIZE_T RecvLen = recv(TCPSocket, RecvBuffer.get(), (int)TCPRequestParameter.RecvSize, 0) - (SSIZE_T)sizeof(uint16_t);
	if (RecvLen <= 0 || (SSIZE_T)htons(((uint16_t *)RecvBuffer.get())[0]) > RecvLen) //Connection is RESET or other errors(including SOCKET_ERROR) when sending or server fin the connection.
	{
		RecvBuffer.reset();
		if (TCPRequestParameter.ServerIndex != 2U && RecvLen == SOCKET_ERROR - (SSIZE_T)sizeof(uint16_t) && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);

			std::unique_lock<std::mutex> TCPMutex(Mutex);
			TCPRequestParameter.ReturnValue = WSAETIMEDOUT;
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}
	else if (RecvLen < DNS_PACKET_MINSIZE && htons(((uint16_t *)RecvBuffer.get())[0]) >= DNS_PACKET_MINSIZE) //TCP segment of a reassembled PDU
	{
		uint16_t PDULen = htons(((uint16_t *)RecvBuffer.get())[0]);
		memset(RecvBuffer.get(), 0, TCPRequestParameter.RecvSize);
		RecvLen = recv(TCPSocket, RecvBuffer.get(), (int)TCPRequestParameter.RecvSize, 0) - (SSIZE_T)sizeof(uint16_t);
		if (RecvLen < (SSIZE_T)PDULen) //Connection is RESET, corrupted packet or sother errors(including SOCKET_ERROR) after sending or finished.
		{
			RecvBuffer.reset();
			if (TCPRequestParameter.ServerIndex != 2U && RecvLen == SOCKET_ERROR - (SSIZE_T)sizeof(uint16_t) && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(TCPSocket);

				std::unique_lock<std::mutex> TCPMutex(Mutex);
				TCPRequestParameter.ReturnValue = WSAETIMEDOUT;
				return WSAETIMEDOUT;
			}
			else {
				closesocket(TCPSocket);
				return EXIT_FAILURE;
			}
		}

		closesocket(TCPSocket);
		if (PDULen >= DNS_PACKET_MINSIZE && PDULen <= TCPRequestParameter.RecvSize)
		{
		//Responses question and answers check
			if (Parameter.DNSDataCheck || Parameter.Blacklist)
			{
			//Pointer check
				for (AddrLen = sizeof(dns_tcp_hdr);AddrLen < (int)((DNS_TCP_PACKET_QUERY_LOCATE(RecvBuffer.get()));AddrLen++)
				{
					if (*(RecvBuffer.get() + AddrLen) == '\xC0')
						break;
				}

			//Last result check
				if (!CheckResponseResult(RecvBuffer.get() + sizeof(uint16_t), RecvLen) || 
					AddrLen != (int)((DNS_TCP_PACKET_QUERY_LOCATE(RecvBuffer.get())))
						return EXIT_FAILURE;
			}

			std::unique_lock<std::mutex> TCPMutex(Mutex);
			if (CheckEmptyBuffer(TCPRequestParameter.Recv, TCPRequestParameter.RecvSize) && (TCPRequestParameter.ReturnValue == 0 || TCPRequestParameter.ReturnValue == WSAETIMEDOUT))
			{
				memcpy(TCPRequestParameter.Recv, RecvBuffer.get() + sizeof(uint16_t), PDULen);
				TCPRequestParameter.ReturnValue = PDULen;

			//Mark DNS Cache.
				if (Parameter.CacheType > 0)
					MarkDomainCache(TCPRequestParameter.Recv, PDULen);

				return PDULen;
			}
			else {
				return EXIT_SUCCESS;
			}
		}
	}
	else if (RecvLen >= DNS_PACKET_MINSIZE)
	{
		closesocket(TCPSocket);
		RecvLen = ntohs(((uint16_t *)RecvBuffer.get())[0]);
		if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && RecvLen <= (SSIZE_T)TCPRequestParameter.RecvSize)
		{
		//Responses question and answers check
			if (Parameter.DNSDataCheck || Parameter.Blacklist)
			{
			//Pointer check
				for (AddrLen = sizeof(dns_tcp_hdr);AddrLen < (int)((DNS_TCP_PACKET_QUERY_LOCATE(RecvBuffer.get()));AddrLen++)
				{
					if (*(RecvBuffer.get() + AddrLen) == '\xC0')
						break;
				}

			//Last result check
				if (!CheckResponseResult(RecvBuffer.get() + sizeof(uint16_t), RecvLen) || 
					AddrLen != (int)((DNS_TCP_PACKET_QUERY_LOCATE(RecvBuffer.get())))
						return EXIT_FAILURE;
			}

			std::unique_lock<std::mutex> TCPMutex(Mutex);
			if (CheckEmptyBuffer(TCPRequestParameter.Recv, TCPRequestParameter.RecvSize) && (TCPRequestParameter.ReturnValue == 0 || TCPRequestParameter.ReturnValue == WSAETIMEDOUT))
			{
				memcpy(TCPRequestParameter.Recv, RecvBuffer.get() + sizeof(uint16_t), RecvLen);
				TCPRequestParameter.ReturnValue = RecvLen;

			//Mark DNS Cache.
				if (Parameter.CacheType > 0)
					MarkDomainCache(TCPRequestParameter.Recv, RecvLen);

				return RecvLen;
			}
			else {
				return EXIT_SUCCESS;
			}
		}
	}
	else {
		closesocket(TCPSocket);
	}

	return EXIT_FAILURE;
}
*/

//Transmission and reception of TCP protocol(Multithreading)
size_t __fastcall TCPRequestMulti(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsAlternate)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[sizeof(uint16_t) + SendSize]());
	std::vector<SOCKET_DATA> TCPSocketDataList;
	memcpy(SendBuffer.get(), OriginalSend, SendSize);

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	size_t DataLength = AddLengthToTCPDNSHeader(SendBuffer.get(), SendSize, sizeof(uint16_t) + SendSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket initialization
	if (Parameter.GatewayAvailable_IPv6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
		std::shared_ptr<SOCKET_DATA> TCPSocketData(new SOCKET_DATA());
		ULONG SocketMode = 1U;

	//Main
		if (!IsAlternate)
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;Index++)
			{
				TCPSocketData->SockAddr = Parameter.DNSTarget.IPv6.AddressData.Storage;
				TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			//Socket check
				if (TCPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_WINSOCK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
				else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					closesocket(TCPSocketData->Socket);

					return EXIT_FAILURE;
				}

				TCPSocketData->AddrLen = sizeof(sockaddr_in6);
				TCPSocketDataList.push_back(*TCPSocketData);
				memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;Index++)
			{
				TCPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage;
				TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			//Socket check
				if (TCPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_WINSOCK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
				else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:TCPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}

				TCPSocketData->AddrLen = sizeof(sockaddr_in6);
				TCPSocketDataList.push_back(*TCPSocketData);
				memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Other servers
		if (Parameter.DNSTarget.IPv6_Multi != nullptr && !IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				for (size_t Index = 0;Index < Parameter.MultiRequestTimes;Index++)
				{
					TCPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
					TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
				//Socket check
					if (TCPSocketData->Socket == INVALID_SOCKET)
					{
						PrintError(LOG_ERROR_WINSOCK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
						return EXIT_FAILURE;
					}
				//Set Non-blocking Mode
					else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
					{
						PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
						for (auto SocketDataIter:TCPSocketDataList)
							closesocket(SocketDataIter.Socket);

						return EXIT_FAILURE;
					}

					TCPSocketData->AddrLen = sizeof(sockaddr_in6);
					TCPSocketDataList.push_back(*TCPSocketData);
					memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
				}
			}
		}
	}
	else if (Parameter.GatewayAvailable_IPv4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		std::shared_ptr<SOCKET_DATA> TCPSocketData(new SOCKET_DATA());
		ULONG SocketMode = 1U;

	//Main
		if (!IsAlternate)
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;Index++)
			{
				TCPSocketData->SockAddr = Parameter.DNSTarget.IPv4.AddressData.Storage;
				TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			//Socket check
				if (TCPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_WINSOCK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
				else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					closesocket(TCPSocketData->Socket);

					return EXIT_FAILURE;
				}

				TCPSocketData->AddrLen = sizeof(sockaddr_in);
				TCPSocketDataList.push_back(*TCPSocketData);
				memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;Index++)
			{
				TCPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage;
				TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			//Socket check
				if (TCPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_WINSOCK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
				else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:TCPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}

				TCPSocketData->AddrLen = sizeof(sockaddr_in);
				TCPSocketDataList.push_back(*TCPSocketData);
				memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Other servers
		if (Parameter.DNSTarget.IPv4_Multi != nullptr && !IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				for (size_t Index = 0;Index < Parameter.MultiRequestTimes;Index++)
				{
					TCPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
					TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
				//Socket check
					if (TCPSocketData->Socket == INVALID_SOCKET)
					{
						PrintError(LOG_ERROR_WINSOCK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
						return EXIT_FAILURE;
					}
				//Set Non-blocking Mode
					else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
					{
						PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
						for (auto SocketDataIter:TCPSocketDataList)
							closesocket(SocketDataIter.Socket);

						return EXIT_FAILURE;
					}

					TCPSocketData->AddrLen = sizeof(sockaddr_in);
					TCPSocketDataList.push_back(*TCPSocketData);
					memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
				}
			}
		}
	}
	else {
		return EXIT_FAILURE;
	}

//Connect to servers.
	for (auto SocketDataIter = TCPSocketDataList.begin();SocketDataIter != TCPSocketDataList.end();)
	{
		if (connect(SocketDataIter->Socket, (PSOCKADDR)&SocketDataIter->SockAddr, SocketDataIter->AddrLen) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
		{
			closesocket(SocketDataIter->Socket);
			SocketDataIter = TCPSocketDataList.erase(SocketDataIter);
			if (SocketDataIter == TCPSocketDataList.end())
				goto StopLoop;
		}
		else {
			SocketDataIter++;
		}
	}
//Stop loop.
	StopLoop: 
	if (TCPSocketDataList.empty())
		return EXIT_FAILURE;

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	timeval Timeout = {0};
	FD_ZERO(WriteFDS.get());
	for (auto SocketDataIter:TCPSocketDataList)
	{
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0, RecvLen = 0;
	std::vector<uint16_t> PDULenList(TCPSocketDataList.size(), 0);
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
		Timeout.tv_sec = Parameter.ReliableSocketTimeout / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.ReliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND;
		FD_ZERO(ReadFDS.get());
		for (auto SocketDataIter:TCPSocketDataList)
		{
			if (SocketDataIter.Socket > 0)
			{
				FD_SET(SocketDataIter.Socket, ReadFDS.get());
			}
		}

	//Wait for system calling.
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
		if (SelectResult > 0)
		{
		//Receive.
			for (size_t Index = 0;Index < TCPSocketDataList.size();Index++)
			{
				if (FD_ISSET(TCPSocketDataList[Index].Socket, ReadFDS.get()))
				{
					RecvLen = recv(TCPSocketDataList[Index].Socket, OriginalRecv, (int)RecvSize, 0);

				//TCP segment of a reassembled PDU
					if (RecvLen < DNS_PACKET_MINSIZE)
					{
						if (RecvLen > 0 && htons(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE)
						{
							PDULenList[Index] = htons(((uint16_t *)OriginalRecv)[0]);
							memset(OriginalRecv, 0, RecvSize);
							continue;
						}
					//Invalid packet.
						else {
							closesocket(TCPSocketDataList[Index].Socket);
							TCPSocketDataList[Index].Socket = 0;
							break;
						}
					}
					else {
					//Length check.
						if ((SSIZE_T)PDULenList[Index] > RecvLen)
						{
							closesocket(TCPSocketDataList[Index].Socket);
							TCPSocketDataList[Index].Socket = 0;
							break;
						}
					//Receive again.
						else if (PDULenList[Index] > 0)
						{
						//Jump to normal receive process.
							if (PDULenList[Index] >= DNS_PACKET_MINSIZE)
							{
								RecvLen = (SSIZE_T)PDULenList[Index];
								goto JumpFromPDU;
							}

							memset(OriginalRecv, 0, RecvSize);
							continue;
						}
					//First receive.
						else {
						//Length check
							if ((SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]) > RecvLen)
							{
								closesocket(TCPSocketDataList[Index].Socket);
								TCPSocketDataList[Index].Socket = 0;
								break;
							}
							else {
								RecvLen = (SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]);
								if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
								{
									memmove(OriginalRecv, OriginalRecv + sizeof(uint16_t), RecvLen);

								//Jump here when TCP segment of a reassembled PDU.
									JumpFromPDU: 

								//Responses question and answers check
									if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, false, nullptr))
									{
										memset(OriginalRecv, 0, RecvSize);
										continue;
									}

								//Close sockets and remove response length of TCP requesting.
									for (auto SocketDataIter:TCPSocketDataList)
									{
										if (SocketDataIter.Socket > 0)
											closesocket(SocketDataIter.Socket);
									}

								//Mark DNS Cache.
									if (Parameter.CacheType > 0)
										MarkDomainCache(OriginalRecv, RecvLen);

									return RecvLen;
								}
							//Length check
								else {
									closesocket(TCPSocketDataList[Index].Socket);
									TCPSocketDataList[Index].Socket = 0;
									break;
								}
							}
						}
					}
				}
			}

		//Send.
			for (auto SocketDataIter:TCPSocketDataList)
			{
				if (FD_ISSET(SocketDataIter.Socket, WriteFDS.get()))
					send(SocketDataIter.Socket, SendBuffer.get(), (int)DataLength, 0);
			}

			FD_ZERO(WriteFDS.get());
		}
	//Timeout
		else if (SelectResult == 0)
		{
			for (auto SocketDataIter:TCPSocketDataList)
			{
				if (SocketDataIter.Socket > 0)
					closesocket(SocketDataIter.Socket);
			}
			memset(OriginalRecv, 0, RecvSize);
			return WSAETIMEDOUT;
		}
	//SOCKET_ERROR
		else {
			break;
		}
	}

	for (auto SocketDataIter:TCPSocketDataList)
	{
		if (SocketDataIter.Socket > 0)
			closesocket(SocketDataIter.Socket);
	}
	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Transmission of UDP protocol
size_t __fastcall UDPRequest(const PSTR OriginalSend, const size_t Length, const size_t ListIndex, const bool IsAlternate)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (Parameter.GatewayAvailable_IPv6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
		if (IsAlternate)
		{
			if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}
		else {
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
		}

		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr->ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.GatewayAvailable_IPv4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		if (IsAlternate)
		{
			if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}
		else {
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
		}

		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr->ss_family = AF_INET;
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send requesting.
	if (sendto(UDPSocket, OriginalSend, (int)Length, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"UDP request error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Mark port to list.
	if (ListIndex < QUEUE_MAXLEN * QUEUE_PARTNUM)
	{
		if (getsockname(UDPSocket, (PSOCKADDR)SockAddr.get(), (PINT)&AddrLen) != 0)
		{
			closesocket(UDPSocket);
			return EXIT_FAILURE;
		}

		std::shared_ptr<SOCKET_DATA> SocketDataTemp(new SOCKET_DATA());
		if (AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			SocketDataTemp->AddrLen = sizeof(sockaddr_in6);
			SocketDataTemp->SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SocketDataTemp->SockAddr)->sin6_port = ((PSOCKADDR_IN6)SockAddr.get())->sin6_port;

			std::unique_lock<std::mutex> PortListMutex(PortListLock);
			PortList.SendData[ListIndex].push_back(*SocketDataTemp);
			PortList.SendData[ListIndex].shrink_to_fit();
		}
		else { //IPv4
			SocketDataTemp->AddrLen = sizeof(sockaddr_in);
			SocketDataTemp->SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SocketDataTemp->SockAddr)->sin_port = ((PSOCKADDR_IN)SockAddr.get())->sin_port;

			std::unique_lock<std::mutex> PortListMutex(PortListLock);
			PortList.SendData[ListIndex].push_back(*SocketDataTemp);
			PortList.SendData[ListIndex].shrink_to_fit();
		}

	//Mark send time.
	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
		if (ListIndex > QUEUE_MAXLEN * QUEUE_PARTNUM / 2U && ListIndex < QUEUE_MAXLEN * QUEUE_PARTNUM) //TCP
		#ifdef _WIN64
			AlternateSwapList.PcapAlternateTimeout[ListIndex] = GetTickCount64() + Parameter.ReliableSocketTimeout;
		#else //x86
		{
			if (Parameter.GetTickCount64PTR != nullptr)
				AlternateSwapList.PcapAlternateTimeout[ListIndex] = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.ReliableSocketTimeout);
			else 
				AlternateSwapList.PcapAlternateTimeout[ListIndex] = GetTickCount() + Parameter.ReliableSocketTimeout;
		}
		#endif
		else 
		#ifdef _WIN64
			AlternateSwapList.PcapAlternateTimeout[ListIndex] = GetTickCount64() + Parameter.UnreliableSocketTimeout;
		#else //x86
		{
			if (Parameter.GetTickCount64PTR != nullptr)
				AlternateSwapList.PcapAlternateTimeout[ListIndex] = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.UnreliableSocketTimeout);
			else 
				AlternateSwapList.PcapAlternateTimeout[ListIndex] = GetTickCount() + Parameter.UnreliableSocketTimeout;
		}
		#endif
	}

//Block Port Unreachable messages of system or close the TCP requesting connections.
	if (ListIndex > QUEUE_MAXLEN * QUEUE_PARTNUM / 2U && ListIndex < QUEUE_MAXLEN * QUEUE_PARTNUM) //TCP
		Sleep(Parameter.ReliableSocketTimeout);
	else //UDP
		Sleep(Parameter.UnreliableSocketTimeout);
	closesocket(UDPSocket);
	return EXIT_SUCCESS;
}

/* Old version(2014-12-09)
//Transmission of UDP protocol(Multithreading)
size_t __fastcall UDPRequestMulti(UDP_REQUEST_MULTITHREAD_PARAMETER UDPRequestParameter)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && UDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in6) || //IPv6
		Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0 && UDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in)) //Non-IPv4
	{
	//All server(including Alternate) Multi Request
		if (UDPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (UDPRequestParameter.ServerIndex == 1U)
			{
				if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0)
				{
					((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Alternate
			else if (UDPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
				{
					((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv6_Multi != nullptr && Parameter.DNSTarget.IPv6_Multi->size() > UDPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.IPv6_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr->ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
	//All server(including Alternate) Multi Request
		if (UDPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (UDPRequestParameter.ServerIndex == 1U)
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}
		//Alternate
			else if (UDPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
				{
					((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv4_Multi != nullptr && Parameter.DNSTarget.IPv4_Multi->size() > UDPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr->ss_family = AF_INET;
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send requesting.
	if (sendto(UDPSocket, UDPRequestParameter.Send, (int)UDPRequestParameter.Length, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"UDP request error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Mark port to list.
	if (UDPRequestParameter.Index < QUEUE_MAXLEN * QUEUE_PARTNUM)
	{
		if (getsockname(UDPSocket, (PSOCKADDR)SockAddr.get(), (PINT)&AddrLen) != 0)
		{
			closesocket(UDPSocket);
			return EXIT_FAILURE;
		}

		std::shared_ptr<SOCKET_DATA> SocketDataTemp(new SOCKET_DATA());
	//Minimum supported system of GetTickCount64() is Windows Vista.
		if (AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			SocketDataTemp->AddrLen = sizeof(sockaddr_in6);
			SocketDataTemp->SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SocketDataTemp->SockAddr)->sin6_port = ((PSOCKADDR_IN6)SockAddr.get())->sin6_port;

			std::unique_lock<std::mutex> PortListMutex(PortListLock);
			PortList.SendData[UDPRequestParameter.Index].push_back(*SocketDataTemp);
			PortList.SendData[UDPRequestParameter.Index].shrink_to_fit();
		}
		else //IPv4
		{
			SocketDataTemp->AddrLen = sizeof(sockaddr_in);
			SocketDataTemp->SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SocketDataTemp->SockAddr)->sin_port = ((PSOCKADDR_IN)SockAddr.get())->sin_port;

			std::unique_lock<std::mutex> PortListMutex(PortListLock);
			PortList.SendData[UDPRequestParameter.Index].push_back(*SocketDataTemp);
			PortList.SendData[UDPRequestParameter.Index].shrink_to_fit();
		}

	//Mark send time
		if (UDPRequestParameter.Index > QUEUE_MAXLEN * QUEUE_PARTNUM / 2U && UDPRequestParameter.Index < QUEUE_MAXLEN * QUEUE_PARTNUM) //TCP
		#ifdef _WIN64
			AlternateSwapList.PcapAlternateTimeout[UDPRequestParameter.Index] = GetTickCount64() + Parameter.ReliableSocketTimeout;
		#else //x86
			AlternateSwapList.PcapAlternateTimeout[UDPRequestParameter.Index] = GetTickCount() + Parameter.ReliableSocketTimeout;
		#endif
		else
		#ifdef _WIN64
			AlternateSwapList.PcapAlternateTimeout[UDPRequestParameter.Index] = GetTickCount64() + Parameter.UnreliableSocketTimeout;
		#else //x86
			AlternateSwapList.PcapAlternateTimeout[UDPRequestParameter.Index] = GetTickCount() + Parameter.UnreliableSocketTimeout;
		#endif
	}

//Block Port Unreachable messages of system or close the TCP requesting connections.
	if (UDPRequestParameter.Index > QUEUE_MAXLEN * QUEUE_PARTNUM / 2U && UDPRequestParameter.Index < QUEUE_MAXLEN * QUEUE_PARTNUM) //TCP
		Sleep(Parameter.ReliableSocketTimeout);
	else //UDP
		Sleep(Parameter.UnreliableSocketTimeout);
	closesocket(UDPSocket);
	return EXIT_SUCCESS;
}
*/

//Transmission of UDP protocol(Multithreading)
size_t __fastcall UDPRequestMulti(const PSTR OriginalSend, const size_t Length, const size_t ListIndex, const bool IsAlternate)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;

//Socket initialization
	if (Parameter.GatewayAvailable_IPv6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
		std::shared_ptr<SOCKET_DATA> UDPSocketData(new SOCKET_DATA());
		ULONG SocketMode = 1U;

	//Main
		if (!IsAlternate)
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.IPv6.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(UDPSocketData->Socket);

				return EXIT_FAILURE;
			}

			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && (IsAlternate || ListIndex == QUEUE_MAXLEN * QUEUE_PARTNUM || Parameter.AlternateMultiRequest))
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}

			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Other servers
		if (Parameter.DNSTarget.IPv6_Multi != nullptr && (!IsAlternate && Parameter.AlternateMultiRequest || ListIndex == QUEUE_MAXLEN * QUEUE_PARTNUM))
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				UDPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
				UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			//Socket check
				if (UDPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_WINSOCK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
				else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}

				UDPSocketData->AddrLen = sizeof(sockaddr_in6);
				UDPSocketDataList.push_back(*UDPSocketData);
				memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}
	}
	else if (Parameter.GatewayAvailable_IPv4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		std::shared_ptr<SOCKET_DATA> UDPSocketData(new SOCKET_DATA());
		ULONG SocketMode = 1U;

	//Main
		if (!IsAlternate)
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.IPv4.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(UDPSocketData->Socket);

				return EXIT_FAILURE;
			}

			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && (IsAlternate || ListIndex == QUEUE_MAXLEN * QUEUE_PARTNUM || Parameter.AlternateMultiRequest))
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}

			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Other servers
		if (Parameter.DNSTarget.IPv4_Multi != nullptr && (!IsAlternate && Parameter.AlternateMultiRequest || ListIndex == QUEUE_MAXLEN * QUEUE_PARTNUM))
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				UDPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
				UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			//Socket check
				if (UDPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_WINSOCK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
				else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}

				UDPSocketData->AddrLen = sizeof(sockaddr_in);
				UDPSocketDataList.push_back(*UDPSocketData);
				memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}
	}
	else {
		return EXIT_FAILURE;
	}

//Send request and receive result.
	std::shared_ptr<fd_set> WriteFDS(new fd_set());
	timeval Timeout = {0};
	FD_ZERO(WriteFDS.get());
	for (auto SocketDataIter:UDPSocketDataList)
	{
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0;
	for (;;)
	{
	//Reset parameters.
		Timeout.tv_sec = Parameter.UnreliableSocketTimeout / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.UnreliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND;

	//Wait for system calling.
		SelectResult = select(0, nullptr, WriteFDS.get(), nullptr, &Timeout);
		if (SelectResult > 0)
		{
		//Send.
			for (auto SocketDataIter:UDPSocketDataList)
			{
				if (FD_ISSET(SocketDataIter.Socket, WriteFDS.get()))
				{
					for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
						sendto(SocketDataIter.Socket, OriginalSend, (int)Length, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);
				}
			}

			break;
		}
	//Timeout or SOCKET_ERROR
		else {
			for (auto SocketDataIter:UDPSocketDataList)
				closesocket(SocketDataIter.Socket);
			return EXIT_FAILURE;
		}
	}

//Mark port to list.
	if (ListIndex < QUEUE_MAXLEN * QUEUE_PARTNUM)
	{
		std::shared_ptr<SOCKET_DATA> SocketDataTemp(new SOCKET_DATA());
		for (auto SocketDataIter:UDPSocketDataList)
		{
			memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));

		//Get socket information.
			if (getsockname(SocketDataIter.Socket, (PSOCKADDR)&SocketDataIter.SockAddr, (PINT)&SocketDataIter.AddrLen) != 0)
			{
				closesocket(SocketDataIter.Socket);
				continue;
			}

		//Add to global list.
			if (SocketDataIter.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				SocketDataTemp->AddrLen = sizeof(sockaddr_in6);
				SocketDataTemp->SockAddr.ss_family = AF_INET6;
				((PSOCKADDR_IN6)&SocketDataTemp->SockAddr)->sin6_port = ((PSOCKADDR_IN6)&SocketDataIter.SockAddr)->sin6_port;

				std::unique_lock<std::mutex> PortListMutex(PortListLock);
				PortList.SendData[ListIndex].push_back(*SocketDataTemp);
				PortList.SendData[ListIndex].shrink_to_fit();
			}
			else { //IPv4
				SocketDataTemp->AddrLen = sizeof(sockaddr_in);
				SocketDataTemp->SockAddr.ss_family = AF_INET;
				((PSOCKADDR_IN)&SocketDataTemp->SockAddr)->sin_port = ((PSOCKADDR_IN)&SocketDataIter.SockAddr)->sin_port;

				std::unique_lock<std::mutex> PortListMutex(PortListLock);
				PortList.SendData[ListIndex].push_back(*SocketDataTemp);
				PortList.SendData[ListIndex].shrink_to_fit();
			}
		}

	//Mark send time.
	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
		if (ListIndex > QUEUE_MAXLEN * QUEUE_PARTNUM / 2U && ListIndex < QUEUE_MAXLEN * QUEUE_PARTNUM) //TCP
		#ifdef _WIN64
			AlternateSwapList.PcapAlternateTimeout[ListIndex] = GetTickCount64() + Parameter.ReliableSocketTimeout;
		#else //x86
		{
			if (Parameter.GetTickCount64PTR != nullptr)
				AlternateSwapList.PcapAlternateTimeout[ListIndex] = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.ReliableSocketTimeout);
			else 
				AlternateSwapList.PcapAlternateTimeout[ListIndex] = GetTickCount() + Parameter.ReliableSocketTimeout;
		}
		#endif
		else
		#ifdef _WIN64
			AlternateSwapList.PcapAlternateTimeout[ListIndex] = GetTickCount64() + Parameter.UnreliableSocketTimeout;
		#else //x86
		{
			if (Parameter.GetTickCount64PTR != nullptr)
				AlternateSwapList.PcapAlternateTimeout[ListIndex] = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.UnreliableSocketTimeout);
			else 
				AlternateSwapList.PcapAlternateTimeout[ListIndex] = GetTickCount() + Parameter.UnreliableSocketTimeout;
		}
		#endif
	}

//Block Port Unreachable messages of system or close the TCP requesting connections.
	if (ListIndex > QUEUE_MAXLEN * QUEUE_PARTNUM / 2U && ListIndex < QUEUE_MAXLEN * QUEUE_PARTNUM) //TCP
		Sleep(Parameter.ReliableSocketTimeout);
	else //UDP
		Sleep(Parameter.UnreliableSocketTimeout);
	for (auto SocketDataIter:UDPSocketDataList)
		closesocket(SocketDataIter.Socket);
	return EXIT_FAILURE;
}

//Complete transmission of UDP protocol
size_t __fastcall UDPCompleteRequest(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsLocal, const bool IsAlternate)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (Parameter.GatewayAvailable_IPv6 && (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 || IsLocal && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0)) //IPv6
	{
		if (IsAlternate) //Alternate
		{
			if (IsLocal && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0) //Local
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port;
				SockAddr->ss_family = AF_INET6;
			}
			else if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0) //Main
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				SockAddr->ss_family = AF_INET6;
			}
		}
		
		if (SockAddr->ss_family == 0)
		{
			if (IsLocal && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0) //Local
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port;
			}
			else if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0) //Main
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}

			SockAddr->ss_family = AF_INET6;
		}

		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.GatewayAvailable_IPv4 && (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 || IsLocal && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0)) //IPv4
	{
		if (IsAlternate) //Alternate
		{
			if (IsLocal && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0) //Local
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port;
				SockAddr->ss_family = AF_INET;
			}
			else if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0) //Main
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				SockAddr->ss_family = AF_INET;
			}
		}
		
		if (SockAddr->ss_family == 0)
		{
			if (IsLocal && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port;
			}
			else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //Main
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}

			SockAddr->ss_family = AF_INET;
		}

		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send requesting.
	if (sendto(UDPSocket, OriginalSend, (int)SendSize, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Receive result.
	SSIZE_T RecvLen = recvfrom(UDPSocket, OriginalRecv, (int)RecvSize, 0, (PSOCKADDR)SockAddr.get(), (PINT)&AddrLen);
	if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		if (RecvLen == SOCKET_ERROR)
			RecvLen = WSAGetLastError();
		closesocket(UDPSocket);
		memset(OriginalRecv, 0, RecvSize);
		if (RecvLen == WSAETIMEDOUT)
			return WSAETIMEDOUT;
	}
	else {
	//Hosts Only Extended check
		if (Parameter.DNSDataCheck || Parameter.Blacklist)
		{
			for (;;)
			{
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, IsLocal, nullptr))
				{
					memset(OriginalRecv, 0, RecvSize);
					if (IsLocal) //Stop waitting when it is Local requesting.
					{
						closesocket(UDPSocket);
						return EXIT_FAILURE;
					}
					else {
						RecvLen = recvfrom(UDPSocket, OriginalRecv, (int)RecvSize, 0, (PSOCKADDR)SockAddr.get(), (PINT)&AddrLen);
						if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
						{
							if (RecvLen == SOCKET_ERROR)
								RecvLen = WSAGetLastError();
							closesocket(UDPSocket);
							memset(OriginalRecv, 0, RecvSize);
							if (RecvLen == WSAETIMEDOUT)
								return WSAETIMEDOUT;
							else
								return EXIT_FAILURE;
						}

						Sleep(LOOP_INTERVAL_TIME);
					}
				}
				else {
					closesocket(UDPSocket);
					break;
				}
			}
		}
/*
	//Check timeout.
		if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
		{
			memset(Recv, 0, RecvSize);
			if (RecvLen == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(UDPSocket);
				return WSAETIMEDOUT;
			}
			else {
				closesocket(UDPSocket);
				return EXIT_FAILURE;
			}
		}
		else {
			closesocket(UDPSocket);
		}
*/
	//Mark DNS Cache.
		if (Parameter.CacheType > 0)
			MarkDomainCache(OriginalRecv, RecvLen);

		return RecvLen;
	}

	return EXIT_FAILURE;
}

/* Old version(2014-12-09)
//Complete transmission of UDP protocol(Multithreading)
size_t __fastcall UDPCompleteRequestMulti(TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER &UDPRequestParameter, std::mutex &Mutex)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && UDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in6) || //IPv6
		Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0 && UDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in)) //Non-IPv4
	{
	//All server(including Alternate) Multi Request
		if (UDPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (UDPRequestParameter.ServerIndex == 1U)
			{
				if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0)
				{
					((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Alternate
			else if (UDPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
				{
					((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv6_Multi != nullptr && Parameter.DNSTarget.IPv6_Multi->size() > UDPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.IPv6_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr->ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
	//All server(including Alternate) Multi Request
		if (UDPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (UDPRequestParameter.ServerIndex == 1U)
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}
		//Alternate
			else if (UDPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
				{
					((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv4_Multi != nullptr && Parameter.DNSTarget.IPv4_Multi->size() > UDPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr->ss_family = AF_INET;
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send requesting.
	if (sendto(UDPSocket, UDPRequestParameter.Send, (int)UDPRequestParameter.SendSize, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Receive result.
	std::shared_ptr<char> RecvBuffer(new char[UDPRequestParameter.RecvSize]());
	SSIZE_T RecvLen = recvfrom(UDPSocket, RecvBuffer.get(), (int)UDPRequestParameter.RecvSize, 0, (PSOCKADDR)SockAddr.get(), (PINT)&AddrLen);
	if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		if (RecvLen == SOCKET_ERROR)
			RecvLen = WSAGetLastError();
		closesocket(UDPSocket);

		if (RecvLen == WSAETIMEDOUT)
		{
			std::unique_lock<std::mutex> UDPMutex(Mutex);
			UDPRequestParameter.ReturnValue = WSAETIMEDOUT;
			return WSAETIMEDOUT;
		}
		else {
			return EXIT_FAILURE;
		}
	}
	else {
	//Hosts Only Extended check
		if (Parameter.DNSDataCheck || Parameter.Blacklist)
		{
			for (;;)
			{
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseResult(RecvBuffer.get(), RecvLen))
				{
					memset(RecvBuffer.get(), 0, UDPRequestParameter.RecvSize);
					RecvLen = recvfrom(UDPSocket, RecvBuffer.get(), (int)UDPRequestParameter.RecvSize, 0, (PSOCKADDR)SockAddr.get(), (PINT)&AddrLen);
					if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
					{
						if (RecvLen == SOCKET_ERROR)
							RecvLen = WSAGetLastError();
						closesocket(UDPSocket);

						if (RecvLen == WSAETIMEDOUT)
						{
							std::unique_lock<std::mutex> UDPMutex(Mutex);
							UDPRequestParameter.ReturnValue = WSAETIMEDOUT;
							return WSAETIMEDOUT;
						}
						else {
							return EXIT_FAILURE;
						}
					}
				}
				else {
					closesocket(UDPSocket);
					break;
				}
			}
		}

/*
	//Check timeout.
		if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
		{
			if (RecvLen == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(UDPSocket);

				std::unique_lock<std::mutex> UDPMutex(Mutex);
				UDPRequestParameter.ReturnValue = WSAETIMEDOUT;
				return WSAETIMEDOUT;
			}
			else {
				closesocket(UDPSocket);
				return EXIT_FAILURE;
			}
		}
		else {
			closesocket(UDPSocket);
		}

		std::unique_lock<std::mutex> TCPMutex(Mutex);
		if (CheckEmptyBuffer(UDPRequestParameter.Recv, UDPRequestParameter.RecvSize) && (UDPRequestParameter.ReturnValue == 0 || UDPRequestParameter.ReturnValue == WSAETIMEDOUT))
		{
			memcpy(UDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
			UDPRequestParameter.ReturnValue = RecvLen;

		//Mark DNS Cache.
			if (Parameter.CacheType > 0)
				MarkDomainCache(UDPRequestParameter.Recv, RecvLen);

			return RecvLen;
		}
		else {
			return EXIT_SUCCESS;
		}
	}

	return EXIT_FAILURE;
}
*/

//Complete transmission of UDP protocol(Multithreading)
size_t __fastcall UDPCompleteRequestMulti(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsAlternate)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;

//Socket initialization
	if (Parameter.GatewayAvailable_IPv6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
		std::shared_ptr<SOCKET_DATA> UDPSocketData(new SOCKET_DATA());
		ULONG SocketMode = 1U;

	//Main
		if (!IsAlternate)
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.IPv6.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(UDPSocketData->Socket);

				return EXIT_FAILURE;
			}

			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}

			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Other servers
		if (Parameter.DNSTarget.IPv6_Multi != nullptr && !IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				UDPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
				UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			//Socket check
				if (UDPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
				else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}

				UDPSocketData->AddrLen = sizeof(sockaddr_in6);
				UDPSocketDataList.push_back(*UDPSocketData);
				memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}
	}
	else if (Parameter.GatewayAvailable_IPv4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		std::shared_ptr<SOCKET_DATA> UDPSocketData(new SOCKET_DATA());
		ULONG SocketMode = 1U;

	//Main
		if (!IsAlternate)
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.IPv4.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(UDPSocketData->Socket);

				return EXIT_FAILURE;
			}

			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}

			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Other servers
		if (Parameter.DNSTarget.IPv4_Multi != nullptr && !IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				UDPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
				UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			//Socket check
				if (UDPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
				else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}

				UDPSocketData->AddrLen = sizeof(sockaddr_in);
				UDPSocketDataList.push_back(*UDPSocketData);
				memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}
	}
	else {
		return EXIT_FAILURE;
	}

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	timeval Timeout = {0};
	FD_ZERO(WriteFDS.get());
	for (auto SocketDataIter:UDPSocketDataList)
	{
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0, RecvLen = 0;
	size_t Index = 0;
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
		Timeout.tv_sec = Parameter.UnreliableSocketTimeout / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.UnreliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND;
		FD_ZERO(ReadFDS.get());
		for (auto SocketDataIter:UDPSocketDataList)
		{
			if (SocketDataIter.Socket > 0)
			{
				FD_SET(SocketDataIter.Socket, ReadFDS.get());
			}
		}

	//Wait for system calling.
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
		if (SelectResult > 0)
		{
		//Receive.
			for (Index = 0;Index < UDPSocketDataList.size();Index++)
			{
				if (FD_ISSET(UDPSocketDataList[Index].Socket, ReadFDS.get()))
				{
					RecvLen = recvfrom(UDPSocketDataList[Index].Socket, OriginalRecv, (int)RecvSize, 0, (PSOCKADDR)&UDPSocketDataList[Index].SockAddr, (PINT)&UDPSocketDataList[Index].AddrLen);
					if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
					{
						memset(OriginalRecv, 0, RecvSize);
						closesocket(UDPSocketDataList[Index].Socket);
						UDPSocketDataList[Index].Socket = 0;
						continue;
					}
					else {
					//Hosts Only Extended check
						if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, false, nullptr))
						{
							memset(OriginalRecv, 0, RecvSize);
							closesocket(UDPSocketDataList[Index].Socket);
							UDPSocketDataList[Index].Socket = 0;
							continue;
						}

					//Mark DNS Cache.
						if (Parameter.CacheType > 0)
							MarkDomainCache(OriginalRecv, RecvLen);

						for (auto SocketDataIter:UDPSocketDataList)
						{
							if (SocketDataIter.Socket > 0)
								closesocket(SocketDataIter.Socket);
						}
						return RecvLen;
					}
				}
			}

		//Send.
			for (auto SocketDataIter:UDPSocketDataList)
			{
				if (FD_ISSET(SocketDataIter.Socket, WriteFDS.get()))
				{
					for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;InnerIndex++)
						sendto(SocketDataIter.Socket, OriginalSend, (int)SendSize, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);
				}
			}

			FD_ZERO(WriteFDS.get());
		}
	//Timeout
		else if (SelectResult == 0)
		{
			for (auto SocketDataIter:UDPSocketDataList)
			{
				if (SocketDataIter.Socket > 0)
					closesocket(SocketDataIter.Socket);
			}
			memset(OriginalRecv, 0, RecvSize);
			return WSAETIMEDOUT;
		}
	//SOCKET_ERROR
		else {
			break;
		}
	}

	for (auto SocketDataIter:UDPSocketDataList)
	{
		if (SocketDataIter.Socket > 0)
			closesocket(SocketDataIter.Socket);
	}
	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}
