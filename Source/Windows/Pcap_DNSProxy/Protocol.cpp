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
extern std::vector<AddressRange> *AddressRangeUsing;
extern std::vector<ResultBlacklistTable> *ResultBlacklistUsing;
extern std::vector<AddressPrefixBlock> *LocalRoutingListUsing;
extern std::mutex LocalAddressLock[QUEUE_PARTNUM / 2U], AddressRangeLock, LocalRoutingListLock;

//Check empty buffer
bool __fastcall CheckEmptyBuffer(const void *Buffer, const size_t Length)
{
	if (Buffer == nullptr)
		return true;

	for (size_t Index = 0;Index < Length;Index++)
	{
		if (((uint8_t *)Buffer)[Index] != NULL)
			return false;
	}

	return true;
}

/*
//Convert host values to network byte order with 64 bits
uint64_t __fastcall hton64(const uint64_t Val)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return (((uint64_t)htonl((int32_t)((Val << 32U) >> 32U))) << 32U)|(uint32_t)htonl((int32_t)(Val >> 32U));
#else //Big-Endian
	return Val;
#endif
}

//Convert network byte order to host values with 64 bits
uint64_t __fastcall ntoh64(const uint64_t Val)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return (((uint64_t)ntohl((int32_t)((Val << 32U) >> 32U))) << 32U)|(uint32_t)ntohl((int32_t)(Val >> 32U));
#else //Big-Endian
	return Val;
#endif
}
*/

//Convert lowercase/uppercase words to uppercase/lowercase words.
size_t __fastcall CaseConvert(bool IsLowerUpper, const PSTR Buffer, const size_t Length)
{
	for (size_t Index = 0;Index < Length;Index++)
	{
	//Lowercase to uppercase
		if (IsLowerUpper)
		{
			if (Buffer[Index] > ASCII_ACCENT && Buffer[Index] < ASCII_BRACES_LEAD)
				Buffer[Index] -= ASCII_LOWER_TO_UPPER;
		}
	//Uppercase to lowercase
		else {
			if (Buffer[Index] > ASCII_AT && Buffer[Index] < ASCII_BRACKETS_LEAD)
				Buffer[Index] += ASCII_UPPER_TO_LOWER;
		}
	}

	return EXIT_SUCCESS;
}

//Convert address strings to binary.
size_t __fastcall AddressStringToBinary(const PSTR AddrString, void *OriginalAddr, const uint16_t Protocol, SSIZE_T &ErrorCode)
{
	std::string sAddrString(AddrString);

//inet_ntop() and inet_pton() was only support in Windows Vista and newer system. [Roy Tam]
#ifdef _WIN64
	SSIZE_T Result = 0;
#else //x86
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	int SockLength = 0;
#endif

	if (Protocol == AF_INET6) //IPv6
	{
	//Check IPv6 addresses
		for (auto StringIter:sAddrString)
		{
			if (StringIter < ASCII_ZERO || StringIter > ASCII_COLON && StringIter < ASCII_UPPERCASE_A || StringIter > ASCII_UPPERCASE_F && StringIter < ASCII_LOWERCASE_A || StringIter > ASCII_LOWERCASE_F)
				break;
		}

	//Check abbreviation format.
		if (sAddrString.find(ASCII_COLON) == std::string::npos)
		{
			sAddrString.clear();
			sAddrString.append("::");
			sAddrString.append(AddrString);
		}
		else if (sAddrString.find(ASCII_COLON) == sAddrString.rfind(ASCII_COLON))
		{
			sAddrString.replace(sAddrString.find(ASCII_COLON), 1U, ("::"));
		}

	//Convert to binary.
	#ifdef _WIN64
		Result = inet_pton(AF_INET6, sAddrString.c_str(), OriginalAddr);
		if (Result == SOCKET_ERROR || Result == FALSE)
	#else //x86
		SockLength = sizeof(sockaddr_in6);
		if (WSAStringToAddressA((PSTR)sAddrString.c_str(), AF_INET6, NULL, (LPSOCKADDR)SockAddr.get(), &SockLength) == SOCKET_ERROR)
	#endif
		{
			ErrorCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#ifdef _WIN64
	#else //x86
		memcpy(OriginalAddr, &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, sizeof(in6_addr));
	#endif
	}
	else { //IPv4
		size_t CommaNum = 0;

	//Check IPv4 addresses
		for (auto StringIter:sAddrString)
		{
			if (StringIter != ASCII_PERIOD && StringIter < ASCII_ZERO || StringIter > ASCII_NINE)
				return EXIT_FAILURE;
			else if (StringIter == ASCII_PERIOD)
				CommaNum++;
		}

	//Delete zeros before whole data.
		while (sAddrString.length() > 1U && sAddrString[0] == ASCII_ZERO && sAddrString[1U] != ASCII_PERIOD)
			sAddrString.erase(0, 1U);

	//Check abbreviation format.
		if (CommaNum == 0)
		{
			sAddrString.clear();
			sAddrString.append("0.0.0.");
			sAddrString.append(AddrString);
		}
		else if (CommaNum == 1U)
		{
			sAddrString.replace(sAddrString.find(ASCII_PERIOD), 1U, (".0.0."));
		}
		else if (CommaNum == 2U)
		{
			sAddrString.replace(sAddrString.find(ASCII_PERIOD), 1U, (".0."));
		}

	//Delete zeros before data.
		while (sAddrString.find(".00") != std::string::npos)
			sAddrString.replace(sAddrString.find(".00"), 3U, ("."));
		while (sAddrString.find(".0") != std::string::npos)
			sAddrString.replace(sAddrString.find(".0"), 2U, ("."));
		while (sAddrString.find("..") != std::string::npos)
			sAddrString.replace(sAddrString.find(".."), 2U, (".0."));
		if (sAddrString[sAddrString.length() - 1U] == ASCII_PERIOD)
			sAddrString.append("0");

	//Convert to binary.
	#ifdef _WIN64
		Result = inet_pton(AF_INET, sAddrString.c_str(), OriginalAddr);
		if (Result == SOCKET_ERROR || Result == FALSE)
	#else //x86
		SockLength = sizeof(sockaddr_in);
		if (WSAStringToAddressA((PSTR)sAddrString.c_str(), AF_INET, NULL, (LPSOCKADDR)SockAddr.get(), &SockLength) == SOCKET_ERROR)
	#endif
		{
			ErrorCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#ifdef _WIN64
	#else //x86
		memcpy(OriginalAddr, &((PSOCKADDR_IN)SockAddr.get())->sin_addr, sizeof(in_addr));
	#endif
	}

	return EXIT_SUCCESS;
}

//Get local address list
PADDRINFOA __fastcall GetLocalAddressList(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> HostName(new char[DOMAIN_MAXSIZE]());
	std::shared_ptr<addrinfo> Hints(new addrinfo());
	PADDRINFOA Result = nullptr /* , PTR = nullptr */;
	
	if (Protocol == AF_INET6) //IPv6
		Hints->ai_family = AF_INET6;
	else //IPv4
		Hints->ai_family = AF_INET;
	Hints->ai_socktype = SOCK_DGRAM;
	Hints->ai_protocol = IPPROTO_UDP;

//Get localhost name.
	if (gethostname(HostName.get(), DOMAIN_MAXSIZE) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Get localhost names error", WSAGetLastError(), nullptr, NULL);
		return nullptr;
	}

//Get localhost data.
	int ResultGetaddrinfo = getaddrinfo(HostName.get(), NULL, Hints.get(), &Result);
	if (ResultGetaddrinfo != 0)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Get localhost addresses error", ResultGetaddrinfo, nullptr, NULL);

		freeaddrinfo(Result);
		return nullptr;
	}

	return Result;
}

//Get information of local addresses
size_t __fastcall GetLocalAddressInformation(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	std::string Result;
	SSIZE_T Index = 0;

/* Old version(2014-09-13)
//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista. [Roy Tam]
#ifdef _WIN64
#else //x86
	DWORD BufferLength = ADDR_STRING_MAXSIZE;
#endif
*/
	PADDRINFOA LocalAddressList = nullptr, LocalAddressListIter = nullptr;
	dns_hdr *pdns_hdr = nullptr;
	dns_qry *pdns_qry = nullptr;
	dns_aaaa_record *pdns_aaaa_record = nullptr;
	dns_a_record *pdns_a_record = nullptr;
	for (;;)
	{
	//Get localhost address(es)
		LocalAddressList = GetLocalAddressList(Protocol);
		if (LocalAddressList == nullptr)
		{
		//Auto-refresh
			if (Parameter.FileRefreshTime == 0)
			{
				return EXIT_SUCCESS;
			}
			else {
				Sleep((DWORD)Parameter.FileRefreshTime);
				continue;
			}
		}
		else {
			std::string DNSPTRString;
			if (Protocol == AF_INET6) //IPv6
			{
			//Initialization
				std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[0]);
				memset(Parameter.LocalAddress[0], 0, PACKET_MAXSIZE);
				Parameter.LocalAddressLength[0] = 0;
				Parameter.LocalAddressPTR[0]->clear();
				Parameter.LocalAddressPTR[0]->shrink_to_fit();

			//Mark local addresses(A part).
				pdns_hdr = (dns_hdr *)Parameter.LocalAddress[0];
				pdns_hdr->Flags = htons(DNS_SQR_NEA);
				pdns_hdr->Questions = htons(U16_NUM_ONE);
				Parameter.LocalAddressLength[0] += sizeof(dns_hdr);
				memcpy(Parameter.LocalAddress[0] + Parameter.LocalAddressLength[0], Parameter.LocalFQDN, Parameter.LocalFQDNLength);
				Parameter.LocalAddressLength[0] += Parameter.LocalFQDNLength;
				pdns_qry = (dns_qry *)(Parameter.LocalAddress[0] + Parameter.LocalAddressLength[0]);
				pdns_qry->Type = htons(DNS_RECORD_AAAA);
				pdns_qry->Classes = htons(DNS_CLASS_IN);
				Parameter.LocalAddressLength[0] += sizeof(dns_qry);

			//Read addresses list and convert to Fully Qualified Domain Name/FQDN PTR.
//				size_t Location = 0, Colon = 0;
				for (LocalAddressListIter = LocalAddressList;LocalAddressListIter != nullptr;LocalAddressListIter = LocalAddressListIter->ai_next)
				{
					if (LocalAddressListIter->ai_family == Protocol && LocalAddressListIter->ai_addrlen == sizeof(sockaddr_in6) && 
						LocalAddressListIter->ai_addr->sa_family == Protocol)
					{
					//Mark local addresses(B part).
						if (Parameter.LocalAddressLength[0] <= PACKET_MAXSIZE - sizeof(dns_aaaa_record))
						{
							pdns_aaaa_record = (dns_aaaa_record *)(Parameter.LocalAddress[0] + Parameter.LocalAddressLength[0]);
							pdns_aaaa_record->Name = htons(DNS_QUERY_PTR);
							pdns_aaaa_record->Classes = htons(DNS_CLASS_IN);
							pdns_aaaa_record->TTL = htonl(Parameter.HostsDefaultTTL);
							pdns_aaaa_record->Type = htons(DNS_RECORD_AAAA);
							pdns_aaaa_record->Length = htons(sizeof(in6_addr));
							pdns_aaaa_record->Addr = ((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr;
							Parameter.LocalAddressLength[0] += sizeof(dns_aaaa_record);
							pdns_hdr->Answer++;
						}

					//IPv6 tunnels support(6to4, ISATAP and Teredo), but only check preferred address.
//						Parameter.Tunnel_Teredo.clear();
						if (((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr.u.Word[0] == htons(0x2001) && ((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr.u.Word[1U] == 0 || //Teredo relay/tunnel Addresses(2001::/32, RFC 4380)
							((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr.u.Word[0] == htons(0x2002) || //6to4 relay/tunnel Addresses(2002::/16, Section 2 in RFC 3056)
							((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr.u.Byte[0] >= 0x80 && ((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr.u.Byte[1U] <= 0xBF && //Link-Local Unicast Contrast Addresses/LUC(FE80::/10, Section 2.5.6 in RFC 4291)
							((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr.u.Word[4U] == 0 && ((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr.u.Word[5U] == htons(0x5EFE)) //ISATAP Interface Identifiers Addresses(Prefix:0:5EFE:0:0:0:0/64, which also in Link-Local Unicast Contrast Addresses/LUC, Section 6.1 in RFC 5214)
/*
						{
							in_addr TeredoTunnelAddress = {0};
							TeredoTunnelAddress.S_un.S_un_w.s_w1 = ((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr.u.Word[2U];
							TeredoTunnelAddress.S_un.S_un_w.s_w2 = ((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr.u.Word[3U];
							Parameter.Tunnel_Teredo.push_back(TeredoTunnelAddress);
						}
*/
								Parameter.Tunnel_IPv6 = true;

					//Initialization
						DNSPTRString.clear();
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

/* Old version(2014-09-13)
						Location = 0;
						Colon = 0;

					//Convert from in6_addr to string.
					//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista. [Roy Tam]
					#ifdef _WIN64
						if (inet_ntop(AF_INET6, &((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE) == nullptr)
					#else //x86
						if (WSAAddressToStringA((LPSOCKADDR)LocalAddressListIter->ai_addr, sizeof(sockaddr_in6), NULL, Addr.get(), &BufferLength) == SOCKET_ERROR)
					#endif
						{
							PrintError(LOG_ERROR_WINSOCK, L"Local IPv6 Address format error", WSAGetLastError(), nullptr, NULL);
							return EXIT_FAILURE;
						}
						DNSPTRString[0].append(Addr.get());

					//Count colons
						for (auto StringIndex:DNSPTRString[0])
						{
							if (StringIndex == 58)
								Colon++;
						}

					//Convert to standard IPv6 address format B part("::" -> ":0000:...").
						Location = DNSPTRString[0].find("::");
						Colon = 8U - Colon;
						DNSPTRString[1U].append(DNSPTRString[0], 0, Location);
						while (Colon != 0)
						{
							DNSPTRString[1U].append(":0000");
							Colon--;
						}
						DNSPTRString[1U].append(DNSPTRString[0], Location + 1U, DNSPTRString[0].length() - Location + 1U);

						for (LocalAddressIter = DNSPTRString[1U].begin();LocalAddressIter != DNSPTRString[1U].end();LocalAddressIter++)
						{
							if (*LocalAddressIter == 58)
								LocalAddressIter = DNSPTRString[1U].erase(LocalAddressIter);
						}

					//Convert to DNS PTR Record and copy to Result.
						for (Index = (SSIZE_T)(DNSPTRString[1U].length() - 1U);Index != -1;Index--)
						{
							char Word[] = {0, 0};
							Word[0] = DNSPTRString[1U].at(Index);
							Result.append(Word);
							Result.append(".");
						}
*/
					//Convert from in6_addr to string.
						size_t AddrStringLen = 0;
						for (Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
						{
							_ultoa_s(htons(((PSOCKADDR_IN6)LocalAddressListIter->ai_addr)->sin6_addr.u.Word[Index]), Addr.get(), ADDR_STRING_MAXSIZE, NUM_HEX);

						//Add zeros to beginning of string.
							if (strlen(Addr.get()) < 4U)
							{
								AddrStringLen = strlen(Addr.get());
								memmove(Addr.get() + 4U - strlen(Addr.get()), Addr.get(), strlen(Addr.get()));
								memset(Addr.get(), ASCII_ZERO, 4U - AddrStringLen);
							}
							DNSPTRString.append(Addr.get());
							memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

						//Last
							if (Index < sizeof(in6_addr) / sizeof(uint16_t) - 1U)
								DNSPTRString.append(":");
						}

					//Convert to standard IPv6 address format(":0:" -> ":0000:").
						Index = 0;
						while (DNSPTRString.find(":0:", Index) != std::string::npos)
							DNSPTRString.replace(DNSPTRString.find(":0:", Index), 3U, ":0000:");

					//Delete all colons
						while (DNSPTRString.find(":") != std::string::npos)
							DNSPTRString.erase(DNSPTRString.find(":"), 1U);

					//Convert standard IPv6 address string to DNS PTR.
						for (Index = DNSPTRString.length() - 1U;Index >= 0;Index--)
						{
							Result.append(DNSPTRString, Index, 1U);
							Result.append(".");
						}
						Result.append("ip6.arpa");

					//Add to global list.
						Parameter.LocalAddressPTR[0]->push_back(Result);
						Result.clear();
						Result.shrink_to_fit();
					}
				}

			//Mark local addresses(C part).
				if (pdns_hdr->Answer == 0)
				{
					memset(Parameter.LocalAddress[0], 0, PACKET_MAXSIZE);
					Parameter.LocalAddressLength[0] = 0;
				}
				else {
					pdns_hdr->Answer = htons(pdns_hdr->Answer);
				}

			//Add to global list.
				LocalAddressMutexIPv6.unlock();
				freeaddrinfo(LocalAddressList);
				LocalAddressList = nullptr;
			}
			else { //IPv4
			//Initialization
				std::unique_lock<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[1U]);
				memset(Parameter.LocalAddress[1U], 0, PACKET_MAXSIZE);
				Parameter.LocalAddressLength[1U] = 0;
				Parameter.LocalAddressPTR[1U]->clear();
				Parameter.LocalAddressPTR[1U]->shrink_to_fit();

			//Mark local addresses(A part).
				pdns_hdr = (dns_hdr *)Parameter.LocalAddress[1U];
				pdns_hdr->Flags = htons(DNS_SQR_NEA);
				pdns_hdr->Questions = htons(U16_NUM_ONE);
				Parameter.LocalAddressLength[1U] += sizeof(dns_hdr);
				memcpy(Parameter.LocalAddress[1U] + Parameter.LocalAddressLength[1U], Parameter.LocalFQDN, Parameter.LocalFQDNLength);
				Parameter.LocalAddressLength[1U] += Parameter.LocalFQDNLength;
				pdns_qry = (dns_qry *)(Parameter.LocalAddress[1U] + Parameter.LocalAddressLength[1U]);
				pdns_qry->Type = htons(DNS_RECORD_AAAA);
				pdns_qry->Classes = htons(DNS_CLASS_IN);
				Parameter.LocalAddressLength[1U] += sizeof(dns_qry);

			//Read addresses list and convert to Fully Qualified Domain Name/FQDN PTR.
//				char CharAddr[4U][4U] = {0};
//				size_t Localtion[] = {0, 0};
				for (LocalAddressListIter = LocalAddressList;LocalAddressListIter != nullptr;LocalAddressListIter = LocalAddressListIter->ai_next)
				{
					if (LocalAddressListIter->ai_family == Protocol && LocalAddressListIter->ai_addrlen == sizeof(sockaddr_in) && 
						LocalAddressListIter->ai_addr->sa_family == Protocol)
					{
					//Mark local addresses(B part).
						if (Parameter.LocalAddressLength[1U] <= PACKET_MAXSIZE - sizeof(dns_a_record))
						{
							pdns_a_record = (dns_a_record *)(Parameter.LocalAddress[1U] + Parameter.LocalAddressLength[1U]);
							pdns_a_record->Name = htons(DNS_QUERY_PTR);
							pdns_a_record->Classes = htons(DNS_CLASS_IN);
							pdns_a_record->TTL = htonl(Parameter.HostsDefaultTTL);
							pdns_a_record->Type = htons(DNS_RECORD_A);
							pdns_a_record->Length = htons(sizeof(in_addr));
							pdns_a_record->Addr = ((PSOCKADDR_IN)LocalAddressListIter->ai_addr)->sin_addr;
							Parameter.LocalAddressLength[1U] += sizeof(dns_a_record);
							pdns_hdr->Answer++;
						}

					//Initialization
						DNSPTRString.clear();
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

/* Old version(2014-09-13)
						memset(&CharAddr, 0, sizeof(CharAddr));
						memset(&Localtion, 0, sizeof(Localtion));

					//Convert from in_addr to string.
					//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista. [Roy Tam]
					#ifdef _WIN64
						if (inet_ntop(AF_INET, &((PSOCKADDR_IN)LocalAddressListIter->ai_addr)->sin_addr, Addr.get(), ADDR_STRING_MAXSIZE) == nullptr)
					#else //x86
						if (WSAAddressToStringA((LPSOCKADDR)LocalAddressListIter->ai_addr, sizeof(sockaddr_in), NULL, Addr.get(), &BufferLength) == SOCKET_ERROR)
					#endif
						{
							PrintError(LOG_ERROR_WINSOCK, L"Local IPv4 Address format error", WSAGetLastError(), nullptr, NULL);
							return EXIT_FAILURE;
						}

					//Detach Address data.
						for (Index = 0;Index < (SSIZE_T)strlen(Addr.get());Index++)
						{
							if (Addr.get()[Index] == 46)
							{
								Localtion[1U] = 0;
								Localtion[0]++;
							}
							else {
								CharAddr[Localtion[0]][Localtion[1U]] = Addr.get()[Index];
								Localtion[1U]++;
							}
						}

					//Convert to DNS PTR Record and copy to Result.
						for (Index = 4;Index > 0;Index--)
						{
							Result.append(CharAddr[Index - 1]);
							Result.append(".");
						}
*/
					//Convert from in_addr to DNS PTR.
						_itoa_s(((PSOCKADDR_IN)LocalAddressListIter->ai_addr)->sin_addr.S_un.S_un_b.s_b4, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						_itoa_s(((PSOCKADDR_IN)LocalAddressListIter->ai_addr)->sin_addr.S_un.S_un_b.s_b3, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						_itoa_s(((PSOCKADDR_IN)LocalAddressListIter->ai_addr)->sin_addr.S_un.S_un_b.s_b2, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						_itoa_s(((PSOCKADDR_IN)LocalAddressListIter->ai_addr)->sin_addr.S_un.S_un_b.s_b1, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						Result.append("in-addr.arpa");

					//Add to global list.
						(Parameter.LocalAddressPTR[1U])->push_back(Result);
						Result.clear();
						Result.shrink_to_fit();
					}
				}

			//Mark local addresses(C part).
				if (pdns_hdr->Answer == 0)
				{
					memset(Parameter.LocalAddress[1U], 0, PACKET_MAXSIZE);
					Parameter.LocalAddressLength[1U] = 0;
				}
				else {
					pdns_hdr->Answer = htons(pdns_hdr->Answer);
				}

			//Add to global list.
				LocalAddressMutexIPv4.unlock();
				freeaddrinfo(LocalAddressList);
				LocalAddressList = nullptr;
			}
		}

	//Auto-refresh
		if (Parameter.FileRefreshTime == 0)
			return EXIT_SUCCESS;
		else 
			Sleep((DWORD)Parameter.FileRefreshTime);
	}

	PrintError(LOG_ERROR_SYSTEM, L"Get Local Address Information module Monitor terminated", NULL, nullptr, NULL);
	return EXIT_SUCCESS;
}

//Convert service name to port
uint16_t __fastcall ServiceNameToHex(const PSTR Buffer)
{
//Server name
	if (strstr(Buffer, ("TCPMUX")) != nullptr || strstr(Buffer, ("tcpmux")) != nullptr)
		return htons(IPPORT_TCPMUX);
	else if (strstr(Buffer, ("ECHO")) != nullptr || strstr(Buffer, ("echo")) != nullptr)
		return htons(IPPORT_ECHO);
	else if (strstr(Buffer, ("DISCARD")) != nullptr || strstr(Buffer, ("discard")) != nullptr)
		return htons(IPPORT_DISCARD);
	else if (strstr(Buffer, ("SYSTAT")) != nullptr || strstr(Buffer, ("systat")) != nullptr)
		return htons(IPPORT_SYSTAT);
	else if (strstr(Buffer, ("DAYTIME")) != nullptr || strstr(Buffer, ("daytime")) != nullptr)
		return htons(IPPORT_DAYTIME);
	else if (strstr(Buffer, ("NETSTAT")) != nullptr || strstr(Buffer, ("netstat")) != nullptr)
		return htons(IPPORT_NETSTAT);
	else if (strstr(Buffer, ("QOTD")) != nullptr || strstr(Buffer, ("qotd")) != nullptr)
		return htons(IPPORT_QOTD);
	else if (strstr(Buffer, ("MSP")) != nullptr || strstr(Buffer, ("msp")) != nullptr)
		return htons(IPPORT_MSP);
	else if (strstr(Buffer, ("CHARGEN")) != nullptr || strstr(Buffer, ("chargen")) != nullptr)
		return htons(IPPORT_CHARGEN);
	else if (strstr(Buffer, ("FTPDATA")) != nullptr || strstr(Buffer, ("ftpdata")) != nullptr)
		return htons(IPPORT_FTP_DATA);
	else if (strstr(Buffer, ("FTP")) != nullptr || strstr(Buffer, ("ftp")) != nullptr)
		return htons(IPPORT_FTP);
	else if (strstr(Buffer, ("SSH")) != nullptr || strstr(Buffer, ("ssh")) != nullptr)
		return htons(IPPORT_SSH);
	else if (strstr(Buffer, ("TELNET")) != nullptr || strstr(Buffer, ("telnet")) != nullptr)
		return htons(IPPORT_TELNET);
	else if (strstr(Buffer, ("SMTP")) != nullptr || strstr(Buffer, ("smtp")) != nullptr)
		return htons(IPPORT_SMTP);
	else if (strstr(Buffer, ("TIME")) != nullptr || strstr(Buffer, ("time")) != nullptr)
		return htons(IPPORT_TIMESERVER);
	else if (strstr(Buffer, ("RAP")) != nullptr || strstr(Buffer, ("rap")) != nullptr)
		return htons(IPPORT_RAP);
	else if (strstr(Buffer, ("RLP")) != nullptr || strstr(Buffer, ("rlp")) != nullptr)
		return htons(IPPORT_RLP);
	else if (strstr(Buffer, ("NAME")) != nullptr || strstr(Buffer, ("name")) != nullptr)
		return htons(IPPORT_NAMESERVER);
	else if (strstr(Buffer, ("WHOIS")) != nullptr || strstr(Buffer, ("whois")) != nullptr)
		return htons(IPPORT_WHOIS);
	else if (strstr(Buffer, ("TACACS")) != nullptr || strstr(Buffer, ("tacacs")) != nullptr)
		return htons(IPPORT_TACACS);
	else if (strstr(Buffer, ("DNS")) != nullptr || strstr(Buffer, ("dns")) != nullptr)
		return htons(IPPORT_DNS);
	else if (strstr(Buffer, ("XNSAUTH")) != nullptr || strstr(Buffer, ("xnsauth")) != nullptr)
		return htons(IPPORT_XNSAUTH);
	else if (strstr(Buffer, ("MTP")) != nullptr || strstr(Buffer, ("mtp")) != nullptr)
		return htons(IPPORT_MTP);
	else if (strstr(Buffer, ("BOOTPS")) != nullptr || strstr(Buffer, ("bootps")) != nullptr)
		return htons(IPPORT_BOOTPS);
	else if (strstr(Buffer, ("BOOTPC")) != nullptr || strstr(Buffer, ("bootpc")) != nullptr)
		return htons(IPPORT_BOOTPC);
	else if (strstr(Buffer, ("TFTP")) != nullptr || strstr(Buffer, ("tftp")) != nullptr)
		return htons(IPPORT_TFTP);
	else if (strstr(Buffer, ("RJE")) != nullptr || strstr(Buffer, ("rje")) != nullptr)
		return htons(IPPORT_RJE);
	else if (strstr(Buffer, ("FINGER")) != nullptr || strstr(Buffer, ("finger")) != nullptr)
		return htons(IPPORT_FINGER);
	else if (strstr(Buffer, ("HTTP")) != nullptr || strstr(Buffer, ("http")) != nullptr)
		return htons(IPPORT_HTTP);
	else if (strstr(Buffer, ("HTTPBACKUP")) != nullptr || strstr(Buffer, ("httpbackup")) != nullptr)
		return htons(IPPORT_HTTPBACKUP);
	else if (strstr(Buffer, ("TTYLINK")) != nullptr || strstr(Buffer, ("ttylink")) != nullptr)
		return htons(IPPORT_TTYLINK);
	else if (strstr(Buffer, ("SUPDUP")) != nullptr || strstr(Buffer, ("supdup")) != nullptr)
		return htons(IPPORT_SUPDUP);
	else if (strstr(Buffer, ("POP3")) != nullptr || strstr(Buffer, ("pop3")) != nullptr)
		return htons(IPPORT_POP3);
	else if (strstr(Buffer, ("SUNRPC")) != nullptr || strstr(Buffer, ("sunrpc")) != nullptr)
		return htons(IPPORT_SUNRPC);
	else if (strstr(Buffer, ("SQL")) != nullptr || strstr(Buffer, ("sql")) != nullptr)
		return htons(IPPORT_SQL);
	else if (strstr(Buffer, ("NTP")) != nullptr || strstr(Buffer, ("ntp")) != nullptr)
		return htons(IPPORT_NTP);
	else if (strstr(Buffer, ("EPMAP")) != nullptr || strstr(Buffer, ("epmap")) != nullptr)
		return htons(IPPORT_EPMAP);
	else if (strstr(Buffer, ("NETBIOSNS")) != nullptr || strstr(Buffer, ("netbiosns")) != nullptr)
		return htons(IPPORT_NETBIOS_NS);
	else if (strstr(Buffer, ("NETBIOSDGM")) != nullptr || strstr(Buffer, ("netbiosdgm")) != nullptr)
		return htons(IPPORT_NETBIOS_DGM);
	else if (strstr(Buffer, ("NETBIOSSSN")) != nullptr || strstr(Buffer, ("netbiosssn")) != nullptr)
		return htons(IPPORT_NETBIOS_SSN);
	else if (strstr(Buffer, ("IMAP")) != nullptr || strstr(Buffer, ("imap")) != nullptr)
		return htons(IPPORT_IMAP);
	else if (strstr(Buffer, ("BFTP")) != nullptr || strstr(Buffer, ("bftp")) != nullptr)
		return htons(IPPORT_BFTP);
	else if (strstr(Buffer, ("SGMP")) != nullptr || strstr(Buffer, ("sgmp")) != nullptr)
		return htons(IPPORT_SGMP);
	else if (strstr(Buffer, ("SQLSRV")) != nullptr || strstr(Buffer, ("sqlsrv")) != nullptr)
		return htons(IPPORT_SQLSRV);
	else if (strstr(Buffer, ("DMSP")) != nullptr || strstr(Buffer, ("dmsp")) != nullptr)
		return htons(IPPORT_DMSP);
	else if (strstr(Buffer, ("SNMP")) != nullptr || strstr(Buffer, ("snmp")) != nullptr)
		return htons(IPPORT_SNMP);
	else if (strstr(Buffer, ("SNMPTRAP")) != nullptr || strstr(Buffer, ("snmptrap")) != nullptr)
		return htons(IPPORT_SNMP_TRAP);
	else if (strstr(Buffer, ("ATRTMP")) != nullptr || strstr(Buffer, ("atrtmp")) != nullptr)
		return htons(IPPORT_ATRTMP);
	else if (strstr(Buffer, ("ATHBP")) != nullptr || strstr(Buffer, ("athbp")) != nullptr)
		return htons(IPPORT_ATHBP);
	else if (strstr(Buffer, ("QMTP")) != nullptr || strstr(Buffer, ("qmtp")) != nullptr)
		return htons(IPPORT_QMTP);
	else if (strstr(Buffer, ("IPX")) != nullptr || strstr(Buffer, ("ipx")) != nullptr)
		return htons(IPPORT_IPX);
	else if (strstr(Buffer, ("IMAP3")) != nullptr || strstr(Buffer, ("imap3")) != nullptr)
		return htons(IPPORT_IMAP3);
	else if (strstr(Buffer, ("BGMP")) != nullptr || strstr(Buffer, ("bgmp")) != nullptr)
		return htons(IPPORT_BGMP);
	else if (strstr(Buffer, ("TSP")) != nullptr || strstr(Buffer, ("tsp")) != nullptr)
		return htons(IPPORT_TSP);
	else if (strstr(Buffer, ("IMMP")) != nullptr || strstr(Buffer, ("immp")) != nullptr)
		return htons(IPPORT_IMMP);
	else if (strstr(Buffer, ("ODMR")) != nullptr || strstr(Buffer, ("odmr")) != nullptr)
		return htons(IPPORT_ODMR);
	else if (strstr(Buffer, ("RPC2PORTMAP")) != nullptr || strstr(Buffer, ("rpc2portmap")) != nullptr)
		return htons(IPPORT_RPC2PORTMAP);
	else if (strstr(Buffer, ("CLEARCASE")) != nullptr || strstr(Buffer, ("clearcase")) != nullptr)
		return htons(IPPORT_CLEARCASE);
	else if (strstr(Buffer, ("HPALARMMGR")) != nullptr || strstr(Buffer, ("hpalarmmgr")) != nullptr)
		return htons(IPPORT_HPALARMMGR);
	else if (strstr(Buffer, ("ARNS")) != nullptr || strstr(Buffer, ("arns")) != nullptr)
		return htons(IPPORT_ARNS);
	else if (strstr(Buffer, ("AURP")) != nullptr || strstr(Buffer, ("aurp")) != nullptr)
		return htons(IPPORT_AURP);
	else if (strstr(Buffer, ("LDAP")) != nullptr || strstr(Buffer, ("ldap")) != nullptr)
		return htons(IPPORT_LDAP);
	else if (strstr(Buffer, ("UPS")) != nullptr || strstr(Buffer, ("ups")) != nullptr)
		return htons(IPPORT_UPS);
	else if (strstr(Buffer, ("SLP")) != nullptr || strstr(Buffer, ("slp")) != nullptr)
		return htons(IPPORT_SLP);
	else if (strstr(Buffer, ("HTTPS")) != nullptr || strstr(Buffer, ("https")) != nullptr)
		return htons(IPPORT_HTTPS);
	else if (strstr(Buffer, ("SNPP")) != nullptr || strstr(Buffer, ("snpp")) != nullptr)
		return htons(IPPORT_SNPP);
	else if (strstr(Buffer, ("MICROSOFTDS")) != nullptr || strstr(Buffer, ("microsoftds")) != nullptr)
		return htons(IPPORT_MICROSOFT_DS);
	else if (strstr(Buffer, ("KPASSWD")) != nullptr || strstr(Buffer, ("kpasswd")) != nullptr)
		return htons(IPPORT_KPASSWD);
	else if (strstr(Buffer, ("TCPNETHASPSRV")) != nullptr || strstr(Buffer, ("tcpnethaspsrv")) != nullptr)
		return htons(IPPORT_TCPNETHASPSRV);
	else if (strstr(Buffer, ("RETROSPECT")) != nullptr || strstr(Buffer, ("retrospect")) != nullptr)
		return htons(IPPORT_RETROSPECT);
	else if (strstr(Buffer, ("ISAKMP")) != nullptr || strstr(Buffer, ("isakmp")) != nullptr)
		return htons(IPPORT_ISAKMP);
	else if (strstr(Buffer, ("BIFFUDP")) != nullptr || strstr(Buffer, ("biffudp")) != nullptr)
		return htons(IPPORT_BIFFUDP);
	else if (strstr(Buffer, ("WHOSERVER")) != nullptr || strstr(Buffer, ("whoserver")) != nullptr)
		return htons(IPPORT_WHOSERVER);
	else if (strstr(Buffer, ("SYSLOG")) != nullptr || strstr(Buffer, ("syslog")) != nullptr)
		return htons(IPPORT_SYSLOG);
	else if (strstr(Buffer, ("ROUTERSERVER")) != nullptr || strstr(Buffer, ("routerserver")) != nullptr)
		return htons(IPPORT_ROUTESERVER);
	else if (strstr(Buffer, ("NCP")) != nullptr || strstr(Buffer, ("ncp")) != nullptr)
		return htons(IPPORT_NCP);
	else if (strstr(Buffer, ("COURIER")) != nullptr || strstr(Buffer, ("courier")) != nullptr)
		return htons(IPPORT_COURIER);
	else if (strstr(Buffer, ("COMMERCE")) != nullptr || strstr(Buffer, ("commerce")) != nullptr)
		return htons(IPPORT_COMMERCE);
	else if (strstr(Buffer, ("RTSP")) != nullptr || strstr(Buffer, ("rtsp")) != nullptr)
		return htons(IPPORT_RTSP);
	else if (strstr(Buffer, ("NNTP")) != nullptr || strstr(Buffer, ("nntp")) != nullptr)
		return htons(IPPORT_NNTP);
	else if (strstr(Buffer, ("HTTPRPCEPMAP")) != nullptr || strstr(Buffer, ("httprpcepmap")) != nullptr)
		return htons(IPPORT_HTTPRPCEPMAP);
	else if (strstr(Buffer, ("IPP")) != nullptr || strstr(Buffer, ("ipp")) != nullptr)
		return htons(IPPORT_IPP);
	else if (strstr(Buffer, ("LDAPS")) != nullptr || strstr(Buffer, ("ldaps")) != nullptr)
		return htons(IPPORT_LDAPS);
	else if (strstr(Buffer, ("MSDP")) != nullptr || strstr(Buffer, ("msdp")) != nullptr)
		return htons(IPPORT_MSDP);
	else if (strstr(Buffer, ("AODV")) != nullptr || strstr(Buffer, ("aodv")) != nullptr)
		return htons(IPPORT_AODV);
	else if (strstr(Buffer, ("FTPSDATA")) != nullptr || strstr(Buffer, ("ftpsdata")) != nullptr)
		return htons(IPPORT_FTPSDATA);
	else if (strstr(Buffer, ("FTPS")) != nullptr || strstr(Buffer, ("ftps")) != nullptr)
		return htons(IPPORT_FTPS);
	else if (strstr(Buffer, ("NAS")) != nullptr || strstr(Buffer, ("nas")) != nullptr)
		return htons(IPPORT_NAS);
	else if (strstr(Buffer, ("TELNETS")) != nullptr || strstr(Buffer, ("telnets")) != nullptr)
		return htons(IPPORT_TELNETS);
//No match.
	return 0;
}

//Convert DNS type name to hex
uint16_t __fastcall DNSTypeNameToHex(const PSTR Buffer)
{
//DNS type name
	if (strstr(Buffer, ("A")) != nullptr || strstr(Buffer, ("a")) != nullptr)
		return htons(DNS_RECORD_A);
	else if (strstr(Buffer, ("NS")) != nullptr || strstr(Buffer, ("ns")) != nullptr)
		return htons(DNS_RECORD_NS);
	else if (strstr(Buffer, ("MD")) != nullptr || strstr(Buffer, ("md")) != nullptr)
		return htons(DNS_RECORD_MD);
	else if (strstr(Buffer, ("MF")) != nullptr || strstr(Buffer, ("mf")) != nullptr)
		return htons(DNS_RECORD_MF);
	else if (strstr(Buffer, ("CNAME")) != nullptr || strstr(Buffer, ("cname")) != nullptr)
		return htons(DNS_RECORD_CNAME);
	else if (strstr(Buffer, ("SOA")) != nullptr || strstr(Buffer, ("soa")) != nullptr)
		return htons(DNS_RECORD_SOA);
	else if (strstr(Buffer, ("MB")) != nullptr || strstr(Buffer, ("mb")) != nullptr)
		return htons(DNS_RECORD_MB);
	else if (strstr(Buffer, ("MG")) != nullptr || strstr(Buffer, ("mg")) != nullptr)
		return htons(DNS_RECORD_MG);
	else if (strstr(Buffer, ("MR")) != nullptr || strstr(Buffer, ("mr")) != nullptr)
		return htons(DNS_RECORD_MR);
	else if (strstr(Buffer, ("PTR")) != nullptr || strstr(Buffer, ("ptr")) != nullptr)
		return htons(DNS_RECORD_PTR);
	else if (strstr(Buffer, ("NULL")) != nullptr || strstr(Buffer, ("null")) != nullptr)
		return htons(DNS_RECORD_NULL);
	else if (strstr(Buffer, ("WKS")) != nullptr || strstr(Buffer, ("wks")) != nullptr)
		return htons(DNS_RECORD_WKS);
	else if (strstr(Buffer, ("HINFO")) != nullptr || strstr(Buffer, ("hinfo")) != nullptr)
		return htons(DNS_RECORD_HINFO);
	else if (strstr(Buffer, ("MINFO")) != nullptr || strstr(Buffer, ("minfo")) != nullptr)
		return htons(DNS_RECORD_MINFO);
	else if (strstr(Buffer, ("MX")) != nullptr || strstr(Buffer, ("mx")) != nullptr)
		return htons(DNS_RECORD_MX);
	else if (strstr(Buffer, ("TXT")) != nullptr || strstr(Buffer, ("txt")) != nullptr)
		return htons(DNS_RECORD_TXT);
	else if (strstr(Buffer, ("RP")) != nullptr || strstr(Buffer, ("rp")) != nullptr)
		return htons(DNS_RECORD_RP);
	else if (strstr(Buffer, ("SIG")) != nullptr || strstr(Buffer, ("sig")) != nullptr)
		return htons(DNS_RECORD_SIG);
	else if (strstr(Buffer, ("AFSDB")) != nullptr || strstr(Buffer, ("afsdb")) != nullptr)
		return htons(DNS_RECORD_AFSDB);
	else if (strstr(Buffer, ("X25")) != nullptr || strstr(Buffer, ("x25")) != nullptr)
		return htons(DNS_RECORD_X25);
	else if (strstr(Buffer, ("ISDN")) != nullptr || strstr(Buffer, ("isdn")) != nullptr)
		return htons(DNS_RECORD_ISDN);
	else if (strstr(Buffer, ("RT")) != nullptr || strstr(Buffer, ("rt")) != nullptr)
		return htons(DNS_RECORD_RT);
	else if (strstr(Buffer, ("NSAP")) != nullptr || strstr(Buffer, ("nsap")) != nullptr)
		return htons(DNS_RECORD_NSAP);
	else if (strstr(Buffer, ("NSAPPTR")) != nullptr || strstr(Buffer, ("nsapptr")) != nullptr)
		return htons(DNS_RECORD_NSAP_PTR);
	else if (strstr(Buffer, ("SIG")) != nullptr || strstr(Buffer, ("sig")) != nullptr)
		return htons(DNS_RECORD_SIG);
	else if (strstr(Buffer, ("KEY")) != nullptr || strstr(Buffer, ("key")) != nullptr)
		return htons(DNS_RECORD_KEY);
	else if (strstr(Buffer, ("AAAA")) != nullptr || strstr(Buffer, ("aaaa")) != nullptr)
		return htons(DNS_RECORD_AAAA);
	else if (strstr(Buffer, ("PX")) != nullptr || strstr(Buffer, ("px")) != nullptr)
		return htons(DNS_RECORD_PX);
	else if (strstr(Buffer, ("GPOS")) != nullptr || strstr(Buffer, ("gpos")) != nullptr)
		return htons(DNS_RECORD_GPOS);
	else if (strstr(Buffer, ("LOC")) != nullptr || strstr(Buffer, ("loc")) != nullptr)
		return htons(DNS_RECORD_LOC);
	else if (strstr(Buffer, ("NXT")) != nullptr || strstr(Buffer, ("nxt")) != nullptr)
		return htons(DNS_RECORD_NXT);
	else if (strstr(Buffer, ("EID")) != nullptr || strstr(Buffer, ("eid")) != nullptr)
		return htons(DNS_RECORD_EID);
	else if (strstr(Buffer, ("NIMLOC")) != nullptr || strstr(Buffer, ("nimloc")) != nullptr)
		return htons(DNS_RECORD_NIMLOC);
	else if (strstr(Buffer, ("SRV")) != nullptr || strstr(Buffer, ("srv")) != nullptr)
		return htons(DNS_RECORD_SRV);
	else if (strstr(Buffer, ("ATMA")) != nullptr || strstr(Buffer, ("atma")) != nullptr)
		return htons(DNS_RECORD_ATMA);
	else if (strstr(Buffer, ("NAPTR")) != nullptr || strstr(Buffer, ("naptr")) != nullptr)
		return htons(DNS_RECORD_NAPTR);
	else if (strstr(Buffer, ("KX")) != nullptr || strstr(Buffer, ("kx")) != nullptr)
		return htons(DNS_RECORD_KX);
	else if (strstr(Buffer, ("CERT")) != nullptr || strstr(Buffer, ("cert")) != nullptr)
		return htons(DNS_RECORD_CERT);
	else if (strstr(Buffer, ("A6")) != nullptr || strstr(Buffer, ("a6")) != nullptr)
		return htons(DNS_RECORD_A6);
	else if (strstr(Buffer, ("DNAME")) != nullptr || strstr(Buffer, ("dname")) != nullptr)
		return htons(DNS_RECORD_DNAME);
	else if (strstr(Buffer, ("SINK")) != nullptr || strstr(Buffer, ("sink")) != nullptr)
		return htons(DNS_RECORD_SINK);
	else if (strstr(Buffer, ("OPT")) != nullptr || strstr(Buffer, ("opt")) != nullptr)
		return htons(DNS_RECORD_OPT);
	else if (strstr(Buffer, ("APL")) != nullptr || strstr(Buffer, ("apl")) != nullptr)
		return htons(DNS_RECORD_APL);
	else if (strstr(Buffer, ("DS")) != nullptr || strstr(Buffer, ("ds")) != nullptr)
		return htons(DNS_RECORD_DS);
	else if (strstr(Buffer, ("SSHFP")) != nullptr || strstr(Buffer, ("sshfp")) != nullptr)
		return htons(DNS_RECORD_SSHFP);
	else if (strstr(Buffer, ("IPSECKEY")) != nullptr || strstr(Buffer, ("ipseckey")) != nullptr)
		return htons(DNS_RECORD_IPSECKEY);
	else if (strstr(Buffer, ("RRSIG")) != nullptr || strstr(Buffer, ("rrsig")) != nullptr)
		return htons(DNS_RECORD_RRSIG);
	else if (strstr(Buffer, ("NSEC")) != nullptr || strstr(Buffer, ("nsec")) != nullptr)
		return htons(DNS_RECORD_NSEC);
	else if (strstr(Buffer, ("DNSKEY")) != nullptr || strstr(Buffer, ("dnskey")) != nullptr)
		return htons(DNS_RECORD_DNSKEY);
	else if (strstr(Buffer, ("DHCID")) != nullptr || strstr(Buffer, ("dhcid")) != nullptr)
		return htons(DNS_RECORD_DHCID);
	else if (strstr(Buffer, ("NSEC3")) != nullptr || strstr(Buffer, ("nsec3")) != nullptr)
		return htons(DNS_RECORD_NSEC3);
	else if (strstr(Buffer, ("NSEC3PARAM")) != nullptr || strstr(Buffer, ("nsec3param")) != nullptr)
		return htons(DNS_RECORD_NSEC3PARAM);
	else if (strstr(Buffer, ("TLSA")) != nullptr || strstr(Buffer, ("tlsa")) != nullptr)
		return htons(DNS_RECORD_TLSA);
	else if (strstr(Buffer, ("HIP")) != nullptr || strstr(Buffer, ("hip")) != nullptr)
		return htons(DNS_RECORD_HIP);
	else if (strstr(Buffer, ("HINFO")) != nullptr || strstr(Buffer, ("hinfo")) != nullptr)
		return htons(DNS_RECORD_HINFO);
	else if (strstr(Buffer, ("RKEY")) != nullptr || strstr(Buffer, ("rkey")) != nullptr)
		return htons(DNS_RECORD_RKEY);
	else if (strstr(Buffer, ("TALINK")) != nullptr || strstr(Buffer, ("talink")) != nullptr)
		return htons(DNS_RECORD_TALINK);
	else if (strstr(Buffer, ("CDS")) != nullptr || strstr(Buffer, ("cds")) != nullptr)
		return htons(DNS_RECORD_CDS);
	else if (strstr(Buffer, ("CDNSKEY")) != nullptr || strstr(Buffer, ("cdnskey")) != nullptr)
		return htons(DNS_RECORD_CDNSKEY);
	else if (strstr(Buffer, ("OPENPGPKEY")) != nullptr || strstr(Buffer, ("openpgpkey")) != nullptr)
		return htons(DNS_RECORD_OPENPGPKEY);
	else if (strstr(Buffer, ("SPF")) != nullptr || strstr(Buffer, ("spf")) != nullptr)
		return htons(DNS_RECORD_SPF);
	else if (strstr(Buffer, ("UINFO")) != nullptr || strstr(Buffer, ("uinfo")) != nullptr)
		return htons(DNS_RECORD_UINFO);
	else if (strstr(Buffer, ("UID")) != nullptr || strstr(Buffer, ("uid")) != nullptr)
		return htons(DNS_RECORD_UID);
	else if (strstr(Buffer, ("GID")) != nullptr || strstr(Buffer, ("gid")) != nullptr)
		return htons(DNS_RECORD_GID);
	else if (strstr(Buffer, ("UNSPEC")) != nullptr || strstr(Buffer, ("unspec")) != nullptr)
		return htons(DNS_RECORD_UNSPEC);
	else if (strstr(Buffer, ("NID")) != nullptr || strstr(Buffer, ("nid")) != nullptr)
		return htons(DNS_RECORD_NID);
	else if (strstr(Buffer, ("L32")) != nullptr || strstr(Buffer, ("l32")) != nullptr)
		return htons(DNS_RECORD_L32);
	else if (strstr(Buffer, ("L64")) != nullptr || strstr(Buffer, ("l64")) != nullptr)
		return htons(DNS_RECORD_L64);
	else if (strstr(Buffer, ("LP")) != nullptr || strstr(Buffer, ("lp")) != nullptr)
		return htons(DNS_RECORD_LP);
	else if (strstr(Buffer, ("EUI48")) != nullptr || strstr(Buffer, ("eui48")) != nullptr)
		return htons(DNS_RECORD_EUI48);
	else if (strstr(Buffer, ("EUI64")) != nullptr || strstr(Buffer, ("eui64")) != nullptr)
		return htons(DNS_RECORD_EUI64);
	else if (strstr(Buffer, ("TKEY")) != nullptr || strstr(Buffer, ("tkey")) != nullptr)
		return htons(DNS_RECORD_TKEY);
	else if (strstr(Buffer, ("TSIG")) != nullptr || strstr(Buffer, ("tsig")) != nullptr)
		return htons(DNS_RECORD_TSIG);
	else if (strstr(Buffer, ("IXFR")) != nullptr || strstr(Buffer, ("ixfr")) != nullptr)
		return htons(DNS_RECORD_IXFR);
	else if (strstr(Buffer, ("AXFR")) != nullptr || strstr(Buffer, ("axfr")) != nullptr)
		return htons(DNS_RECORD_AXFR);
	else if (strstr(Buffer, ("MAILB")) != nullptr || strstr(Buffer, ("mailb")) != nullptr)
		return htons(DNS_RECORD_MAILB);
	else if (strstr(Buffer, ("MAILA")) != nullptr || strstr(Buffer, ("maila")) != nullptr)
		return htons(DNS_RECORD_MAILA);
	else if (strstr(Buffer, ("ANY")) != nullptr || strstr(Buffer, ("any")) != nullptr)
		return htons(DNS_RECORD_ANY);
	else if (strstr(Buffer, ("URI")) != nullptr || strstr(Buffer, ("uri")) != nullptr)
		return htons(DNS_RECORD_URI);
	else if (strstr(Buffer, ("CAA")) != nullptr || strstr(Buffer, ("caa")) != nullptr)
		return htons(DNS_RECORD_CAA);
	else if (strstr(Buffer, ("TA")) != nullptr || strstr(Buffer, ("ta")) != nullptr)
		return htons(DNS_RECORD_TA);
	else if (strstr(Buffer, ("DLV")) != nullptr || strstr(Buffer, ("dlv")) != nullptr)
		return htons(DNS_RECORD_DLV);
	else if (strstr(Buffer, ("RESERVED")) != nullptr || strstr(Buffer, ("reserved")) != nullptr)
		return htons(DNS_RECORD_RESERVED);
//No match.
	return 0;
}

//Check IP(v4/v6) special addresses
bool __fastcall CheckSpecialAddress(const void *Addr, const uint16_t Protocol, const PSTR Domain)
{
	if (Protocol == AF_INET6) //IPv6
	{
		if (
		//DNS Poisoning addresses from CERNET2, see https://code.google.com/p/goagent/issues/detail?id=17571.
			((in6_addr *)Addr)->u.Word[0] == 0 && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Byte[8U] == 0x90 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == 0 || //::90xx:xxxx:0:0
			((in6_addr *)Addr)->u.Word[0] == htons(0x0010) && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x2222) || //10::2222
			((in6_addr *)Addr)->u.Word[0] == htons(0x0021) && ((in6_addr *)Addr)->u.Word[1U] == htons(0x0002) && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x0002) || //21:2::2
			((in6_addr *)Addr)->u.Word[0] == htons(0x0101) && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x1234) || //101::1234
			((in6_addr *)Addr)->u.Word[0] == htons(0x2001) && 
//			(((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x0212) || //2001::212
			((in6_addr *)Addr)->u.Word[1U] == htons(0x0DA8) && ((in6_addr *)Addr)->u.Word[2U] == htons(0x0112) && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x21AE) || //2001:DA8:112::21AE
			((in6_addr *)Addr)->u.Word[0] == htons(0x2003) && ((in6_addr *)Addr)->u.Word[1U] == htons(0x00FF) && ((in6_addr *)Addr)->u.Word[2U] == htons(0x0001) && ((in6_addr *)Addr)->u.Word[3U] == htons(0x0002) && ((in6_addr *)Addr)->u.Word[4U] == htons(0x0003) && ((in6_addr *)Addr)->u.Word[5U] == htons(0x0004) && ((in6_addr *)Addr)->u.Word[6U] == htons(0x5FFF) /* && ((in6_addr *)Addr)->u.Word[7U] == htons(0x0006) */ || //2003:FF:1:2:3:4:5FFF:xxxx
			((in6_addr *)Addr)->u.Word[0] == htons(0x2123) && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x3E12) || //2123::3E12
		//Special-use and reserved addresses, see https://en.wikipedia.org/wiki/IPv6_address#Presentation and https://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv6_addresses.
			(((in6_addr *)Addr)->u.Word[0] == 0 && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && 
			((((in6_addr *)Addr)->u.Word[5U] == 0 && 
			((((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == 0 || //Unspecified Addresses(::, Section 2.5.2 in RFC 4291)
			((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x0001)) || //Loopback Addresses(::1, Section 2.5.3 in RFC 4291)
			((in6_addr *)Addr)->u.Word[5U] == 0)) || //IPv4-Compatible Contrast Addresses(::/96, Section 2.5.5.1 in RFC 4291)
			((in6_addr *)Addr)->u.Word[5U] == htons(0xFFFF))) || //IPv4-mapped Addresses(::FFFF:0:0/96, Section 2.5.5 in RFC 4291)
//			((in6_addr *)Addr)->u.Word[0] == htons(0x0064) && ((in6_addr *)Addr)->u.Word[1U] == htons(0xFF9B) && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 || //Well Known Prefix Addresses(64:FF9B::/96, Section 2.1 in RFC 4773)
			((in6_addr *)Addr)->u.Word[0] == htons(0x0100) && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[1U] == 0 || //Discard Prefix Addresses(100::/64, Section 4 RFC 6666)
			((in6_addr *)Addr)->u.Word[0] == htons(0x2001) && 
			(((in6_addr *)Addr)->u.Word[1U] == 0 || //Teredo relay/tunnel Addresses(2001::/32, RFC 4380)
			((in6_addr *)Addr)->u.Byte[2U] == 0 && ((in6_addr *)Addr)->u.Byte[3U] <= 0x07 || //Sub-TLA IDs assigned to IANA Addresses(2001:0000::/29, Section 2 in RFC 4773)
			((in6_addr *)Addr)->u.Byte[3U] >= 0x10 && ((in6_addr *)Addr)->u.Byte[3U] <= 0x1F || //Overlay Routable Cryptographic Hash IDentifiers/ORCHID Addresses(2001:10::/28 in RFC 4843)
			((in6_addr *)Addr)->u.Byte[2U] >= 0x01 && ((in6_addr *)Addr)->u.Byte[3U] >= 0xF8 || //Sub-TLA IDs assigned to IANA Addresses(2001:01F8::/29, Section 2 in RFC 4773)
			((in6_addr *)Addr)->u.Word[1U] == htons(0x0DB8)) || //Contrast Address prefix reserved for documentation Addresses(2001:DB8::/32, RFC 3849)
//			((in6_addr *)Addr)->u.Word[0] == htons(0x2002) || //6to4 relay/tunnel Addresses(2002::/16, Section 2 in RFC 3056)
			((in6_addr *)Addr)->u.Word[0] == htons(0x3FFE) && ((in6_addr *)Addr)->u.Word[1U] == 0 || //6bone Addresses(3FFE::/16, RFC 3701)
			((in6_addr *)Addr)->u.Byte[0] == 0x5F || //6bone(5F00::/8, RFC 3701)
//			((in6_addr *)Addr)->u.Byte[0] >= 0xFC && ((in6_addr *)Addr)->u.Byte[0] <= 0xFD || //Unique Local Unicast Addresses/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
			((in6_addr *)Addr)->u.Byte[0] == 0xFE && 
			(((in6_addr *)Addr)->u.Byte[1U] >= 0x80 && (((in6_addr *)Addr)->u.Byte[1U] <= 0xBF || //Link-Local Unicast Contrast Addresses/LUC(FE80::/10, Section 2.5.6 in RFC 4291)
//			((in6_addr *)Addr)->u.Byte[1U] <= 0xBF && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == htons(0x5EFE)) || //ISATAP Interface Identifiers Addresses(Prefix:0:5EFE:0:0:0:0/64, which also in Link-Local Unicast Contrast Addresses/LUC, Section 6.1 in RFC 5214)
			((in6_addr *)Addr)->u.Byte[1U] >= 0xC0))) //Site-Local scoped Addresses(FEC0::/10, RFC 3879)
//			((in6_addr *)Addr)->u.Byte[0] == 0xFF || //Multicast Addresses(FF00::/8, Section 2.7 in RFC 4291)
				return true;

	//Extended check
		if (Domain != nullptr)
		{
		//Domain Case Conversion
			CaseConvert(false, Domain, strlen(Domain));

		//Main check
			for (auto ResultBlacklistIter:*ResultBlacklistUsing)
			{
				if (ResultBlacklistIter.Addresses.front().Begin.ss_family == AF_INET6 && 
					(ResultBlacklistIter.PatternString.empty() || std::regex_match(Domain, ResultBlacklistIter.Pattern)))
				{
					for (auto AddressRangeIter:ResultBlacklistIter.Addresses)
					{
						if (AddressRangeIter.End.ss_family == AF_INET6 && 
							CompareAddresses(Addr, &((PSOCKADDR_IN6)&AddressRangeIter.Begin)->sin6_addr, AF_INET6) >= ADDRESS_COMPARE_EQUAL &&
							CompareAddresses(Addr, &((PSOCKADDR_IN6)&AddressRangeIter.End)->sin6_addr, AF_INET6) <= ADDRESS_COMPARE_EQUAL || 
							memcmp(Addr, &((PSOCKADDR_IN6)&AddressRangeIter.Begin)->sin6_addr, sizeof(in6_addr)) == 0)
								return true;
					}
				}
			}
		}
	}
	else { //IPv4
		if (
		//Traditional DNS Poisoning addresses, see https://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93#.E8.99.9A.E5.81.87IP.E5.9C.B0.E5.9D.80.
			((in_addr *)Addr)->S_un.S_addr == htonl(0x042442B2) || //4.36.66.178
			((in_addr *)Addr)->S_un.S_addr == htonl(0x0807C62D) || //8.7.198.45
			((in_addr *)Addr)->S_un.S_addr == htonl(0x253D369E) || //37.61.54.158
			((in_addr *)Addr)->S_un.S_addr == htonl(0x2E52AE44) || //46.82.174.68
			((in_addr *)Addr)->S_un.S_addr == htonl(0x3B1803AD) || //59.24.3.173
			((in_addr *)Addr)->S_un.S_addr == htonl(0x402158A1) || //64.33.88.161
			((in_addr *)Addr)->S_un.S_addr == htonl(0x4021632F) || //64.33.99.47
			((in_addr *)Addr)->S_un.S_addr == htonl(0x4042A3FB) || //64.66.163.251
			((in_addr *)Addr)->S_un.S_addr == htonl(0x4168CAFC) || //65.104.202.252
			((in_addr *)Addr)->S_un.S_addr == htonl(0x41A0DB71) || //65.160.219.113
			((in_addr *)Addr)->S_un.S_addr == htonl(0x422DFCED) || //66.45.252.237
			((in_addr *)Addr)->S_un.S_addr == htonl(0x480ECD63) || //72.14.205.99
			((in_addr *)Addr)->S_un.S_addr == htonl(0x480ECD68) || //72.14.205.104
			((in_addr *)Addr)->S_un.S_addr == htonl(0x4E10310F) || //78.16.49.15
			((in_addr *)Addr)->S_un.S_addr == htonl(0x5D2E0859) || //93.46.8.89
			((in_addr *)Addr)->S_un.S_addr == htonl(0x80797E8B) || //128.121.126.139
			((in_addr *)Addr)->S_un.S_addr == htonl(0x9F6A794B) || //159.106.121.75
			((in_addr *)Addr)->S_un.S_addr == htonl(0xA9840D67) || //169.132.13.103
			((in_addr *)Addr)->S_un.S_addr == htonl(0xC043C606) || //192.67.198.6
			((in_addr *)Addr)->S_un.S_addr == htonl(0xCA6A0102) || //202.106.1.2
			((in_addr *)Addr)->S_un.S_addr == htonl(0xCAB50755) || //202.181.7.85
			((in_addr *)Addr)->S_un.S_addr == htonl(0xCB620741) || //203.98.7.65
			((in_addr *)Addr)->S_un.S_addr == htonl(0xCBA1E6AB) || //203.161.230.171
			((in_addr *)Addr)->S_un.S_addr == htonl(0xCF0C5862) || //207.12.88.98
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD0381F2B) || //208.56.31.43
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD1244921) || //209.36.73.33
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD1913632) || //209.145.54.50
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD1DC1EAE) || //209.220.30.174
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD35E4293) || //211.94.66.147
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD5A9FB23) || //213.169.251.35
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD8DDBCD6) || //216.221.188.182
		//New DNS Poisoning addresses which had been added in May 2011, see http://forums.internetfreedom.org/index.php?topic=7953.0.
			((in_addr *)Addr)->S_un.S_addr == htonl(0x1759053C) || //23.89.5.60
			((in_addr *)Addr)->S_un.S_addr == htonl(0x31027B38) || //49.2.123.56
			((in_addr *)Addr)->S_un.S_addr == htonl(0x364C8701) || //54.76.135.1
			((in_addr *)Addr)->S_un.S_addr == htonl(0x4D04075C) || //77.4.7.92
			((in_addr *)Addr)->S_un.S_addr == htonl(0x76050460) || //118.5.4.96
			((in_addr *)Addr)->S_un.S_addr == htonl(0xBC050460) || //188.5.4.96
			((in_addr *)Addr)->S_un.S_addr == htonl(0xBDA31105) || //189.163.17.5
			((in_addr *)Addr)->S_un.S_addr == htonl(0xC504040C) || //197.4.4.12
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD8EAB30D) || //216.234.179.13
//			((in_addr *)Addr)->S_un.S_addr == htonl(0xF3B9BB27) || //243.185.187.39, including in reserved address ranges
//			((in_addr *)Addr)->S_un.S_addr == htonl(0xF9812E30) || //249.129.46.48, including in reserved address ranges
//			((in_addr *)Addr)->S_un.S_addr == htonl(0xFD9D0EA5) || //253.157.14.165, including in reserved address ranges
		//China Network Anomaly in 2014-01-21, see https ://zh.wikipedia.org/wiki/2014%E5%B9%B4%E4%B8%AD%E5%9B%BD%E7%BD%91%E7%BB%9C%E5%BC%82%E5%B8%B8%E4%BA%8B%E4%BB%B6
			((in_addr *)Addr)->S_un.S_addr == htonl(0x413102B2) || //65.49.2.178
		//New addresses in IPv6 which has been added in September 2014, see https://code.google.com/p/goagent/issues/detail?id=17571.
			((in_addr *)Addr)->S_un.S_addr == htonl(0x01010101) || //1.1.1.1
			((in_addr *)Addr)->S_un.S_addr == htonl(0x0A0A0A0A) || //10.10.10.10
			((in_addr *)Addr)->S_un.S_addr == htonl(0x14141414) || //20.20.20.20
//			((in_addr *)Addr)->S_un.S_addr == htonl(0xFFFFFFFF) || //255.255.255.255, including in reserved address ranges
		//New DNS Poisoning addresses which had been added in December 2014, see https://www.v2ex.com/t/156926.
//			((in_addr *)Addr)->S_un.S_addr == 0 || //0.0.0.0, including in reserved address ranges
			((in_addr *)Addr)->S_un.S_addr == htonl(0x02010102) || //2.1.1.2
			((in_addr *)Addr)->S_un.S_addr == htonl(0x04C15000) || //4.193.80.0
			((in_addr *)Addr)->S_un.S_addr == htonl(0x08695400) || //8.105.84.0
			((in_addr *)Addr)->S_un.S_addr == htonl(0x0C578500) || //12.87.133.0
			((in_addr *)Addr)->S_un.S_addr == htonl(0x103F9B00) || //16.63.155.0
			((in_addr *)Addr)->S_un.S_addr == htonl(0x148B3800) || //20.139.56.0
			((in_addr *)Addr)->S_un.S_addr == htonl(0x1833B800) || //24.51.184.0
			((in_addr *)Addr)->S_un.S_addr == htonl(0x1C797E8B) || //28.121.126.139
			((in_addr *)Addr)->S_un.S_addr == htonl(0x1C0DD800) || //28.13.216.0
			((in_addr *)Addr)->S_un.S_addr == htonl(0x2E147EFC) || //46.20.126.252
			((in_addr *)Addr)->S_un.S_addr == htonl(0x2E2618D1) || //46.38.24.209
			((in_addr *)Addr)->S_un.S_addr == htonl(0x3D361C06) || //61.54.28.6
			((in_addr *)Addr)->S_un.S_addr == htonl(0x42CE0BC2) || //66.206.11.194
			((in_addr *)Addr)->S_un.S_addr == htonl(0x4A75398A) || //74.117.57.138
			((in_addr *)Addr)->S_un.S_addr == htonl(0x591F376A) || //89.31.55.106
			((in_addr *)Addr)->S_un.S_addr == htonl(0x710BC2BE) || //113.11.194.190
			((in_addr *)Addr)->S_un.S_addr == htonl(0x76053106) || //118.5.49.6
			((in_addr *)Addr)->S_un.S_addr == htonl(0x7ADA65BE) || //122.218.101.190
			((in_addr *)Addr)->S_un.S_addr == htonl(0x7B3231AB) || //123.50.49.171
			((in_addr *)Addr)->S_un.S_addr == htonl(0x7B7EF9EE) || //123.126.249.238
			((in_addr *)Addr)->S_un.S_addr == htonl(0x7DE69430) || //125.230.148.48
//			((in_addr *)Addr)->S_un.S_addr == htonl(0x7F000002) || //127.0.0.2, including in reserved address ranges
			((in_addr *)Addr)->S_un.S_addr == htonl(0xADC9D806) || //173.201.216.6
			((in_addr *)Addr)->S_un.S_addr == htonl(0xCBC73951) || //203.199.57.81
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD06D8A37) || //208.109.138.55
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD3058512) || //211.5.133.18
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD308451B) || //211.8.69.27
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD5BA2105) || //213.186.33.5
			((in_addr *)Addr)->S_un.S_addr == htonl(0xD88BD590) || //216.139.213.144
			((in_addr *)Addr)->S_un.S_addr == htonl(0xDD08451B) || //221.8.69.27
//			((in_addr *)Addr)->S_un.S_addr == htonl(0xF3B9BB03) || //243.185.187.3, including in reserved address ranges
//			((in_addr *)Addr)->S_un.S_addr == htonl(0xF3B9BB1E) || //243.185.187.30, including in reserved address ranges
		//Special-use and reserved addresses, see https://en.wikipedia.org/wiki/IPv4#Special-use_addresses and https://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv4_addresses.
			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0 || //Current network whick only valid as source Addresses(0.0.0.0/8, Section 3.2.1.3 in RFC 1122)
//			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0x0A || //Private class A Addresses(10.0.0.0/8, Section 3 in RFC 1918)
			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
//			((in_addr *)Addr)->S_un.S_un_b.s_b1 == && ((in_addr *)Addr)->S_un.S_un_b.s_b2 > 0x40 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 < 0x7F || //Carrier-grade NAT Addresses(100.64.0.0/10, Section 7 in RFC 6598)
			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xA9 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 >= 0xFE || //Link-local Addresses(169.254.0.0/16, Section 1.5 in RFC 3927)
//			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xAC && ((in_addr *)Addr)->S_un.S_un_b.s_b2 >= 0x10 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 <= 0x1F || //Private class B Addresses(172.16.0.0/16, Section 3 in RFC 1918)
			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xC0 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 == 0 && ((in_addr *)Addr)->S_un.S_un_b.s_b3 == 0 && ((in_addr *)Addr)->S_un.S_un_b.s_b4 >= 0 && ((in_addr *)Addr)->S_un.S_un_b.s_b4 < 0x08 || //DS-Lite transition mechanism Addresses(192.0.0.0/29, Section 3 in RFC 6333)
			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xC0 && (((in_addr *)Addr)->S_un.S_un_b.s_b2 == 0 && (((in_addr *)Addr)->S_un.S_un_b.s_b3 == 0 || //Reserved for IETF protocol assignments Addresses(192.0.0.0/24, Section 3 in RFC 5735)
			((in_addr *)Addr)->S_un.S_un_b.s_b3 == 0x02)) || //TEST-NET-1 Addresses(192.0.2.0/24, Section 3 in RFC 5735)
//			((in_addr *)Addr)->S_un.S_un_b.s_b2 == 0x58 && ((in_addr *)Addr)->S_un.S_un_b.s_b3 == 0x63 || //6to4 relay/tunnel Addresses(192.88.99.0/24, Section 2.3 in RFC 3068)
//			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xC0 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 == 0xA8 || //Private class C Addresses(192.168.0.0/24, Section 3 in RFC 1918)
			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xC6 && (((in_addr *)Addr)->S_un.S_un_b.s_b2 == 0x12 || //Benchmarking Methodology for Network Interconnect Devices Addresses(198.18.0.0/15, Section 11.4.1 in RFC 2544)
			((in_addr *)Addr)->S_un.S_un_b.s_b2 == 0x33 && ((in_addr *)Addr)->S_un.S_un_b.s_b3 == 0x64) || //TEST-NET-2 Addresses(198.51.100.0/24, Section 3 in RFC 5737)
			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xCB && ((in_addr *)Addr)->S_un.S_un_b.s_b2 == 0 && ((in_addr *)Addr)->S_un.S_un_b.s_b3 == 0x71 || //TEST-NET-3 Addresses(203.0.113.0/24, Section 3 in RFC 5737)
//			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xE0 || //Multicast Addresses(224.0.0.0/4, Section 2 in RFC 3171)
			((in_addr *)Addr)->S_un.S_un_b.s_b1 >= 0xF0) //Reserved for future use address(240.0.0.0/4, Section 4 in RFC 1112) and Broadcast Addresses(255.255.255.255/32, Section 7 in RFC 919/RFC 922)
				return true;

	//Extended check
		if (Domain != nullptr)
		{
		//Domain Case Conversion
			CaseConvert(false, Domain, strlen(Domain));

		//Main check
			for (auto ResultBlacklistIter:*ResultBlacklistUsing)
			{
				if (ResultBlacklistIter.Addresses.front().Begin.ss_family == AF_INET && 
					(ResultBlacklistIter.PatternString.empty() || std::regex_match(Domain, ResultBlacklistIter.Pattern)))
				{
					for (auto AddressRangeIter:ResultBlacklistIter.Addresses)
					{
						if (AddressRangeIter.End.ss_family == AF_INET &&
							CompareAddresses(Addr, &((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr, AF_INET) >= ADDRESS_COMPARE_EQUAL &&
							CompareAddresses(Addr, &((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr, AF_INET) <= ADDRESS_COMPARE_EQUAL || 
							((in_addr *)Addr)->S_un.S_addr == ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_addr)
								return true;
					}
				}
			}
		}
	}

	return false;
}

//Check routing of addresses
bool __fastcall CheckAddressRouting(const void *Addr, const uint16_t Protocol)
{
	std::unique_lock<std::mutex> LocalRoutingListMutex(LocalRoutingListLock);

//Check address routing.
	for (auto AddressPrefixBlockIter:*LocalRoutingListUsing)
	{
		if (Protocol == AddressPrefixBlockIter.AddressData.Storage.ss_family)
		{
		//IPv6
			if (Protocol == AF_INET6)
			{
				size_t Prefix = AddressPrefixBlockIter.Prefix;
				for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
				{
					if (Prefix == sizeof(uint16_t) * BYTES_TO_BITS)
					{
						if (((in6_addr *)Addr)->u.Word[Index] == AddressPrefixBlockIter.AddressData.IPv6.sin6_addr.u.Word[Index])
							return true;
						else
							break;
					}
					else if (Prefix > sizeof(uint16_t) * BYTES_TO_BITS)
					{
						if (((in6_addr *)Addr)->u.Word[Index] == AddressPrefixBlockIter.AddressData.IPv6.sin6_addr.u.Word[Index])
							Prefix -= sizeof(uint16_t) * BYTES_TO_BITS;
						else
							break;
					}
					else {
						if (ntohs(((in6_addr *)Addr)->u.Word[Index]) >> (sizeof(uint16_t) * BYTES_TO_BITS - Prefix) ==
							ntohs(AddressPrefixBlockIter.AddressData.IPv6.sin6_addr.u.Word[Index]) >> (sizeof(uint16_t) * BYTES_TO_BITS - Prefix))
								return true;
						else
							break;
					}
				}
			}
		//IPv4
			else {
				if (ntohl(((in_addr *)Addr)->S_un.S_addr) >> (sizeof(in_addr) * BYTES_TO_BITS - AddressPrefixBlockIter.Prefix) == 
					ntohl(AddressPrefixBlockIter.AddressData.IPv4.sin_addr.S_un.S_addr) >> (sizeof(in_addr) * BYTES_TO_BITS - AddressPrefixBlockIter.Prefix))
						return true;
			}
		}
	}

	return false;
}

//Custom Mode addresses filter
bool __fastcall CustomModeFilter(const void *OriginalAddr, const uint16_t Protocol)
{
	std::unique_lock<std::mutex> AddressRangeMutex(AddressRangeLock);
	if (Protocol == AF_INET6) //IPv6
	{
		auto Addr = (in6_addr *)OriginalAddr;
	//Permit
		if (Parameter.IPFilterType)
		{
			for (auto AddressRangeIter:*AddressRangeUsing)
			{
			//Check Protocol and Level.
				if (AddressRangeIter.Begin.ss_family != AF_INET6 || Parameter.IPFilterLevel != 0 && AddressRangeIter.Level < Parameter.IPFilterLevel)
					continue;

			//Check address.
				for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
				{
					if (ntohs(Addr->u.Word[Index]) > ntohs(((PSOCKADDR_IN6)&AddressRangeIter.Begin)->sin6_addr.u.Word[Index]) && ntohs(Addr->u.Word[Index]) < ntohs(((PSOCKADDR_IN6)&AddressRangeIter.End)->sin6_addr.u.Word[Index]))
					{
						return true;
					}
					else if (Addr->u.Word[Index] == ((PSOCKADDR_IN6)&AddressRangeIter.Begin)->sin6_addr.u.Word[Index] || Addr->u.Word[Index] == ((PSOCKADDR_IN6)&AddressRangeIter.End)->sin6_addr.u.Word[Index])
					{
						if (Index == sizeof(in6_addr) / sizeof(uint16_t) - 1U)
							return true;
						else 
							continue;
					}
					else {
						return false;
					}
				}
			}
		}
	//Deny
		else {
			for (auto AddressRangeIter:*AddressRangeUsing)
			{
			//Check Protocol and Level.
				if (AddressRangeIter.Begin.ss_family != AF_INET6 || Parameter.IPFilterLevel != 0 && AddressRangeIter.Level < Parameter.IPFilterLevel)
					continue;

			//Check address.
				for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
				{
					if (ntohs(Addr->u.Word[Index]) > ntohs(((PSOCKADDR_IN6)&AddressRangeIter.Begin)->sin6_addr.u.Word[Index]) && ntohs(Addr->u.Word[Index]) < ntohs(((PSOCKADDR_IN6)&AddressRangeIter.End)->sin6_addr.u.Word[Index]))
					{
						return false;
					}
					else if (Addr->u.Word[Index] == ((PSOCKADDR_IN6)&AddressRangeIter.Begin)->sin6_addr.u.Word[Index] || Addr->u.Word[Index] == ((PSOCKADDR_IN6)&AddressRangeIter.End)->sin6_addr.u.Word[Index])
					{
						if (Index == sizeof(in6_addr) / sizeof(uint16_t) - 1U)
							return false;
						else 
							continue;
					}
					else {
						return true;
					}
				}
			}
		}
	}
	else { //IPv4
		auto Addr = (in_addr *)OriginalAddr;
	//Permit
		if (Parameter.IPFilterType)
		{
			for (auto AddressRangeIter:*AddressRangeUsing)
			{
			//Check Protocol and Level.
				if (AddressRangeIter.Begin.ss_family != AF_INET || Parameter.IPFilterLevel != 0 && AddressRangeIter.Level < Parameter.IPFilterLevel)
					continue;

			//Check address.
				if (Addr->S_un.S_un_b.s_b1 > ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b1 && Addr->S_un.S_un_b.s_b1 < ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b1)
				{
					return true;
				}
				else if (Addr->S_un.S_un_b.s_b1 == ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b1 || Addr->S_un.S_un_b.s_b1 == ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b1)
				{
					if (Addr->S_un.S_un_b.s_b2 > ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b2 && Addr->S_un.S_un_b.s_b2 < ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b2)
					{
						return true;
					}
					else if (Addr->S_un.S_un_b.s_b2 == ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b2 || Addr->S_un.S_un_b.s_b2 == ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b2)
					{
						if (Addr->S_un.S_un_b.s_b3 > ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b3 && Addr->S_un.S_un_b.s_b3 < ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b3)
						{
							return true;
						}
						else if (Addr->S_un.S_un_b.s_b3 == ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b3 || Addr->S_un.S_un_b.s_b3 == ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b3)
						{
							if (Addr->S_un.S_un_b.s_b4 >= ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b4 && Addr->S_un.S_un_b.s_b4 <= ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b4)
							{
								return true;
							}
							else {
								return false;
							}
						}
						else {
							return false;
						}
					}
					else {
						return false;
					}
				}
				else {
					return false;
				}
			}
		}
	//Deny
		else {
			for (auto AddressRangeIter:*AddressRangeUsing)
			{
			//Check Protocol and Level.
				if (AddressRangeIter.Begin.ss_family != AF_INET || Parameter.IPFilterLevel != 0 && AddressRangeIter.Level < Parameter.IPFilterLevel)
					continue;

			//Check address.
				if (Addr->S_un.S_un_b.s_b1 > ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b1 && Addr->S_un.S_un_b.s_b1 < ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b1)
				{
					return false;
				}
				else if (Addr->S_un.S_un_b.s_b1 == ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b1 || Addr->S_un.S_un_b.s_b1 == ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b1)
				{
					if (Addr->S_un.S_un_b.s_b2 > ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b2 && Addr->S_un.S_un_b.s_b2 < ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b2)
					{
						return false;
					}
					else if (Addr->S_un.S_un_b.s_b2 == ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b2 || Addr->S_un.S_un_b.s_b2 == ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b2)
					{
						if (Addr->S_un.S_un_b.s_b3 > ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b3 && Addr->S_un.S_un_b.s_b3 < ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b3)
						{
							return false;
						}
						else if (Addr->S_un.S_un_b.s_b3 == ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b3 || Addr->S_un.S_un_b.s_b3 == ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b3)
						{
							if (Addr->S_un.S_un_b.s_b4 >= ((PSOCKADDR_IN)&AddressRangeIter.Begin)->sin_addr.S_un.S_un_b.s_b4 && Addr->S_un.S_un_b.s_b4 <= ((PSOCKADDR_IN)&AddressRangeIter.End)->sin_addr.S_un.S_un_b.s_b4)
							{
								return false;
							}
							else {
								return true;
							}
						}
						else {
							return true;
						}
					}
					else {
						return true;
					}
				}
				else {
					return true;
				}
			}
		}
	}

	return true;
}

/*
//Get Ethernet Frame Check Sequence/FCS
uint32_t __fastcall GetFCS(const PUINT8 Buffer, const size_t Length)
{
	uint32_t Table[FCS_TABLE_SIZE] = {0}, Gx = 0x04C11DB7, Temp = 0, CRCTable = 0, Value = 0, UI = 0;
	char ReflectNum[] = {8, 32};
	int Index[3U] = {0};

	for (Index[0] = 0;Index[0] <= U8_MAXNUM;Index[0]++)
	{
		Value = 0;
		UI = Index[0];
		for (Index[1U] = 1;Index[1U] < 9;Index[1U]++)
		{
			if (UI & 1)
				Value |= 1 << (ReflectNum[0]-Index[1U]);
			UI >>= 1;
		}
		Temp = Value;
		Table[Index[0]] = Temp << 24U;

		for (Index[2U] = 0;Index[2U] < 8;Index[2U]++)
		{
			unsigned long int t1 = 0, t2 = 0, Flag = Table[Index[0]] & 0x80000000;
			t1 = (Table[Index[0]] << 1);
			if (Flag == 0)
				t2 = 0;
			else
				t2 = Gx;
			Table[Index[0]] = t1 ^ t2;
		}
		CRCTable = Table[Index[0]];

		UI = Table[Index[0]];
		Value = 0;
		for (Index[1U] = 1;Index[1U] < 33;Index[1U]++)
		{
			if (UI & 1)
				Value |= 1 << (ReflectNum[1U] - Index[1U]);
			UI >>= 1;
		}
		Table[Index[0]] = Value;
	}

	uint32_t CRC = U32_MAXNUM;
	for (Index[0] = 0;Index[0] < (int)Length;Index[0]++)
		CRC = Table[(CRC ^ (*(Buffer + Index[0]))) & U8_MAXNUM]^(CRC >> 8U);

	return ~CRC;
}
*/

//Get Checksum
uint16_t __fastcall GetChecksum(const uint16_t *Buffer, const size_t Length)
{
	uint32_t Checksum = CHECKSUM_SUCCESS;
	size_t InnerLength = Length;

	while (InnerLength > 1U)
	{ 
		Checksum += *Buffer++;
		InnerLength -= sizeof(uint16_t);
	}
	
	if (InnerLength)
		Checksum += *(PUINT8)Buffer;

	Checksum = (Checksum >> 16U) + (Checksum & U16_MAXNUM);
	Checksum += (Checksum >> 16U);

	return (uint16_t)(~Checksum);
}

//Get ICMPv6 checksum
uint16_t __fastcall ICMPv6Checksum(const PUINT8 Buffer, const size_t Length, const in6_addr Destination, const in6_addr Source)
{
	std::shared_ptr<char> Validation(new char[sizeof(ipv6_psd_hdr) + Length]());

//Get checksum
	auto pipv6_psd_hdr = (ipv6_psd_hdr *)Validation.get();
	pipv6_psd_hdr->Dst = Destination;
	pipv6_psd_hdr->Src = Source;
	pipv6_psd_hdr->Length = htonl((uint32_t)Length);
	pipv6_psd_hdr->Next_Header = IPPROTO_ICMPV6;
	memcpy(Validation.get() + sizeof(ipv6_psd_hdr), Buffer + sizeof(ipv6_hdr), Length);
	return GetChecksum((PUINT16)Validation.get(), sizeof(ipv6_psd_hdr) + Length);
}

//Get TCP or UDP checksum
uint16_t __fastcall TCPUDPChecksum(const PUINT8 Buffer, const size_t Length, const uint16_t NetworkLayer, const uint16_t TransportLayer)
{
//Get checksum.
	uint16_t Result = EXIT_FAILURE;
	if (NetworkLayer == AF_INET6) //IPv6
	{
		std::shared_ptr<char> Validation(new char[sizeof(ipv6_psd_hdr) + Length]());
		auto pipv6_psd_hdr = (ipv6_psd_hdr *)Validation.get();
		pipv6_psd_hdr->Dst = ((ipv6_hdr *)Buffer)->Dst;
		pipv6_psd_hdr->Src = ((ipv6_hdr *)Buffer)->Src;
		pipv6_psd_hdr->Length = htonl((uint32_t)Length);
		pipv6_psd_hdr->Next_Header = (uint8_t)TransportLayer;

		memcpy(Validation.get() + sizeof(ipv6_psd_hdr), Buffer + sizeof(ipv6_hdr), Length);
		Result = GetChecksum((PUINT16)Validation.get(), sizeof(ipv6_psd_hdr) + Length);
	}
	else { //IPv4
		auto pipv4_hdr = (ipv4_hdr *)Buffer;
		std::shared_ptr<char> Validation(new char[sizeof(ipv4_psd_hdr) + Length /* - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES */ ]());
		auto pipv4_psd_hdr = (ipv4_psd_hdr *)Validation.get();
		pipv4_psd_hdr->Dst = ((ipv4_hdr *)Buffer)->Dst;
		pipv4_psd_hdr->Src = ((ipv4_hdr *)Buffer)->Src;
		pipv4_psd_hdr->Length = htons((uint16_t) /* ( */ Length /* - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES) */);
		pipv4_psd_hdr->Protocol = (uint8_t)TransportLayer;

		memcpy(Validation.get() + sizeof(ipv4_psd_hdr), Buffer + pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES, Length /* - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES */ );
		Result = GetChecksum((PUINT16)Validation.get(), sizeof(ipv4_psd_hdr) + Length /* - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES */);
	}

	return Result;
}

//Add length parameters to TCP DNS transmission
size_t __fastcall AddLengthToTCPDNSHeader(PSTR Buffer, const size_t RecvLen, const size_t MaxLen)
{
	if (MaxLen >= RecvLen + sizeof(uint16_t))
	{
		memmove(Buffer + sizeof(uint16_t), Buffer, RecvLen);
		auto ptcp_dns_hdr = (tcp_dns_hdr *)Buffer;
		ptcp_dns_hdr->Length = htons((uint16_t)RecvLen);
		return RecvLen + sizeof(uint16_t);
	}
	
	return EXIT_FAILURE;
}

//Convert data from chars to DNS query
size_t __fastcall CharToDNSQuery(const PSTR FName, PSTR TName)
{
	int Index[] = {(int)strlen(FName) - 1, 0, 0};
	Index[2U] = Index[0] + 1;
	TName[Index[0] + 2] = 0;

	for (;Index[0] >= 0;Index[0]--,Index[2U]--)
	{
		if (FName[Index[0]] == ASCII_PERIOD)
		{
			TName[Index[2U]] = (char)Index[1U];
			Index[1U] = 0;
		}
		else
		{
			TName[Index[2U]] = FName[Index[0]];
			Index[1U]++;
		}
	}
	TName[Index[2U]] = (char)Index[1U];

	return strlen(TName) + 1U;
}

//Count DNS Query Name length
size_t __fastcall CheckDNSQueryNameLength(const PSTR Buffer)
{
	size_t Index = 0;
	for (Index = 0;Index < DOMAIN_MAXSIZE;Index++)
	{
		if (Buffer[Index] == 0)
		{
			break;
		}
		else if ((UCHAR)Buffer[Index] >= 0xC0) //Pointer
		{
			return Index + sizeof(uint16_t) - 1U;
		}
	}

	return Index;
}

//Convert data from DNS query to chars
size_t __fastcall DNSQueryToChar(const PSTR TName, PSTR FName /* , uint16_t &Truncated */ )
{
//Initialization
	size_t uIndex = 0;
	int Index[] = {0, 0};

//Convert domain.
	for (uIndex = 0;uIndex < DOMAIN_MAXSIZE;uIndex++)
	{
	//Pointer
		if ((UCHAR)TName[uIndex] >= 0xC0)
		{
//			Truncated = (UCHAR)(TName[uIndex] & 0x3F);
//			Truncated = Truncated << sizeof(char) * BYTES_TO_BITS;
//			Truncated += (UCHAR)TName[uIndex + 1U];
			return uIndex + sizeof(uint16_t);
		}
		else if (uIndex == 0)
		{
			Index[0] = TName[uIndex];
		}
		else if (uIndex == Index[0] + Index[1U] + 1U)
		{
			Index[0] = TName[uIndex];
			if (Index[0] == 0)
				break;
			Index[1U] = (int)uIndex;

			FName[uIndex - 1U] = ASCII_PERIOD;
		}
		else {
			FName[uIndex - 1U] = TName[uIndex];
		}
	}

//	Truncated = 0;
	return uIndex;
}

//Flush DNS Cache undocumented API of Microsoft Windows.
BOOL WINAPI FlushDNSResolverCache(void)
{
	BOOL(WINAPI *DnsFlushResolverCache)(void);
	HMODULE HM_DNSAPI = LoadLibraryW(L"dnsapi.dll");
	if (HM_DNSAPI != nullptr)
	{
		*(FARPROC *)&DnsFlushResolverCache = GetProcAddress(HM_DNSAPI, "DnsFlushResolverCache");
		if (DnsFlushResolverCache)
			return DnsFlushResolverCache();
	}

	return FALSE;
}

//Make ramdom domains
void __fastcall MakeRamdomDomain(PSTR Buffer)
{
//Ramdom number distribution initialization
	std::uniform_int_distribution<int> RamdomDistribution(0, DOMAIN_LEVEL_DATA_MAXSIZE);

//Make ramdom domain length.
	size_t RamdomLength = RamdomDistribution(*Parameter.RamdomEngine), Index = 0;
	if (RamdomLength < 4U)
		RamdomLength += 4U;

//Make ramdom domain.
	if (RamdomLength % 2U == 0)
	{
		for (Index = 0;Index < RamdomLength - 3U;Index++)
		{
			Buffer[Index] = Parameter.DomainTable[RamdomDistribution(*Parameter.RamdomEngine)];
		//Convert to lowercase letters.
			if (Buffer[Index] > ASCII_AT && Buffer[Index] < ASCII_BRACKETS_LEAD)
				Buffer[Index] += ASCII_UPPER_TO_LOWER;
		}

	//Make random domain like a normal Top-level domain/TLD.
		Buffer[RamdomLength - 3U] = ASCII_PERIOD;
		Index = RamdomDistribution(*Parameter.RamdomEngine);
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Buffer[RamdomLength - 2U] = Parameter.DomainTable[Index];
		Index = RamdomDistribution(*Parameter.RamdomEngine);
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Buffer[RamdomLength - 1U] = Parameter.DomainTable[Index];
	}
	else {
		for (Index = 0;Index < RamdomLength - 4U;Index++)
		{
			Buffer[Index] = Parameter.DomainTable[RamdomDistribution(*Parameter.RamdomEngine)];
		//Convert to lowercase letters.
			if (Buffer[Index] > ASCII_AT && Buffer[Index] < ASCII_BRACKETS_LEAD)
				Buffer[Index] += ASCII_UPPER_TO_LOWER;
		}

	//Make random domain like a normal Top-level domain/TLD.
		Buffer[RamdomLength - 4U] = ASCII_PERIOD;
		Index = RamdomDistribution(*Parameter.RamdomEngine);
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Buffer[RamdomLength - 3U] = Parameter.DomainTable[Index];
		Index = RamdomDistribution(*Parameter.RamdomEngine);
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Buffer[RamdomLength - 2U] = Parameter.DomainTable[Index];
		Index = RamdomDistribution(*Parameter.RamdomEngine);
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Buffer[RamdomLength - 1U] = Parameter.DomainTable[Index];
	}

	return;
}

//Make Domain Case Conversion
void __fastcall MakeDomainCaseConversion(PSTR Buffer)
{
	size_t Index = 0;

//Ramdom number distribution initialization
	std::uniform_int_distribution<int> RamdomDistribution(0, 1U);

//Make Case Conversion.
	if (RamdomDistribution(*Parameter.RamdomEngine) % 2U == 0)
	{
		for (Index = 0;Index < strlen(Buffer);Index++)
		{
			if (Index % 2U == 0 && *(Buffer + Index) > ASCII_ACCENT && *(Buffer + Index) < ASCII_BRACES_LEAD)
				*(Buffer + Index) -= ASCII_LOWER_TO_UPPER;
		}
	}
	else {
		for (Index = 0;Index < strlen(Buffer);Index++)
		{
			if (Index % 2U != 0 && *(Buffer + Index) > ASCII_ACCENT && *(Buffer + Index) < ASCII_BRACES_LEAD)
				*(Buffer + Index) -= ASCII_LOWER_TO_UPPER;
		}
	}

	return;
}

//Make Compression Pointer Mutation
size_t __fastcall MakeCompressionPointerMutation(const PSTR Buffer, const size_t Length)
{
//Ramdom number distribution initialization
	std::uniform_int_distribution<int> RamdomDistribution(0, 2U);
	size_t Index = RamdomDistribution(*Parameter.RamdomEngine);

//Check Compression Pointer Mutation options.
	switch (Index)
	{
		case 0:
		{
			if (!Parameter.CPMPointerToHeader)
			{
				if (Parameter.CPMPointerToRR)
					Index++;
				else //Pointer to Additional(2)
					Index += 2U;
			}
		}break;
		case 1U:
		{
			if (!Parameter.CPMPointerToRR)
			{
				if (Parameter.CPMPointerToHeader)
					Index--;
				else //Pointer to Additional(1)
					Index += 1U;
			}
		}break;
		case 2U:
		{
			if (!Parameter.CPMPointerToAdditional)
			{
				if (Parameter.CPMPointerToHeader)
					Index -= 2U;
				else //Pointer to header
					Index--;
			}
		}break;
		default:
		{
			return EXIT_FAILURE;
		}
	}

//Make Compression Pointer Mutation.
	if (Index == 0) //Pointer to header, like "[DNS Header][Domain][Pointer][Query]" and the pointer is point to [DNS Header].
	{
		memmove(Buffer + Length - sizeof(dns_qry) + 1U, Buffer + Length - sizeof(dns_qry), sizeof(dns_qry));
		*(Buffer + Length - sizeof(dns_qry) - 1U) = '\xC0';

	#ifdef _WIN64
		Index = GetTickCount64() % 4U;
	#else //_x86
		Index = GetTickCount() % 4U;
	#endif
		switch (Index)
		{
			case 0:
			{
				*(Buffer + Length - sizeof(dns_qry)) = '\x04';
			}break;
			case 1U:
			{
				*(Buffer + Length - sizeof(dns_qry)) = '\x06';
			}break;
			case 2U:
			{
				*(Buffer + Length - sizeof(dns_qry)) = '\x08';
			}break;
			case 3U:
			{
				*(Buffer + Length - sizeof(dns_qry)) = '\x0A';
			}break;
			default:
			{
				return EXIT_FAILURE;
			}
		}

		return Length + 1U;
	}
	else {
		std::shared_ptr<dns_qry> pdns_qry(new dns_qry());
		memcpy(pdns_qry.get(), Buffer + DNS_PACKET_QUERY_LOCATE(Buffer), sizeof(dns_qry));
		memmove(Buffer + sizeof(dns_hdr) + sizeof(uint16_t) + sizeof(dns_qry), Buffer + sizeof(dns_hdr), strlen(Buffer + sizeof(dns_hdr)) + 1U);
		memcpy(Buffer + sizeof(dns_hdr) + sizeof(uint16_t), pdns_qry.get(), sizeof(dns_qry));
		*(Buffer + sizeof(dns_hdr)) = '\xC0';
		*(Buffer + sizeof(dns_hdr) + 1U) = '\x12';

		if (Index == 1U) //Pointer to RR, like "[DNS Header][Pointer][Query][Domain]" and the pointer is point to [Domain].
		{
			return Length + 2U;
		}
		else { //Pointer to Additional, like "[DNS Header][Pointer][Query][Additional]" and the pointer is point to domain in [Additional].
			auto pdns_hdr = (dns_hdr *)Buffer;
			pdns_hdr->Additional = htons(U16_NUM_ONE);

		//Ramdom number distribution initialization
			std::uniform_int_distribution<int> RamdomDistribution_Additional(0, U32_MAXNUM);

		//Make records.
			if (pdns_qry->Type == htons(DNS_RECORD_AAAA))
			{
				auto pdns_aaaa_record = (dns_aaaa_record *)(Buffer + Length);
				pdns_aaaa_record->Type = htons(DNS_RECORD_AAAA);
				pdns_aaaa_record->Classes = htons(DNS_CLASS_IN);
				pdns_aaaa_record->TTL = htonl(RamdomDistribution_Additional(*Parameter.RamdomEngine));
				pdns_aaaa_record->Length = htons(sizeof(in6_addr));
				for (Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
					pdns_aaaa_record->Addr.u.Word[Index] = htons((uint16_t)RamdomDistribution_Additional(*Parameter.RamdomEngine));

				return Length + sizeof(dns_aaaa_record);
			}
			else {
				auto pdns_a_record = (dns_a_record *)(Buffer + Length);
				pdns_a_record->Type = htons(DNS_RECORD_A);
				pdns_a_record->Classes = htons(DNS_CLASS_IN);
				pdns_a_record->TTL = htonl(RamdomDistribution_Additional(*Parameter.RamdomEngine));
				pdns_a_record->Length = htons(sizeof(in_addr));
				pdns_a_record->Addr.S_un.S_addr = htonl(RamdomDistribution_Additional(*Parameter.RamdomEngine));

				return Length + sizeof(dns_a_record);
			}
		}
	}

	return EXIT_FAILURE;
}

//Check DNS response results.
bool __fastcall CheckResponseData(const PSTR Buffer, const size_t Length, bool IsLocal, bool *MarkHopLimit)
{
	auto pdns_hdr = (dns_hdr *)Buffer;

//DNS Options part
	if (Parameter.DNSDataCheck && (pdns_hdr->Questions != htons(U16_NUM_ONE) || //Question Resource Records must be one.
		ntohs(pdns_hdr->Flags) >> 15U == 0 || //No any Question Resource Records
		(ntohs(pdns_hdr->Flags) & U4_MAXNUM) == DNS_RCODE_NOERROR && pdns_hdr->Answer == 0 && pdns_hdr->Authority == 0 && pdns_hdr->Additional == 0 || //No any non-Question Resource Records when RCode is No Error(Normal)
		(ntohs(pdns_hdr->Flags) & 0x0400) >> 10U == 1U && pdns_hdr->Authority == 0 && pdns_hdr->Answer == 0 || //Responses are not authoritative when there are no any Authoritative Nameservers Records/Additional Resource Records.
		Parameter.EDNS0Label && pdns_hdr->Additional == 0)) //Additional EDNS0 Label Resource Records check
			return false;

	if (MarkHopLimit != nullptr && (Parameter.DNSDataCheck && 
		pdns_hdr->Answer != htons(U16_NUM_ONE) || //Less than or more than one Answer Record
		pdns_hdr->Authority > 0 || pdns_hdr->Additional > 0)) //Authority Records and/or Additional Records
			*MarkHopLimit = true;

//No Such Name, not standard query response and no error check.
	if (MarkHopLimit != nullptr && Parameter.DNSDataCheck && 
		(ntohs(pdns_hdr->Flags) & U4_MAXNUM) == DNS_RCODE_NXDOMAIN)
//		pdns_hdr->Flags != htons(DNS_SQR_NE) && pdns_hdr->Flags != htons(DNS_SQR_NEA))
	{
		*MarkHopLimit = true;
		return true;
	}

//Responses question pointer check
	if (Parameter.DNSDataCheck)
	{
		for (size_t Index = sizeof(dns_hdr);Index < DNS_PACKET_QUERY_LOCATE(Buffer);Index++)
		{
			if (*(Buffer + Index) == '\xC0')
				return false;
		}
	}

	std::shared_ptr<char> Domain(new char[DOMAIN_MAXSIZE]());
	DNSQueryToChar(Buffer + sizeof(dns_hdr), Domain.get());
//Domain Test part
	if (MarkHopLimit != nullptr && Parameter.DomainTestData != nullptr)
	{
		if (strlen(Domain.get()) == strlen(Parameter.DomainTestData) &&
			memcmp(Domain.get(), Parameter.DomainTestData, strlen(Parameter.DomainTestData)) == 0 && pdns_hdr->ID == Parameter.DomainTestID)
		{
			*MarkHopLimit = true;
			return true;
		}
	}

//Check repeating DNS Doman without Compression.
/* Old version(2015-01-04)
	if (Parameter.DNSDataCheck && DomainLength > 2U &&
		*(PUINT16)(Buffer + DNS_PACKET_RR_LOCATE(Buffer)) != htons(DNS_QUERY_PTR) &&
		CheckDNSQueryNameLength(Buffer + DNS_PACKET_RR_LOCATE(Buffer)) < DOMAIN_MAXSIZE)
	{
		std::shared_ptr<char> Compression(new char[DOMAIN_MAXSIZE]());

		size_t DomainLengthTemp = DNSQueryToChar(Buffer + DNS_PACKET_RR_LOCATE(Buffer), Compression.get());
		if (DomainLength == DomainLengthTemp &&
		memcmp(Result.get(), Compression.get(), DomainLengthTemp) == 0)
		return false;
	}
*/
	if (Parameter.DNSDataCheck && pdns_hdr->Answer == htons(U16_NUM_ONE) && pdns_hdr->Additional == 0 && pdns_hdr->Additional == 0 && 
		CheckDNSQueryNameLength(Buffer + sizeof(dns_hdr)) == CheckDNSQueryNameLength(Buffer + DNS_PACKET_RR_LOCATE(Buffer)))
	{
		auto QuestionDomain = (uint8_t *)(Buffer + sizeof(dns_hdr));
		auto AnswerDomain = (uint8_t *)(Buffer + DNS_PACKET_RR_LOCATE(Buffer));
		auto pdns_standard_record = (dns_standard_record *)(Buffer + DNS_PACKET_RR_LOCATE(Buffer) + CheckDNSQueryNameLength((PSTR)QuestionDomain) + 1U);
		if (pdns_standard_record->Classes == htons(DNS_CLASS_IN) &&
			(pdns_standard_record->Type == htons(DNS_RECORD_A) || pdns_standard_record->Type == htons(DNS_RECORD_AAAA)) && 
			memcmp(QuestionDomain, AnswerDomain, CheckDNSQueryNameLength((PSTR)QuestionDomain) + 1U) == 0)
				return false;
	}

//DNS Responses which have one Answer Resource Records and no any Authority Resource Records or Additional Resource Records may fake.
	auto pdns_qry = (dns_qry *)(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer));
	if (pdns_hdr->Answer == htons(U16_NUM_ONE) && pdns_hdr->Authority == 0 && pdns_hdr->Additional == 0 && pdns_qry->Classes == htons(DNS_CLASS_IN))
	{
	//AAAA Records
		if (pdns_qry->Type == htons(DNS_RECORD_AAAA))
		{
			auto pdns_aaaa_record = (dns_aaaa_record *)(Buffer + (Length - sizeof(dns_aaaa_record)));

		//Records Type in responses check
			if (Parameter.DNSDataCheck && pdns_aaaa_record->Type != pdns_qry->Type)
				return false;

		//Fake responses check
			if (Parameter.Blacklist)
			{
				if (pdns_aaaa_record->Type == htons(DNS_RECORD_AAAA) && pdns_aaaa_record->Classes == htons(DNS_CLASS_IN) && 
					pdns_aaaa_record->TTL > 0 && pdns_aaaa_record->Length == htons(sizeof(in6_addr)) && 
					(CheckSpecialAddress(&pdns_aaaa_record->Addr, AF_INET6, Domain.get()) || 
					Parameter.LocalRouting && IsLocal && !CheckAddressRouting(&pdns_aaaa_record->Addr, AF_INET6)))
						return false;
			}
		}
	//A Records.
		else if (pdns_qry->Type == htons(DNS_RECORD_A))
		{
			auto pdns_a_record = (dns_a_record *)(Buffer + (Length - sizeof(dns_a_record)));

		//Records Type in responses check
			if (Parameter.DNSDataCheck && pdns_a_record->Type != pdns_qry->Type)
				return false;

		//Fake responses check
			if (Parameter.Blacklist)
			{
				if (pdns_a_record->Type == htons(DNS_RECORD_A) && pdns_a_record->Classes == htons(DNS_CLASS_IN) &&
					pdns_a_record->TTL > 0 && pdns_a_record->Length == htons(sizeof(in_addr)) &&
					(CheckSpecialAddress(&pdns_a_record->Addr, AF_INET, Domain.get()) || 
					Parameter.LocalRouting && IsLocal && !CheckAddressRouting(&pdns_a_record->Addr, AF_INET)))
						return false;
			}
		}
	}
//Normal check
	else {
		size_t Index = 0, DataLength = DNS_PACKET_RR_LOCATE(Buffer);
		dns_standard_record *pdns_standard_record = nullptr;
		in6_addr *pin6_addr = nullptr;
		in_addr *pin_addr = nullptr;

	//Scan all results.
		for (Index = 0;Index < (size_t)(ntohs(pdns_hdr->Answer) + ntohs(pdns_hdr->Authority) + ntohs(pdns_hdr->Additional));Index++)
		{
		//Resource Records Name(Domain)
			DataLength += CheckDNSQueryNameLength(Buffer + DataLength) + 1U;
		//Length check
			if (DataLength > Length)
				return false;

		//Standard Resource Records
			pdns_standard_record = (dns_standard_record *)(Buffer + DataLength);
			DataLength += sizeof(dns_standard_record);
		//Length check
			if (DataLength > Length)
				return false;

		//Resource Records Data
			if (pdns_standard_record->Classes == htons(DNS_CLASS_IN) && pdns_standard_record->TTL > 0)
			{
				if (pdns_standard_record->Type == htons(DNS_RECORD_AAAA) && pdns_standard_record->Length == htons(sizeof(in6_addr)))
				{
					pin6_addr = (in6_addr *)(Buffer + DataLength);
					if (CheckSpecialAddress(pin6_addr, AF_INET6, Domain.get()) || Parameter.LocalRouting && IsLocal && !CheckAddressRouting(pin6_addr, AF_INET6))
						return false;
				}
				else if (pdns_standard_record->Type == htons(DNS_RECORD_A) && pdns_standard_record->Length == htons(sizeof(in_addr)))
				{
					pin_addr = (in_addr *)(Buffer + DataLength);
					if (CheckSpecialAddress(pin_addr, AF_INET, Domain.get()) || Parameter.LocalRouting && IsLocal && !CheckAddressRouting(pin_addr, AF_INET))
					{
						return false;
					}
				}
			}

			DataLength += ntohs(pdns_standard_record->Length);
		//Length check
			if (DataLength > Length)
				return false;
		}
	}

	return true;
}
