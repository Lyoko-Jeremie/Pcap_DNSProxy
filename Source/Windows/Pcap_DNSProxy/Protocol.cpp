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

extern Configuration Parameter;
extern std::vector<std::string> LocalhostPTR[QUEUE_PARTNUM / 2U];
extern std::vector<AddressRange> *AddressRangeUsing;
extern std::vector<ResultBlacklistTable> *ResultBlacklistUsing;
extern std::mutex LocalhostPTRLock[QUEUE_PARTNUM / 2U], AddressRangeLock, ResultBlacklistLock;

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

//Convert address strings to binary.
size_t __fastcall AddressStringToBinary(const PSTR AddrString, void *pAddr, const uint16_t Protocol, SSIZE_T &ErrorCode)
{
	std::string sAddrString(AddrString);

//inet_ntop() and inet_pton() was only support in Windows Vista and newer system. [Roy Tam]
#ifdef _WIN64
	SSIZE_T Result = 0;
#else //x86
	sockaddr_storage SockAddr = {0};
	int SockLength = 0;
#endif

//IPv6
	if (Protocol == AF_INET6)
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
		Result = inet_pton(AF_INET6, sAddrString.c_str(), pAddr);
		if (Result == SOCKET_ERROR || Result == FALSE)
	#else //x86
		SockLength = sizeof(sockaddr_in6);
		if (WSAStringToAddressA((PSTR)sAddrString.c_str(), AF_INET6, NULL, (LPSOCKADDR)&SockAddr, &SockLength) == SOCKET_ERROR)
	#endif
		{
			ErrorCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#ifdef _WIN64
	#else //x86
		memcpy(pAddr, &((PSOCKADDR_IN6)&SockAddr)->sin6_addr, sizeof(in6_addr));
	#endif
	}
//IPv4
	else {
		size_t CommaNum = 0;

	//Check IPv4 addresses
		for (auto StringIter:sAddrString)
		{
			if (StringIter != ASCII_PERIOD && StringIter < ASCII_ZERO || StringIter > ASCII_NINE)
				return EXIT_FAILURE;
			else if (StringIter == ASCII_PERIOD)
				CommaNum++;
		}

	//Delete zero(s) before whole data.
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

	//Delete zero(s) before data.
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
		Result = inet_pton(AF_INET, sAddrString.c_str(), pAddr);
		if (Result == SOCKET_ERROR || Result == FALSE)
	#else //x86
		SockLength = sizeof(sockaddr_in);
		if (WSAStringToAddressA((PSTR)sAddrString.c_str(), AF_INET, NULL, (LPSOCKADDR)&SockAddr, &SockLength) == SOCKET_ERROR)
	#endif
		{
			ErrorCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#ifdef _WIN64
	#else //x86
		memcpy(pAddr, &((PSOCKADDR_IN)&SockAddr)->sin_addr, sizeof(in_addr));
	#endif
	}

	return EXIT_SUCCESS;
}

//Get local address list
PADDRINFOA __fastcall GetLocalAddressList(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> HostName(new char[DOMAIN_MAXSIZE]());
	addrinfo Hints = {0}, *Result = nullptr /* , *PTR = nullptr */;

	if (Protocol == AF_INET6) //IPv6
		Hints.ai_family = AF_INET6;
	else //IPv4
		Hints.ai_family = AF_INET;
	Hints.ai_socktype = SOCK_DGRAM;
	Hints.ai_protocol = IPPROTO_UDP;

//Get localhost name.
	if (gethostname(HostName.get(), DOMAIN_MAXSIZE) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Get localhost name error", WSAGetLastError(), nullptr, NULL);
		return nullptr;
	}

//Get localhost data.
	SSIZE_T ResultGetaddrinfo = getaddrinfo(HostName.get(), NULL, &Hints, &Result);
	if (ResultGetaddrinfo != 0)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Get localhost address(es) error", ResultGetaddrinfo, nullptr, NULL);

		freeaddrinfo(Result);
		return nullptr;
	}
	else {
		return Result;
	}

//Report
/* Need to get all local addresses(2014-09-13)
	for (PTR = Result;PTR != nullptr;PTR = PTR->ai_next)
	{
	//IPv6
		if (PTR->ai_family == AF_INET6 && Protocol == AF_INET6 && 
			!IN6_IS_ADDR_LINKLOCAL((in6_addr *)(PTR->ai_addr)) &&
			!(((PSOCKADDR_IN6)(PTR->ai_addr))->sin6_scope_id == 0)) //Get port from first(Main) IPv6 device
		{
			SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SockAddr)->sin6_addr = ((PSOCKADDR_IN6)(PTR->ai_addr))->sin6_addr;
			freeaddrinfo(Result);
			return true;
		}
	//IPv4
		else if (PTR->ai_family == AF_INET && Protocol == AF_INET && 
			((PSOCKADDR_IN)(PTR->ai_addr))->sin_addr.S_un.S_addr != INADDR_LOOPBACK && 
			((PSOCKADDR_IN)(PTR->ai_addr))->sin_addr.S_un.S_addr != INADDR_BROADCAST)
		{
			SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SockAddr)->sin_addr = ((PSOCKADDR_IN)(PTR->ai_addr))->sin_addr;
			freeaddrinfo(Result);
			return true;
		}
	}

	freeaddrinfo(Result);
	return nullptr;
*/
}

//Get information of local addresses
size_t __fastcall GetLocalAddressInformation(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	std::string Result;

/* Old version(2014-09-13)
//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista. [Roy Tam]
#ifdef _WIN64
#else //x86
	DWORD BufferLength = ADDR_STRING_MAXSIZE;
#endif
*/
	SSIZE_T Index = 0;
	PADDRINFOA LocalAddressList = nullptr, LocalAddressListPTR = nullptr;
	while (true)
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

		//IPv6
			if (Protocol == AF_INET6)
			{
			//Initialization
				std::unique_lock<std::mutex> LocalhostPTRMutexIPv6(LocalhostPTRLock[0]);
				LocalhostPTR[0].clear();
				LocalhostPTR[0].shrink_to_fit();

			//Read addresses list and convert to Fully Qualified Domain Name/FQDN PTR.
//				size_t Location = 0, Colon = 0;
				for (LocalAddressListPTR = LocalAddressList;LocalAddressListPTR != nullptr;LocalAddressListPTR = LocalAddressListPTR->ai_next)
				{
					if (LocalAddressListPTR->ai_family == Protocol && LocalAddressListPTR->ai_addrlen == sizeof(sockaddr_in6) && 
						LocalAddressListPTR->ai_addr->sa_family == Protocol)
					{
					//IPv6 tunnels support(6to4, ISATAP and Teredo), but only check preferred address.
//						Parameter.Tunnel_Teredo.clear();
						if (((PSOCKADDR_IN6)LocalAddressListPTR->ai_addr)->sin6_addr.u.Word[0] == htons(0x2001) && ((PSOCKADDR_IN6)LocalAddressListPTR->ai_addr)->sin6_addr.u.Word[1U] == 0 || //Teredo relay/tunnel Addresses(2001::/32, RFC 4380)
							((PSOCKADDR_IN6)LocalAddressListPTR->ai_addr)->sin6_addr.u.Word[0] == htons(0x2002) || //6to4 relay/tunnel Addresses(2002::/16, Section 2 in RFC 3056)
							((PSOCKADDR_IN6)LocalAddressListPTR->ai_addr)->sin6_addr.u.Byte[0] >= 0x80 && ((PSOCKADDR_IN6)LocalAddressListPTR->ai_addr)->sin6_addr.u.Byte[1U] <= 0xBF && //Link-Local Unicast Contrast Addresses/LUC(FE80::/10, Section 2.5.6 in RFC 4291)
							((PSOCKADDR_IN6)LocalAddressListPTR->ai_addr)->sin6_addr.u.Word[4U] == 0 && ((PSOCKADDR_IN6)LocalAddressListPTR->ai_addr)->sin6_addr.u.Word[5U] == htons(0x5EFE)) //ISATAP Interface Identifiers Addresses(Prefix:0:5EFE:0:0:0:0/64, which also in Link-Local Unicast Contrast Addresses/LUC, Section 6.1 in RFC 5214)
					/*
						{
							in_addr TeredoTunnelAddress = {0};
							TeredoTunnelAddress.S_un.S_un_w.s_w1 = ((PSOCKADDR_IN6)LocalAddressListPTR->ai_addr)->sin6_addr.u.Word[2U];
							TeredoTunnelAddress.S_un.S_un_w.s_w2 = ((PSOCKADDR_IN6)LocalAddressListPTR->ai_addr)->sin6_addr.u.Word[3U];
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
						if (inet_ntop(AF_INET6, &((PSOCKADDR_IN6)LocalAddressListPTR->ai_addr)->sin6_addr, Addr.get(), ADDR_STRING_MAXSIZE) == nullptr)
					#else //x86
						if (WSAAddressToStringA((LPSOCKADDR)LocalAddressListPTR->ai_addr, sizeof(sockaddr_in6), NULL, Addr.get(), &BufferLength) == SOCKET_ERROR)
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
							_ultoa_s(htons(((PSOCKADDR_IN6)LocalAddressListPTR->ai_addr)->sin6_addr.u.Word[Index]), Addr.get(), ADDR_STRING_MAXSIZE, NUM_HEX);

						//Add zero(s) to beginning of string.
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
						{
							Index = DNSPTRString.find(":0:", Index);
							DNSPTRString.replace(Index, 3U, ":0000:");
						}

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
						LocalhostPTR[0].push_back(Result);
						Result.clear();
						Result.shrink_to_fit();
					}
				}

				LocalhostPTRMutexIPv6.unlock();
				freeaddrinfo(LocalAddressListPTR);
				LocalAddressListPTR = nullptr;
			}
		//IPv4
			else {
			//Initialization
				std::unique_lock<std::mutex> LocalhostPTRMutexIPv4(LocalhostPTRLock[1U]);
				LocalhostPTR[1U].clear();
				LocalhostPTR[1U].shrink_to_fit();

			//Read addresses list and convert to Fully Qualified Domain Name/FQDN PTR.
//				char CharAddr[4U][4U] = {0};
//				size_t Localtion[] = {0, 0};
				for (LocalAddressListPTR = LocalAddressList;LocalAddressListPTR != nullptr;LocalAddressListPTR = LocalAddressListPTR->ai_next)
				{
					if (LocalAddressListPTR->ai_family == Protocol && LocalAddressListPTR->ai_addrlen == sizeof(sockaddr_in) && 
						LocalAddressListPTR->ai_addr->sa_family == Protocol)
					{
					//Initialization
						DNSPTRString.clear();
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

				/* Old version(2014-09-13)
						memset(&CharAddr, 0, sizeof(CharAddr));
						memset(&Localtion, 0, sizeof(Localtion));

					//Convert from in_addr to string.
					//Minimum supported system of inet_ntop() and inet_pton() is Windows Vista. [Roy Tam]
					#ifdef _WIN64
						if (inet_ntop(AF_INET, &((PSOCKADDR_IN)LocalAddressListPTR->ai_addr)->sin_addr, Addr.get(), ADDR_STRING_MAXSIZE) == nullptr)
					#else //x86
						if (WSAAddressToStringA((LPSOCKADDR)LocalAddressListPTR->ai_addr, sizeof(sockaddr_in), NULL, Addr.get(), &BufferLength) == SOCKET_ERROR)
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
						_itoa_s(((PSOCKADDR_IN)LocalAddressListPTR->ai_addr)->sin_addr.S_un.S_un_b.s_b4, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						_itoa_s(((PSOCKADDR_IN)LocalAddressListPTR->ai_addr)->sin_addr.S_un.S_un_b.s_b3, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						_itoa_s(((PSOCKADDR_IN)LocalAddressListPTR->ai_addr)->sin_addr.S_un.S_un_b.s_b2, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						_itoa_s(((PSOCKADDR_IN)LocalAddressListPTR->ai_addr)->sin_addr.S_un.S_un_b.s_b1, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						Result.append("in-addr.arpa");

					//Add to global list.
						LocalhostPTR[1U].push_back(Result);
						Result.clear();
						Result.shrink_to_fit();
					}
				}

				LocalhostPTRMutexIPv4.unlock();
				freeaddrinfo(LocalAddressListPTR);
				LocalAddressListPTR = nullptr;
			}
		}

	//Auto-refresh
		if (Parameter.FileRefreshTime == 0)
			return EXIT_SUCCESS;
		else 
			Sleep((DWORD)Parameter.FileRefreshTime);
	}

	return EXIT_SUCCESS;
}

//Convert service name to port
uint16_t __fastcall ServiceNameToPort(const PSTR Buffer)
{
	uint16_t Port = 0;

//Server name
	if (strstr(Buffer, ("TCPMUX")) != nullptr || strstr(Buffer, ("tcpmux")) != nullptr)
		Port = htons(IPPORT_TCPMUX);
	else if (strstr(Buffer, ("ECHO")) != nullptr || strstr(Buffer, ("echo")) != nullptr)
		Port = htons(IPPORT_ECHO);
	else if (strstr(Buffer, ("DISCARD")) != nullptr || strstr(Buffer, ("discard")) != nullptr)
		Port = htons(IPPORT_DISCARD);
	else if (strstr(Buffer, ("SYSTAT")) != nullptr || strstr(Buffer, ("systat")) != nullptr)
		Port = htons(IPPORT_SYSTAT);
	else if (strstr(Buffer, ("DAYTIME")) != nullptr || strstr(Buffer, ("daytime")) != nullptr)
		Port = htons(IPPORT_DAYTIME);
	else if (strstr(Buffer, ("NETSTAT")) != nullptr || strstr(Buffer, ("netstat")) != nullptr)
		Port = htons(IPPORT_NETSTAT);
	else if (strstr(Buffer, ("QOTD")) != nullptr || strstr(Buffer, ("qotd")) != nullptr)
		Port = htons(IPPORT_QOTD);
	else if (strstr(Buffer, ("MSP")) != nullptr || strstr(Buffer, ("msp")) != nullptr)
		Port = htons(IPPORT_MSP);
	else if (strstr(Buffer, ("CHARGEN")) != nullptr || strstr(Buffer, ("chargen")) != nullptr)
		Port = htons(IPPORT_CHARGEN);
	else if (strstr(Buffer, ("FTPDATA")) != nullptr || strstr(Buffer, ("ftpdata")) != nullptr)
		Port = htons(IPPORT_FTP_DATA);
	else if (strstr(Buffer, ("FTP")) != nullptr || strstr(Buffer, ("ftp")) != nullptr)
		Port = htons(IPPORT_FTP);
	else if (strstr(Buffer, ("SSH")) != nullptr || strstr(Buffer, ("ssh")) != nullptr)
		Port = htons(IPPORT_SSH);
	else if (strstr(Buffer, ("TELNET")) != nullptr || strstr(Buffer, ("telnet")) != nullptr)
		Port = htons(IPPORT_TELNET);
	else if (strstr(Buffer, ("SMTP")) != nullptr || strstr(Buffer, ("smtp")) != nullptr)
		Port = htons(IPPORT_SMTP);
	else if (strstr(Buffer, ("TIME")) != nullptr || strstr(Buffer, ("time")) != nullptr)
		Port = htons(IPPORT_TIMESERVER);
	else if (strstr(Buffer, ("RAP")) != nullptr || strstr(Buffer, ("rap")) != nullptr)
		Port = htons(IPPORT_RAP);
	else if (strstr(Buffer, ("RLP")) != nullptr || strstr(Buffer, ("rlp")) != nullptr)
		Port = htons(IPPORT_RLP);
	else if (strstr(Buffer, ("NAME")) != nullptr || strstr(Buffer, ("name")) != nullptr)
		Port = htons(IPPORT_NAMESERVER);
	else if (strstr(Buffer, ("WHOIS")) != nullptr || strstr(Buffer, ("whois")) != nullptr)
		Port = htons(IPPORT_WHOIS);
	else if (strstr(Buffer, ("TACACS")) != nullptr || strstr(Buffer, ("tacacs")) != nullptr)
		Port = htons(IPPORT_TACACS);
	else if (strstr(Buffer, ("DNS")) != nullptr || strstr(Buffer, ("dns")) != nullptr)
		Port = htons(IPPORT_DNS);
	else if (strstr(Buffer, ("XNSAUTH")) != nullptr || strstr(Buffer, ("xnsauth")) != nullptr)
		Port = htons(IPPORT_XNSAUTH);
	else if (strstr(Buffer, ("MTP")) != nullptr || strstr(Buffer, ("mtp")) != nullptr)
		Port = htons(IPPORT_MTP);
	else if (strstr(Buffer, ("BOOTPS")) != nullptr || strstr(Buffer, ("bootps")) != nullptr)
		Port = htons(IPPORT_BOOTPS);
	else if (strstr(Buffer, ("BOOTPC")) != nullptr || strstr(Buffer, ("bootpc")) != nullptr)
		Port = htons(IPPORT_BOOTPC);
	else if (strstr(Buffer, ("TFTP")) != nullptr || strstr(Buffer, ("tftp")) != nullptr)
		Port = htons(IPPORT_TFTP);
	else if (strstr(Buffer, ("RJE")) != nullptr || strstr(Buffer, ("rje")) != nullptr)
		Port = htons(IPPORT_RJE);
	else if (strstr(Buffer, ("FINGER")) != nullptr || strstr(Buffer, ("finger")) != nullptr)
		Port = htons(IPPORT_FINGER);
	else if (strstr(Buffer, ("HTTP")) != nullptr || strstr(Buffer, ("http")) != nullptr)
		Port = htons(IPPORT_HTTP);
	else if (strstr(Buffer, ("HTTPBACKUP")) != nullptr || strstr(Buffer, ("httpbackup")) != nullptr)
		Port = htons(IPPORT_HTTPBACKUP);
	else if (strstr(Buffer, ("TTYLINK")) != nullptr || strstr(Buffer, ("ttylink")) != nullptr)
		Port = htons(IPPORT_TTYLINK);
	else if (strstr(Buffer, ("SUPDUP")) != nullptr || strstr(Buffer, ("supdup")) != nullptr)
		Port = htons(IPPORT_SUPDUP);
	else if (strstr(Buffer, ("POP3")) != nullptr || strstr(Buffer, ("pop3")) != nullptr)
		Port = htons(IPPORT_POP3);
	else if (strstr(Buffer, ("SUNRPC")) != nullptr || strstr(Buffer, ("sunrpc")) != nullptr)
		Port = htons(IPPORT_SUNRPC);
	else if (strstr(Buffer, ("SQL")) != nullptr || strstr(Buffer, ("sql")) != nullptr)
		Port = htons(IPPORT_SQL);
	else if (strstr(Buffer, ("NTP")) != nullptr || strstr(Buffer, ("ntp")) != nullptr)
		Port = htons(IPPORT_NTP);
	else if (strstr(Buffer, ("EPMAP")) != nullptr || strstr(Buffer, ("epmap")) != nullptr)
		Port = htons(IPPORT_EPMAP);
	else if (strstr(Buffer, ("NETBIOSNS")) != nullptr || strstr(Buffer, ("netbiosns")) != nullptr)
		Port = htons(IPPORT_NETBIOS_NS);
	else if (strstr(Buffer, ("NETBIOSDGM")) != nullptr || strstr(Buffer, ("netbiosdgm")) != nullptr)
		Port = htons(IPPORT_NETBIOS_DGM);
	else if (strstr(Buffer, ("NETBIOSSSN")) != nullptr || strstr(Buffer, ("netbiosssn")) != nullptr)
		Port = htons(IPPORT_NETBIOS_SSN);
	else if (strstr(Buffer, ("IMAP")) != nullptr || strstr(Buffer, ("imap")) != nullptr)
		Port = htons(IPPORT_IMAP);
	else if (strstr(Buffer, ("BFTP")) != nullptr || strstr(Buffer, ("bftp")) != nullptr)
		Port = htons(IPPORT_BFTP);
	else if (strstr(Buffer, ("SGMP")) != nullptr || strstr(Buffer, ("sgmp")) != nullptr)
		Port = htons(IPPORT_SGMP);
	else if (strstr(Buffer, ("SQLSRV")) != nullptr || strstr(Buffer, ("sqlsrv")) != nullptr)
		Port = htons(IPPORT_SQLSRV);
	else if (strstr(Buffer, ("DMSP")) != nullptr || strstr(Buffer, ("dmsp")) != nullptr)
		Port = htons(IPPORT_DMSP);
	else if (strstr(Buffer, ("SNMP")) != nullptr || strstr(Buffer, ("snmp")) != nullptr)
		Port = htons(IPPORT_SNMP);
	else if (strstr(Buffer, ("SNMPTRAP")) != nullptr || strstr(Buffer, ("snmptrap")) != nullptr)
		Port = htons(IPPORT_SNMP_TRAP);
	else if (strstr(Buffer, ("ATRTMP")) != nullptr || strstr(Buffer, ("atrtmp")) != nullptr)
		Port = htons(IPPORT_ATRTMP);
	else if (strstr(Buffer, ("ATHBP")) != nullptr || strstr(Buffer, ("athbp")) != nullptr)
		Port = htons(IPPORT_ATHBP);
	else if (strstr(Buffer, ("QMTP")) != nullptr || strstr(Buffer, ("qmtp")) != nullptr)
		Port = htons(IPPORT_QMTP);
	else if (strstr(Buffer, ("IPX")) != nullptr || strstr(Buffer, ("ipx")) != nullptr)
		Port = htons(IPPORT_IPX);
	else if (strstr(Buffer, ("IMAP3")) != nullptr || strstr(Buffer, ("imap3")) != nullptr)
		Port = htons(IPPORT_IMAP3);
	else if (strstr(Buffer, ("BGMP")) != nullptr || strstr(Buffer, ("bgmp")) != nullptr)
		Port = htons(IPPORT_BGMP);
	else if (strstr(Buffer, ("TSP")) != nullptr || strstr(Buffer, ("tsp")) != nullptr)
		Port = htons(IPPORT_TSP);
	else if (strstr(Buffer, ("IMMP")) != nullptr || strstr(Buffer, ("immp")) != nullptr)
		Port = htons(IPPORT_IMMP);
	else if (strstr(Buffer, ("ODMR")) != nullptr || strstr(Buffer, ("odmr")) != nullptr)
		Port = htons(IPPORT_ODMR);
	else if (strstr(Buffer, ("RPC2PORTMAP")) != nullptr || strstr(Buffer, ("rpc2portmap")) != nullptr)
		Port = htons(IPPORT_RPC2PORTMAP);
	else if (strstr(Buffer, ("CLEARCASE")) != nullptr || strstr(Buffer, ("clearcase")) != nullptr)
		Port = htons(IPPORT_CLEARCASE);
	else if (strstr(Buffer, ("HPALARMMGR")) != nullptr || strstr(Buffer, ("hpalarmmgr")) != nullptr)
		Port = htons(IPPORT_HPALARMMGR);
	else if (strstr(Buffer, ("ARNS")) != nullptr || strstr(Buffer, ("arns")) != nullptr)
		Port = htons(IPPORT_ARNS);
	else if (strstr(Buffer, ("AURP")) != nullptr || strstr(Buffer, ("aurp")) != nullptr)
		Port = htons(IPPORT_AURP);
	else if (strstr(Buffer, ("LDAP")) != nullptr || strstr(Buffer, ("ldap")) != nullptr)
		Port = htons(IPPORT_LDAP);
	else if (strstr(Buffer, ("UPS")) != nullptr || strstr(Buffer, ("ups")) != nullptr)
		Port = htons(IPPORT_UPS);
	else if (strstr(Buffer, ("SLP")) != nullptr || strstr(Buffer, ("slp")) != nullptr)
		Port = htons(IPPORT_SLP);
	else if (strstr(Buffer, ("HTTPS")) != nullptr || strstr(Buffer, ("https")) != nullptr)
		Port = htons(IPPORT_HTTPS);
	else if (strstr(Buffer, ("SNPP")) != nullptr || strstr(Buffer, ("snpp")) != nullptr)
		Port = htons(IPPORT_SNPP);
	else if (strstr(Buffer, ("MICROSOFTDS")) != nullptr || strstr(Buffer, ("microsoftds")) != nullptr)
		Port = htons(IPPORT_MICROSOFT_DS);
	else if (strstr(Buffer, ("KPASSWD")) != nullptr || strstr(Buffer, ("kpasswd")) != nullptr)
		Port = htons(IPPORT_KPASSWD);
	else if (strstr(Buffer, ("TCPNETHASPSRV")) != nullptr || strstr(Buffer, ("tcpnethaspsrv")) != nullptr)
		Port = htons(IPPORT_TCPNETHASPSRV);
	else if (strstr(Buffer, ("RETROSPECT")) != nullptr || strstr(Buffer, ("retrospect")) != nullptr)
		Port = htons(IPPORT_RETROSPECT);
	else if (strstr(Buffer, ("ISAKMP")) != nullptr || strstr(Buffer, ("isakmp")) != nullptr)
		Port = htons(IPPORT_ISAKMP);
	else if (strstr(Buffer, ("BIFFUDP")) != nullptr || strstr(Buffer, ("biffudp")) != nullptr)
		Port = htons(IPPORT_BIFFUDP);
	else if (strstr(Buffer, ("WHOSERVER")) != nullptr || strstr(Buffer, ("whoserver")) != nullptr)
		Port = htons(IPPORT_WHOSERVER);
	else if (strstr(Buffer, ("SYSLOG")) != nullptr || strstr(Buffer, ("syslog")) != nullptr)
		Port = htons(IPPORT_SYSLOG);
	else if (strstr(Buffer, ("ROUTERSERVER")) != nullptr || strstr(Buffer, ("routerserver")) != nullptr)
		Port = htons(IPPORT_ROUTESERVER);
	else if (strstr(Buffer, ("NCP")) != nullptr || strstr(Buffer, ("ncp")) != nullptr)
		Port = htons(IPPORT_NCP);
	else if (strstr(Buffer, ("COURIER")) != nullptr || strstr(Buffer, ("courier")) != nullptr)
		Port = htons(IPPORT_COURIER);
	else if (strstr(Buffer, ("COMMERCE")) != nullptr || strstr(Buffer, ("commerce")) != nullptr)
		Port = htons(IPPORT_COMMERCE);
	else if (strstr(Buffer, ("RTSP")) != nullptr || strstr(Buffer, ("rtsp")) != nullptr)
		Port = htons(IPPORT_RTSP);
	else if (strstr(Buffer, ("NNTP")) != nullptr || strstr(Buffer, ("nntp")) != nullptr)
		Port = htons(IPPORT_NNTP);
	else if (strstr(Buffer, ("HTTPRPCEPMAP")) != nullptr || strstr(Buffer, ("httprpcepmap")) != nullptr)
		Port = htons(IPPORT_HTTPRPCEPMAP);
	else if (strstr(Buffer, ("IPP")) != nullptr || strstr(Buffer, ("ipp")) != nullptr)
		Port = htons(IPPORT_IPP);
	else if (strstr(Buffer, ("LDAPS")) != nullptr || strstr(Buffer, ("ldaps")) != nullptr)
		Port = htons(IPPORT_LDAPS);
	else if (strstr(Buffer, ("MSDP")) != nullptr || strstr(Buffer, ("msdp")) != nullptr)
		Port = htons(IPPORT_MSDP);
	else if (strstr(Buffer, ("AODV")) != nullptr || strstr(Buffer, ("aodv")) != nullptr)
		Port = htons(IPPORT_AODV);
	else if (strstr(Buffer, ("FTPSDATA")) != nullptr || strstr(Buffer, ("ftpsdata")) != nullptr)
		Port = htons(IPPORT_FTPSDATA);
	else if (strstr(Buffer, ("FTPS")) != nullptr || strstr(Buffer, ("ftps")) != nullptr)
		Port = htons(IPPORT_FTPS);
	else if (strstr(Buffer, ("NAS")) != nullptr || strstr(Buffer, ("nas")) != nullptr)
		Port = htons(IPPORT_NAS);
	else if (strstr(Buffer, ("TELNETS")) != nullptr || strstr(Buffer, ("telnets")) != nullptr)
		Port = htons(IPPORT_TELNETS);

	return Port;
}

//Convert DNS type name to hex
uint16_t __fastcall DNSTypeNameToHex(const PSTR Buffer)
{
	uint16_t Hex = 0;

//DNS type name
	if (strstr(Buffer, ("A")) != nullptr || strstr(Buffer, ("a")) != nullptr)
		Hex = htons(DNS_A_RECORDS);
	else if (strstr(Buffer, ("NS")) != nullptr || strstr(Buffer, ("ns")) != nullptr)
		Hex = htons(DNS_NS_RECORDS);
	else if (strstr(Buffer, ("CNAME")) != nullptr || strstr(Buffer, ("cname")) != nullptr)
		Hex = htons(DNS_CNAME_RECORDS);
	else if (strstr(Buffer, ("SOA")) != nullptr || strstr(Buffer, ("soa")) != nullptr)
		Hex = htons(DNS_SOA_RECORDS);
	else if (strstr(Buffer, ("PTR")) != nullptr || strstr(Buffer, ("ptr")) != nullptr)
		Hex = htons(DNS_PTR_RECORDS);
	else if (strstr(Buffer, ("MX")) != nullptr || strstr(Buffer, ("mx")) != nullptr)
		Hex = htons(DNS_MX_RECORDS);
	else if (strstr(Buffer, ("TXT")) != nullptr || strstr(Buffer, ("txt")) != nullptr)
		Hex = htons(DNS_TXT_RECORDS);
	else if (strstr(Buffer, ("RP")) != nullptr || strstr(Buffer, ("rp")) != nullptr)
		Hex = htons(DNS_RP_RECORDS);
	else if (strstr(Buffer, ("SIG")) != nullptr || strstr(Buffer, ("sig")) != nullptr)
		Hex = htons(DNS_SIG_RECORDS);
	else if (strstr(Buffer, ("KEY")) != nullptr || strstr(Buffer, ("key")) != nullptr)
		Hex = htons(DNS_KEY_RECORDS);
	else if (strstr(Buffer, ("AAAA")) != nullptr || strstr(Buffer, ("aaaa")) != nullptr)
		Hex = htons(DNS_AAAA_RECORDS);
	else if (strstr(Buffer, ("LOC")) != nullptr || strstr(Buffer, ("loc")) != nullptr)
		Hex = htons(DNS_LOC_RECORDS);
	else if (strstr(Buffer, ("SRV")) != nullptr || strstr(Buffer, ("srv")) != nullptr)
		Hex = htons(DNS_SRV_RECORDS);
	else if (strstr(Buffer, ("NAPTR")) != nullptr || strstr(Buffer, ("naptr")) != nullptr)
		Hex = htons(DNS_NAPTR_RECORDS);
	else if (strstr(Buffer, ("KX")) != nullptr || strstr(Buffer, ("kx")) != nullptr)
		Hex = htons(DNS_KX_RECORDS);
	else if (strstr(Buffer, ("CERT")) != nullptr || strstr(Buffer, ("cert")) != nullptr)
		Hex = htons(DNS_CERT_RECORDS);
	else if (strstr(Buffer, ("DNAME")) != nullptr || strstr(Buffer, ("dname")) != nullptr)
		Hex = htons(DNS_DNAME_RECORDS);
	else if (strstr(Buffer, ("EDNS0")) != nullptr || strstr(Buffer, ("edns0")) != nullptr)
		Hex = htons(DNS_EDNS0_RECORDS);
	else if (strstr(Buffer, ("APL")) != nullptr || strstr(Buffer, ("apl")) != nullptr)
		Hex = htons(DNS_APL_RECORDS);
	else if (strstr(Buffer, ("DS")) != nullptr || strstr(Buffer, ("ds")) != nullptr)
		Hex = htons(DNS_DS_RECORDS);
	else if (strstr(Buffer, ("SSHFP")) != nullptr || strstr(Buffer, ("sshfp")) != nullptr)
		Hex = htons(DNS_SSHFP_RECORDS);
	else if (strstr(Buffer, ("IPSECKEY")) != nullptr || strstr(Buffer, ("ipseckey")) != nullptr)
		Hex = htons(DNS_IPSECKEY_RECORDS);
	else if (strstr(Buffer, ("RRSIG")) != nullptr || strstr(Buffer, ("rrsig")) != nullptr)
		Hex = htons(DNS_RRSIG_RECORDS);
	else if (strstr(Buffer, ("NSEC")) != nullptr || strstr(Buffer, ("nsec")) != nullptr)
		Hex = htons(DNS_NSEC_RECORDS);
	else if (strstr(Buffer, ("DNSKEY")) != nullptr || strstr(Buffer, ("dnskey")) != nullptr)
		Hex = htons(DNS_DNSKEY_RECORDS);
	else if (strstr(Buffer, ("DHCID")) != nullptr || strstr(Buffer, ("dhcid")) != nullptr)
		Hex = htons(DNS_DHCID_RECORDS);
	else if (strstr(Buffer, ("NSEC3")) != nullptr || strstr(Buffer, ("nsec3")) != nullptr)
		Hex = htons(DNS_NSEC3_RECORDS);
	else if (strstr(Buffer, ("NSEC3PARAM")) != nullptr || strstr(Buffer, ("nsec3param")) != nullptr)
		Hex = htons(DNS_NSEC3PARAM_RECORDS);
	else if (strstr(Buffer, ("HIP")) != nullptr || strstr(Buffer, ("hip")) != nullptr)
		Hex = htons(DNS_HIP_RECORDS);
	else if (strstr(Buffer, ("SPF")) != nullptr || strstr(Buffer, ("spf")) != nullptr)
		Hex = htons(DNS_SPF_RECORDS);
	else if (strstr(Buffer, ("TKEY")) != nullptr || strstr(Buffer, ("tkey")) != nullptr)
		Hex = htons(DNS_TKEY_RECORDS);
	else if (strstr(Buffer, ("TSIG")) != nullptr || strstr(Buffer, ("tsig")) != nullptr)
		Hex = htons(DNS_TSIG_RECORDS);
	else if (strstr(Buffer, ("IXFR")) != nullptr || strstr(Buffer, ("ixfr")) != nullptr)
		Hex = htons(DNS_IXFR_RECORDS);
	else if (strstr(Buffer, ("AXFR")) != nullptr || strstr(Buffer, ("axfr")) != nullptr)
		Hex = htons(DNS_AXFR_RECORDS);
	else if (strstr(Buffer, ("ANY")) != nullptr || strstr(Buffer, ("any")) != nullptr)
		Hex = htons(DNS_ANY_RECORDS);
	else if (strstr(Buffer, ("TA")) != nullptr || strstr(Buffer, ("ta")) != nullptr)
		Hex = htons(DNS_TA_RECORDS);
	else if (strstr(Buffer, ("DLV")) != nullptr || strstr(Buffer, ("dlv")) != nullptr)
		Hex = htons(DNS_DLV_RECORDS);

	return Hex;
}

//Check IP(v4/v6) special addresses
bool __fastcall CheckSpecialAddress(const void *Addr, const uint16_t Protocol, const PSTR Domain)
{
	if (Protocol == AF_INET6) //IPv6
	{
		if (
		//Some DNS Poisoning addresses from CERNET2
		//About this list, see https://code.google.com/p/goagent/issues/detail?id=17571.
			((in6_addr *)Addr)->u.Word[0] == 0 && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Byte[8U] == 0x90 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == 0 || //::90xx:xxxx:0:0
			((in6_addr *)Addr)->u.Word[0] == htons(0x0010) && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x2222) || //10::2222
			((in6_addr *)Addr)->u.Word[0] == htons(0x0021) && ((in6_addr *)Addr)->u.Word[1U] == htons(0x0002) && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x0002) || //21:2::2
			((in6_addr *)Addr)->u.Word[0] == htons(0x0101) && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x1234) || //101::1234
			((in6_addr *)Addr)->u.Word[0] == htons(0x2001) && 
//			(((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x0212) || //2001::212
			((in6_addr *)Addr)->u.Word[1U] == htons(0x0DA8) && ((in6_addr *)Addr)->u.Word[2U] == htons(0x0112) && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x21AE) || //2001:DA8:112::21AE
			((in6_addr *)Addr)->u.Word[0] == htons(0x2003) && ((in6_addr *)Addr)->u.Word[1U] == htons(0x00FF) && ((in6_addr *)Addr)->u.Word[2U] == htons(0x0001) && ((in6_addr *)Addr)->u.Word[3U] == htons(0x0002) && ((in6_addr *)Addr)->u.Word[4U] == htons(0x0003) && ((in6_addr *)Addr)->u.Word[5U] == htons(0x0004) && ((in6_addr *)Addr)->u.Word[6U] == htons(0x5FFF) /* && ((in6_addr *)Addr)->u.Word[7U] == htons(0x0006) */ || //2003:FF:1:2:3:4:5FFF:xxxx
			((in6_addr *)Addr)->u.Word[0] == htons(0x2123) && ((in6_addr *)Addr)->u.Word[1U] == 0 && ((in6_addr *)Addr)->u.Word[2U] == 0 && ((in6_addr *)Addr)->u.Word[3U] == 0 && ((in6_addr *)Addr)->u.Word[4U] == 0 && ((in6_addr *)Addr)->u.Word[5U] == 0 && ((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x3E12) || //2123::3E12
		//About this list, see https://en.wikipedia.org/wiki/IPv6_address#Presentation and https://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv6_addresses.
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
		//Domain case conversion
			for (size_t Index = 0;Index < strlen(Domain);Index++)
			{
				if (Domain[Index] > ASCII_AT && Domain[Index] < ASCII_BRACKETS_LEAD)
					Domain[Index] += 32U;
			}

		//Main check
			for (auto ResultBlacklistIter:*ResultBlacklistUsing)
			{
				if (ResultBlacklistIter.Addresses.front().ss_family == AF_INET6 && std::regex_match(Domain, ResultBlacklistIter.Pattern))
				{
					for (auto SockAddrIter:ResultBlacklistIter.Addresses)
					{
						if (memcmp(Addr, &((PSOCKADDR_IN6)&SockAddrIter)->sin6_addr, sizeof(in6_addr)) == 0)
							return true;
					}
				}
			}
		}
	}
	else { //IPv4
		if (
		//About this list, see https://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93#.E8.99.9A.E5.81.87IP.E5.9C.B0.E5.9D.80.
			((in_addr *)Addr)->S_un.S_addr == 0xB2422404 || //4.36.66.178
			((in_addr *)Addr)->S_un.S_addr == 0x2DC60708 || //8.7.198.45
			((in_addr *)Addr)->S_un.S_addr == 0x9E363D25 || //37.61.54.158
			((in_addr *)Addr)->S_un.S_addr == 0x44AE522E || //46.82.174.68
			((in_addr *)Addr)->S_un.S_addr == 0xAD03183B || //59.24.3.173
			((in_addr *)Addr)->S_un.S_addr == 0xA1582140 || //64.33.88.161
			((in_addr *)Addr)->S_un.S_addr == 0x2F632140 || //64.33.99.47
			((in_addr *)Addr)->S_un.S_addr == 0xFBA34240 || //64.66.163.251
			((in_addr *)Addr)->S_un.S_addr == 0xFCCA6841 || //65.104.202.252
			((in_addr *)Addr)->S_un.S_addr == 0x71DBA041 || //65.160.219.113
			((in_addr *)Addr)->S_un.S_addr == 0xEDFC2D42 || //66.45.252.237
			((in_addr *)Addr)->S_un.S_addr == 0x63CD0E48 || //72.14.205.99
			((in_addr *)Addr)->S_un.S_addr == 0x68CD0E48 || //72.14.205.104
			((in_addr *)Addr)->S_un.S_addr == 0x0F31104E || //78.16.49.15
			((in_addr *)Addr)->S_un.S_addr == 0x59082E5D || //93.46.8.89
			((in_addr *)Addr)->S_un.S_addr == 0x8B7E7980 || //128.121.126.139
			((in_addr *)Addr)->S_un.S_addr == 0x4B796A9F || //159.106.121.75
			((in_addr *)Addr)->S_un.S_addr == 0x670D84A9 || //169.132.13.103
			((in_addr *)Addr)->S_un.S_addr == 0x06C643C0 || //192.67.198.6
			((in_addr *)Addr)->S_un.S_addr == 0x02016ACA || //202.106.1.2
			((in_addr *)Addr)->S_un.S_addr == 0x5507B5CA || //202.181.7.85
			((in_addr *)Addr)->S_un.S_addr == 0x410762CB || //203.98.7.65
			((in_addr *)Addr)->S_un.S_addr == 0xABE6A1CB || //203.161.230.171
			((in_addr *)Addr)->S_un.S_addr == 0x62580CCF || //207.12.88.98
			((in_addr *)Addr)->S_un.S_addr == 0x2B1F38D0 || //208.56.31.43
			((in_addr *)Addr)->S_un.S_addr == 0x214924D1 || //209.36.73.33
			((in_addr *)Addr)->S_un.S_addr == 0x323691D1 || //209.145.54.50
			((in_addr *)Addr)->S_un.S_addr == 0xAE1EDCD1 || //209.220.30.174
			((in_addr *)Addr)->S_un.S_addr == 0x93425ED3 || //211.94.66.147
			((in_addr *)Addr)->S_un.S_addr == 0x23FBA9D5 || //213.169.251.35
			((in_addr *)Addr)->S_un.S_addr == 0xB6BCD3D8 || //216.221.188.182
		//About this list, see http://forums.internetfreedom.org/index.php?topic=7953.0.
			((in_addr *)Addr)->S_un.S_addr == 0x3C055917 || //23.89.5.60
			((in_addr *)Addr)->S_un.S_addr == 0x387B2531 || //49.2.123.56
			((in_addr *)Addr)->S_un.S_addr == 0x01874C36 || //54.76.135.1
			((in_addr *)Addr)->S_un.S_addr == 0x5C07044D || //77.4.7.92
			((in_addr *)Addr)->S_un.S_addr == 0x06310576 || //118.5.49.6
			((in_addr *)Addr)->S_un.S_addr == 0x600405BC || //188.5.4.96
			((in_addr *)Addr)->S_un.S_addr == 0x0511A3BD || //189.163.17.5
			((in_addr *)Addr)->S_un.S_addr == 0x0C0404C5 || //197.4.4.12
			((in_addr *)Addr)->S_un.S_addr == 0x0DB3EAD8 || //216.234.179.13
		//They are including in reserved address ranges.
//			((in_addr *)Addr)->S_un.S_addr == 0x27BBB9F3 || //243.185.187.39 
//			((in_addr *)Addr)->S_un.S_addr == 0x302E81F9 || //249.129.46.48 
//			((in_addr *)Addr)->S_un.S_addr == 0xA50E9DFD || //253.157.14.165
		//About this list, see https://code.google.com/p/goagent/issues/detail?id=17571.
			((in_addr *)Addr)->S_un.S_addr == 0x01010101 || //1.1.1.1
			((in_addr *)Addr)->S_un.S_addr == 0x0A0A0A0A || //10.10.10.10
			((in_addr *)Addr)->S_un.S_addr == 0x14141414 || //20.20.20.20
		//Other special addresses.
			((in_addr *)Addr)->S_un.S_un_b.s_b1 == 183U && ((in_addr *)Addr)->S_un.S_un_b.s_b2 == 207U && ((in_addr *)Addr)->S_un.S_un_b.s_b3 == 229U || //China Mobile advertisement servers, see https://twitter.com/phuslu/status/500944590828879872
		//About this list, see https://en.wikipedia.org/wiki/IPv4#Special-use_addresses and https://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv4_addresses.
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
		//Domain case conversion
			for (size_t Index = 0;Index < strlen(Domain);Index++)
			{
				if (Domain[Index] > ASCII_AT && Domain[Index] < ASCII_BRACKETS_LEAD)
					Domain[Index] += 32U;
			}

		//Main check
			for (auto ResultBlacklistIter:*ResultBlacklistUsing)
			{
				if (ResultBlacklistIter.Addresses.front().ss_family == AF_INET && std::regex_match(Domain, ResultBlacklistIter.Pattern))
				{
					for (auto SockAddrIter:ResultBlacklistIter.Addresses)
					{
						if (((in_addr *)Addr)->S_un.S_addr == ((PSOCKADDR_IN)&SockAddrIter)->sin_addr.S_un.S_addr)
							return true;
					}
				}
			}
		}
	}

	return false;
}

//Custom Mode addresses filter
bool __fastcall CustomModeFilter(const void *pAddr, const uint16_t Protocol)
{
	size_t Index = 0;

//IPv6
	if (Protocol == AF_INET6)
	{
		auto Addr = (in6_addr *)pAddr;
	//Permit
		if (Parameter.IPFilterOptions.Type)
		{
			std::unique_lock<std::mutex> AddressRangeMutex(AddressRangeLock);
			for (auto AddressRangeIter:*AddressRangeUsing)
			{
			//Check Protocol and Level.
				if (AddressRangeIter.Begin.ss_family != AF_INET6 || Parameter.IPFilterOptions.IPFilterLevel != 0 && AddressRangeIter.Level < Parameter.IPFilterOptions.IPFilterLevel)
					continue;

			//Check address.
				for (Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
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
			std::unique_lock<std::mutex> AddressRangeMutex(AddressRangeLock);
			for (auto AddressRangeIter:*AddressRangeUsing)
			{
			//Check Protocol and Level.
				if (AddressRangeIter.Begin.ss_family != AF_INET6 || Parameter.IPFilterOptions.IPFilterLevel != 0 && AddressRangeIter.Level < Parameter.IPFilterOptions.IPFilterLevel)
					continue;

			//Check address.
				for (Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
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
//IPv4
	else {
		auto Addr = (in_addr *)pAddr;
	//Permit
		if (Parameter.IPFilterOptions.Type)
		{
			std::unique_lock<std::mutex> AddressRangeMutex(AddressRangeLock);
			for (auto AddressRangeIter:*AddressRangeUsing)
			{
			//Check Protocol and Level.
				if (AddressRangeIter.Begin.ss_family != AF_INET || Parameter.IPFilterOptions.IPFilterLevel != 0 && AddressRangeIter.Level < Parameter.IPFilterOptions.IPFilterLevel)
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
			std::unique_lock<std::mutex> AddressRangeMutex(AddressRangeLock);
			for (auto AddressRangeIter:*AddressRangeUsing)
			{
			//Check Protocol and Level.
				if (AddressRangeIter.Begin.ss_family != AF_INET || Parameter.IPFilterOptions.IPFilterLevel != 0 && AddressRangeIter.Level < Parameter.IPFilterOptions.IPFilterLevel)
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
	uint32_t Table[256] = {0}, Gx = 0x04C11DB7, Temp = 0, CRCTable = 0, Value = 0, UI = 0;
	char ReflectNum[] = {8, 32};
	int Index[3U] = {0};

	for (Index[0] = 0;Index[0] <= U8_MAXNUM;Index[0]++)
	{
		Value = 0;
		UI = Index[0];
		for (Index[1U] = 1U;Index[1U] < 9;Index[1U]++)
		{
			if (UI & 1)
				Value |= 1 << (ReflectNum[0]-Index[1U]);
			UI >>= 1;
		}
		Temp = Value;
		Table[Index[0]] = Temp << 24;

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
		CRC = Table[(CRC ^ (*(Buffer + Index[0]))) & U8_MAXNUM]^(CRC >> 8);

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
	auto psd = (ipv6_psd_hdr *)Validation.get();
	psd->Dst = Destination;
	psd->Src = Source;
	psd->Length = htonl((uint32_t)Length);
	psd->Next_Header = IPPROTO_ICMPV6;
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
		auto psd = (ipv6_psd_hdr *)Validation.get();
		psd->Dst = ((ipv6_hdr *)Buffer)->Dst;
		psd->Src = ((ipv6_hdr *)Buffer)->Src;
		psd->Length = htonl((uint32_t)Length);
		psd->Next_Header = (uint8_t)TransportLayer;

		memcpy(Validation.get() + sizeof(ipv6_psd_hdr), Buffer + sizeof(ipv6_hdr), Length);
		Result = GetChecksum((PUINT16)Validation.get(), sizeof(ipv6_psd_hdr) + Length);
	}
	else { //IPv4
		auto pipv4_hdr = (ipv4_hdr *)Buffer;
		std::shared_ptr<char> Validation(new char[sizeof(ipv4_psd_hdr) + Length /* - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES */ ]());
		auto psd = (ipv4_psd_hdr *)Validation.get();
		psd->Dst = ((ipv4_hdr *)Buffer)->Dst;
		psd->Src = ((ipv4_hdr *)Buffer)->Src;
		psd->Length = htons((uint16_t) /* ( */ Length /* - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES) */ );
		psd->Protocol = (uint8_t)TransportLayer;

		memcpy(Validation.get() + sizeof(ipv4_psd_hdr), Buffer + pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES, Length /* - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES */ );
		Result = GetChecksum((PUINT16)Validation.get(), sizeof(ipv4_psd_hdr) + Length /* - pipv4_hdr->IHL * IPv4_IHL_BYTES_TIMES */);
	}

	return Result;
}

//Add length parameters to TCP DNS transmission
size_t __fastcall AddLengthToTCPDNSHeader(PSTR Buffer, const size_t RecvLen, const size_t MaxLen)
{
	if (Buffer != nullptr && MaxLen >= RecvLen + sizeof(uint16_t))
	{
		memmove(Buffer + sizeof(uint16_t), Buffer, RecvLen);
		auto ptcp_dns_hdr = (tcp_dns_hdr *)Buffer;
		ptcp_dns_hdr->Length = htons((uint16_t)RecvLen);
		return RecvLen + sizeof(uint16_t);
	}
	
	return EXIT_FAILURE;
}

//Convert data from char(s) to DNS query
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

//Convert data from DNS query to char(s)
size_t __fastcall DNSQueryToChar(const PSTR TName, PSTR FName)
{
	size_t uIndex = 0;
	int Index[] = {0, 0};
	for (uIndex = 0;uIndex < DOMAIN_MAXSIZE;uIndex++)
	{
		if (uIndex == 0)
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

	return uIndex;
}

//Flush DNS Cache undocumented API of Microsoft Windows.
BOOL WINAPI DnsFlushResolverCache(void)
{
	BOOL (WINAPI *DoDnsFlushResolverCache)(void);
	HMODULE HM_DNSAPI = LoadLibraryW(L"dnsapi.dll");
	if (HM_DNSAPI != nullptr)
	{
		*(FARPROC *)&DoDnsFlushResolverCache = GetProcAddress(HM_DNSAPI, "DnsFlushResolverCache");
		if (DoDnsFlushResolverCache)
			return DoDnsFlushResolverCache();
	}

	return FALSE;
}

//Make ramdom domains
void __fastcall MakeRamdomDomain(PSTR Domain)
{
//Initialization
	std::random_device RamdomDevice;
	std::mt19937 RamdomEngine(RamdomDevice()); //Mersenne Twister Engine
	std::uniform_int_distribution<int> Distribution(0, 63); //Domain length is between 3 and 63(Labels must be 63 characters/bytes or less, Section 2.3.1 in RFC 1035).
	auto RamdomGenerator = std::bind(Distribution, RamdomEngine);

//Make ramdom domain length.
	size_t RamdomLength = RamdomGenerator(), Index = 0;
	if (RamdomLength < 4U)
		RamdomLength += 4U;

//Make ramdom domain.
	if (RamdomLength % 2U == 0)
	{
		for (Index = 0;Index < RamdomLength - 3U;Index++)
		{
			Domain[Index] = Parameter.DomainTable[RamdomGenerator()];
		//Convert to lowercase letters.
			if (Domain[Index] > ASCII_AT && Domain[Index] < ASCII_BRACKETS_LEAD)
				Domain[Index] += 32;
		}

	//Make random domain like a normal Top-level domain/TLD.
		Domain[RamdomLength - 3U] = ASCII_PERIOD;
		Index = RamdomGenerator();
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Domain[RamdomLength - 2U] = Parameter.DomainTable[Index];
		Index = RamdomGenerator();
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Domain[RamdomLength - 1U] = Parameter.DomainTable[Index];
	}
	else {
		for (Index = 0;Index < RamdomLength - 4U;Index++)
		{
			Domain[Index] = Parameter.DomainTable[RamdomGenerator()];
		//Convert to lowercase letters.
			if (Domain[Index] > ASCII_AT && Domain[Index] < ASCII_BRACKETS_LEAD)
				Domain[Index] += 32;
		}

	//Make random domain like a normal Top-level domain/TLD.
		Domain[RamdomLength - 4U] = ASCII_PERIOD;
		Index = RamdomGenerator();
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Domain[RamdomLength - 3U] = Parameter.DomainTable[Index];
		Index = RamdomGenerator();
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Domain[RamdomLength - 2U] = Parameter.DomainTable[Index];
		Index = RamdomGenerator();
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Domain[RamdomLength - 1U] = Parameter.DomainTable[Index];
	}

	return;
}

//Check all DNS last result.
bool __fastcall CheckDNSLastResult(const PSTR Buffer, const size_t Length)
{
//DNS Responses which only have 1 Answer RR and no any Authority RRs or Additional RRs need to check.
	auto pdns_hdr = (dns_hdr *)Buffer;
	if (pdns_hdr->Questions == htons(U16_NUM_1) && /* pdns_hdr->Answer == htons(U16_NUM_1) && */ pdns_hdr->Authority == 0)
	{
		auto pdns_qry = (dns_qry *)(Buffer + sizeof(dns_hdr) + strlen(Buffer + sizeof(dns_hdr)) + 1U);
		if (pdns_qry->Classes == htons(DNS_CLASS_IN)) //Class IN
		{
		//AAAA Records
			if (pdns_qry->Type == htons(DNS_AAAA_RECORDS))
			{
				dns_aaaa_record *DNS_AAAA = nullptr;
				if (pdns_hdr->Additional == 0) //No any Additional records.
					DNS_AAAA = (dns_aaaa_record *)(Buffer + (Length - sizeof(dns_aaaa_record)));
				else //EDNS0 Label
					DNS_AAAA = (dns_aaaa_record *)(Buffer + (Length - sizeof(dns_edns0_label) - sizeof(dns_aaaa_record)));

			//Record(s) Type in responses check
				if (Parameter.DNSDataCheck && DNS_AAAA->Type != pdns_qry->Type)
					return false;

			//Fake responses check
				if (Parameter.Blacklist)
				{
					std::shared_ptr<char> Domain(new char[DOMAIN_MAXSIZE]());
					DNSQueryToChar(Buffer + sizeof(dns_hdr), Domain.get());

					if (DNS_AAAA->Type == htons(DNS_AAAA_RECORDS) && DNS_AAAA->Classes == htons(DNS_CLASS_IN) && 
						DNS_AAAA->TTL != 0 && DNS_AAAA->Length == htons(sizeof(in6_addr)) && 
					//Extended fake responses check
						CheckSpecialAddress(&DNS_AAAA->Addr, AF_INET6, Domain.get()))
							return false;
				}
			}
		//A Records or other records.
			else {
				dns_a_record *DNS_A = nullptr;
				if (pdns_hdr->Additional == 0) //No any Additional records.
					DNS_A = (dns_a_record *)(Buffer + (Length - sizeof(dns_a_record)));
				else //EDNS0 Label
					DNS_A = (dns_a_record *)(Buffer + (Length - sizeof(dns_edns0_label) - sizeof(dns_a_record)));

			//Record(s) Type in responses check
				if (Parameter.DNSDataCheck && pdns_qry->Type == htons(DNS_A_RECORDS) && DNS_A->Type != pdns_qry->Type) //A Records
					return false;

			//Fake responses check
				if (Parameter.Blacklist)
				{
					std::shared_ptr<char> Domain(new char[DOMAIN_MAXSIZE]());
					DNSQueryToChar(Buffer + sizeof(dns_hdr), Domain.get());

					if (DNS_A->Type == htons(DNS_A_RECORDS) && DNS_A->Classes == htons(DNS_CLASS_IN) && 
						DNS_A->TTL != 0 && DNS_A->Length == htons(sizeof(in_addr)) && 
					//Extended fake responses check
						CheckSpecialAddress(&DNS_A->Addr, AF_INET, Domain.get()))
							return false;
				}
			}
		}
	}

	return true;
}
