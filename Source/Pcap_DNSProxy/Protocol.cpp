// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
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


#include "Protocol.h"

//Convert address strings to binary.
bool __fastcall AddressStringToBinary(const char *AddrString, void *OriginalAddr, const uint16_t Protocol, SSIZE_T &ErrCode)
{
	std::string sAddrString(AddrString);

//inet_ntop() and inet_pton() was only support in Windows Vista and newer system. [Roy Tam]
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	int SockLength = 0;
#else
	SSIZE_T Result = 0;
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
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		SockLength = sizeof(sockaddr_in6);
		if (WSAStringToAddressA((LPSTR)sAddrString.c_str(), AF_INET6, nullptr, (PSOCKADDR)SockAddr.get(), &SockLength) == SOCKET_ERROR)
	#else
		Result = inet_pton(AF_INET6, sAddrString.c_str(), OriginalAddr);
		if (Result == SOCKET_ERROR || Result == 0)
	#endif
		{
			ErrCode = WSAGetLastError();
			return false;
		}
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		memcpy_s(OriginalAddr, sizeof(in6_addr), &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, sizeof(in6_addr));
	#endif
	}
	else { //IPv4
		size_t CommaNum = 0;

	//Check IPv4 addresses
		for (auto StringIter:sAddrString)
		{
			if (StringIter != ASCII_PERIOD && StringIter < ASCII_ZERO || StringIter > ASCII_NINE)
				return false;
			else if (StringIter == ASCII_PERIOD)
				++CommaNum;
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
		if (sAddrString.at(sAddrString.length() - 1U) == ASCII_PERIOD)
			sAddrString.append("0");

	//Convert to binary.
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		SockLength = sizeof(sockaddr_in);
		if (WSAStringToAddressA((LPSTR)sAddrString.c_str(), AF_INET, nullptr, (PSOCKADDR)SockAddr.get(), &SockLength) == SOCKET_ERROR)
	#else
		Result = inet_pton(AF_INET, sAddrString.c_str(), OriginalAddr);
		if (Result == SOCKET_ERROR || Result == 0)
	#endif
		{
			ErrCode = WSAGetLastError();
			return false;
		}
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		memcpy_s(OriginalAddr, sizeof(in_addr), &((PSOCKADDR_IN)SockAddr.get())->sin_addr, sizeof(in_addr));
	#endif
	}

	return true;
}

//Compare two addresses
size_t __fastcall AddressesComparing(const void *OriginalAddrBegin, const void *OriginalAddrEnd, const uint16_t Protocol)
{
	if (Protocol == AF_INET6) //IPv6
	{
		auto AddrBegin = (in6_addr *)OriginalAddrBegin, AddrEnd = (in6_addr *)OriginalAddrEnd;
		for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);++Index)
		{
			if (ntohs(AddrBegin->s6_words[Index]) > ntohs(AddrEnd->s6_words[Index]))
			{
				return ADDRESS_COMPARE_GREATER;
			}
			else if (AddrBegin->s6_words[Index] == AddrEnd->s6_words[Index])
			{
				if (Index == sizeof(in6_addr) / sizeof(uint16_t) - 1U)
					return ADDRESS_COMPARE_EQUAL;
				else
					continue;
			}
			else {
				return ADDRESS_COMPARE_LESS;
			}
		}
	}
	else { //IPv4
		auto AddrBegin = (in_addr *)OriginalAddrBegin, AddrEnd = (in_addr *)OriginalAddrEnd;
		if (AddrBegin->s_net > AddrEnd->s_net)
		{
			return ADDRESS_COMPARE_GREATER;
		}
		else if (AddrBegin->s_net == AddrEnd->s_net)
		{
			if (AddrBegin->s_host > AddrEnd->s_host)
			{
				return ADDRESS_COMPARE_GREATER;
			}
			else if (AddrBegin->s_host == AddrEnd->s_host)
			{
				if (AddrBegin->s_lh > AddrEnd->s_lh)
				{
					return ADDRESS_COMPARE_GREATER;
				}
				else if (AddrBegin->s_lh == AddrEnd->s_lh)
				{
					if (AddrBegin->s_impno > AddrEnd->s_impno)
						return ADDRESS_COMPARE_GREATER;
					else if (AddrBegin->s_impno == AddrEnd->s_impno)
						return ADDRESS_COMPARE_EQUAL;
					else
						return ADDRESS_COMPARE_LESS;
				}
				else {
					return ADDRESS_COMPARE_LESS;
				}
			}
			else {
				return ADDRESS_COMPARE_LESS;
			}
		}
		else {
			return ADDRESS_COMPARE_LESS;
		}
	}

	return EXIT_SUCCESS;
}

//Check IPv4/IPv6 special addresses
bool __fastcall CheckSpecialAddress(void *Addr, const uint16_t Protocol, const bool IsPrivateUse, char *Domain)
{
	if (Protocol == AF_INET6) //IPv6
	{
		if (
		//DNS Poisoning addresses from CERNET2, see https://code.google.com/p/goagent/issues/detail?id=17571.
			((in6_addr *)Addr)->s6_words[0] == 0 && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_bytes[8U] == 0x90 && ((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == 0 || //::90xx:xxxx:0:0
			((in6_addr *)Addr)->s6_words[0] == htons(0x0010) && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == 0 && ((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x2222) || //10::2222
			((in6_addr *)Addr)->s6_words[0] == htons(0x0021) && ((in6_addr *)Addr)->s6_words[1U] == htons(0x0002) && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == 0 && ((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x0002) || //21:2::2
			((in6_addr *)Addr)->s6_words[0] == htons(0x0101) && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == 0 && ((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x1234) || //101::1234
			((in6_addr *)Addr)->s6_words[0] == htons(0x2001) && 
			(IsPrivateUse && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == 0 && ((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x0212) || //2001::212
			((in6_addr *)Addr)->s6_words[1U] == htons(0x0DA8) && ((in6_addr *)Addr)->s6_words[2U] == htons(0x0112) && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == 0 && ((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x21AE)) || //2001:DA8:112::21AE
			((in6_addr *)Addr)->s6_words[0] == htons(0x2003) && ((in6_addr *)Addr)->s6_words[1U] == htons(0x00FF) && ((in6_addr *)Addr)->s6_words[2U] == htons(0x0001) && ((in6_addr *)Addr)->s6_words[3U] == htons(0x0002) && ((in6_addr *)Addr)->s6_words[4U] == htons(0x0003) && ((in6_addr *)Addr)->s6_words[5U] == htons(0x0004) && ((in6_addr *)Addr)->s6_words[6U] == htons(0x5FFF) /* && ((in6_addr *)Addr)->s6_words[7U] == htons(0x0006) */ || //2003:FF:1:2:3:4:5FFF:xxxx
			((in6_addr *)Addr)->s6_words[0] == htons(0x2123) && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == 0 && ((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x3E12) || //2123::3E12
		//Special-use or reserved addresses, see https://en.wikipedia.org/wiki/IPv6_address#Presentation and https://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv6_addresses.
			(((in6_addr *)Addr)->s6_words[0] == 0 && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && 
			((((in6_addr *)Addr)->s6_words[5U] == 0 && 
			((((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == 0 || //Unspecified Addresses(::, Section 2.5.2 in RFC 4291)
			((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x0001)) || //Loopback Addresses(::1, Section 2.5.3 in RFC 4291)
			((in6_addr *)Addr)->s6_words[5U] == 0)) || //IPv4-Compatible Contrast Addresses(::/96, Section 2.5.5.1 in RFC 4291)
			((in6_addr *)Addr)->s6_words[5U] == htons(0xFFFF))) || //IPv4-mapped Addresses(::FFFF:0:0/96, Section 2.5.5 in RFC 4291)
			IsPrivateUse && ((in6_addr *)Addr)->s6_words[0] == htons(0x0064) && ((in6_addr *)Addr)->s6_words[1U] == htons(0xFF9B) && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == 0 || //Well Known Prefix Addresses(64:FF9B::/96, Section 2.1 in RFC 4773)
			((in6_addr *)Addr)->s6_words[0] == htons(0x0100) && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[1U] == 0 || //Discard Prefix Addresses(100::/64, Section 4 RFC 6666)
			((in6_addr *)Addr)->s6_words[0] == htons(0x2001) && 
			(((in6_addr *)Addr)->s6_words[1U] == 0 || //Teredo relay/tunnel Addresses(2001::/32, RFC 4380)
			((in6_addr *)Addr)->s6_bytes[2U] == 0 && ((in6_addr *)Addr)->s6_bytes[3U] <= 0x07 || //Sub-TLA IDs assigned to IANA Addresses(2001:0000::/29, Section 2 in RFC 4773)
			((in6_addr *)Addr)->s6_bytes[3U] >= 0x10 && ((in6_addr *)Addr)->s6_bytes[3U] <= 0x1F || //Overlay Routable Cryptographic Hash IDentifiers/ORCHID Addresses(2001:10::/28 in RFC 4843)
			((in6_addr *)Addr)->s6_bytes[2U] >= 0x01 && ((in6_addr *)Addr)->s6_bytes[3U] >= 0xF8 || //Sub-TLA IDs assigned to IANA Addresses(2001:01F8::/29, Section 2 in RFC 4773)
			((in6_addr *)Addr)->s6_words[1U] == htons(0x0DB8)) || //Contrast Address prefix reserved for documentation Addresses(2001:DB8::/32, RFC 3849)
			IsPrivateUse && ((in6_addr *)Addr)->s6_words[0] == htons(0x2002) || //6to4 relay/tunnel Addresses(2002::/16, Section 2 in RFC 3056)
			((in6_addr *)Addr)->s6_words[0] == htons(0x3FFE) && ((in6_addr *)Addr)->s6_words[1U] == 0 || //6bone Addresses(3FFE::/16, RFC 3701)
			((in6_addr *)Addr)->s6_bytes[0] == 0x5F || //6bone(5F00::/8, RFC 3701)
			IsPrivateUse && ((in6_addr *)Addr)->s6_bytes[0] >= 0xFC && ((in6_addr *)Addr)->s6_bytes[0] <= 0xFD || //Unique Local Unicast Addresses/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
			((in6_addr *)Addr)->s6_bytes[0] == 0xFE && 
			IsPrivateUse && (((in6_addr *)Addr)->s6_bytes[1U] >= 0x80 && (((in6_addr *)Addr)->s6_bytes[1U] <= 0xBF || //Link-Local Unicast Contrast Addresses/LUC(FE80::/10, Section 2.5.6 in RFC 4291)
			IsPrivateUse && ((in6_addr *)Addr)->s6_bytes[1U] <= 0xBF && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == htons(0x5EFE)) || //ISATAP Interface Identifiers Addresses(Prefix:0:5EFE:0:0:0:0/64, which also in Link-Local Unicast Contrast Addresses/LUC, Section 6.1 in RFC 5214)
			((in6_addr *)Addr)->s6_bytes[1U] >= 0xC0) || //Site-Local scoped Addresses(FEC0::/10, RFC 3879)
			IsPrivateUse && ((in6_addr *)Addr)->s6_bytes[0] == 0xFF) //Multicast Addresses(FF00::/8, Section 2.7 in RFC 4291)
				return true;

	//Result Blacklist check
		if (Domain != nullptr)
		{
		//Domain Case Conversion
			CaseConvert(false, Domain, strnlen_s(Domain, DOMAIN_MAXSIZE));

		//Main check
			std::unique_lock<std::mutex> ResultBlacklistMutex(ResultBlacklistLock);
			for (auto IPFilterFileSetIter:*IPFilterFileSetUsing)
			{
				for (auto ResultBlacklistTableIter:IPFilterFileSetIter.ResultBlacklist)
				{
					if (ResultBlacklistTableIter.Addresses.front().Begin.ss_family == AF_INET6 && 
						(ResultBlacklistTableIter.PatternString.empty() || std::regex_match(Domain, ResultBlacklistTableIter.Pattern)))
					{
						for (auto AddressRangeTableIter:ResultBlacklistTableIter.Addresses)
						{
							if (AddressRangeTableIter.End.ss_family == AF_INET6 && 
								AddressesComparing(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr, AF_INET6) >= ADDRESS_COMPARE_EQUAL && 
								AddressesComparing(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.End)->sin6_addr, AF_INET6) <= ADDRESS_COMPARE_EQUAL || 
								memcmp(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr, sizeof(in6_addr)) == 0)
									return true;
						}
					}
				}
			}
		}

	//Address Hosts check
		std::unique_lock<std::mutex> AddressHostsListMutex(AddressHostsListLock);
		for (auto HostsFileSetIter:*HostsFileSetUsing)
		{
			for (auto AddressHostsTableIter:HostsFileSetIter.AddressHostsList)
			{
				if (AddressHostsTableIter.Address_Target.front().ss_family == AF_INET6)
				{
					for (auto AddressRangeTableIter:AddressHostsTableIter.Address_Source)
					{
						if (AddressRangeTableIter.Begin.ss_family == AF_INET6 && AddressRangeTableIter.End.ss_family == AF_INET6 && 
							AddressesComparing(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr, AF_INET6) >= ADDRESS_COMPARE_EQUAL && 
							AddressesComparing(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.End)->sin6_addr, AF_INET6) <= ADDRESS_COMPARE_EQUAL || 
							memcmp(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr, sizeof(in6_addr)) == 0)
						{
							if (AddressHostsTableIter.Address_Target.size() > 1U)
							{
							//Get a ramdom one.
								std::uniform_int_distribution<int> RamdomDistribution(0, (int)AddressHostsTableIter.Address_Target.size() - 1U);
								*(in6_addr *)Addr = ((PSOCKADDR_IN6)&AddressHostsTableIter.Address_Target.at(RamdomDistribution(*Parameter.RamdomEngine)))->sin6_addr;
							}
							else {
								*(in6_addr *)Addr = ((PSOCKADDR_IN6)&AddressHostsTableIter.Address_Target.front())->sin6_addr;
							}

							goto StopLoop;
						}
					}
				}
			}
		}
	}
	else { //IPv4
		if (
		//Traditional DNS Poisoning addresses, see https://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93#.E8.99.9A.E5.81.87IP.E5.9C.B0.E5.9D.80.
			((in_addr *)Addr)->s_addr == htonl(0x042442B2) || //4.36.66.178
			((in_addr *)Addr)->s_addr == htonl(0x0807C62D) || //8.7.198.45
			((in_addr *)Addr)->s_addr == htonl(0x253D369E) || //37.61.54.158
			((in_addr *)Addr)->s_addr == htonl(0x2E52AE44) || //46.82.174.68
			((in_addr *)Addr)->s_addr == htonl(0x3B1803AD) || //59.24.3.173
			((in_addr *)Addr)->s_addr == htonl(0x402158A1) || //64.33.88.161
			((in_addr *)Addr)->s_addr == htonl(0x4021632F) || //64.33.99.47
			((in_addr *)Addr)->s_addr == htonl(0x4042A3FB) || //64.66.163.251
			((in_addr *)Addr)->s_addr == htonl(0x4168CAFC) || //65.104.202.252
			((in_addr *)Addr)->s_addr == htonl(0x41A0DB71) || //65.160.219.113
			((in_addr *)Addr)->s_addr == htonl(0x422DFCED) || //66.45.252.237
			((in_addr *)Addr)->s_addr == htonl(0x480ECD63) || //72.14.205.99
			((in_addr *)Addr)->s_addr == htonl(0x480ECD68) || //72.14.205.104
			((in_addr *)Addr)->s_addr == htonl(0x4E10310F) || //78.16.49.15
			((in_addr *)Addr)->s_addr == htonl(0x5D2E0859) || //93.46.8.89
			((in_addr *)Addr)->s_addr == htonl(0x80797E8B) || //128.121.126.139
			((in_addr *)Addr)->s_addr == htonl(0x9F6A794B) || //159.106.121.75
			((in_addr *)Addr)->s_addr == htonl(0xA9840D67) || //169.132.13.103
			((in_addr *)Addr)->s_addr == htonl(0xC043C606) || //192.67.198.6
			((in_addr *)Addr)->s_addr == htonl(0xCA6A0102) || //202.106.1.2
			((in_addr *)Addr)->s_addr == htonl(0xCAB50755) || //202.181.7.85
			((in_addr *)Addr)->s_addr == htonl(0xCB620741) || //203.98.7.65
			((in_addr *)Addr)->s_addr == htonl(0xCBA1E6AB) || //203.161.230.171
			((in_addr *)Addr)->s_addr == htonl(0xCF0C5862) || //207.12.88.98
			((in_addr *)Addr)->s_addr == htonl(0xD0381F2B) || //208.56.31.43
			((in_addr *)Addr)->s_addr == htonl(0xD1244921) || //209.36.73.33
			((in_addr *)Addr)->s_addr == htonl(0xD1913632) || //209.145.54.50
			((in_addr *)Addr)->s_addr == htonl(0xD1DC1EAE) || //209.220.30.174
			((in_addr *)Addr)->s_addr == htonl(0xD35E4293) || //211.94.66.147
			((in_addr *)Addr)->s_addr == htonl(0xD5A9FB23) || //213.169.251.35
			((in_addr *)Addr)->s_addr == htonl(0xD8DDBCD6) || //216.221.188.182
		//New DNS Poisoning addresses which had been added in May 2011, see http://forums.internetfreedom.org/index.php?topic=7953.0.
			((in_addr *)Addr)->s_addr == htonl(0x1759053C) || //23.89.5.60
			((in_addr *)Addr)->s_addr == htonl(0x31027B38) || //49.2.123.56
			((in_addr *)Addr)->s_addr == htonl(0x364C8701) || //54.76.135.1
			((in_addr *)Addr)->s_addr == htonl(0x4D04075C) || //77.4.7.92
			((in_addr *)Addr)->s_addr == htonl(0x76050460) || //118.5.4.96
			((in_addr *)Addr)->s_addr == htonl(0xBC050460) || //188.5.4.96
			((in_addr *)Addr)->s_addr == htonl(0xBDA31105) || //189.163.17.5
			((in_addr *)Addr)->s_addr == htonl(0xC504040C) || //197.4.4.12
			((in_addr *)Addr)->s_addr == htonl(0xD8EAB30D) || //216.234.179.13
//			((in_addr *)Addr)->s_addr == htonl(0xF3B9BB27) || //243.185.187.39, including in reserved address ranges
//			((in_addr *)Addr)->s_addr == htonl(0xF9812E30) || //249.129.46.48, including in reserved address ranges
//			((in_addr *)Addr)->s_addr == htonl(0xFD9D0EA5) || //253.157.14.165, including in reserved address ranges
		//China Network Anomaly in 2014-01-21, see https ://zh.wikipedia.org/wiki/2014%E5%B9%B4%E4%B8%AD%E5%9B%BD%E7%BD%91%E7%BB%9C%E5%BC%82%E5%B8%B8%E4%BA%8B%E4%BB%B6
			((in_addr *)Addr)->s_addr == htonl(0x413102B2) || //65.49.2.178
		//New addresses in IPv6 which has been added in September 2014, see https://code.google.com/p/goagent/issues/detail?id=17571.
			((in_addr *)Addr)->s_addr == htonl(0x01010101) || //1.1.1.1
			((in_addr *)Addr)->s_addr == htonl(0x0A0A0A0A) || //10.10.10.10
			((in_addr *)Addr)->s_addr == htonl(0x14141414) || //20.20.20.20
//			((in_addr *)Addr)->s_addr == htonl(0xFFFFFFFF) || //255.255.255.255, including in reserved address ranges
		//New DNS Poisoning addresses which had been added in December 2014, see https://www.v2ex.com/t/156926.
//			((in_addr *)Addr)->s_addr == 0 || //0.0.0.0, including in reserved address ranges
			((in_addr *)Addr)->s_addr == htonl(0x02010102) || //2.1.1.2
			((in_addr *)Addr)->s_addr == htonl(0x04C15000) || //4.193.80.0
			((in_addr *)Addr)->s_addr == htonl(0x08695400) || //8.105.84.0
			((in_addr *)Addr)->s_addr == htonl(0x0C578500) || //12.87.133.0
			((in_addr *)Addr)->s_addr == htonl(0x103F9B00) || //16.63.155.0
			((in_addr *)Addr)->s_addr == htonl(0x148B3800) || //20.139.56.0
			((in_addr *)Addr)->s_addr == htonl(0x1833B800) || //24.51.184.0
			((in_addr *)Addr)->s_addr == htonl(0x1C797E8B) || //28.121.126.139
			((in_addr *)Addr)->s_addr == htonl(0x1C0DD800) || //28.13.216.0
			((in_addr *)Addr)->s_addr == htonl(0x2E147EFC) || //46.20.126.252
			((in_addr *)Addr)->s_addr == htonl(0x2E2618D1) || //46.38.24.209
			((in_addr *)Addr)->s_addr == htonl(0x3D361C06) || //61.54.28.6
			((in_addr *)Addr)->s_addr == htonl(0x42CE0BC2) || //66.206.11.194
			((in_addr *)Addr)->s_addr == htonl(0x4A75398A) || //74.117.57.138
			((in_addr *)Addr)->s_addr == htonl(0x591F376A) || //89.31.55.106
			((in_addr *)Addr)->s_addr == htonl(0x710BC2BE) || //113.11.194.190
			((in_addr *)Addr)->s_addr == htonl(0x76053106) || //118.5.49.6
			((in_addr *)Addr)->s_addr == htonl(0x7ADA65BE) || //122.218.101.190
			((in_addr *)Addr)->s_addr == htonl(0x7B3231AB) || //123.50.49.171
			((in_addr *)Addr)->s_addr == htonl(0x7B7EF9EE) || //123.126.249.238
			((in_addr *)Addr)->s_addr == htonl(0x7DE69430) || //125.230.148.48
//			((in_addr *)Addr)->s_addr == htonl(0x7F000002) || //127.0.0.2, including in reserved address ranges
			((in_addr *)Addr)->s_addr == htonl(0xADC9D806) || //173.201.216.6
			((in_addr *)Addr)->s_addr == htonl(0xCBC73951) || //203.199.57.81
			((in_addr *)Addr)->s_addr == htonl(0xD06D8A37) || //208.109.138.55
			((in_addr *)Addr)->s_addr == htonl(0xD3058512) || //211.5.133.18
			((in_addr *)Addr)->s_addr == htonl(0xD308451B) || //211.8.69.27
			((in_addr *)Addr)->s_addr == htonl(0xD5BA2105) || //213.186.33.5
			((in_addr *)Addr)->s_addr == htonl(0xD88BD590) || //216.139.213.144
			((in_addr *)Addr)->s_addr == htonl(0xDD08451B) || //221.8.69.27
//			((in_addr *)Addr)->s_addr == htonl(0xF3B9BB03) || //243.185.187.3, including in reserved address ranges
//			((in_addr *)Addr)->s_addr == htonl(0xF3B9BB1E) || //243.185.187.30, including in reserved address ranges
		//Special-use or reserved addresses, see https://en.wikipedia.org/wiki/IPv4#Special-use_addresses and https://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv4_addresses.
			((in_addr *)Addr)->s_net == 0 || //Current network whick only valid as source Addresses(0.0.0.0/8, Section 3.2.1.3 in RFC 1122)
			IsPrivateUse && ((in_addr *)Addr)->s_net == 0x0A || //Private class A Addresses(10.0.0.0/8, Section 3 in RFC 1918)
			((in_addr *)Addr)->s_net == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
			IsPrivateUse && ((in_addr *)Addr)->s_net == 0x64 && ((in_addr *)Addr)->s_host > 0x40 && ((in_addr *)Addr)->s_host < 0x7F || //Carrier-grade NAT Addresses(100.64.0.0/10, Section 7 in RFC 6598)
			((in_addr *)Addr)->s_net == 0xA9 && ((in_addr *)Addr)->s_host >= 0xFE || //Link-local Addresses(169.254.0.0/16, Section 1.5 in RFC 3927)
			IsPrivateUse && ((in_addr *)Addr)->s_net == 0xAC && ((in_addr *)Addr)->s_host >= 0x10 && ((in_addr *)Addr)->s_host <= 0x1F || //Private class B Addresses(172.16.0.0/16, Section 3 in RFC 1918)
			((in_addr *)Addr)->s_net == 0xC0 && ((in_addr *)Addr)->s_host == 0 && ((in_addr *)Addr)->s_lh == 0 && ((in_addr *)Addr)->s_impno >= 0 && ((in_addr *)Addr)->s_impno < 0x08 || //DS-Lite transition mechanism Addresses(192.0.0.0/29, Section 3 in RFC 6333)
			((in_addr *)Addr)->s_net == 0xC0 && (((in_addr *)Addr)->s_host == 0 && (((in_addr *)Addr)->s_lh == 0 || //Reserved for IETF protocol assignments Addresses(192.0.0.0/24, Section 3 in RFC 5735)
			((in_addr *)Addr)->s_lh == 0x02)) || //TEST-NET-1 Addresses(192.0.2.0/24, Section 3 in RFC 5735)
			IsPrivateUse && ((in_addr *)Addr)->s_host == 0x58 && ((in_addr *)Addr)->s_lh == 0x63 || //6to4 relay/tunnel Addresses(192.88.99.0/24, Section 2.3 in RFC 3068)
			IsPrivateUse && ((in_addr *)Addr)->s_net == 0xC0 && ((in_addr *)Addr)->s_host == 0xA8 || //Private class C Addresses(192.168.0.0/24, Section 3 in RFC 1918)
			((in_addr *)Addr)->s_net == 0xC6 && (((in_addr *)Addr)->s_host == 0x12 || //Benchmarking Methodology for Network Interconnect Devices Addresses(198.18.0.0/15, Section 11.4.1 in RFC 2544)
			((in_addr *)Addr)->s_host == 0x33 && ((in_addr *)Addr)->s_lh == 0x64) || //TEST-NET-2 Addresses(198.51.100.0/24, Section 3 in RFC 5737)
			((in_addr *)Addr)->s_net == 0xCB && ((in_addr *)Addr)->s_host == 0 && ((in_addr *)Addr)->s_lh == 0x71 || //TEST-NET-3 Addresses(203.0.113.0/24, Section 3 in RFC 5737)
			IsPrivateUse && ((in_addr *)Addr)->s_net == 0xE0 || //Multicast Addresses(224.0.0.0/4, Section 2 in RFC 3171)
			((in_addr *)Addr)->s_net >= 0xF0) //Reserved for future use address(240.0.0.0/4, Section 4 in RFC 1112) and Broadcast Addresses(255.255.255.255/32, Section 7 in RFC 919/RFC 922)
				return true;

	//Result Blacklist check
		if (Domain != nullptr)
		{
		//Domain Case Conversion
			CaseConvert(false, Domain, strnlen_s(Domain, DOMAIN_MAXSIZE));

		//Main check
			std::unique_lock<std::mutex> ResultBlacklistMutex(ResultBlacklistLock);
			for (auto IPFilterFileSetIter:*IPFilterFileSetUsing)
			{
				for (auto ResultBlacklistTableIter:IPFilterFileSetIter.ResultBlacklist)
				{
					if (ResultBlacklistTableIter.Addresses.front().Begin.ss_family == AF_INET && 
						(ResultBlacklistTableIter.PatternString.empty() || std::regex_match(Domain, ResultBlacklistTableIter.Pattern)))
					{
						for (auto AddressRangeTableIter:ResultBlacklistTableIter.Addresses)
						{
							if (AddressRangeTableIter.End.ss_family == AF_INET && 
								AddressesComparing(Addr, &((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr, AF_INET) >= ADDRESS_COMPARE_EQUAL && 
								AddressesComparing(Addr, &((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr, AF_INET) <= ADDRESS_COMPARE_EQUAL || 
								((in_addr *)Addr)->s_addr == ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_addr)
									return true;
						}
					}
				}
			}
		}

	//Address Hosts check
		std::unique_lock<std::mutex> AddressHostsListMutex(AddressHostsListLock);
		for (auto HostsFileSetIter:*HostsFileSetUsing)
		{
			for (auto AddressHostsTableIter:HostsFileSetIter.AddressHostsList)
			{
				if (AddressHostsTableIter.Address_Target.front().ss_family == AF_INET)
				{
					for (auto AddressRangeTableIter:AddressHostsTableIter.Address_Source)
					{
						if (AddressRangeTableIter.Begin.ss_family == AF_INET && AddressRangeTableIter.End.ss_family == AF_INET && 
							AddressesComparing(Addr, &((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr, AF_INET) >= ADDRESS_COMPARE_EQUAL && 
							AddressesComparing(Addr, &((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr, AF_INET) <= ADDRESS_COMPARE_EQUAL || 
							((in_addr *)Addr)->s_addr == ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_addr)
						{
							if (AddressHostsTableIter.Address_Target.size() > 1U)
							{
							//Get a ramdom one.
								std::uniform_int_distribution<int> RamdomDistribution(0, (int)AddressHostsTableIter.Address_Target.size() - 1U);
								*(in_addr *)Addr = ((PSOCKADDR_IN)&AddressHostsTableIter.Address_Target.at(RamdomDistribution(*Parameter.RamdomEngine)))->sin_addr;
							}
							else {
								*(in_addr *)Addr = ((PSOCKADDR_IN)&AddressHostsTableIter.Address_Target.front())->sin_addr;
							}

							break;
						}
					}
				}
			}
		}
	}

//Stop loop.
	StopLoop: 
	return false;
}

//Check routing of addresses
bool __fastcall CheckAddressRouting(const void *Addr, const uint16_t Protocol)
{
	std::unique_lock<std::mutex> LocalRoutingListMutex(LocalRoutingListLock);

//Check address routing.
	if (Protocol == AF_INET6) //IPv6
	{
		uint64_t *AddrFront = (uint64_t *)Addr, *AddrBack = (uint64_t *)((PUCHAR)Addr + sizeof(in6_addr) / 2U);
		std::map<uint64_t, std::set<uint64_t>>::iterator AddrMapIter;
		for (auto IPFilterFileSetIter:*IPFilterFileSetUsing)
		{
			for (auto LocalRoutingTableIter:IPFilterFileSetIter.LocalRoutingList_IPv6)
			{
				if (LocalRoutingTableIter.Prefix < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
				{
					if (LocalRoutingTableIter.AddressRoutingList_IPv6.count(ntoh64(*AddrFront) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - LocalRoutingTableIter.Prefix))))
						return true;
				}
				else {
					AddrMapIter = LocalRoutingTableIter.AddressRoutingList_IPv6.find(ntoh64(*AddrFront));
					if (AddrMapIter != LocalRoutingTableIter.AddressRoutingList_IPv6.end() && 
						AddrMapIter->second.count(ntoh64(*AddrBack) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - LocalRoutingTableIter.Prefix))))
							return true;
				}
			}
		}
	}
	else { //IPv4
		for (auto IPFilterFileSetIter:*IPFilterFileSetUsing)
		{
			for (auto LocalRoutingTableIter:IPFilterFileSetIter.LocalRoutingList_IPv4)
			{
				if (LocalRoutingTableIter.AddressRoutingList_IPv4.count(ntohl(((in_addr *)Addr)->s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - LocalRoutingTableIter.Prefix))))
					return true;
			}
		}
	}

	return false;
}

//Custom Mode address filter
bool __fastcall CheckCustomModeFilter(const void *OriginalAddr, const uint16_t Protocol)
{
	std::unique_lock<std::mutex> AddressRangeMutex(AddressRangeLock);
	if (Protocol == AF_INET6) //IPv6
	{
		auto Addr = (in6_addr *)OriginalAddr;
	//Permit
		if (Parameter.IPFilterType)
		{
			for (auto IPFilterFileSetIter:*IPFilterFileSetUsing)
			{
				for (auto AddressRangeTableIter:IPFilterFileSetIter.AddressRange)
				{
				//Check Protocol and Level.
					if (AddressRangeTableIter.Begin.ss_family != AF_INET6 || Parameter.IPFilterLevel > 0 && AddressRangeTableIter.Level < Parameter.IPFilterLevel)
						continue;

				//Check address.
					for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);++Index)
					{
						if (ntohs(Addr->s6_words[Index]) > ntohs(((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr.s6_words[Index]) && ntohs(Addr->s6_words[Index]) < ntohs(((PSOCKADDR_IN6)&AddressRangeTableIter.End)->sin6_addr.s6_words[Index]))
						{
							return true;
						}
						else if (Addr->s6_words[Index] == ((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr.s6_words[Index] || Addr->s6_words[Index] == ((PSOCKADDR_IN6)&AddressRangeTableIter.End)->sin6_addr.s6_words[Index])
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
		}
	//Deny
		else {
			for (auto IPFilterFileSetIter:*IPFilterFileSetUsing)
			{
				for (auto AddressRangeTableIter:IPFilterFileSetIter.AddressRange)
				{
				//Check Protocol and Level.
					if (AddressRangeTableIter.Begin.ss_family != AF_INET6 || Parameter.IPFilterLevel > 0 && AddressRangeTableIter.Level < Parameter.IPFilterLevel)
						continue;

				//Check address.
					for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);++Index)
					{
						if (ntohs(Addr->s6_words[Index]) > ntohs(((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr.s6_words[Index]) && ntohs(Addr->s6_words[Index]) < ntohs(((PSOCKADDR_IN6)&AddressRangeTableIter.End)->sin6_addr.s6_words[Index]))
						{
							return false;
						}
						else if (Addr->s6_words[Index] == ((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr.s6_words[Index] || Addr->s6_words[Index] == ((PSOCKADDR_IN6)&AddressRangeTableIter.End)->sin6_addr.s6_words[Index])
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
	}
	else { //IPv4
		auto Addr = (in_addr *)OriginalAddr;
	//Permit
		if (Parameter.IPFilterType)
		{
			for (auto IPFilterFileSetIter:*IPFilterFileSetUsing)
			{
				for (auto AddressRangeTableIter:IPFilterFileSetIter.AddressRange)
				{
				//Check Protocol and Level.
					if (AddressRangeTableIter.Begin.ss_family != AF_INET || Parameter.IPFilterLevel > 0 && AddressRangeTableIter.Level < Parameter.IPFilterLevel)
						continue;

				//Check address.
					if (Addr->s_net > ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_net && Addr->s_net < ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_net)
					{
						return true;
					}
					else if (Addr->s_net == ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_net || Addr->s_net == ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_net)
					{
						if (Addr->s_host > ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_host && Addr->s_host < ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_host)
						{
							return true;
						}
						else if (Addr->s_host == ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_host || Addr->s_host == ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_host)
						{
							if (Addr->s_lh > ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_lh && Addr->s_lh < ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_lh)
							{
								return true;
							}
							else if (Addr->s_lh == ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_lh || Addr->s_lh == ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_lh)
							{
								if (Addr->s_impno >= ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_impno && Addr->s_impno <= ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_impno)
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
		}
	//Deny
		else {
			for (auto IPFilterFileSetIter:*IPFilterFileSetUsing)
			{
				for (auto AddressRangeTableIter:IPFilterFileSetIter.AddressRange)
				{
				//Check Protocol and Level.
					if (AddressRangeTableIter.Begin.ss_family != AF_INET || Parameter.IPFilterLevel > 0 && AddressRangeTableIter.Level < Parameter.IPFilterLevel)
						continue;

				//Check address.
					if (Addr->s_net > ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_net && Addr->s_net < ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_net)
					{
						return false;
					}
					else if (Addr->s_net == ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_net || Addr->s_net == ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_net)
					{
						if (Addr->s_host > ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_host && Addr->s_host < ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_host)
						{
							return false;
						}
						else if (Addr->s_host == ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_host || Addr->s_host == ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_host)
						{
							if (Addr->s_lh > ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_lh && Addr->s_lh < ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_lh)
							{
								return false;
							}
							else if (Addr->s_lh == ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_lh || Addr->s_lh == ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_lh)
							{
								if (Addr->s_impno >= ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_impno && Addr->s_impno <= ((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr.s_impno)
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
	}

	return true;
}

//Count DNS Query Name length
size_t __fastcall CheckDNSQueryNameLength(const char *Buffer)
{
	size_t Index = 0;
	for (Index = 0;Index < DOMAIN_MAXSIZE;++Index)
	{
		if (Buffer[Index] == 0)
		{
			break;
		}
		else if ((UCHAR)Buffer[Index] >= DNS_POINTER_BITS)
		{
			return Index + sizeof(uint16_t) - 1U;
		}
	}

	return Index;
}

//Check DNS response results.
size_t __fastcall CheckResponseData(const char *Buffer, const size_t Length, const bool IsLocal)
{
	auto DNS_Header = (pdns_hdr)Buffer;

//DNS Options part
	if (Parameter.DNSDataCheck && 
	//Not a response packet
		((ntohs(DNS_Header->Flags) & DNS_GET_BIT_RESPONSE) == 0 ||
	//Question Resource Records must be one.
		DNS_Header->Questions != htons(U16_NUM_ONE) || 
	//Not any Non-Question Resource Records when RCode is No Error
		(ntohs(DNS_Header->Flags) & DNS_GET_BIT_RCODE) == DNS_RCODE_NOERROR && DNS_Header->Answer == 0 && DNS_Header->Authority == 0 && DNS_Header->Additional == 0 || 
	//Responses are not authoritative when there are no Authoritative Nameservers Records and Additional Resource Records.
//		(ntohs(DNS_Header->Flags) & DNS_GET_BIT_AA) != 0 && DNS_Header->Authority == 0 && DNS_Header->Additional == 0 || 
	//Do query recursively bit must be set when RCode is No Error and there are Answers Resource Records.
		(ntohs(DNS_Header->Flags) & DNS_GET_BIT_RD) == 0 && (ntohs(DNS_Header->Flags) & DNS_GET_BIT_RCODE) == DNS_RCODE_NOERROR && DNS_Header->Answer == 0 || 
	//Local requesting failed or Truncated
		IsLocal && ((ntohs(DNS_Header->Flags) & DNS_GET_BIT_RCODE) > DNS_RCODE_NOERROR || (ntohs(DNS_Header->Flags) & DNS_GET_BIT_TC) > 0 && DNS_Header->Answer == 0) || 
	//Additional EDNS Label Resource Records check
		Parameter.EDNS_Label && DNS_Header->Additional == 0))
			return EXIT_FAILURE;

//Responses question pointer check
	if (Parameter.DNSDataCheck)
	{
		for (size_t Index = sizeof(dns_hdr); Index < DNS_PACKET_QUERY_LOCATE(Buffer); ++Index)
		{
			if (*(Buffer + Index) == DNS_POINTER_BITS_STRING)
				return EXIT_FAILURE;
		}

	//Check repeating DNS Domain without Compression.
		if (DNS_Header->Answer == htons(U16_NUM_ONE) && DNS_Header->Authority == 0 && DNS_Header->Additional == 0 && 
			CheckDNSQueryNameLength(Buffer + sizeof(dns_hdr)) == CheckDNSQueryNameLength(Buffer + DNS_PACKET_RR_LOCATE(Buffer)))
		{
			auto QuestionDomain = (uint8_t *)(Buffer + sizeof(dns_hdr));
			auto AnswerDomain = (uint8_t *)(Buffer + DNS_PACKET_RR_LOCATE(Buffer));
			auto DNS_Record_Standard = (pdns_record_standard)(Buffer + DNS_PACKET_RR_LOCATE(Buffer) + CheckDNSQueryNameLength((PSTR)QuestionDomain) + 1U);
			if (DNS_Record_Standard->Classes == htons(DNS_CLASS_IN) &&
				(DNS_Record_Standard->Type == htons(DNS_RECORD_A) || DNS_Record_Standard->Type == htons(DNS_RECORD_AAAA)) &&
				memcmp(QuestionDomain, AnswerDomain, CheckDNSQueryNameLength((PSTR)QuestionDomain) + 1U) == 0)
					return EXIT_FAILURE;
		}
	}

//Mark domain.
	std::shared_ptr<char> Domain(new char[DOMAIN_MAXSIZE]());
	memset(Domain.get(), 0, DOMAIN_MAXSIZE);
	DNSQueryToChar(Buffer + sizeof(dns_hdr), Domain.get());

//Initialization
	auto DNS_Query = (pdns_qry)(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer));
	size_t DataLength = DNS_PACKET_RR_LOCATE(Buffer);
	uint16_t DNS_Pointer = 0;
	pdns_record_standard DNS_Record_Standard = nullptr;
	in6_addr *pin6_addr = nullptr;
	in_addr *pin_addr = nullptr;

//DNS Responses which have one Answer Resource Records and not any Authority Resource Records or Additional Resource Records may fake.
	if (DNS_Header->Answer == htons(U16_NUM_ONE) && DNS_Header->Authority == 0 && DNS_Header->Additional == 0 && DNS_Query->Classes == htons(DNS_CLASS_IN))
	{
	//Pointer check
		if (DataLength + sizeof(uint16_t) < Length && (UCHAR)Buffer[DataLength] >= DNS_POINTER_BITS)
		{
			DNS_Pointer = ntohs(*(uint16_t *)(Buffer + DataLength)) & DNS_POINTER_BITS_GET_LOCATE;
			if (DNS_Pointer >= Length || DNS_Pointer < sizeof(dns_hdr) || DNS_Pointer == DataLength || DNS_Pointer == DataLength + 1U)
				return EXIT_FAILURE;
		}

	//Records Type in responses check
		DataLength += CheckDNSQueryNameLength(Buffer + DataLength) + 1U;
		DNS_Record_Standard = (pdns_record_standard)(Buffer + DataLength);
		if (Parameter.DNSDataCheck && (DNS_Record_Standard->TTL == 0 || DNS_Record_Standard->Classes == htons(DNS_CLASS_IN) && 
			(DNS_Query->Type != htons(DNS_RECORD_A) && DNS_Record_Standard->Type == htons(DNS_RECORD_A) || 
			DNS_Query->Type != htons(DNS_RECORD_AAAA) && DNS_Record_Standard->Type == htons(DNS_RECORD_AAAA))))
				return EXIT_FAILURE;

	//Check addresses.
		if (Parameter.BlacklistCheck)
		{
			DataLength += sizeof(dns_record_standard);
			if (DNS_Record_Standard->Type == htons(DNS_RECORD_AAAA) && DNS_Record_Standard->Length == htons(sizeof(in6_addr)))
			{
				pin6_addr = (in6_addr *)(Buffer + DataLength);
				if (CheckSpecialAddress(pin6_addr, AF_INET6, false, Domain.get()) || 
					!Parameter.LocalHosts && Parameter.LocalRouting && IsLocal && !CheckAddressRouting(pin6_addr, AF_INET6))
						return EXIT_FAILURE;
			}
			else if (DNS_Record_Standard->Type == htons(DNS_RECORD_A) && DNS_Record_Standard->Length == htons(sizeof(in_addr)))
			{
				pin_addr = (in_addr *)(Buffer + DataLength);
				if (CheckSpecialAddress(pin_addr, AF_INET, false, Domain.get()) || 
					!Parameter.LocalHosts && Parameter.LocalRouting && IsLocal && !CheckAddressRouting(pin_addr, AF_INET))
						return EXIT_FAILURE;
			}
		}
	}
//Scan all Resource Records.
	else {
		uint16_t BeforeType = 0;
		auto IsEDNS_Label = false, IsDNSSEC_Records = false;	
		for (size_t Index = 0;Index < (size_t)(ntohs(DNS_Header->Answer) + ntohs(DNS_Header->Authority) + ntohs(DNS_Header->Additional));++Index)
		{
		//Pointer check
			if (DataLength + sizeof(uint16_t) < Length && (UCHAR)Buffer[DataLength] >= DNS_POINTER_BITS)
			{
				DNS_Pointer = ntohs(*(uint16_t *)(Buffer + DataLength)) & DNS_POINTER_BITS_GET_LOCATE;
				if (DNS_Pointer >= Length || DNS_Pointer < sizeof(dns_hdr) || DNS_Pointer == DataLength || DNS_Pointer == DataLength + 1U)
					return EXIT_FAILURE;
			}

		//Resource Records Name(Domain)
			DataLength += CheckDNSQueryNameLength(Buffer + DataLength) + 1U;
			if (DataLength + sizeof(dns_record_standard) > Length)
				return EXIT_FAILURE;

		//Standard Resource Records
			DNS_Record_Standard = (pdns_record_standard)(Buffer + DataLength);
			DataLength += sizeof(dns_record_standard);
			if (DataLength > Length || DataLength + ntohs(DNS_Record_Standard->Length) > Length)
				return EXIT_FAILURE;

		//EDNS Label(OPT Records) and DNSSEC Records(RRSIG/DNSKEY/DS/NSEC/NSEC3/NSEC3PARAM) check
			if (Parameter.EDNS_Label)
			{
				if (DNS_Record_Standard->Type == htons(DNS_RECORD_OPT))
					IsEDNS_Label = true;
				else if (Parameter.DNSSEC_Request && 
					(DNS_Record_Standard->Type == htons(DNS_RECORD_SIG) || DNS_Record_Standard->Type == htons(DNS_RECORD_KEY) || DNS_Record_Standard->Type == htons(DNS_RECORD_DS) || 
					DNS_Record_Standard->Type == htons(DNS_RECORD_RRSIG) || DNS_Record_Standard->Type == htons(DNS_RECORD_NSEC) || DNS_Record_Standard->Type == htons(DNS_RECORD_DNSKEY) || 
					DNS_Record_Standard->Type == htons(DNS_RECORD_NSEC3) || DNS_Record_Standard->Type == htons(DNS_RECORD_NSEC3PARAM) || DNS_Record_Standard->Type == htons(DNS_RECORD_CDS) || 
					DNS_Record_Standard->Type == htons(DNS_RECORD_CDNSKEY)))
				{
					IsDNSSEC_Records = true;

				//DNSSEC Validation
					if (Parameter.DNSSEC_Validation && !CheckDNSSECRecords(Buffer + DataLength, ntohs(DNS_Record_Standard->Length), DNS_Record_Standard->Type, BeforeType))
						return EXIT_FAILURE;
				}
			}

		//Read Resource Records data
			if (DNS_Record_Standard->Classes == htons(DNS_CLASS_IN) && DNS_Record_Standard->TTL > 0)
			{
			//AAAA Records
				if (DNS_Record_Standard->Type == htons(DNS_RECORD_AAAA) && DNS_Record_Standard->Length == htons(sizeof(in6_addr)))
				{
				//Records Type in responses check
					if (Parameter.DNSDataCheck && DNS_Query->Type == htons(DNS_RECORD_A))
						return EXIT_FAILURE;

				//Check addresses.
					pin6_addr = (in6_addr *)(Buffer + DataLength);
					if (Parameter.BlacklistCheck && CheckSpecialAddress(pin6_addr, AF_INET6, false, Domain.get()) || 
						Index < ntohs(DNS_Header->Answer) && !Parameter.LocalHosts && Parameter.LocalRouting && IsLocal && !CheckAddressRouting(pin6_addr, AF_INET6))
							return EXIT_FAILURE;
				}
			//A Records
				else if (DNS_Record_Standard->Type == htons(DNS_RECORD_A) && DNS_Record_Standard->Length == htons(sizeof(in_addr)))
				{
				//Records Type in responses check
					if (Parameter.DNSDataCheck && DNS_Query->Type == htons(DNS_RECORD_AAAA))
						return EXIT_FAILURE;

				//Check addresses.
					pin_addr = (in_addr *)(Buffer + DataLength);
					if (Parameter.BlacklistCheck && CheckSpecialAddress(pin_addr, AF_INET, false, Domain.get()) || 
						Index < ntohs(DNS_Header->Answer) && !Parameter.LocalHosts && Parameter.LocalRouting && IsLocal && !CheckAddressRouting(pin_addr, AF_INET))
							return EXIT_FAILURE;
				}
			}

			DataLength += ntohs(DNS_Record_Standard->Length);
		//Mark Resource Records type.
			if (Parameter.EDNS_Label && Parameter.DNSSEC_Request && Parameter.DNSSEC_Validation)
				BeforeType = DNS_Record_Standard->Type;
		}

	//Additional EDNS Label Resource Records and DNSSEC Validation check
		if (Parameter.EDNS_Label && (!IsEDNS_Label || Parameter.DNSSEC_Request && Parameter.DNSSEC_ForceValidation && !IsDNSSEC_Records))
			return EXIT_FAILURE;
	}

#if defined(ENABLE_PCAP)
//Mark Hop Limits or TTL.
	if (Parameter.DNSDataCheck && (DNS_Header->Answer != htons(U16_NUM_ONE) || DNS_Header->Authority > 0 || DNS_Header->Additional > 0 || //Less than or more than one Answer Records or Authority Records and/or Additional Records
		(ntohs(DNS_Header->Flags) & DNS_GET_BIT_RCODE) == DNS_RCODE_NXDOMAIN) || //No Such Name, not standard query response and no error check.
	//Domain Test part
		Parameter.DomainTest_Data != nullptr && strnlen_s(Domain.get(), DOMAIN_MAXSIZE) == strnlen_s(Parameter.DomainTest_Data, DOMAIN_MAXSIZE) && 
		memcmp(Domain.get(), Parameter.DomainTest_Data, strnlen_s(Parameter.DomainTest_Data, DOMAIN_MAXSIZE)) == 0 && DNS_Header->ID == Parameter.DomainTest_ID)
			return EXIT_CHECK_RESPONSE_DATA_MARK_HOP_LIMITS;
#endif

	return EXIT_SUCCESS;
}

//Check DNSSEC Records
bool __fastcall CheckDNSSECRecords(const char *Buffer, const size_t Length, const uint16_t Type, const uint16_t BeforeType)
{
//DS and CDS Records
	if (Type == htons(DNS_RECORD_DS) || Type == htons(DNS_RECORD_CDS))
	{
		auto DNS_Record_DS = (pdns_record_ds)Buffer;

	//Key Tag, Algorithm and Digest Type check
		if (DNS_Record_DS->KeyTag == 0 || 
			DNS_Record_DS->Algorithm == DNSSEC_AlGORITHM_RESERVED_0 || DNS_Record_DS->Algorithm == DNSSEC_AlGORITHM_RESERVED_4 || DNS_Record_DS->Algorithm == DNSSEC_AlGORITHM_RESERVED_9 || 
			DNS_Record_DS->Algorithm == DNSSEC_AlGORITHM_RESERVED_11 || DNS_Record_DS->Algorithm >= DNSSEC_AlGORITHM_RESERVED_123 && DNS_Record_DS->Algorithm >= DNSSEC_AlGORITHM_RESERVED_251 || 
			DNS_Record_DS->Algorithm == DNSSEC_AlGORITHM_RESERVED_255 || 
			DNS_Record_DS->Type == DNSSEC_DS_TYPE_RESERVED)
				return false;

	//Algorithm length check
		if (DNS_Record_DS->Type == DNSSEC_DS_TYPE_SHA1 && Length != sizeof(dns_record_ds) + SHA1_LENGTH || 
			DNS_Record_DS->Type == DNSSEC_DS_TYPE_SHA256 && Length != sizeof(dns_record_ds) + SHA256_LENGTH || 
			DNS_Record_DS->Type == DNSSEC_DS_TYPE_GOST && Length != sizeof(dns_record_ds) + GOST_LENGTH || 
			DNS_Record_DS->Type == DNSSEC_DS_TYPE_SHA384 && Length != sizeof(dns_record_ds) + SHA384_LENGTH)
				return false;
	}
//SIG and RRSIG Records
	else if (Type == htons(DNS_RECORD_SIG) || Type == htons(DNS_RECORD_RRSIG))
	{
		auto DNS_Record_RRSIG = (pdns_record_rrsig)Buffer;

	//RRSIG header check
		if (
		//Type Coverded check
			DNS_Record_RRSIG->TypeCovered != BeforeType || 
		//Algorithm check
			DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RESERVED_0 || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RESERVED_4 || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RESERVED_9 || 
			DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RESERVED_11 || DNS_Record_RRSIG->Algorithm >= DNSSEC_AlGORITHM_RESERVED_123 && DNS_Record_RRSIG->Algorithm >= DNSSEC_AlGORITHM_RESERVED_251 || 
			DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RESERVED_255 || 
		//Labels, Original TTL and Key Tag check
			DNS_Record_RRSIG->Labels == 0 || DNS_Record_RRSIG->TTL == 0 || DNS_Record_RRSIG->KeyTag == 0 || 
		//Signature available time check
			time(nullptr) < (time_t)ntohl(DNS_Record_RRSIG->Inception) || time(nullptr) > (time_t)ntohl(DNS_Record_RRSIG->Expiration))
				return false;

	//Algorithm length check
		if (
		//The Signature length must longer than 512 bits/64 bytes in RSA suite.
			(DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RSA_MD5 || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RSA_SHA1 || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RSA_SHA1_NSEC3_SHA1 ||
			DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RSA_SHA256 || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RSA_SHA512) && Length <= sizeof(dns_record_rrsig) + RSA_MIN_LENGTH || 
		//The Signature length must longer than 768 bits/96 bytes in Diffie-Hellman suite.
			DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_DH && Length <= sizeof(dns_record_rrsig) + DH_MIN_LENGTH || 
		//The Signature length must longer than 1024 bits/128 bytes in DSA suite.
			(DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_DSA || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_DSA_NSEC3_SHA1) && Length <= sizeof(dns_record_rrsig) + DSA_MIN_LENGTH || 
		//The Signature length must longer than 192 bits/24 bytes in ECC suite.
			(DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_ECC_GOST || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_ECDSA_P256_SHA256 || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_ECDSA_P386_SHA386) && 
			Length <= sizeof(dns_record_rrsig) + ECC_MIN_LENGTH)
				return false;
	}
//DNSKEY and CDNSKEY Records
	else if (Type == htons(DNS_RECORD_DNSKEY) || Type == htons(DNS_RECORD_CDNSKEY))
	{
		auto DNS_Record_DNSKEY = (pdns_record_dnskey)Buffer;

	//Key Revoked bit, Protocol and Algorithm check
		if ((ntohs(DNS_Record_DNSKEY->Flags) & DNSSEC_DNSKEY_FLAGS_RSV) > 0 || DNS_Record_DNSKEY->Protocol != DNSSEC_DNSKEY_PROTOCOL ||
			DNS_Record_DNSKEY->Algorithm == DNSSEC_AlGORITHM_RESERVED_0 || DNS_Record_DNSKEY->Algorithm == DNSSEC_AlGORITHM_RESERVED_4 || DNS_Record_DNSKEY->Algorithm == DNSSEC_AlGORITHM_RESERVED_9 || 
			DNS_Record_DNSKEY->Algorithm == DNSSEC_AlGORITHM_RESERVED_11 || DNS_Record_DNSKEY->Algorithm >= DNSSEC_AlGORITHM_RESERVED_123 && DNS_Record_DNSKEY->Algorithm >= DNSSEC_AlGORITHM_RESERVED_251 || 
			DNS_Record_DNSKEY->Algorithm == DNSSEC_AlGORITHM_RESERVED_255)
				return false;
	}
//NSEC3 Records
	else if (Type == htons(DNS_RECORD_NSEC3))
	{
		auto DNS_Record_NSEC3 = (pdns_record_nsec3)Buffer;

	//Algorithm check
		if (DNS_Record_NSEC3->Algorithm == DNSSEC_AlGORITHM_RESERVED_0 || DNS_Record_NSEC3->Algorithm == DNSSEC_AlGORITHM_RESERVED_4 || DNS_Record_NSEC3->Algorithm == DNSSEC_AlGORITHM_RESERVED_9 || 
			DNS_Record_NSEC3->Algorithm == DNSSEC_AlGORITHM_RESERVED_11 || DNS_Record_NSEC3->Algorithm >= DNSSEC_AlGORITHM_RESERVED_123 && DNS_Record_NSEC3->Algorithm >= DNSSEC_AlGORITHM_RESERVED_251 || 
			DNS_Record_NSEC3->Algorithm == DNSSEC_AlGORITHM_RESERVED_255)
				return false;

	//Hash Length check
		if (sizeof(dns_record_nsec3param) + DNS_Record_NSEC3->SaltLength < Length && DNS_Record_NSEC3->Algorithm == DNSSEC_NSEC3_ALGORITHM_SHA1 &&
			*(uint8_t *)(Buffer + sizeof(dns_record_nsec3param) + DNS_Record_NSEC3->SaltLength) != SHA1_LENGTH)
				return false;
	}
//NSEC3PARAM Records
	else if (Type == htons(DNS_RECORD_NSEC3PARAM))
	{
		auto DNS_Record_NSEC3PARAM = (pdns_record_nsec3param)Buffer;

	//Algorithm check
		if (DNS_Record_NSEC3PARAM->Algorithm == DNSSEC_AlGORITHM_RESERVED_0 || DNS_Record_NSEC3PARAM->Algorithm == DNSSEC_AlGORITHM_RESERVED_4 || DNS_Record_NSEC3PARAM->Algorithm == DNSSEC_AlGORITHM_RESERVED_9 || 
			DNS_Record_NSEC3PARAM->Algorithm == DNSSEC_AlGORITHM_RESERVED_11 || DNS_Record_NSEC3PARAM->Algorithm >= DNSSEC_AlGORITHM_RESERVED_123 && DNS_Record_NSEC3PARAM->Algorithm >= DNSSEC_AlGORITHM_RESERVED_251 || 
			DNS_Record_NSEC3PARAM->Algorithm == DNSSEC_AlGORITHM_RESERVED_255)
				return false;
	}

	return true;
}
