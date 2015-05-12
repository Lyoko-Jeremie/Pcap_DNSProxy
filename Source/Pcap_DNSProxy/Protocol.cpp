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

//Convert host values to network byte order with 64 bits
uint64_t __fastcall hton64(const uint64_t Val)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return (((uint64_t)htonl((int32_t)((Val << 32U) >> 32U))) << 32U)|(uint32_t)htonl((int32_t)(Val >> 32U));
#else //BIG_ENDIAN
	return Val;
#endif
}

//Convert network byte order to host values with 64 bits
uint64_t __fastcall ntoh64(const uint64_t Val)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return (((uint64_t)ntohl((int32_t)((Val << 32U) >> 32U))) << 32U)|(uint32_t)ntohl((int32_t)(Val >> 32U));
#else //BIG_ENDIAN
	return Val;
#endif
}

/* Get Ethernet Frame Check Sequence/FCS
uint32_t __fastcall GetFCS(const unsigned char *Buffer, const size_t Length)
{
	uint32_t Table[FCS_TABLE_SIZE] = {0}, Gx = 0x04C11DB7, Temp = 0, CRCTable = 0, Value = 0, UI = 0;
	char ReflectNum[] = {8, 32};
	int Index[3U] = {0};

	for (Index[0] = 0;Index[0] <= UINT8_MAX;Index[0]++)
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

	uint32_t CRC = UINT32_MAX;
	for (Index[0] = 0;Index[0] < (int)Length;Index[0]++)
		CRC = Table[(CRC ^ (*(Buffer + Index[0]))) & UINT8_MAX]^(CRC >> 8U);

	return ~CRC;
}
*/

//Convert address strings to binary.
size_t __fastcall AddressStringToBinary(const char *AddrString, void *OriginalAddr, const uint16_t Protocol, SSIZE_T &ErrCode)
{
	std::string sAddrString(AddrString);

//inet_ntop() and inet_pton() was only support in Windows Vista and newer system. [Roy Tam]
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
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
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
		SockLength = sizeof(sockaddr_in6);
		if (WSAStringToAddressA((LPSTR)sAddrString.c_str(), AF_INET6, nullptr, (PSOCKADDR)SockAddr.get(), &SockLength) == SOCKET_ERROR)
	#else
		Result = inet_pton(AF_INET6, sAddrString.c_str(), OriginalAddr);
		if (Result == SOCKET_ERROR || Result == FALSE)
	#endif
		{
			ErrCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
		memcpy_s(OriginalAddr, sizeof(in6_addr), &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, sizeof(in6_addr));
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
		if (sAddrString[sAddrString.length() - 1U] == ASCII_PERIOD)
			sAddrString.append("0");

	//Convert to binary.
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
		SockLength = sizeof(sockaddr_in);
		if (WSAStringToAddressA((LPSTR)sAddrString.c_str(), AF_INET, nullptr, (PSOCKADDR)SockAddr.get(), &SockLength) == SOCKET_ERROR)
	#else
		Result = inet_pton(AF_INET, sAddrString.c_str(), OriginalAddr);
		if (Result == SOCKET_ERROR || Result == FALSE)
	#endif
		{
			ErrCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
		memcpy_s(OriginalAddr, sizeof(in_addr), &((PSOCKADDR_IN)SockAddr.get())->sin_addr, sizeof(in_addr));
	#endif
	}

	return EXIT_SUCCESS;
}

//Compare two addresses
size_t __fastcall CompareAddresses(const void *OriginalAddrBegin, const void *OriginalAddrEnd, const uint16_t Protocol)
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

//Get local address list
#if defined(PLATFORM_WIN)
PADDRINFOA __fastcall GetLocalAddressList(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> HostName(new char[DOMAIN_MAXSIZE]());
	memset(HostName.get(), 0, DOMAIN_MAXSIZE);
	std::shared_ptr<addrinfo> Hints(new addrinfo());
	memset(Hints.get(), 0, sizeof(addrinfo));
	PADDRINFOA Result = nullptr;

	if (Protocol == AF_INET6) //IPv6
		Hints->ai_family = AF_INET6;
	else //IPv4
		Hints->ai_family = AF_INET;
	Hints->ai_socktype = SOCK_DGRAM;
	Hints->ai_protocol = IPPROTO_UDP;

//Get localhost name.
	if (gethostname(HostName.get(), DOMAIN_MAXSIZE) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Get localhost name error", WSAGetLastError(), nullptr, 0);
		return nullptr;
	}

//Get localhost data.
	int ResultGetaddrinfo = getaddrinfo(HostName.get(), nullptr, Hints.get(), &Result);
	if (ResultGetaddrinfo != 0)
	{
		PrintError(LOG_ERROR_NETWORK, L"Get localhost address error", ResultGetaddrinfo, nullptr, 0);

		freeaddrinfo(Result);
		return nullptr;
	}

	return Result;
}
#endif

#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Get address from best network interface
	size_t GetBestInterfaceAddress(const uint16_t Protocol, const sockaddr_storage *OriginalSockAddr)
	{
	//Initialization
		std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
		memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
		SockAddr->ss_family = Protocol;
		SOCKET InterfaceSocket = socket(Protocol, SOCK_DGRAM, IPPROTO_UDP);
		socklen_t AddrLen = 0;

	//Check socket.
		if (InterfaceSocket == INVALID_SOCKET)
		{
			Parameter.TunnelAvailable_IPv6 = false;
			if (Protocol == AF_INET6)
				Parameter.GatewayAvailable_IPv6 = false;
			else //IPv4
				Parameter.GatewayAvailable_IPv4 = false;

			PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
			return EXIT_FAILURE;
		}

	//Check parameter.
		if (Protocol == AF_INET6)
		{
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = ((PSOCKADDR_IN6)OriginalSockAddr)->sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = ((PSOCKADDR_IN6)OriginalSockAddr)->sin6_port;
			AddrLen = sizeof(sockaddr_in6);

		//UDP connecting
			if (connect(InterfaceSocket, (PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6)) == SOCKET_ERROR || 
				getsockname(InterfaceSocket, (PSOCKADDR)SockAddr.get(), &AddrLen) == SOCKET_ERROR || SockAddr->ss_family != AF_INET6 || 
				AddrLen != sizeof(sockaddr_in6) || CheckEmptyBuffer(&((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, sizeof(in6_addr)))
			{
				Parameter.GatewayAvailable_IPv6 = false;
				Parameter.TunnelAvailable_IPv6 = false;

				close(InterfaceSocket);
				return EXIT_FAILURE;
			}

		//Address check(IPv6 tunnels support: 6to4, ISATAP and Teredo)
			if (((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[0] == htons(0x2001) && ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[1U] == 0 || //Teredo relay/tunnel Addresses(2001::/32, RFC 4380)
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[0] == htons(0x2002) || //6to4 relay/tunnel Addresses(2002::/16, Section 2 in RFC 3056)
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[0] >= 0x80 && ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[1U] <= 0xBF && //Link-Local Unicast Contrast Addresses/LUC(FE80::/10, Section 2.5.6 in RFC 4291)
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[4U] == 0 && ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[5U] == htons(0x5EFE)) //ISATAP Interface Identifiers Addresses(Prefix:0:5EFE:0:0:0:0/64, which also in Link-Local Unicast Contrast Addresses/LUC, Section 6.1 in RFC 5214)
					Parameter.TunnelAvailable_IPv6 = true;
		}
		else { //IPv4
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = ((PSOCKADDR_IN)OriginalSockAddr)->sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = ((PSOCKADDR_IN)OriginalSockAddr)->sin_port;
			AddrLen = sizeof(sockaddr_in);

		//UDP connecting
			if (connect(InterfaceSocket, (PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in)) == SOCKET_ERROR || 
				getsockname(InterfaceSocket, (PSOCKADDR)SockAddr.get(), &AddrLen) == SOCKET_ERROR || SockAddr->ss_family != AF_INET || 
				AddrLen != sizeof(sockaddr_in) || CheckEmptyBuffer(&((PSOCKADDR_IN)SockAddr.get())->sin_addr, sizeof(in_addr)))
			{
				Parameter.GatewayAvailable_IPv4 = false;
				Parameter.TunnelAvailable_IPv6 = false;

				close(InterfaceSocket);
				return EXIT_FAILURE;
			}
		}

		close(InterfaceSocket);
		return EXIT_SUCCESS;
	}
#endif

//Get gateway information
void __fastcall GetGatewayInformation(const uint16_t Protocol)
{
//IPv6
	if (Protocol == AF_INET6)
	{
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0 && 
			Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family == 0
		#if defined(ENABLE_LIBSODIUM)
			&& DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv6 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}
	#if defined(PLATFORM_WIN)
		DWORD AdaptersIndex = 0;
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Local_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv6 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}

	//IPv6 Multi
		if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				if (GetBestInterfaceEx((PSOCKADDR)&DNSServerDataIter.AddressData.IPv6, &AdaptersIndex) != NO_ERROR)
				{
					Parameter.GatewayAvailable_IPv6 = false;
					Parameter.TunnelAvailable_IPv6 = false;
					return;
				}
			}
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.IPv6.AddressData.Storage) == EXIT_FAILURE || 
			Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage) == EXIT_FAILURE || 
			Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.Local_IPv6.AddressData.Storage) == EXIT_FAILURE || 
			Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage) == EXIT_FAILURE
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET6, &DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage) == EXIT_FAILURE || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET6, &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage) == EXIT_FAILURE
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv6 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}

	//IPv6 Multi
		if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				if (GetBestInterfaceAddress(AF_INET6, &DNSServerDataIter.AddressData.Storage) == EXIT_FAILURE)
				{
					Parameter.GatewayAvailable_IPv6 = false;
					Parameter.TunnelAvailable_IPv6 = false;
					return;
				}
			}
		}
	#endif

		Parameter.GatewayAvailable_IPv6 = true;
		Parameter.TunnelAvailable_IPv6 = true;
	}
//IPv4
	else {
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0 && 
			Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family == 0
		#if defined(ENABLE_LIBSODIUM)
			&& DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv4 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}
	#if defined(PLATFORM_WIN)
		DWORD AdaptersIndex = 0;
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Local_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv4 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}

	//IPv4 Multi
		if (Parameter.DNSTarget.IPv4_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				if (GetBestInterfaceEx((PSOCKADDR)&DNSServerDataIter.AddressData.IPv4, &AdaptersIndex) != NO_ERROR)
				{
					Parameter.GatewayAvailable_IPv4 = false;
					Parameter.TunnelAvailable_IPv6 = false;
					return;
				}
			}
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.IPv4.AddressData.Storage) == EXIT_FAILURE || 
			Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage) == EXIT_FAILURE || 
			Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.Local_IPv4.AddressData.Storage) == EXIT_FAILURE || 
			Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage) == EXIT_FAILURE
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET, &DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage) == EXIT_FAILURE || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceAddress(AF_INET, &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage) == EXIT_FAILURE
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv4 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}

	//IPv4 Multi
		if (Parameter.DNSTarget.IPv4_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				if (GetBestInterfaceAddress(AF_INET, &DNSServerDataIter.AddressData.Storage) == EXIT_FAILURE)
				{
					Parameter.GatewayAvailable_IPv4 = false;
					Parameter.TunnelAvailable_IPv6 = false;
					return;
				}
			}
		}
	#endif

		Parameter.GatewayAvailable_IPv4 = true;
	}

	return;
}

//Get information of local addresses
size_t __fastcall GetNetworkingInformation(void)
{
//Initialization
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	std::string Result;
	SSIZE_T Index = 0;

#if defined(PLATFORM_WIN)
	PADDRINFOA LocalAddressList = nullptr, LocalAddressTableIter = nullptr;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	ifaddrs *InterfaceAddressList = nullptr, *InterfaceAddressIter = nullptr;
	auto ErrorFirstPrint = true;
#endif
	pdns_hdr DNS_Header = nullptr;
	pdns_qry DNS_Query = nullptr;
	pdns_record_aaaa DNS_Record_AAAA = nullptr;
	pdns_record_a DNS_Record_A = nullptr;
	for (;;)
	{
	//Get localhost addresses(IPv6)
	#if defined(PLATFORM_WIN)
		LocalAddressList = GetLocalAddressList(AF_INET6);
		if (LocalAddressList == nullptr)
		{
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (getifaddrs(&InterfaceAddressList) != 0 || InterfaceAddressList == nullptr)
		{
			if (InterfaceAddressList != nullptr)
				freeifaddrs(InterfaceAddressList);
			InterfaceAddressList = nullptr;
			PrintError(LOG_ERROR_NETWORK, L"Get localhost address error", errno, nullptr, 0);
	#endif

			Sleep(Parameter.FileRefreshTime);
			continue;
		}
		else {
			std::string DNSPTRString;
			std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[0]);
			memset(Parameter.LocalAddress[0], 0, PACKET_MAXSIZE);
			Parameter.LocalAddressLength[0] = 0;
			Parameter.LocalAddressPTR[0]->clear();
			Parameter.LocalAddressPTR[0]->shrink_to_fit();

		//Mark local addresses(A part).
			DNS_Header = (pdns_hdr)Parameter.LocalAddress[0];
			DNS_Header->Flags = htons(DNS_SQR_NEA);
			DNS_Header->Questions = htons(U16_NUM_ONE);
			Parameter.LocalAddressLength[0] += sizeof(dns_hdr);
			memcpy_s(Parameter.LocalAddress[0] + Parameter.LocalAddressLength[0], PACKET_MAXSIZE - Parameter.LocalAddressLength[0], Parameter.LocalFQDN, Parameter.LocalFQDNLength);
			Parameter.LocalAddressLength[0] += Parameter.LocalFQDNLength;
			DNS_Query = (pdns_qry)(Parameter.LocalAddress[0] + Parameter.LocalAddressLength[0]);
			DNS_Query->Type = htons(DNS_RECORD_AAAA);
			DNS_Query->Classes = htons(DNS_CLASS_IN);
			Parameter.LocalAddressLength[0] += sizeof(dns_qry);

		//Read addresses list and convert to Fully Qualified Domain Name/FQDN PTR.
		#if defined(PLATFORM_WIN)
			for (LocalAddressTableIter = LocalAddressList;LocalAddressTableIter != nullptr;LocalAddressTableIter = LocalAddressTableIter->ai_next)
			{
				if (LocalAddressTableIter->ai_family == AF_INET6 && LocalAddressTableIter->ai_addrlen == sizeof(sockaddr_in6) && 
					LocalAddressTableIter->ai_addr->sa_family == AF_INET6)
				{
				//Mark local addresses(B part).
					if (Parameter.LocalAddressLength[0] <= PACKET_MAXSIZE - sizeof(dns_record_aaaa))
					{
						DNS_Record_AAAA = (pdns_record_aaaa)(Parameter.LocalAddress[0] + Parameter.LocalAddressLength[0]);
						DNS_Record_AAAA->Name = htons(DNS_QUERY_PTR);
						DNS_Record_AAAA->Classes = htons(DNS_CLASS_IN);
						DNS_Record_AAAA->TTL = htonl(Parameter.HostsDefaultTTL);
						DNS_Record_AAAA->Type = htons(DNS_RECORD_AAAA);
						DNS_Record_AAAA->Length = htons(sizeof(in6_addr));
						DNS_Record_AAAA->Addr = ((PSOCKADDR_IN6)LocalAddressTableIter->ai_addr)->sin6_addr;
						Parameter.LocalAddressLength[0] += sizeof(dns_record_aaaa);
						++DNS_Header->Answer;
					}

				//Initialization
					DNSPTRString.clear();
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

				//Convert from in6_addr to string.
					size_t AddrStringLen = 0;
					for (Index = 0;Index < (SSIZE_T)(sizeof(in6_addr) / sizeof(uint16_t));++Index)
					{
						sprintf_s(Addr.get(), ADDR_STRING_MAXSIZE, "%x", ntohs(((PSOCKADDR_IN6)LocalAddressTableIter->ai_addr)->sin6_addr.s6_words[Index]));

					//Add zeros to beginning of string.
						if (strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE) < 4U)
						{
							AddrStringLen = strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);
							memmove_s(Addr.get() + 4U - strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE), ADDR_STRING_MAXSIZE, Addr.get(), strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE));
							memset(Addr.get(), ASCII_ZERO, 4U - AddrStringLen);
						}
						DNSPTRString.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

					//Last
						if (Index < (SSIZE_T)(sizeof(in6_addr) / sizeof(uint16_t) - 1U))
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
					for (Index = DNSPTRString.length() - 1U;Index >= 0;--Index)
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
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			for (InterfaceAddressIter = InterfaceAddressList;InterfaceAddressIter != nullptr;InterfaceAddressIter = InterfaceAddressIter->ifa_next)
			{
				if (InterfaceAddressIter->ifa_addr != nullptr && InterfaceAddressIter->ifa_addr->sa_family == AF_INET6)
				{
				//Mark local addresses(B part).
					if (Parameter.LocalAddressLength[0] <= PACKET_MAXSIZE - sizeof(dns_record_aaaa))
					{
						DNS_Record_AAAA = (pdns_record_aaaa)(Parameter.LocalAddress[0] + Parameter.LocalAddressLength[0]);
						DNS_Record_AAAA->Name = htons(DNS_QUERY_PTR);
						DNS_Record_AAAA->Classes = htons(DNS_CLASS_IN);
						DNS_Record_AAAA->TTL = htonl(Parameter.HostsDefaultTTL);
						DNS_Record_AAAA->Type = htons(DNS_RECORD_AAAA);
						DNS_Record_AAAA->Length = htons(sizeof(in6_addr));
						DNS_Record_AAAA->Addr = ((PSOCKADDR_IN6)InterfaceAddressIter->ifa_addr)->sin6_addr;
						Parameter.LocalAddressLength[0] += sizeof(dns_record_aaaa);
						++DNS_Header->Answer;
					}

				//Initialization
					DNSPTRString.clear();
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

				//Convert from in6_addr to string.
					size_t AddrStringLen = 0;
					for (Index = 0;Index < (SSIZE_T)(sizeof(in6_addr) / sizeof(uint16_t));++Index)
					{
						snprintf(Addr.get(), ADDR_STRING_MAXSIZE, "%x", ntohs(((PSOCKADDR_IN6)InterfaceAddressIter->ifa_addr)->sin6_addr.s6_words[Index]));

					//Add zeros to beginning of string.
						if (strnlen(Addr.get(), ADDR_STRING_MAXSIZE) < 4U)
						{
							AddrStringLen = strnlen(Addr.get(), ADDR_STRING_MAXSIZE);
							memmove_s(Addr.get() + 4U - strnlen(Addr.get(), ADDR_STRING_MAXSIZE), ADDR_STRING_MAXSIZE, Addr.get(), strnlen(Addr.get(), ADDR_STRING_MAXSIZE));
							memset(Addr.get(), ASCII_ZERO, 4U - AddrStringLen);
						}
						DNSPTRString.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

					//Last
						if (Index < (SSIZE_T)(sizeof(in6_addr) / sizeof(uint16_t) - 1U))
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
					for (Index = DNSPTRString.length() - 1U;Index >= 0;--Index)
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
		#endif

		//Mark local addresses(C part).
			if (DNS_Header->Answer == 0)
			{
				memset(Parameter.LocalAddress[0], 0, PACKET_MAXSIZE);
				Parameter.LocalAddressLength[0] = 0;
			}
			else {
				DNS_Header->Answer = htons(DNS_Header->Answer);
			}

		//Add to global list.
			LocalAddressMutexIPv6.unlock();
		#if defined(PLATFORM_WIN)
			freeaddrinfo(LocalAddressList);
			LocalAddressList = nullptr;
		#endif
		}

	//Get localhost addresses(IPv4)
	#if defined(PLATFORM_WIN)
		LocalAddressList = GetLocalAddressList(AF_INET);
		if (LocalAddressList == nullptr)
		{
			Sleep(Parameter.FileRefreshTime);
			continue;
		}
		else {
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		{
	#endif
			std::string DNSPTRString;
			std::unique_lock<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[1U]);
			memset(Parameter.LocalAddress[1U], 0, PACKET_MAXSIZE);
			Parameter.LocalAddressLength[1U] = 0;
			Parameter.LocalAddressPTR[1U]->clear();
			Parameter.LocalAddressPTR[1U]->shrink_to_fit();

		//Mark local addresses(A part).
			DNS_Header = (pdns_hdr)Parameter.LocalAddress[1U];
			DNS_Header->Flags = htons(DNS_SQR_NEA);
			DNS_Header->Questions = htons(U16_NUM_ONE);
			Parameter.LocalAddressLength[1U] += sizeof(dns_hdr);
			memcpy_s(Parameter.LocalAddress[1U] + Parameter.LocalAddressLength[1U], PACKET_MAXSIZE - Parameter.LocalAddressLength[1U], Parameter.LocalFQDN, Parameter.LocalFQDNLength);
			Parameter.LocalAddressLength[1U] += Parameter.LocalFQDNLength;
			DNS_Query = (pdns_qry)(Parameter.LocalAddress[1U] + Parameter.LocalAddressLength[1U]);
			DNS_Query->Type = htons(DNS_RECORD_AAAA);
			DNS_Query->Classes = htons(DNS_CLASS_IN);
			Parameter.LocalAddressLength[1U] += sizeof(dns_qry);

		//Read addresses list and convert to Fully Qualified Domain Name/FQDN PTR.
		#if defined(PLATFORM_WIN)
			for (LocalAddressTableIter = LocalAddressList;LocalAddressTableIter != nullptr;LocalAddressTableIter = LocalAddressTableIter->ai_next)
			{
				if (LocalAddressTableIter->ai_family == AF_INET && LocalAddressTableIter->ai_addrlen == sizeof(sockaddr_in) && 
					LocalAddressTableIter->ai_addr->sa_family == AF_INET)
				{
				//Mark local addresses(B part).
					if (Parameter.LocalAddressLength[1U] <= PACKET_MAXSIZE - sizeof(dns_record_a))
					{
						DNS_Record_A = (pdns_record_a)(Parameter.LocalAddress[1U] + Parameter.LocalAddressLength[1U]);
						DNS_Record_A->Name = htons(DNS_QUERY_PTR);
						DNS_Record_A->Classes = htons(DNS_CLASS_IN);
						DNS_Record_A->TTL = htonl(Parameter.HostsDefaultTTL);
						DNS_Record_A->Type = htons(DNS_RECORD_A);
						DNS_Record_A->Length = htons(sizeof(in_addr));
						DNS_Record_A->Addr = ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr;
						Parameter.LocalAddressLength[1U] += sizeof(dns_record_a);
						++DNS_Header->Answer;
					}

				//Initialization
					DNSPTRString.clear();
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

				//Convert from in_addr to DNS PTR.
					sprintf_s(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_impno);
					Result.append(Addr.get());
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					Result.append(".");
					sprintf_s(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_lh);
					Result.append(Addr.get());
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					Result.append(".");
					sprintf_s(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_host);
					Result.append(Addr.get());
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					Result.append(".");
					sprintf_s(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_net);
					Result.append(Addr.get());
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					Result.append(".");
					Result.append("in-addr.arpa");

				//Add to global list.
					Parameter.LocalAddressPTR[1U]->push_back(Result);
					Result.clear();
					Result.shrink_to_fit();
				}
			}
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			for (InterfaceAddressIter = InterfaceAddressList;InterfaceAddressIter != nullptr;InterfaceAddressIter = InterfaceAddressIter->ifa_next)
			{
				if (InterfaceAddressIter->ifa_addr != nullptr && InterfaceAddressIter->ifa_addr->sa_family == AF_INET)
				{
				//Mark local addresses(B part).
					if (Parameter.LocalAddressLength[1U] <= PACKET_MAXSIZE - sizeof(dns_record_a))
					{
						DNS_Record_A = (pdns_record_a)(Parameter.LocalAddress[1U] + Parameter.LocalAddressLength[1U]);
						DNS_Record_A->Name = htons(DNS_QUERY_PTR);
						DNS_Record_A->Classes = htons(DNS_CLASS_IN);
						DNS_Record_A->TTL = htonl(Parameter.HostsDefaultTTL);
						DNS_Record_A->Type = htons(DNS_RECORD_A);
						DNS_Record_A->Length = htons(sizeof(in_addr));
						DNS_Record_A->Addr = ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr;
						Parameter.LocalAddressLength[1U] += sizeof(dns_record_a);
						++DNS_Header->Answer;
					}

				//Initialization
					DNSPTRString.clear();
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

				//Convert from in_addr to DNS PTR.
					snprintf(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr.s_impno);
					Result.append(Addr.get());
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					Result.append(".");
					snprintf(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr.s_lh);
					Result.append(Addr.get());
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					Result.append(".");
					snprintf(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr.s_host);
					Result.append(Addr.get());
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					Result.append(".");
					snprintf(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr.s_net);
					Result.append(Addr.get());
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					Result.append(".");
					Result.append("in-addr.arpa");

				//Add to global list.
					Parameter.LocalAddressPTR[1U]->push_back(Result);
					Result.clear();
					Result.shrink_to_fit();
				}
			}
		#endif

		//Mark local addresses(C part).
			if (DNS_Header->Answer == 0)
			{
				memset(Parameter.LocalAddress[1U], 0, PACKET_MAXSIZE);
				Parameter.LocalAddressLength[1U] = 0;
			}
			else {
				DNS_Header->Answer = htons(DNS_Header->Answer);
			}

		//Add to global list.
			LocalAddressMutexIPv4.unlock();
		#if defined(PLATFORM_WIN)
			freeaddrinfo(LocalAddressList);
			LocalAddressList = nullptr;
		#endif
		}

	//Free list.
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (InterfaceAddressList != nullptr)
			freeifaddrs(InterfaceAddressList);
		InterfaceAddressList = nullptr;
	#endif

	//Get gateway information and check.
		GetGatewayInformation(AF_INET6);
		GetGatewayInformation(AF_INET);
		if (!Parameter.GatewayAvailable_IPv4)
		{
		#if defined(PLATFORM_WIN)
			if (!Parameter.GatewayAvailable_IPv6)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (!ErrorFirstPrint &&!Parameter.GatewayAvailable_IPv6)
		#endif
				PrintError(LOG_ERROR_NETWORK, L"Not any available gateways to public network", 0, nullptr, 0);

			Parameter.TunnelAvailable_IPv6 = false;
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			ErrorFirstPrint = false;
		#endif
		}

	//Auto-refresh
		Sleep(Parameter.FileRefreshTime);
	}

	PrintError(LOG_ERROR_SYSTEM, L"Get Local Address Information module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Convert service name to port
uint16_t __fastcall ServiceNameToHex(const char *OriginalBuffer)
{
	std::string Buffer(OriginalBuffer);

//Server name
	if (Buffer == "TCPMUX" || Buffer == "tcpmux")
		return htons(IPPORT_TCPMUX);
	else if (Buffer == "ECHO" || Buffer == "echo")
		return htons(IPPORT_ECHO);
	else if (Buffer == "DISCARD" || Buffer == "discard")
		return htons(IPPORT_DISCARD);
	else if (Buffer == "SYSTAT" || Buffer == "systat")
		return htons(IPPORT_SYSTAT);
	else if (Buffer == "DAYTIME" || Buffer == "daytime")
		return htons(IPPORT_DAYTIME);
	else if (Buffer == "NETSTAT" || Buffer == "netstat")
		return htons(IPPORT_NETSTAT);
	else if (Buffer == "QOTD" || Buffer == "qotd")
		return htons(IPPORT_QOTD);
	else if (Buffer == "MSP" || Buffer == "msp")
		return htons(IPPORT_MSP);
	else if (Buffer == "CHARGEN" || Buffer == "chargen")
		return htons(IPPORT_CHARGEN);
	else if (Buffer == "FTPDATA" || Buffer == "ftpdata")
		return htons(IPPORT_FTP_DATA);
	else if (Buffer == "FTP" || Buffer == "ftp")
		return htons(IPPORT_FTP);
	else if (Buffer == "SSH" || Buffer == "ssh")
		return htons(IPPORT_SSH);
	else if (Buffer == "TELNET" || Buffer == "telnet")
		return htons(IPPORT_TELNET);
	else if (Buffer == "SMTP" || Buffer == "smtp")
		return htons(IPPORT_SMTP);
	else if (Buffer == "TIME" || Buffer == "time")
		return htons(IPPORT_TIMESERVER);
	else if (Buffer == "RAP" || Buffer == "rap")
		return htons(IPPORT_RAP);
	else if (Buffer == "RLP" || Buffer == "rlp")
		return htons(IPPORT_RLP);
	else if (Buffer == "NAME" || Buffer == "name")
		return htons(IPPORT_NAMESERVER);
	else if (Buffer == "WHOIS" || Buffer == "whois")
		return htons(IPPORT_WHOIS);
	else if (Buffer == "TACACS" || Buffer == "tacacs")
		return htons(IPPORT_TACACS);
	else if (Buffer == "DNS" || Buffer == "dns")
		return htons(IPPORT_DNS);
	else if (Buffer == "XNSAUTH" || Buffer == "xnsauth")
		return htons(IPPORT_XNSAUTH);
	else if (Buffer == "MTP" || Buffer == "mtp")
		return htons(IPPORT_MTP);
	else if (Buffer == "BOOTPS" || Buffer == "bootps")
		return htons(IPPORT_BOOTPS);
	else if (Buffer == "BOOTPC" || Buffer == "bootpc")
		return htons(IPPORT_BOOTPC);
	else if (Buffer == "TFTP" || Buffer == "tftp")
		return htons(IPPORT_TFTP);
	else if (Buffer == "RJE" || Buffer == "rje")
		return htons(IPPORT_RJE);
	else if (Buffer == "FINGER" || Buffer == "finger")
		return htons(IPPORT_FINGER);
	else if (Buffer == "HTTP" || Buffer == "http")
		return htons(IPPORT_HTTP);
	else if (Buffer == "HTTPBACKUP" || Buffer == "httpbackup")
		return htons(IPPORT_HTTPBACKUP);
	else if (Buffer == "TTYLINK" || Buffer == "ttylink")
		return htons(IPPORT_TTYLINK);
	else if (Buffer == "SUPDUP" || Buffer == "supdup")
		return htons(IPPORT_SUPDUP);
	else if (Buffer == "POP3" || Buffer == "pop3")
		return htons(IPPORT_POP3);
	else if (Buffer == "SUNRPC" || Buffer == "sunrpc")
		return htons(IPPORT_SUNRPC);
	else if (Buffer == "SQL" || Buffer == "sql")
		return htons(IPPORT_SQL);
	else if (Buffer == "NTP" || Buffer == "ntp")
		return htons(IPPORT_NTP);
	else if (Buffer == "EPMAP" || Buffer == "epmap")
		return htons(IPPORT_EPMAP);
	else if (Buffer == "NETBIOSNS" || Buffer == "netbiosns")
		return htons(IPPORT_NETBIOS_NS);
	else if (Buffer == "NETBIOSDGM" || Buffer == "netbiosdgm")
		return htons(IPPORT_NETBIOS_DGM);
	else if (Buffer == "NETBIOSSSN" || Buffer == "netbiosssn")
		return htons(IPPORT_NETBIOS_SSN);
	else if (Buffer == "IMAP" || Buffer == "imap")
		return htons(IPPORT_IMAP);
	else if (Buffer == "BFTP" || Buffer == "bftp")
		return htons(IPPORT_BFTP);
	else if (Buffer == "SGMP" || Buffer == "sgmp")
		return htons(IPPORT_SGMP);
	else if (Buffer == "SQLSRV" || Buffer == "sqlsrv")
		return htons(IPPORT_SQLSRV);
	else if (Buffer == "DMSP" || Buffer == "dmsp")
		return htons(IPPORT_DMSP);
	else if (Buffer == "SNMP" || Buffer == "snmp")
		return htons(IPPORT_SNMP);
	else if (Buffer == "SNMPTRAP" || Buffer == "snmptrap")
		return htons(IPPORT_SNMP_TRAP);
	else if (Buffer == "ATRTMP" || Buffer == "atrtmp")
		return htons(IPPORT_ATRTMP);
	else if (Buffer == "ATHBP" || Buffer == "athbp")
		return htons(IPPORT_ATHBP);
	else if (Buffer == "QMTP" || Buffer == "qmtp")
		return htons(IPPORT_QMTP);
	else if (Buffer == "IPX" || Buffer == "ipx")
		return htons(IPPORT_IPX);
	else if (Buffer == "IMAP3" || Buffer == "imap3")
		return htons(IPPORT_IMAP3);
	else if (Buffer == "BGMP" || Buffer == "bgmp")
		return htons(IPPORT_BGMP);
	else if (Buffer == "TSP" || Buffer == "tsp")
		return htons(IPPORT_TSP);
	else if (Buffer == "IMMP" || Buffer == "immp")
		return htons(IPPORT_IMMP);
	else if (Buffer == "ODMR" || Buffer == "odmr")
		return htons(IPPORT_ODMR);
	else if (Buffer == "RPC2PORTMAP" || Buffer == "rpc2portmap")
		return htons(IPPORT_RPC2PORTMAP);
	else if (Buffer == "CLEARCASE" || Buffer == "clearcase")
		return htons(IPPORT_CLEARCASE);
	else if (Buffer == "HPALARMMGR" || Buffer == "hpalarmmgr")
		return htons(IPPORT_HPALARMMGR);
	else if (Buffer == "ARNS" || Buffer == "arns")
		return htons(IPPORT_ARNS);
	else if (Buffer == "AURP" || Buffer == "aurp")
		return htons(IPPORT_AURP);
	else if (Buffer == "LDAP" || Buffer == "ldap")
		return htons(IPPORT_LDAP);
	else if (Buffer == "UPS" || Buffer == "ups")
		return htons(IPPORT_UPS);
	else if (Buffer == "SLP" || Buffer == "slp")
		return htons(IPPORT_SLP);
	else if (Buffer == "HTTPS" || Buffer == "https")
		return htons(IPPORT_HTTPS);
	else if (Buffer == "SNPP" || Buffer == "snpp")
		return htons(IPPORT_SNPP);
	else if (Buffer == "MICROSOFTDS" || Buffer == "microsoftds")
		return htons(IPPORT_MICROSOFT_DS);
	else if (Buffer == "KPASSWD" || Buffer == "kpasswd")
		return htons(IPPORT_KPASSWD);
	else if (Buffer == "TCPNETHASPSRV" || Buffer == "tcpnethaspsrv")
		return htons(IPPORT_TCPNETHASPSRV);
	else if (Buffer == "RETROSPECT" || Buffer == "retrospect")
		return htons(IPPORT_RETROSPECT);
	else if (Buffer == "ISAKMP" || Buffer == "isakmp")
		return htons(IPPORT_ISAKMP);
	else if (Buffer == "BIFFUDP" || Buffer == "biffudp")
		return htons(IPPORT_BIFFUDP);
	else if (Buffer == "WHOSERVER" || Buffer == "whoserver")
		return htons(IPPORT_WHOSERVER);
	else if (Buffer == "SYSLOG" || Buffer == "syslog")
		return htons(IPPORT_SYSLOG);
	else if (Buffer == "ROUTERSERVER" || Buffer == "routerserver")
		return htons(IPPORT_ROUTESERVER);
	else if (Buffer == "NCP" || Buffer == "ncp")
		return htons(IPPORT_NCP);
	else if (Buffer == "COURIER" || Buffer == "courier")
		return htons(IPPORT_COURIER);
	else if (Buffer == "COMMERCE" || Buffer == "commerce")
		return htons(IPPORT_COMMERCE);
	else if (Buffer == "RTSP" || Buffer == "rtsp")
		return htons(IPPORT_RTSP);
	else if (Buffer == "NNTP" || Buffer == "nntp")
		return htons(IPPORT_NNTP);
	else if (Buffer == "HTTPRPCEPMAP" || Buffer == "httprpcepmap")
		return htons(IPPORT_HTTPRPCEPMAP);
	else if (Buffer == "IPP" || Buffer == "ipp")
		return htons(IPPORT_IPP);
	else if (Buffer == "LDAPS" || Buffer == "ldaps")
		return htons(IPPORT_LDAPS);
	else if (Buffer == "MSDP" || Buffer == "msdp")
		return htons(IPPORT_MSDP);
	else if (Buffer == "AODV" || Buffer == "aodv")
		return htons(IPPORT_AODV);
	else if (Buffer == "FTPSDATA" || Buffer == "ftpsdata")
		return htons(IPPORT_FTPSDATA);
	else if (Buffer == "FTPS" || Buffer == "ftps")
		return htons(IPPORT_FTPS);
	else if (Buffer == "NAS" || Buffer == "nas")
		return htons(IPPORT_NAS);
	else if (Buffer == "TELNETS" || Buffer == "telnets")
		return htons(IPPORT_TELNETS);

//No match.
	return FALSE;
}

//Convert DNS type name to hex
uint16_t __fastcall DNSTypeNameToHex(const char *OriginalBuffer)
{
	std::string Buffer(OriginalBuffer);

//DNS type name
	if (Buffer == "A" || Buffer == "a")
		return htons(DNS_RECORD_A);
	else if (Buffer == "NS" || Buffer == "ns")
		return htons(DNS_RECORD_NS);
	else if (Buffer == "MD" || Buffer == "md")
		return htons(DNS_RECORD_MD);
	else if (Buffer == "MF" || Buffer == "mf")
		return htons(DNS_RECORD_MF);
	else if (Buffer == "CNAME" || Buffer == "cname")
		return htons(DNS_RECORD_CNAME);
	else if (Buffer == "SOA" || Buffer == "soa")
		return htons(DNS_RECORD_SOA);
	else if (Buffer == "MB" || Buffer == "mb")
		return htons(DNS_RECORD_MB);
	else if (Buffer == "MG" || Buffer == "mg")
		return htons(DNS_RECORD_MG);
	else if (Buffer == "MR" || Buffer == "mr")
		return htons(DNS_RECORD_MR);
	else if (Buffer == "PTR" || Buffer == "ptr")
		return htons(DNS_RECORD_PTR);
	else if (Buffer == "NULL" || Buffer == "null")
		return htons(DNS_RECORD_NULL);
	else if (Buffer == "WKS" || Buffer == "wks")
		return htons(DNS_RECORD_WKS);
	else if (Buffer == "HINFO" || Buffer == "hinfo")
		return htons(DNS_RECORD_HINFO);
	else if (Buffer == "MINFO" || Buffer == "minfo")
		return htons(DNS_RECORD_MINFO);
	else if (Buffer == "MX" || Buffer == "mx")
		return htons(DNS_RECORD_MX);
	else if (Buffer == "TXT" || Buffer == "txt")
		return htons(DNS_RECORD_TXT);
	else if (Buffer == "RP" || Buffer == "rp")
		return htons(DNS_RECORD_RP);
	else if (Buffer == "SIG" || Buffer == "sig")
		return htons(DNS_RECORD_SIG);
	else if (Buffer == "AFSDB" || Buffer == "afsdb")
		return htons(DNS_RECORD_AFSDB);
	else if (Buffer == "X25" || Buffer == "x25")
		return htons(DNS_RECORD_X25);
	else if (Buffer == "ISDN" || Buffer == "isdn")
		return htons(DNS_RECORD_ISDN);
	else if (Buffer == "RT" || Buffer == "rt")
		return htons(DNS_RECORD_RT);
	else if (Buffer == "NSAP" || Buffer == "nsap")
		return htons(DNS_RECORD_NSAP);
	else if (Buffer == "NSAPPTR" || Buffer == "nsapptr")
		return htons(DNS_RECORD_NSAP_PTR);
	else if (Buffer == "SIG" || Buffer == "sig")
		return htons(DNS_RECORD_SIG);
	else if (Buffer == "KEY" || Buffer == "key")
		return htons(DNS_RECORD_KEY);
	else if (Buffer == "AAAA" || Buffer == "aaaa")
		return htons(DNS_RECORD_AAAA);
	else if (Buffer == "PX" || Buffer == "px")
		return htons(DNS_RECORD_PX);
	else if (Buffer == "GPOS" || Buffer == "gpos")
		return htons(DNS_RECORD_GPOS);
	else if (Buffer == "LOC" || Buffer == "loc")
		return htons(DNS_RECORD_LOC);
	else if (Buffer == "NXT" || Buffer == "nxt")
		return htons(DNS_RECORD_NXT);
	else if (Buffer == "EID" || Buffer == "eid")
		return htons(DNS_RECORD_EID);
	else if (Buffer == "NIMLOC" || Buffer == "nimloc")
		return htons(DNS_RECORD_NIMLOC);
	else if (Buffer == "SRV" || Buffer == "srv")
		return htons(DNS_RECORD_SRV);
	else if (Buffer == "ATMA" || Buffer == "atma")
		return htons(DNS_RECORD_ATMA);
	else if (Buffer == "NAPTR" || Buffer == "naptr")
		return htons(DNS_RECORD_NAPTR);
	else if (Buffer == "KX" || Buffer == "kx")
		return htons(DNS_RECORD_KX);
	else if (Buffer == "CERT" || Buffer == "cert")
		return htons(DNS_RECORD_CERT);
	else if (Buffer == "A6" || Buffer == "a6")
		return htons(DNS_RECORD_A6);
	else if (Buffer == "DNAME" || Buffer == "dname")
		return htons(DNS_RECORD_DNAME);
	else if (Buffer == "SINK" || Buffer == "sink")
		return htons(DNS_RECORD_SINK);
	else if (Buffer == "OPT" || Buffer == "opt")
		return htons(DNS_RECORD_OPT);
	else if (Buffer == "APL" || Buffer == "apl")
		return htons(DNS_RECORD_APL);
	else if (Buffer == "DS" || Buffer == "ds")
		return htons(DNS_RECORD_DS);
	else if (Buffer == "SSHFP" || Buffer == "sshfp")
		return htons(DNS_RECORD_SSHFP);
	else if (Buffer == "IPSECKEY" || Buffer == "ipseckey")
		return htons(DNS_RECORD_IPSECKEY);
	else if (Buffer == "RRSIG" || Buffer == "rrsig")
		return htons(DNS_RECORD_RRSIG);
	else if (Buffer == "NSEC" || Buffer == "nsec")
		return htons(DNS_RECORD_NSEC);
	else if (Buffer == "DNSKEY" || Buffer == "dnskey")
		return htons(DNS_RECORD_DNSKEY);
	else if (Buffer == "DHCID" || Buffer == "dhcid")
		return htons(DNS_RECORD_DHCID);
	else if (Buffer == "NSEC3" || Buffer == "nsec3")
		return htons(DNS_RECORD_NSEC3);
	else if (Buffer == "NSEC3PARAM" || Buffer == "nsec3param")
		return htons(DNS_RECORD_NSEC3PARAM);
	else if (Buffer == "TLSA" || Buffer == "tlsa")
		return htons(DNS_RECORD_TLSA);
	else if (Buffer == "HIP" || Buffer == "hip")
		return htons(DNS_RECORD_HIP);
	else if (Buffer == "HINFO" || Buffer == "hinfo")
		return htons(DNS_RECORD_HINFO);
	else if (Buffer == "RKEY" || Buffer == "rkey")
		return htons(DNS_RECORD_RKEY);
	else if (Buffer == "TALINK" || Buffer == "talink")
		return htons(DNS_RECORD_TALINK);
	else if (Buffer == "CDS" || Buffer == "cds")
		return htons(DNS_RECORD_CDS);
	else if (Buffer == "CDNSKEY" || Buffer == "cdnskey")
		return htons(DNS_RECORD_CDNSKEY);
	else if (Buffer == "OPENPGPKEY" || Buffer == "openpgpkey")
		return htons(DNS_RECORD_OPENPGPKEY);
	else if (Buffer == "SPF" || Buffer == "spf")
		return htons(DNS_RECORD_SPF);
	else if (Buffer == "UINFO" || Buffer == "uinfo")
		return htons(DNS_RECORD_UINFO);
	else if (Buffer == "UID" || Buffer == "uid")
		return htons(DNS_RECORD_UID);
	else if (Buffer == "GID" || Buffer == "gid")
		return htons(DNS_RECORD_GID);
	else if (Buffer == "UNSPEC" || Buffer == "unspec")
		return htons(DNS_RECORD_UNSPEC);
	else if (Buffer == "NID" || Buffer == "nid")
		return htons(DNS_RECORD_NID);
	else if (Buffer == "L32" || Buffer == "l32")
		return htons(DNS_RECORD_L32);
	else if (Buffer == "L64" || Buffer == "l64")
		return htons(DNS_RECORD_L64);
	else if (Buffer == "LP" || Buffer == "lp")
		return htons(DNS_RECORD_LP);
	else if (Buffer == "EUI48" || Buffer == "eui48")
		return htons(DNS_RECORD_EUI48);
	else if (Buffer == "EUI64" || Buffer == "eui64")
		return htons(DNS_RECORD_EUI64);
	else if (Buffer == "TKEY" || Buffer == "tkey")
		return htons(DNS_RECORD_TKEY);
	else if (Buffer == "TSIG" || Buffer == "tsig")
		return htons(DNS_RECORD_TSIG);
	else if (Buffer == "IXFR" || Buffer == "ixfr")
		return htons(DNS_RECORD_IXFR);
	else if (Buffer == "AXFR" || Buffer == "axfr")
		return htons(DNS_RECORD_AXFR);
	else if (Buffer == "MAILB" || Buffer == "mailb")
		return htons(DNS_RECORD_MAILB);
	else if (Buffer == "MAILA" || Buffer == "maila")
		return htons(DNS_RECORD_MAILA);
	else if (Buffer == "ANY" || Buffer == "any")
		return htons(DNS_RECORD_ANY);
	else if (Buffer == "URI" || Buffer == "uri")
		return htons(DNS_RECORD_URI);
	else if (Buffer == "CAA" || Buffer == "caa")
		return htons(DNS_RECORD_CAA);
	else if (Buffer == "TA" || Buffer == "ta")
		return htons(DNS_RECORD_TA);
	else if (Buffer == "DLV" || Buffer == "dlv")
		return htons(DNS_RECORD_DLV);
	else if (Buffer == "RESERVED" || Buffer == "reserved")
		return htons(DNS_RECORD_RESERVED);

//No match.
	return FALSE;
}

//Check IPv4/IPv6 special addresses
bool __fastcall CheckSpecialAddress(void *Addr, const uint16_t Protocol, char *Domain)
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
//			(((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == 0 && ((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x0212) || //2001::212
			((in6_addr *)Addr)->s6_words[1U] == htons(0x0DA8) && ((in6_addr *)Addr)->s6_words[2U] == htons(0x0112) && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == 0 && ((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x21AE) || //2001:DA8:112::21AE
			((in6_addr *)Addr)->s6_words[0] == htons(0x2003) && ((in6_addr *)Addr)->s6_words[1U] == htons(0x00FF) && ((in6_addr *)Addr)->s6_words[2U] == htons(0x0001) && ((in6_addr *)Addr)->s6_words[3U] == htons(0x0002) && ((in6_addr *)Addr)->s6_words[4U] == htons(0x0003) && ((in6_addr *)Addr)->s6_words[5U] == htons(0x0004) && ((in6_addr *)Addr)->s6_words[6U] == htons(0x5FFF) /* && ((in6_addr *)Addr)->s6_words[7U] == htons(0x0006) */ || //2003:FF:1:2:3:4:5FFF:xxxx
			((in6_addr *)Addr)->s6_words[0] == htons(0x2123) && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == 0 && ((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x3E12) || //2123::3E12
		//Special-use and reserved addresses, see https://en.wikipedia.org/wiki/IPv6_address#Presentation and https://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv6_addresses.
			(((in6_addr *)Addr)->s6_words[0] == 0 && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && 
			((((in6_addr *)Addr)->s6_words[5U] == 0 && 
			((((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == 0 || //Unspecified Addresses(::, Section 2.5.2 in RFC 4291)
			((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x0001)) || //Loopback Addresses(::1, Section 2.5.3 in RFC 4291)
			((in6_addr *)Addr)->s6_words[5U] == 0)) || //IPv4-Compatible Contrast Addresses(::/96, Section 2.5.5.1 in RFC 4291)
			((in6_addr *)Addr)->s6_words[5U] == htons(0xFFFF))) || //IPv4-mapped Addresses(::FFFF:0:0/96, Section 2.5.5 in RFC 4291)
//			((in6_addr *)Addr)->s6_words[0] == htons(0x0064) && ((in6_addr *)Addr)->s6_words[1U] == htons(0xFF9B) && ((in6_addr *)Addr)->s6_words[2U] == 0 && ((in6_addr *)Addr)->s6_words[3U] == 0 && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == 0 || //Well Known Prefix Addresses(64:FF9B::/96, Section 2.1 in RFC 4773)
			((in6_addr *)Addr)->s6_words[0] == htons(0x0100) && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[1U] == 0 && ((in6_addr *)Addr)->s6_words[1U] == 0 || //Discard Prefix Addresses(100::/64, Section 4 RFC 6666)
			((in6_addr *)Addr)->s6_words[0] == htons(0x2001) && 
			(((in6_addr *)Addr)->s6_words[1U] == 0 || //Teredo relay/tunnel Addresses(2001::/32, RFC 4380)
			((in6_addr *)Addr)->s6_bytes[2U] == 0 && ((in6_addr *)Addr)->s6_bytes[3U] <= 0x07 || //Sub-TLA IDs assigned to IANA Addresses(2001:0000::/29, Section 2 in RFC 4773)
			((in6_addr *)Addr)->s6_bytes[3U] >= 0x10 && ((in6_addr *)Addr)->s6_bytes[3U] <= 0x1F || //Overlay Routable Cryptographic Hash IDentifiers/ORCHID Addresses(2001:10::/28 in RFC 4843)
			((in6_addr *)Addr)->s6_bytes[2U] >= 0x01 && ((in6_addr *)Addr)->s6_bytes[3U] >= 0xF8 || //Sub-TLA IDs assigned to IANA Addresses(2001:01F8::/29, Section 2 in RFC 4773)
			((in6_addr *)Addr)->s6_words[1U] == htons(0x0DB8)) || //Contrast Address prefix reserved for documentation Addresses(2001:DB8::/32, RFC 3849)
//			((in6_addr *)Addr)->s6_words[0] == htons(0x2002) || //6to4 relay/tunnel Addresses(2002::/16, Section 2 in RFC 3056)
			((in6_addr *)Addr)->s6_words[0] == htons(0x3FFE) && ((in6_addr *)Addr)->s6_words[1U] == 0 || //6bone Addresses(3FFE::/16, RFC 3701)
			((in6_addr *)Addr)->s6_bytes[0] == 0x5F || //6bone(5F00::/8, RFC 3701)
//			((in6_addr *)Addr)->s6_bytes[0] >= 0xFC && ((in6_addr *)Addr)->s6_bytes[0] <= 0xFD || //Unique Local Unicast Addresses/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
			((in6_addr *)Addr)->s6_bytes[0] == 0xFE && 
			(((in6_addr *)Addr)->s6_bytes[1U] >= 0x80 && (((in6_addr *)Addr)->s6_bytes[1U] <= 0xBF || //Link-Local Unicast Contrast Addresses/LUC(FE80::/10, Section 2.5.6 in RFC 4291)
//			((in6_addr *)Addr)->s6_bytes[1U] <= 0xBF && ((in6_addr *)Addr)->s6_words[4U] == 0 && ((in6_addr *)Addr)->s6_words[5U] == htons(0x5EFE)) || //ISATAP Interface Identifiers Addresses(Prefix:0:5EFE:0:0:0:0/64, which also in Link-Local Unicast Contrast Addresses/LUC, Section 6.1 in RFC 5214)
			((in6_addr *)Addr)->s6_bytes[1U] >= 0xC0))) //Site-Local scoped Addresses(FEC0::/10, RFC 3879)
//			((in6_addr *)Addr)->s6_bytes[0] == 0xFF || //Multicast Addresses(FF00::/8, Section 2.7 in RFC 4291)
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
								CompareAddresses(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr, AF_INET6) >= ADDRESS_COMPARE_EQUAL && 
								CompareAddresses(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.End)->sin6_addr, AF_INET6) <= ADDRESS_COMPARE_EQUAL || 
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
				if (AddressHostsTableIter.TargetAddress.front().ss_family == AF_INET6)
				{
					for (auto AddressRangeTableIter:AddressHostsTableIter.SourceAddress)
					{
						if (AddressRangeTableIter.Begin.ss_family == AF_INET6 && AddressRangeTableIter.End.ss_family == AF_INET6 && 
							CompareAddresses(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr, AF_INET6) >= ADDRESS_COMPARE_EQUAL && 
							CompareAddresses(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.End)->sin6_addr, AF_INET6) <= ADDRESS_COMPARE_EQUAL || 
							memcmp(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr, sizeof(in6_addr)) == 0)
						{
							if (AddressHostsTableIter.TargetAddress.size() > 1U)
							{
							//Get a ramdom one.
								std::uniform_int_distribution<int> RamdomDistribution(0, (int)AddressHostsTableIter.TargetAddress.size() - 1U);
								*(in6_addr *)Addr = ((PSOCKADDR_IN6)&AddressHostsTableIter.TargetAddress.at(RamdomDistribution(*Parameter.RamdomEngine)))->sin6_addr;
							}
							else {
								*(in6_addr *)Addr = ((PSOCKADDR_IN6)&AddressHostsTableIter.TargetAddress.front())->sin6_addr;
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
		//Special-use and reserved addresses, see https://en.wikipedia.org/wiki/IPv4#Special-use_addresses and https://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv4_addresses.
			((in_addr *)Addr)->s_net == 0 || //Current network whick only valid as source Addresses(0.0.0.0/8, Section 3.2.1.3 in RFC 1122)
//			((in_addr *)Addr)->s_net == 0x0A || //Private class A Addresses(10.0.0.0/8, Section 3 in RFC 1918)
			((in_addr *)Addr)->s_net == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
//			((in_addr *)Addr)->s_net == && ((in_addr *)Addr)->s_host > 0x40 && ((in_addr *)Addr)->s_host < 0x7F || //Carrier-grade NAT Addresses(100.64.0.0/10, Section 7 in RFC 6598)
			((in_addr *)Addr)->s_net == 0xA9 && ((in_addr *)Addr)->s_host >= 0xFE || //Link-local Addresses(169.254.0.0/16, Section 1.5 in RFC 3927)
//			((in_addr *)Addr)->s_net == 0xAC && ((in_addr *)Addr)->s_host >= 0x10 && ((in_addr *)Addr)->s_host <= 0x1F || //Private class B Addresses(172.16.0.0/16, Section 3 in RFC 1918)
			((in_addr *)Addr)->s_net == 0xC0 && ((in_addr *)Addr)->s_host == 0 && ((in_addr *)Addr)->s_lh == 0 && ((in_addr *)Addr)->s_impno >= 0 && ((in_addr *)Addr)->s_impno < 0x08 || //DS-Lite transition mechanism Addresses(192.0.0.0/29, Section 3 in RFC 6333)
			((in_addr *)Addr)->s_net == 0xC0 && (((in_addr *)Addr)->s_host == 0 && (((in_addr *)Addr)->s_lh == 0 || //Reserved for IETF protocol assignments Addresses(192.0.0.0/24, Section 3 in RFC 5735)
			((in_addr *)Addr)->s_lh == 0x02)) || //TEST-NET-1 Addresses(192.0.2.0/24, Section 3 in RFC 5735)
//			((in_addr *)Addr)->s_host == 0x58 && ((in_addr *)Addr)->s_lh == 0x63 || //6to4 relay/tunnel Addresses(192.88.99.0/24, Section 2.3 in RFC 3068)
//			((in_addr *)Addr)->s_net == 0xC0 && ((in_addr *)Addr)->s_host == 0xA8 || //Private class C Addresses(192.168.0.0/24, Section 3 in RFC 1918)
			((in_addr *)Addr)->s_net == 0xC6 && (((in_addr *)Addr)->s_host == 0x12 || //Benchmarking Methodology for Network Interconnect Devices Addresses(198.18.0.0/15, Section 11.4.1 in RFC 2544)
			((in_addr *)Addr)->s_host == 0x33 && ((in_addr *)Addr)->s_lh == 0x64) || //TEST-NET-2 Addresses(198.51.100.0/24, Section 3 in RFC 5737)
			((in_addr *)Addr)->s_net == 0xCB && ((in_addr *)Addr)->s_host == 0 && ((in_addr *)Addr)->s_lh == 0x71 || //TEST-NET-3 Addresses(203.0.113.0/24, Section 3 in RFC 5737)
//			((in_addr *)Addr)->s_net == 0xE0 || //Multicast Addresses(224.0.0.0/4, Section 2 in RFC 3171)
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
								CompareAddresses(Addr, &((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr, AF_INET) >= ADDRESS_COMPARE_EQUAL && 
								CompareAddresses(Addr, &((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr, AF_INET) <= ADDRESS_COMPARE_EQUAL || 
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
				if (AddressHostsTableIter.TargetAddress.front().ss_family == AF_INET)
				{
					for (auto AddressRangeTableIter:AddressHostsTableIter.SourceAddress)
					{
						if (AddressRangeTableIter.Begin.ss_family == AF_INET && AddressRangeTableIter.End.ss_family == AF_INET && 
							CompareAddresses(Addr, &((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr, AF_INET) >= ADDRESS_COMPARE_EQUAL && 
							CompareAddresses(Addr, &((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr, AF_INET) <= ADDRESS_COMPARE_EQUAL || 
							((in_addr *)Addr)->s_addr == ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_addr)
						{
							if (AddressHostsTableIter.TargetAddress.size() > 1U)
							{
							//Get a ramdom one.
								std::uniform_int_distribution<int> RamdomDistribution(0, (int)AddressHostsTableIter.TargetAddress.size() - 1U);
								*(in_addr *)Addr = ((PSOCKADDR_IN)&AddressHostsTableIter.TargetAddress.at(RamdomDistribution(*Parameter.RamdomEngine)))->sin_addr;
							}
							else {
								*(in_addr *)Addr = ((PSOCKADDR_IN)&AddressHostsTableIter.TargetAddress.front())->sin_addr;
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
		uint64_t *AddrFront = (uint64_t *)Addr, *AddrBack = (uint64_t *)((PUCHAR)Addr + 8U);
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
bool __fastcall CustomModeFilter(const void *OriginalAddr, const uint16_t Protocol)
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

	Checksum = (Checksum >> 16U) + (Checksum & UINT16_MAX);
	Checksum += (Checksum >> 16U);

	return (uint16_t)(~Checksum);
}

//Get ICMPv6 checksum
uint16_t __fastcall ICMPv6Checksum(const unsigned char *Buffer, const size_t Length, const in6_addr &Destination, const in6_addr &Source)
{
	std::shared_ptr<char> Validation(new char[sizeof(ipv6_psd_hdr) + Length]());
	memset(Validation.get(), 0, sizeof(ipv6_psd_hdr) + Length);

//Get checksum
	auto IPv6_Pseudo_Header = (pipv6_psd_hdr)Validation.get();
	IPv6_Pseudo_Header->Dst = Destination;
	IPv6_Pseudo_Header->Src = Source;
	IPv6_Pseudo_Header->Length = htonl((uint32_t)Length);
	IPv6_Pseudo_Header->NextHeader = IPPROTO_ICMPV6;
	memcpy_s(Validation.get() + sizeof(ipv6_psd_hdr), Length, Buffer + sizeof(ipv6_hdr), Length);
	return GetChecksum((PUINT16)Validation.get(), sizeof(ipv6_psd_hdr) + Length);
}

//Get TCP or UDP checksum
uint16_t __fastcall TCPUDPChecksum(const unsigned char *Buffer, const size_t Length, const uint16_t NetworkLayer, const uint16_t TransportLayer)
{
//Get checksum.
	uint16_t Result = EXIT_FAILURE;
	if (NetworkLayer == AF_INET6) //IPv6
	{
		std::shared_ptr<char> Validation(new char[sizeof(ipv6_psd_hdr) + Length]());
		memset(Validation.get(), 0, sizeof(ipv6_psd_hdr) + Length);
		auto IPv6_Pseudo_Header = (pipv6_psd_hdr)Validation.get();
		IPv6_Pseudo_Header->Dst = ((pipv6_hdr)Buffer)->Dst;
		IPv6_Pseudo_Header->Src = ((pipv6_hdr)Buffer)->Src;
		IPv6_Pseudo_Header->Length = htonl((uint32_t)Length);
		IPv6_Pseudo_Header->NextHeader = (uint8_t)TransportLayer;

		memcpy_s(Validation.get() + sizeof(ipv6_psd_hdr), Length, Buffer + sizeof(ipv6_hdr), Length);
		Result = GetChecksum((PUINT16)Validation.get(), sizeof(ipv6_psd_hdr) + Length);
	}
	else { //IPv4
		auto IPv4_Header = (pipv4_hdr)Buffer;
		std::shared_ptr<char> Validation(new char[sizeof(ipv4_psd_hdr) + Length]());
		memset(Validation.get(), 0, sizeof(ipv4_psd_hdr) + Length);
		auto IPv4_Pseudo_Header = (pipv4_psd_hdr)Validation.get();
		IPv4_Pseudo_Header->Dst = ((pipv4_hdr)Buffer)->Dst;
		IPv4_Pseudo_Header->Src = ((pipv4_hdr)Buffer)->Src;
		IPv4_Pseudo_Header->Length = htons((uint16_t)Length);
		IPv4_Pseudo_Header->Protocol = (uint8_t)TransportLayer;

		memcpy_s(Validation.get() + sizeof(ipv4_psd_hdr), Length, Buffer + IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES, Length);
		Result = GetChecksum((PUINT16)Validation.get(), sizeof(ipv4_psd_hdr) + Length);
	}

	return Result;
}

//Add length parameters to TCP DNS transmission
size_t __fastcall AddLengthToTCPDNSHeader(PSTR Buffer, const size_t RecvLen, const size_t MaxLen)
{
	if (MaxLen >= RecvLen + sizeof(uint16_t))
	{
		memmove_s(Buffer + sizeof(uint16_t), MaxLen, Buffer, RecvLen);
		auto DNS_TCP_Header = (pdns_tcp_hdr)Buffer;
		DNS_TCP_Header->Length = htons((uint16_t)RecvLen);
		return RecvLen + sizeof(uint16_t);
	}

	return EXIT_FAILURE;
}

//Convert data from chars to DNS query
size_t __fastcall CharToDNSQuery(const char *FName, PSTR TName)
{
	int Index[] = {(int)strnlen_s(FName, DOMAIN_MAXSIZE) - 1, 0, 0};
	Index[2U] = Index[0] + 1;
	TName[Index[0] + 2] = 0;

	for (;Index[0] >= 0;--Index[0], --Index[2U])
	{
		if (FName[Index[0]] == ASCII_PERIOD)
		{
			TName[Index[2U]] = (char)Index[1U];
			Index[1U] = 0;
		}
		else
		{
			TName[Index[2U]] = FName[Index[0]];
			++Index[1U];
		}
	}

	TName[Index[2U]] = (char)Index[1U];
	return strnlen_s(TName, DOMAIN_MAXSIZE - 1U) + 1U;
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
		else if ((UCHAR)Buffer[Index] >= 0xC0) //Pointer
		{
			return Index + sizeof(uint16_t) - 1U;
		}
	}

	return Index;
}

//Convert data from DNS query to chars
size_t __fastcall DNSQueryToChar(const char *TName, PSTR FName)
{
//Initialization
	size_t uIndex = 0;
	int Index[] = {0, 0};

//Convert domain.
	for (uIndex = 0;uIndex < DOMAIN_MAXSIZE;++uIndex)
	{
	//Pointer
		if ((UCHAR)TName[uIndex] >= 0xC0)
		{
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

	return uIndex;
}

//Flush DNS cache
void __fastcall FlushSystemDNSCache(void)
{
//Flush DNS cache in program.
	std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	DNSCacheList.clear();
	DNSCacheList.shrink_to_fit();
	DNSCacheListMutex.unlock();

//Flush DNS cache in system.
#if defined(PLATFORM_WIN)
	system("ipconfig /flushdns");
#elif defined(PLATFORM_LINUX)
	system("service nscd restart"); //Name Service Cache Daemon service
	system("service dnsmasq restart"); //Dnsmasq service
	system("rndc restart"); //Name server control utility or BIND DNS service
#elif defined(PLATFORM_MACX)
//	system("lookupd -flushcache"); //Less than Mac OS X Tiger(10.4)
//	system("dscacheutil -flushcache"); //Mac OS X Leopard(10.5) and Snow Leopard(10.6)
	system("killall -HUP mDNSResponder"); //Mac OS X Lion(10.7), Mountain Lion(10.8) and Mavericks(10.9)
	system("discoveryutil mdnsflushcache"); //Mac OS X Yosemite(10.10) and other latest version
#endif

	return;
}

//Make ramdom domains
void __fastcall MakeRamdomDomain(PSTR Buffer)
{
//Ramdom number distribution initialization
	std::uniform_int_distribution<int> RamdomDistribution(0, DOMAIN_LEVEL_DATA_MAXSIZE);

//Make ramdom domain length.
	size_t RamdomLength = RamdomDistribution(*Parameter.RamdomEngine), Index = 0;
	if (RamdomLength < 4U)
		RamdomLength += 7U; //The shortest domain length is 3 bytes.

//Make ramdom domain.
	if (RamdomLength % 2U == 0)
	{
		for (Index = 0;Index < RamdomLength - 3U;++Index)
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
		for (Index = 0;Index < RamdomLength - 4U;++Index)
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
		for (Index = 0;Index < strnlen_s(Buffer, DOMAIN_MAXSIZE);++Index)
		{
			if (Index % 2U == 0 && *(Buffer + Index) > ASCII_ACCENT && *(Buffer + Index) < ASCII_BRACES_LEAD)
				*(Buffer + Index) -= ASCII_LOWER_TO_UPPER;
		}
	}
	else {
		for (Index = 0;Index < strnlen_s(Buffer, DOMAIN_MAXSIZE);++Index)
		{
			if (Index % 2U != 0 && *(Buffer + Index) > ASCII_ACCENT && *(Buffer + Index) < ASCII_BRACES_LEAD)
				*(Buffer + Index) -= ASCII_LOWER_TO_UPPER;
		}
	}

	return;
}

//Make Compression Pointer Mutation
size_t __fastcall MakeCompressionPointerMutation(char *Buffer, const size_t Length)
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
					++Index;
				else //Pointer to Additional(2)
					Index += 2U;
			}
		}break;
		case 1U:
		{
			if (!Parameter.CPMPointerToRR)
			{
				if (Parameter.CPMPointerToHeader)
					--Index;
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
					--Index;
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
		memmove_s(Buffer + Length - sizeof(dns_qry) + 1U, sizeof(dns_qry), Buffer + Length - sizeof(dns_qry), sizeof(dns_qry));
		*(Buffer + Length - sizeof(dns_qry) - 1U) = '\xC0';

	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
		if (Parameter.GetTickCount64PTR != nullptr)
			Index = (*Parameter.GetTickCount64PTR)() % 4U;
		else 
			Index = GetTickCount() % 4U;
	#else
		Index = GetTickCount64() % 4U;
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
		std::shared_ptr<dns_qry> DNS_Query(new dns_qry());
		memset(DNS_Query.get(), 0, sizeof(dns_qry));
		memcpy_s(DNS_Query.get(), sizeof(dns_qry), Buffer + DNS_PACKET_QUERY_LOCATE(Buffer), sizeof(dns_qry));
		memmove_s(Buffer + sizeof(dns_hdr) + sizeof(uint16_t) + sizeof(dns_qry), Length, Buffer + sizeof(dns_hdr), strnlen_s(Buffer + sizeof(dns_hdr), Length - sizeof(dns_hdr)) + 1U);
		memcpy_s(Buffer + sizeof(dns_hdr) + sizeof(uint16_t), Length - sizeof(dns_hdr) - sizeof(uint16_t), DNS_Query.get(), sizeof(dns_qry));
		*(Buffer + sizeof(dns_hdr)) = '\xC0';
		*(Buffer + sizeof(dns_hdr) + 1U) = '\x12';

		if (Index == 1U) //Pointer to RR, like "[DNS Header][Pointer][Query][Domain]" and the pointer is point to [Domain].
		{
			return Length + 2U;
		}
		else { //Pointer to Additional, like "[DNS Header][Pointer][Query][Additional]" and the pointer is point to domain in [Additional].
			auto DNS_Header = (pdns_hdr)Buffer;
			DNS_Header->Additional = htons(U16_NUM_ONE);

		//Ramdom number distribution initialization
			std::uniform_int_distribution<int> RamdomDistribution_Additional(0, UINT32_MAX);

		//Make records.
			if (DNS_Query->Type == htons(DNS_RECORD_AAAA))
			{
				auto DNS_Record_AAAA = (pdns_record_aaaa)(Buffer + Length);
				DNS_Record_AAAA->Type = htons(DNS_RECORD_AAAA);
				DNS_Record_AAAA->Classes = htons(DNS_CLASS_IN);
				DNS_Record_AAAA->TTL = htonl(RamdomDistribution_Additional(*Parameter.RamdomEngine));
				DNS_Record_AAAA->Length = htons(sizeof(in6_addr));
				for (Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);++Index)
					DNS_Record_AAAA->Addr.s6_words[Index] = htons((uint16_t)RamdomDistribution_Additional(*Parameter.RamdomEngine));

				return Length + sizeof(dns_record_aaaa);
			}
			else {
				auto DNS_Record_A = (pdns_record_a)(Buffer + Length);
				DNS_Record_A->Type = htons(DNS_RECORD_A);
				DNS_Record_A->Classes = htons(DNS_CLASS_IN);
				DNS_Record_A->TTL = htonl(RamdomDistribution_Additional(*Parameter.RamdomEngine));
				DNS_Record_A->Length = htons(sizeof(in_addr));
				DNS_Record_A->Addr.s_addr = htonl(RamdomDistribution_Additional(*Parameter.RamdomEngine));

				return Length + sizeof(dns_record_a);
			}
		}
	}

	return EXIT_FAILURE;
}

//Check DNS response results.
bool __fastcall CheckResponseData(const char *Buffer, const size_t Length, const bool IsLocal, bool *IsMarkHopLimit)
{
	auto DNS_Header = (pdns_hdr)Buffer;

//DNS Options part
	if (Parameter.DNSDataCheck && (DNS_Header->Questions != htons(U16_NUM_ONE) || //Question Resource Records must be one.
		ntohs(DNS_Header->Flags) >> 15U == 0 || //No any Question Resource Records
		(ntohs(DNS_Header->Flags) & DNS_GET_BIT_AA) != 0 && DNS_Header->Authority == 0 && DNS_Header->Additional == 0 || //Responses are not authoritative when there are no any Authoritative Nameservers Records and Additional Resource Records.
		IsLocal && ((ntohs(DNS_Header->Flags) & DNS_GET_BIT_RCODE) > DNS_RCODE_NOERROR || (ntohs(DNS_Header->Flags) & DNS_GET_BIT_TC) != 0 && DNS_Header->Answer == 0) || //Local requesting failed or Truncated(xxxxxx1xxxxxxxxx & 0000001000000000 >> 9 == 1)
		Parameter.EDNS0Label && DNS_Header->Additional == 0)) //Additional EDNS0 Label Resource Records check
			return false;

	if (IsMarkHopLimit != nullptr && (Parameter.DNSDataCheck && 
		DNS_Header->Answer != htons(U16_NUM_ONE) || //Less than or more than one Answer Record
		DNS_Header->Authority > 0 || DNS_Header->Additional > 0)) //Authority Records and/or Additional Records
			*IsMarkHopLimit = true;

//No Such Name, not standard query response and no error check.
	if (IsMarkHopLimit != nullptr && Parameter.DNSDataCheck && 
		(ntohs(DNS_Header->Flags) & DNS_GET_BIT_RCODE) == DNS_RCODE_NXDOMAIN)
	{
		*IsMarkHopLimit = true;
		return true;
	}

//Responses question pointer check
	if (Parameter.DNSDataCheck)
	{
		for (size_t Index = sizeof(dns_hdr);Index < DNS_PACKET_QUERY_LOCATE(Buffer);++Index)
		{
			if (*(Buffer + Index) == '\xC0')
				return false;
		}
	}

	std::shared_ptr<char> Domain(new char[DOMAIN_MAXSIZE]());
	memset(Domain.get(), 0, DOMAIN_MAXSIZE);
	DNSQueryToChar(Buffer + sizeof(dns_hdr), Domain.get());
//Domain Test part
	if (IsMarkHopLimit != nullptr && Parameter.DomainTestData != nullptr)
	{
		if (strnlen_s(Domain.get(), DOMAIN_MAXSIZE) == strnlen_s(Parameter.DomainTestData, DOMAIN_MAXSIZE) && 
			memcmp(Domain.get(), Parameter.DomainTestData, strnlen_s(Parameter.DomainTestData, DOMAIN_MAXSIZE)) == 0 && DNS_Header->ID == Parameter.DomainTestID)
		{
			*IsMarkHopLimit = true;
			return true;
		}
	}

//Check repeating DNS Domain without Compression.
	if (Parameter.DNSDataCheck && DNS_Header->Answer == htons(U16_NUM_ONE) && DNS_Header->Authority == 0 && DNS_Header->Additional == 0 && 
		CheckDNSQueryNameLength(Buffer + sizeof(dns_hdr)) == CheckDNSQueryNameLength(Buffer + DNS_PACKET_RR_LOCATE(Buffer)))
	{
		auto QuestionDomain = (uint8_t *)(Buffer + sizeof(dns_hdr));
		auto AnswerDomain = (uint8_t *)(Buffer + DNS_PACKET_RR_LOCATE(Buffer));
		auto DNS_Record_Standard = (pdns_record_standard)(Buffer + DNS_PACKET_RR_LOCATE(Buffer) + CheckDNSQueryNameLength((PSTR)QuestionDomain) + 1U);
		if (DNS_Record_Standard->Classes == htons(DNS_CLASS_IN) && 
			(DNS_Record_Standard->Type == htons(DNS_RECORD_A) || DNS_Record_Standard->Type == htons(DNS_RECORD_AAAA)) && 
			memcmp(QuestionDomain, AnswerDomain, CheckDNSQueryNameLength((PSTR)QuestionDomain) + 1U) == 0)
				return false;
	}

//DNS Responses which have one Answer Resource Records and no any Authority Resource Records or Additional Resource Records may fake.
	auto DNS_Query = (pdns_qry)(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer));
	size_t DataLength = DNS_PACKET_RR_LOCATE(Buffer);
	pdns_record_standard DNS_Record_Standard = nullptr;
	in6_addr *pin6_addr = nullptr;
	in_addr *pin_addr = nullptr;
	if (DNS_Header->Answer == htons(U16_NUM_ONE) && DNS_Header->Authority == 0 && DNS_Header->Additional == 0 && DNS_Query->Classes == htons(DNS_CLASS_IN))
	{
	//Records Type in responses check
		DataLength += CheckDNSQueryNameLength(Buffer + DataLength) + 1U;
		DNS_Record_Standard = (pdns_record_standard)(Buffer + DataLength);
		if (Parameter.DNSDataCheck && (DNS_Record_Standard->TTL == 0 || DNS_Record_Standard->Classes == htons(DNS_CLASS_IN) && 
			(DNS_Query->Type != htons(DNS_RECORD_A) && DNS_Record_Standard->Type == htons(DNS_RECORD_A) || 
			DNS_Query->Type != htons(DNS_RECORD_AAAA) && DNS_Record_Standard->Type == htons(DNS_RECORD_AAAA))))
				return false;

	//Check addresses.
		if (Parameter.Blacklist)
		{
			DataLength += sizeof(dns_record_standard);
			if (DNS_Record_Standard->Type == htons(DNS_RECORD_AAAA) && DNS_Record_Standard->Length == htons(sizeof(in6_addr)))
			{
				pin6_addr = (in6_addr *)(Buffer + DataLength);
				if (CheckSpecialAddress(pin6_addr, AF_INET6, Domain.get()) || 
					!Parameter.LocalHosts && Parameter.LocalRouting && IsLocal && !CheckAddressRouting(pin6_addr, AF_INET6))
						return false;
			}
			else if (DNS_Record_Standard->Type == htons(DNS_RECORD_A) && DNS_Record_Standard->Length == htons(sizeof(in_addr)))
			{
				pin_addr = (in_addr *)(Buffer + DataLength);
				if (CheckSpecialAddress(pin_addr, AF_INET, Domain.get()) || 
					!Parameter.LocalHosts && Parameter.LocalRouting && IsLocal && !CheckAddressRouting(pin_addr, AF_INET))
						return false;
			}
		}
	}
//Scan all results.
	else {
		for (size_t Index = 0;Index < (size_t)(ntohs(DNS_Header->Answer) + ntohs(DNS_Header->Authority) + ntohs(DNS_Header->Additional));++Index)
		{
		//Resource Records Name(Domain)
			DataLength += CheckDNSQueryNameLength(Buffer + DataLength) + 1U;
		//Length check
			if (DataLength > Length)
				return false;

		//Standard Resource Records
			DNS_Record_Standard = (pdns_record_standard)(Buffer + DataLength);
			DataLength += sizeof(dns_record_standard);
		//Length check
			if (DataLength > Length)
				return false;

		//Resource Records Data
			if (DNS_Record_Standard->Classes == htons(DNS_CLASS_IN) && DNS_Record_Standard->TTL > 0)
			{
				if (DNS_Record_Standard->Type == htons(DNS_RECORD_AAAA) && DNS_Record_Standard->Length == htons(sizeof(in6_addr)))
				{
				//Records Type in responses check
					if (Parameter.DNSDataCheck && DNS_Query->Type == htons(DNS_RECORD_A))
						return false;

				//Check addresses.
					pin6_addr = (in6_addr *)(Buffer + DataLength);
					if (Parameter.Blacklist && CheckSpecialAddress(pin6_addr, AF_INET6, Domain.get()) || 
						!Parameter.LocalHosts && Parameter.LocalRouting && IsLocal && !CheckAddressRouting(pin6_addr, AF_INET6))
							return false;
				}
				else if (DNS_Record_Standard->Type == htons(DNS_RECORD_A) && DNS_Record_Standard->Length == htons(sizeof(in_addr)))
				{
				//Records Type in responses check
					if (Parameter.DNSDataCheck && DNS_Query->Type == htons(DNS_RECORD_AAAA))
						return false;

				//Check addresses.
					pin_addr = (in_addr *)(Buffer + DataLength);
					if (Parameter.Blacklist && CheckSpecialAddress(pin_addr, AF_INET, Domain.get()) || 
						!Parameter.LocalHosts && Parameter.LocalRouting && IsLocal && !CheckAddressRouting(pin_addr, AF_INET))
							return false;
				}
			}

			DataLength += ntohs(DNS_Record_Standard->Length);
		//Length check
			if (DataLength > Length)
				return false;
		}
	}

	return true;
}
