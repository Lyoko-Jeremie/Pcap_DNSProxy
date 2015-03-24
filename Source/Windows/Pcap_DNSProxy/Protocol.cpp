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


#include "Protocol.h"

//Check empty buffer
bool __fastcall CheckEmptyBuffer(const void *Buffer, const size_t Length)
{
	if (Buffer == nullptr)
		return true;

	for (size_t Index = 0;Index < Length;Index++)
	{
		if (((uint8_t *)Buffer)[Index] != 0)
			return false;
	}

	return true;
}

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

//Convert lowercase/uppercase words to uppercase/lowercase words.
size_t __fastcall CaseConvert(bool IsLowerUpper, const PSTR Buffer, const size_t Length)
{
	for (size_t Index = 0;Index < Length;Index++)
	{
	//Lowercase to uppercase
		if (IsLowerUpper)
		{
//			if (Buffer[Index] > ASCII_ACCENT && Buffer[Index] < ASCII_BRACES_LEAD)
//				Buffer[Index] -= ASCII_LOWER_TO_UPPER;
			Buffer[Index] = (char)toupper(Buffer[Index]);
		}
	//Uppercase to lowercase
		else {
//			if (Buffer[Index] > ASCII_AT && Buffer[Index] < ASCII_BRACKETS_LEAD)
//				Buffer[Index] += ASCII_UPPER_TO_LOWER;
			Buffer[Index] = (char)tolower(Buffer[Index]);
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
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
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
		if (WSAStringToAddressA((PSTR)sAddrString.c_str(), AF_INET6, nullptr, (PSOCKADDR)SockAddr.get(), &SockLength) == SOCKET_ERROR)
	#endif
		{
			ErrorCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#ifdef _WIN64
	#else //x86
//		memcpy(OriginalAddr, &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, sizeof(in6_addr));
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
		if (WSAStringToAddressA((PSTR)sAddrString.c_str(), AF_INET, nullptr, (PSOCKADDR)SockAddr.get(), &SockLength) == SOCKET_ERROR)
	#endif
		{
			ErrorCode = WSAGetLastError();
			return EXIT_FAILURE;
		}
	#ifdef _WIN64
	#else //x86
//		memcpy(OriginalAddr, &((PSOCKADDR_IN)SockAddr.get())->sin_addr, sizeof(in_addr));
		memcpy_s(OriginalAddr, sizeof(in_addr), &((PSOCKADDR_IN)SockAddr.get())->sin_addr, sizeof(in_addr));
	#endif
	}

	return EXIT_SUCCESS;
}

//Get local address list
PADDRINFOA __fastcall GetLocalAddressList(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> HostName(new char[DOMAIN_MAXSIZE]());
	memset(HostName.get(), 0, DOMAIN_MAXSIZE);
	std::shared_ptr<addrinfo> Hints(new addrinfo());
	memset(Hints.get(), 0, sizeof(addrinfo));
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
		PrintError(LOG_ERROR_WINSOCK, L"Get localhost names error", WSAGetLastError(), nullptr, 0);
		return nullptr;
	}

//Get localhost data.
	int ResultGetaddrinfo = getaddrinfo(HostName.get(), nullptr, Hints.get(), &Result);
	if (ResultGetaddrinfo != 0)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Get localhost addresses error", ResultGetaddrinfo, nullptr, 0);

		freeaddrinfo(Result);
		return nullptr;
	}

	return Result;
}

//Get gateway information
void __fastcall GetGatewayInformation(const uint16_t Protocol)
{
/* Old version(2015-02-09)
//Minimum supported system of GetIpForwardTable2() is Windows Vista(Windows XP with SP3 support).
#ifdef _WIN64
	PMIB_IPFORWARD_TABLE2 IPForwardTable = nullptr;
	size_t Index = 0;
	auto GatewayAvailable = false;

	if (Protocol == AF_INET6) //IPv6
	{
	//Get default gateway.
		if (GetIpForwardTable2(AF_INET6, &IPForwardTable) == NO_ERROR)
		{
			for (Index = 0;Index < IPForwardTable->NumEntries;Index++)
			{
				if (!IPForwardTable->Table[Index].Loopback && IPForwardTable->Table[Index].DestinationPrefix.PrefixLength == 0 && 
					IPForwardTable->Table[Index].DestinationPrefix.Prefix.si_family == AF_INET6 && CheckEmptyBuffer(&IPForwardTable->Table[Index].DestinationPrefix.Prefix.Ipv6.sin6_addr, sizeof(in6_addr)))
				{
					GatewayAvailable = true;
					
				//IPv6 tunnels support(6to4, ISATAP and Teredo), but only check preferred address.
					if (IPForwardTable->Table[Index].NextHop.si_family == AF_INET6 && (CheckEmptyBuffer(&IPForwardTable->Table[Index].NextHop.Ipv6.sin6_addr, sizeof(in6_addr)) || //Default gateway is On-link.
						IPForwardTable->Table[Index].NextHop.Ipv6.sin6_addr.s6_words[0] == htons(0x2001) && IPForwardTable->Table[Index].NextHop.Ipv6.sin6_addr.s6_words[1U] == 0 || //Teredo relay/tunnel Addresses(2001::/32, RFC 4380)
						IPForwardTable->Table[Index].NextHop.Ipv6.sin6_addr.s6_words[0] == htons(0x2002) || //6to4 relay/tunnel Addresses(2002::/16, Section 2 in RFC 3056)
						IPForwardTable->Table[Index].NextHop.Ipv6.sin6_addr.s6_words[0] >= 0x80 && IPForwardTable->Table[Index].NextHop.Ipv6.sin6_addr.s6_words[1U] <= 0xBF && //Link-Local Unicast Contrast Addresses/LUC(FE80::/10, Section 2.5.6 in RFC 4291)
						IPForwardTable->Table[Index].NextHop.Ipv6.sin6_addr.s6_words[4U] == 0 && IPForwardTable->Table[Index].NextHop.Ipv6.sin6_addr.s6_words[5U] == htons(0x5EFE))) //ISATAP Interface Identifiers Addresses(Prefix:0:5EFE:0:0:0:0/64, which also in Link-Local Unicast Contrast Addresses/LUC, Section 6.1 in RFC 5214)
							Parameter.TunnelAvailable_IPv6 = true;

					break;
				}
			}

			if (!GatewayAvailable)
				Parameter.GatewayAvailable_IPv6 = false;
			else 
				Parameter.GatewayAvailable_IPv6 = true;
		}
		else {
			Parameter.GatewayAvailable_IPv6 = false;
		}
	}
	else { //IPv4
	//Get default gateway.
		if (GetIpForwardTable2(AF_INET, &IPForwardTable) == NO_ERROR)
		{
			for (Index = 0;Index < IPForwardTable->NumEntries;Index++)
			{
				if (!IPForwardTable->Table[Index].Loopback && IPForwardTable->Table[Index].DestinationPrefix.PrefixLength == 0 && 
					IPForwardTable->Table[Index].DestinationPrefix.Prefix.si_family == AF_INET && IPForwardTable->Table[Index].DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr == 0)
				{
					GatewayAvailable = true;
					Parameter.GatewayAvailable_IPv4 = true;
					break;
				}
			}

			if (!GatewayAvailable)
				Parameter.GatewayAvailable_IPv4 = false;
		}
		else {
			Parameter.GatewayAvailable_IPv4 = false;
		}
	}

//Cleanup structure.
	if (IPForwardTable != nullptr)
		FreeMibTable(IPForwardTable);
#else //x86
#endif
*/
	DWORD AdaptersIndex = 0;
	if (Protocol == AF_INET6) //IPv6
	{
/* Old version(2015-02-15)
		PSOCKADDR SockAddr = nullptr;

		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0)
		{
			SockAddr = (PSOCKADDR)&Parameter.DNSTarget.IPv6.AddressData.IPv6;
		}
		else if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
			SockAddr = (PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6;
		}
		else if (Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0)
		{
			SockAddr = (PSOCKADDR)&Parameter.DNSTarget.Local_IPv6.AddressData.IPv6;
		}
		else if (Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0)
		{
			SockAddr = (PSOCKADDR)&Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6;
		}
		else if (DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0)
		{
			SockAddr = (PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6;
		}
		else if (DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
			SockAddr = (PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6;
		}
	//IPv6 Multi
		else if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			SockAddr = (PSOCKADDR)&Parameter.DNSTarget.IPv6_Multi->front().AddressData.IPv6;
		}
		else {
			Parameter.GatewayAvailable_IPv6 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}

	//Get best interface to route.
		if (GetBestInterfaceEx((PSOCKADDR)SockAddr, &AdaptersIndex) == NO_ERROR)
		{
			Parameter.GatewayAvailable_IPv6 = true;
			ULONG BufferSize = 0;

		//Get Adapter of Index addresses information.
			if (GetAdaptersAddresses(AF_INET6, 0, nullptr, nullptr, &BufferSize) == ERROR_BUFFER_OVERFLOW && BufferSize > 0)
			{
				std::shared_ptr<char> AdaptersAddressesListBuffer(new char[BufferSize]());
				PIP_ADAPTER_ADDRESSES AdaptersAddressesList = (PIP_ADAPTER_ADDRESSES)AdaptersAddressesListBuffer.get();
				GetAdaptersAddresses(AF_INET6, 0, nullptr, AdaptersAddressesList, &BufferSize);
				while (AdaptersAddressesList != nullptr)
				{
				//IPv6 tunnels support(6to4, ISATAP and Teredo)
				//Windows XP with SP3 support
					if ((AdaptersIndex == AdaptersAddressesList->IfIndex || AdaptersIndex == AdaptersAddressesList->Ipv6IfIndex) && 
						(AdaptersAddressesList->IfType == IF_TYPE_TUNNEL || 
					#ifdef _WIN64
						AdaptersAddressesList->TunnelType != TUNNEL_TYPE_NONE))
					#else //x86
						IsGreaterThanVista() && AdaptersAddressesList->TunnelType != TUNNEL_TYPE_NONE || 
						!IsGreaterThanVista() && AdaptersAddressesList->FirstUnicastAddress->Address.iSockaddrLength == sizeof(sockaddr_in6) && 
						(((PSOCKADDR_IN6)AdaptersAddressesList->FirstUnicastAddress->Address.lpSockaddr)->sin6_addr.s6_words[0] == htons(0x2001) && ((PSOCKADDR_IN6)AdaptersAddressesList->FirstUnicastAddress->Address.lpSockaddr)->sin6_addr.s6_words[1U] == 0 || //Teredo relay/tunnel Addresses(2001::/32, RFC 4380)
						((PSOCKADDR_IN6)AdaptersAddressesList->FirstUnicastAddress->Address.lpSockaddr)->sin6_addr.s6_words[0] == htons(0x2002) || //6to4 relay/tunnel Addresses(2002::/16, Section 2 in RFC 3056)
						((PSOCKADDR_IN6)AdaptersAddressesList->FirstUnicastAddress->Address.lpSockaddr)->sin6_addr.s6_words[0] >= 0x80 && ((PSOCKADDR_IN6)AdaptersAddressesList->FirstUnicastAddress->Address.lpSockaddr)->sin6_addr.s6_words[1U] <= 0xBF && //Link-Local Unicast Contrast Addresses/LUC(FE80::/10, Section 2.5.6 in RFC 4291)
						((PSOCKADDR_IN6)AdaptersAddressesList->FirstUnicastAddress->Address.lpSockaddr)->sin6_addr.s6_words[4U] == 0 && ((PSOCKADDR_IN6)AdaptersAddressesList->FirstUnicastAddress->Address.lpSockaddr)->sin6_addr.s6_words[5U] == htons(0x5EFE)))) //ISATAP Interface Identifiers Addresses(Prefix:0:5EFE:0:0:0:0/64, which also in Link-Local Unicast Contrast Addresses/LUC, Section 6.1 in RFC 5214)
					#endif
					{
						Parameter.TunnelAvailable_IPv6 = true;
						break;
					}

				//Not any available IPv6 tunnels.
					if (AdaptersAddressesList->Next == nullptr)
					{
						Parameter.TunnelAvailable_IPv6 = false;
						break;
					}
					else {
						AdaptersAddressesList = AdaptersAddressesList->Next;
					}
				}
			}
		}
		else {

			Parameter.GatewayAvailable_IPv6 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}
*/
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0 && 
			Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family == 0 && 
			DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0 || 
			Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Local_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR)
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

		Parameter.GatewayAvailable_IPv6 = true;
		Parameter.TunnelAvailable_IPv6 = true;
	}
	else { //IPv4
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0 && 
			Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family == 0 && 
			DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0 || 
			Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Local_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR)
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

	PADDRINFOA LocalAddressList = nullptr, LocalAddressTableIter = nullptr;
	pdns_hdr DNS_Header = nullptr;
	pdns_qry DNS_Query = nullptr;
	pdns_record_aaaa DNS_Record_AAAA = nullptr;
	pdns_record_a DNS_Record_A = nullptr;
	for (;;)
	{
	//Get localhost addresses(IPv6)
		LocalAddressList = GetLocalAddressList(AF_INET6);
		if (LocalAddressList == nullptr)
		{
		//Auto-refresh
			if (Parameter.FileRefreshTime > 0)
			{
				Sleep((DWORD)Parameter.FileRefreshTime);
				continue;
			}
			else {
				Sleep(LOOP_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}
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
//			memcpy(Parameter.LocalAddress[0] + Parameter.LocalAddressLength[0], Parameter.LocalFQDN, Parameter.LocalFQDNLength);
			memcpy_s(Parameter.LocalAddress[0] + Parameter.LocalAddressLength[0], PACKET_MAXSIZE - Parameter.LocalAddressLength[0], Parameter.LocalFQDN, Parameter.LocalFQDNLength);
			Parameter.LocalAddressLength[0] += Parameter.LocalFQDNLength;
			DNS_Query = (pdns_qry)(Parameter.LocalAddress[0] + Parameter.LocalAddressLength[0]);
			DNS_Query->Type = htons(DNS_RECORD_AAAA);
			DNS_Query->Classes = htons(DNS_CLASS_IN);
			Parameter.LocalAddressLength[0] += sizeof(dns_qry);

		//Read addresses list and convert to Fully Qualified Domain Name/FQDN PTR.
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
						DNS_Header->Answer++;
					}

				//Initialization
					DNSPTRString.clear();
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

				//Convert from in6_addr to string.
					size_t AddrStringLen = 0;
					for (Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
					{
						_ultoa_s(htons(((PSOCKADDR_IN6)LocalAddressTableIter->ai_addr)->sin6_addr.s6_words[Index]), Addr.get(), ADDR_STRING_MAXSIZE, NUM_HEX);

					//Add zeros to beginning of string.
//						if (strlen(Addr.get()) < 4U)
						if (strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE) < 4U)
						{
//							AddrStringLen = strlen(Addr.get());
							AddrStringLen = strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);
//							memmove(Addr.get() + 4U - strlen(Addr.get()), Addr.get(), strlen(Addr.get()));
							memmove_s(Addr.get() + 4U - strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE), ADDR_STRING_MAXSIZE, Addr.get(), strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE));
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
			freeaddrinfo(LocalAddressList);
			LocalAddressList = nullptr;
		}

	//Get localhost addresses(IPv4)
		LocalAddressList = GetLocalAddressList(AF_INET);
		if (LocalAddressList == nullptr)
		{
		//Auto-refresh
			if (Parameter.FileRefreshTime > 0)
			{
				Sleep((DWORD)Parameter.FileRefreshTime);
				continue;
			}
			else {
				Sleep(LOOP_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}
		}
		else {
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
//			memcpy(Parameter.LocalAddress[1U] + Parameter.LocalAddressLength[1U], Parameter.LocalFQDN, Parameter.LocalFQDNLength);
			memcpy_s(Parameter.LocalAddress[1U] + Parameter.LocalAddressLength[1U], PACKET_MAXSIZE - Parameter.LocalAddressLength[1U], Parameter.LocalFQDN, Parameter.LocalFQDNLength);
			Parameter.LocalAddressLength[1U] += Parameter.LocalFQDNLength;
			DNS_Query = (pdns_qry)(Parameter.LocalAddress[1U] + Parameter.LocalAddressLength[1U]);
			DNS_Query->Type = htons(DNS_RECORD_AAAA);
			DNS_Query->Classes = htons(DNS_CLASS_IN);
			Parameter.LocalAddressLength[1U] += sizeof(dns_qry);

		//Read addresses list and convert to Fully Qualified Domain Name/FQDN PTR.
			for (LocalAddressTableIter = LocalAddressList; LocalAddressTableIter != nullptr; LocalAddressTableIter = LocalAddressTableIter->ai_next)
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
						DNS_Header->Answer++;
					}

				//Initialization
					DNSPTRString.clear();
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

				//Convert from in_addr to DNS PTR.
					_itoa_s(((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_impno, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
					Result.append(Addr.get());
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					Result.append(".");
					_itoa_s(((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_lh, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
					Result.append(Addr.get());
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					Result.append(".");
					_itoa_s(((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_host, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
					Result.append(Addr.get());
					memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
					Result.append(".");
					_itoa_s(((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_net, Addr.get(), ADDR_STRING_MAXSIZE, NUM_DECIMAL);
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
			freeaddrinfo(LocalAddressList);
			LocalAddressList = nullptr;
		}

	//Get gateway information and check.
		GetGatewayInformation(AF_INET6);
		GetGatewayInformation(AF_INET);
		if (!Parameter.GatewayAvailable_IPv4)
		{
			if (!Parameter.GatewayAvailable_IPv6)
				PrintError(LOG_ERROR_WINSOCK, L"Not any available gateways to public network", 0, nullptr, 0);
			Parameter.TunnelAvailable_IPv6 = false;
		}

	//Auto-refresh
		if (Parameter.FileRefreshTime > 0)
			Sleep((DWORD)Parameter.FileRefreshTime);
		else 
			Sleep(LOOP_INTERVAL_TIME * SECOND_TO_MILLISECOND);
	}

	PrintError(LOG_ERROR_SYSTEM, L"Get Local Address Information module Monitor terminated", 0, nullptr, 0);
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
	return FALSE;
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
	return FALSE;
}

//Check IPv4/IPv6 special addresses
bool __fastcall CheckSpecialAddress(void *Addr, const uint16_t Protocol, const PSTR Domain)
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
//			CaseConvert(false, Domain, strlen(Domain));
			CaseConvert(false, Domain, strnlen_s(Domain, DOMAIN_MAXSIZE));

		//Main check
			std::unique_lock<std::mutex> ResultBlacklistMutex(ResultBlacklistLock);
			for (auto ResultBlacklistTableIter:*ResultBlacklistUsing)
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

	//Address Hosts check
		std::unique_lock<std::mutex> AddressHostsListMutex(AddressHostsListLock);
		if (!AddressHostsListUsing->empty())
		{
		//Main check
			for (auto AddressHostsTableIter:*AddressHostsListUsing)
			{
				if (AddressHostsTableIter.TargetAddress.ss_family == AF_INET6)
				{
					for (auto AddressRangeTableIter:AddressHostsTableIter.Addresses)
					{
						if (AddressRangeTableIter.Begin.ss_family == AF_INET6 && AddressRangeTableIter.End.ss_family == AF_INET6 && 
							CompareAddresses(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr, AF_INET6) >= ADDRESS_COMPARE_EQUAL && 
							CompareAddresses(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.End)->sin6_addr, AF_INET6) <= ADDRESS_COMPARE_EQUAL || 
							memcmp(Addr, &((PSOCKADDR_IN6)&AddressRangeTableIter.Begin)->sin6_addr, sizeof(in6_addr)) == 0)
						{
							*(in6_addr *)Addr = ((PSOCKADDR_IN6)&AddressHostsTableIter.TargetAddress)->sin6_addr;
							break;
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
//			CaseConvert(false, Domain, strlen(Domain));
			CaseConvert(false, Domain, strnlen_s(Domain, DOMAIN_MAXSIZE));

		//Main check
			std::unique_lock<std::mutex> ResultBlacklistMutex(ResultBlacklistLock);
			for (auto ResultBlacklistTableIter:*ResultBlacklistUsing)
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

	//Address Hosts check
		std::unique_lock<std::mutex> AddressHostsListMutex(AddressHostsListLock);
		if (!AddressHostsListUsing->empty())
		{
		//Main check
			for (auto AddressHostsTableIter:*AddressHostsListUsing)
			{
				if (AddressHostsTableIter.TargetAddress.ss_family == AF_INET)
				{
					for (auto AddressRangeTableIter:AddressHostsTableIter.Addresses)
					{
						if (AddressRangeTableIter.Begin.ss_family == AF_INET && AddressRangeTableIter.End.ss_family == AF_INET && 
							CompareAddresses(Addr, &((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr, AF_INET) >= ADDRESS_COMPARE_EQUAL && 
							CompareAddresses(Addr, &((PSOCKADDR_IN)&AddressRangeTableIter.End)->sin_addr, AF_INET) <= ADDRESS_COMPARE_EQUAL || 
							((in_addr *)Addr)->s_addr == ((PSOCKADDR_IN)&AddressRangeTableIter.Begin)->sin_addr.s_addr)
						{
							*(in_addr *)Addr = ((PSOCKADDR_IN)&AddressHostsTableIter.TargetAddress)->sin_addr;
							break;
						}
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
/* Old version(2015-03-22)
	for (auto AddressPrefixTableIter:*LocalRoutingListUsing)
	{
		if (Protocol == AddressPrefixTableIter.AddressData.Storage.ss_family)
		{
		//IPv6
			if (Protocol == AF_INET6)
			{
				size_t Prefix = AddressPrefixTableIter.Prefix;
				for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
				{
					if (Prefix == sizeof(uint16_t) * BYTES_TO_BITS)
					{
						if (((in6_addr *)Addr)->s6_words[Index] == AddressPrefixTableIter.AddressData.IPv6.sin6_addr.s6_words[Index])
							return true;
						else
							break;
					}
					else if (Prefix > sizeof(uint16_t) * BYTES_TO_BITS)
					{
						if (((in6_addr *)Addr)->s6_words[Index] == AddressPrefixTableIter.AddressData.IPv6.sin6_addr.s6_words[Index])
							Prefix -= sizeof(uint16_t) * BYTES_TO_BITS;
						else
							break;
					}
					else {
						if (ntohs(((in6_addr *)Addr)->s6_words[Index]) >> (sizeof(uint16_t) * BYTES_TO_BITS - Prefix) ==
							ntohs(AddressPrefixTableIter.AddressData.IPv6.sin6_addr.s6_words[Index]) >> (sizeof(uint16_t) * BYTES_TO_BITS - Prefix))
								return true;
						else
							break;
					}
				}
			}
		//IPv4
			else {
				if (ntohl(((in_addr *)Addr)->s_addr) >> (sizeof(in_addr) * BYTES_TO_BITS - AddressPrefixTableIter.Prefix) == 
					ntohl(AddressPrefixTableIter.AddressData.IPv4.sin_addr.s_addr) >> (sizeof(in_addr) * BYTES_TO_BITS - AddressPrefixTableIter.Prefix))
						return true;
			}
		}
	}
*/
	if (Protocol == AF_INET6) //IPv6
	{
		uint64_t *AddrFront = (uint64_t *)Addr, *AddrBack = (uint64_t *)((PUCHAR)Addr + 8U);
		std::map<uint64_t, std::set<uint64_t>>::iterator AddrMapIter;
		for (auto LocalRoutingTableIter:*LocalRoutingList_IPv6_Using)
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
	else { //IPv4
		for (auto LocalRoutingTableIter:*LocalRoutingList_IPv4_Using)
		{
			if (LocalRoutingTableIter.AddressRoutingList_IPv4.count(ntohl(((in_addr *)Addr)->s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - LocalRoutingTableIter.Prefix))))
				return true;
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
			for (auto AddressRangeTableIter:*AddressRangeUsing)
			{
			//Check Protocol and Level.
				if (AddressRangeTableIter.Begin.ss_family != AF_INET6 || Parameter.IPFilterLevel > 0 && AddressRangeTableIter.Level < Parameter.IPFilterLevel)
					continue;

			//Check address.
				for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
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
	//Deny
		else {
			for (auto AddressRangeTableIter:*AddressRangeUsing)
			{
			//Check Protocol and Level.
				if (AddressRangeTableIter.Begin.ss_family != AF_INET6 || Parameter.IPFilterLevel > 0 && AddressRangeTableIter.Level < Parameter.IPFilterLevel)
					continue;

			//Check address.
				for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
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
	else { //IPv4
		auto Addr = (in_addr *)OriginalAddr;
	//Permit
		if (Parameter.IPFilterType)
		{
			for (auto AddressRangeTableIter:*AddressRangeUsing)
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
	//Deny
		else {
			for (auto AddressRangeTableIter:*AddressRangeUsing)
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

	return true;
}

/*
//Get Ethernet Frame Check Sequence/FCS
uint32_t __fastcall GetFCS(const PUINT8 Buffer, const size_t Length)
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
uint16_t __fastcall ICMPv6Checksum(const PUINT8 Buffer, const size_t Length, const in6_addr Destination, const in6_addr Source)
{
	std::shared_ptr<char> Validation(new char[sizeof(ipv6_psd_hdr) + Length]());
	memset(Validation.get(), 0, sizeof(ipv6_psd_hdr) + Length);

//Get checksum
	auto IPv6_Pseudo_Header = (pipv6_psd_hdr)Validation.get();
	IPv6_Pseudo_Header->Dst = Destination;
	IPv6_Pseudo_Header->Src = Source;
	IPv6_Pseudo_Header->Length = htonl((uint32_t)Length);
	IPv6_Pseudo_Header->NextHeader = IPPROTO_ICMPV6;
//	memcpy(Validation.get() + sizeof(ipv6_psd_hdr), Buffer + sizeof(ipv6_hdr), Length);
	memcpy_s(Validation.get() + sizeof(ipv6_psd_hdr), Length, Buffer + sizeof(ipv6_hdr), Length);
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
		memset(Validation.get(), 0, sizeof(ipv6_psd_hdr) + Length);
		auto IPv6_Pseudo_Header = (pipv6_psd_hdr)Validation.get();
		IPv6_Pseudo_Header->Dst = ((pipv6_hdr)Buffer)->Dst;
		IPv6_Pseudo_Header->Src = ((pipv6_hdr)Buffer)->Src;
		IPv6_Pseudo_Header->Length = htonl((uint32_t)Length);
		IPv6_Pseudo_Header->NextHeader = (uint8_t)TransportLayer;

//		memcpy(Validation.get() + sizeof(ipv6_psd_hdr), Buffer + sizeof(ipv6_hdr), Length);
		memcpy_s(Validation.get() + sizeof(ipv6_psd_hdr), Length, Buffer + sizeof(ipv6_hdr), Length);
		Result = GetChecksum((PUINT16)Validation.get(), sizeof(ipv6_psd_hdr) + Length);
	}
	else { //IPv4
		auto IPv4_Header = (pipv4_hdr)Buffer;
		std::shared_ptr<char> Validation(new char[sizeof(ipv4_psd_hdr) + Length /* - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES */ ]());
		memset(Validation.get(), 0, sizeof(ipv4_psd_hdr) + Length);
		auto IPv4_Pseudo_Header = (pipv4_psd_hdr)Validation.get();
		IPv4_Pseudo_Header->Dst = ((pipv4_hdr)Buffer)->Dst;
		IPv4_Pseudo_Header->Src = ((pipv4_hdr)Buffer)->Src;
		IPv4_Pseudo_Header->Length = htons((uint16_t) /* ( */ Length /* - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES) */ );
		IPv4_Pseudo_Header->Protocol = (uint8_t)TransportLayer;

//		memcpy(Validation.get() + sizeof(ipv4_psd_hdr), Buffer + IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES, Length /* - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES */ );
		memcpy_s(Validation.get() + sizeof(ipv4_psd_hdr), Length, Buffer + IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES, Length /* - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES */ );
		Result = GetChecksum((PUINT16)Validation.get(), sizeof(ipv4_psd_hdr) + Length /* - IPv4_Header->IHL * IPv4_IHL_BYTES_TIMES */ );
	}

	return Result;
}

//Add length parameters to TCP DNS transmission
size_t __fastcall AddLengthToTCPDNSHeader(PSTR Buffer, const size_t RecvLen, const size_t MaxLen)
{
	if (MaxLen >= RecvLen + sizeof(uint16_t))
	{
//		memmove(Buffer + sizeof(uint16_t), Buffer, RecvLen);
		memmove_s(Buffer + sizeof(uint16_t), MaxLen, Buffer, RecvLen);
		auto DNS_TCP_Header = (pdns_tcp_hdr)Buffer;
		DNS_TCP_Header->Length = htons((uint16_t)RecvLen);
		return RecvLen + sizeof(uint16_t);
	}
	
	return EXIT_FAILURE;
}

//Convert data from chars to DNS query
size_t __fastcall CharToDNSQuery(const PSTR FName, PSTR TName)
{
	int Index[] = {(int)strnlen_s(FName, DOMAIN_MAXSIZE) - 1, 0, 0};
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
	return strnlen_s(TName, DOMAIN_MAXSIZE - 1U) + 1U;
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
size_t __fastcall DNSQueryToChar(const PSTR TName, PSTR FName)
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
		RamdomLength += 7U; //The shortest domain length is 3 bytes.

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
//		for (Index = 0;Index < strlen(Buffer);Index++)
		for (Index = 0;Index < strnlen_s(Buffer, DOMAIN_MAXSIZE);Index++)
		{
			if (Index % 2U == 0 && *(Buffer + Index) > ASCII_ACCENT && *(Buffer + Index) < ASCII_BRACES_LEAD)
				*(Buffer + Index) -= ASCII_LOWER_TO_UPPER;
		}
	}
	else {
//		for (Index = 0;Index < strlen(Buffer);Index++)
		for (Index = 0;Index < strnlen_s(Buffer, DOMAIN_MAXSIZE);Index++)
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
//		memmove(Buffer + Length - sizeof(dns_qry) + 1U, Buffer + Length - sizeof(dns_qry), sizeof(dns_qry));
		memmove_s(Buffer + Length - sizeof(dns_qry) + 1U, sizeof(dns_qry), Buffer + Length - sizeof(dns_qry), sizeof(dns_qry));
		*(Buffer + Length - sizeof(dns_qry) - 1U) = '\xC0';

	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
	#ifdef _WIN64
		Index = GetTickCount64() % 4U;
	#else //_x86
		if (Parameter.GetTickCount64PTR != nullptr)
			Index = (*Parameter.GetTickCount64PTR)() % 4U;
		else 
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
		std::shared_ptr<dns_qry> DNS_Query(new dns_qry());
		memset(DNS_Query.get(), 0, sizeof(dns_qry));
//		memcpy(DNS_Query.get(), Buffer + DNS_PACKET_QUERY_LOCATE(Buffer), sizeof(dns_qry));
		memcpy_s(DNS_Query.get(), sizeof(dns_qry), Buffer + DNS_PACKET_QUERY_LOCATE(Buffer), sizeof(dns_qry));
//		memmove(Buffer + sizeof(dns_hdr) + sizeof(uint16_t) + sizeof(dns_qry), Buffer + sizeof(dns_hdr), strlen(Buffer + sizeof(dns_hdr)) + 1U);
		memmove_s(Buffer + sizeof(dns_hdr) + sizeof(uint16_t) + sizeof(dns_qry), Length, Buffer + sizeof(dns_hdr), strnlen_s(Buffer + sizeof(dns_hdr), Length - sizeof(dns_hdr)) + 1U);
//		memcpy(Buffer + sizeof(dns_hdr) + sizeof(uint16_t), DNS_Query.get(), sizeof(dns_qry));
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
				for (Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);Index++)
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
bool __fastcall CheckResponseData(const PSTR Buffer, const size_t Length, bool IsLocal, bool *IsMarkHopLimit)
{
	auto DNS_Header = (pdns_hdr)Buffer;

//DNS Options part
	if (Parameter.DNSDataCheck && (DNS_Header->Questions != htons(U16_NUM_ONE) || //Question Resource Records must be one.
		ntohs(DNS_Header->Flags) >> 15U == 0 || //No any Question Resource Records
//		(ntohs(DNS_Header->Flags) & UINT4_MAX) == DNS_RCODE_NOERROR && DNS_Header->Answer == 0 && DNS_Header->Authority == 0 && DNS_Header->Additional == 0 || //No any non-Question Resource Records when RCode is No Error(Normal)
		(ntohs(DNS_Header->Flags) & 0x0400) >> 10U > 0 && DNS_Header->Authority == 0 && DNS_Header->Additional == 0 || //Responses are not authoritative when there are no any Authoritative Nameservers Records and Additional Resource Records.
		IsLocal && ((ntohs(DNS_Header->Flags) & UINT4_MAX) > DNS_RCODE_NOERROR || (ntohs(DNS_Header->Flags) & 0x0200) >> 9U > 0 && DNS_Header->Answer == 0) || //Local requesting failed or Truncated(xxxxxx1xxxxxxxxx & 0000001000000000 >> 9 == 1)
		Parameter.EDNS0Label && DNS_Header->Additional == 0)) //Additional EDNS0 Label Resource Records check
			return false;

	if (IsMarkHopLimit != nullptr && (Parameter.DNSDataCheck && 
		DNS_Header->Answer != htons(U16_NUM_ONE) || //Less than or more than one Answer Record
		DNS_Header->Authority > 0 || DNS_Header->Additional > 0)) //Authority Records and/or Additional Records
			*IsMarkHopLimit = true;

//No Such Name, not standard query response and no error check.
	if (IsMarkHopLimit != nullptr && Parameter.DNSDataCheck && 
		(ntohs(DNS_Header->Flags) & UINT4_MAX) == DNS_RCODE_NXDOMAIN)
	{
		*IsMarkHopLimit = true;
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
	memset(Domain.get(), 0, DOMAIN_MAXSIZE);
	DNSQueryToChar(Buffer + sizeof(dns_hdr), Domain.get());
//Domain Test part
	if (IsMarkHopLimit != nullptr && Parameter.DomainTestData != nullptr)
	{
//		if (strlen(Domain.get()) == strlen(Parameter.DomainTestData) && 
//			memcmp(Domain.get(), Parameter.DomainTestData, strlen(Parameter.DomainTestData)) == 0 && DNS_Header->ID == Parameter.DomainTestID)
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
		for (size_t Index = 0;Index < (size_t)(ntohs(DNS_Header->Answer) + ntohs(DNS_Header->Authority) + ntohs(DNS_Header->Additional));Index++)
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
