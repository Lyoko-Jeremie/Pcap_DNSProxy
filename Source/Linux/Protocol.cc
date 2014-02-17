// This code is part of Pcap_DNSProxy
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

std::string LocalhostPTR[2];

extern Configuration Parameter;

/*
//Convert host values to network byte order with 64 bits(Linux)
uint64_t htonl64(uint64_t Val)
{
	if (__BYTE_ORDER == __LITTLE_ENDIAN)
		return (((uint64_t)htonl((int)((Val << 32) >> 32))) << 32)|(u_int)htonl((int)(Val >> 32));
	else //Big-Endian
		return Val;
}

//Convert network byte order to host values with 64 bits(Linux)
uint64_t ntohl64(uint64_t Val)
{
	if (__BYTE_ORDER == __LITTLE_ENDIAN)
		return (((uint64_t)htonl((int)((Val << 32) >> 32))) << 32)|(u_int)htonl((int)(Val >> 32));
	else //Big-Endian
		return Val;
}

//Get Ethernet Frame Check Sequence/FCS
uint32_t GetFCS(const char *Buffer, const size_t Length)
{
	uint32_t Table[256] = {0}, Gx = 0x04C11DB7, Temp = 0, CRCTable = 0, Value = 0, UI = 0;
	char ReflectNum[] = {8, 32};
	int Index[3] = {0};

	for(Index[0] = 0;Index[0] <= 0xFF;Index[0]++)
	{
		Value = 0;
		UI = Index[0];
		for (Index[1] = 1;Index[1] < 9;Index[1]++)
		{
			if (UI & 1)
				Value |= 1 << (ReflectNum[0]-Index[1]);
			UI >>= 1;
		}
		Temp = Value;
		Table[Index[0]] = Temp << 24;

		for (Index[2] = 0;Index[2] < 8;Index[2]++)
		{
			unsigned long int t1 = 0, t2 = 0;
			unsigned long int Flag = Table[Index[0]] & 0x80000000;
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
		for (Index[1] = 1;Index[1] < 33;Index[1]++)
		{
			if (UI & 1)
				Value |= 1 << (ReflectNum[1] - Index[1]);
			UI >>= 1;
		}
		Table[Index[0]] = Value;
	}

	uint32_t CRC = 0xFFFFFFFF;
	for (Index[0] = 0;Index[0] < (int)Length;Index[0]++)
		CRC = Table[(CRC ^ (*(Buffer + Index[0]))) & 0xFF]^(CRC >> 8);

	return ~CRC;
}
*/

//Get Checksum
uint16_t GetChecksum(const uint16_t *Buffer, const size_t Length)
{
	uint32_t Checksum = 0;
	size_t InnerLength = Length;

	while(InnerLength > 1)
	{ 
		Checksum += *Buffer++;
		InnerLength -= sizeof(uint16_t);
	}
	
	if (InnerLength)
		Checksum += *(u_char *)Buffer;

	Checksum = (Checksum >> 16) + (Checksum & 0xFFFF);
	Checksum += (Checksum >> 16);

	return (uint16_t)(~Checksum);
}

//Get ICMPv6 checksum
uint16_t ICMPv6Checksum(const char *Buffer, const size_t Length)
{
//Initialization
	char *Validation = nullptr;
	try {
		Validation = new char[PACKET_MAXSIZE]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", 0, 0);

		return 0;
	}
	memset(Validation, 0, PACKET_MAXSIZE);
	uint16_t Result = 0;

//Get checksum
	if (Length - sizeof(ipv6_hdr) > 0)
	{
		ipv6_psd_hdr *psd = (ipv6_psd_hdr *)Validation;
		psd->Dst = ((ipv6_hdr *)Buffer)->Dst;
		psd->Src = ((ipv6_hdr *)Buffer)->Src;
		psd->Length = htonl((uint32_t)(Length - sizeof(ipv6_hdr)));
		psd->Next_Header = IPPROTO_ICMPV6;

		memcpy(Validation + sizeof(ipv6_psd_hdr), Buffer + sizeof(ipv6_hdr), Length - sizeof(ipv6_hdr));
		Result = GetChecksum((uint16_t *)Validation, sizeof(ipv6_psd_hdr) + Length - sizeof(ipv6_hdr));
	}

	delete[] Validation;
	return Result;
}

//Check IP(v4/v6) special addresses
bool CheckSpecialAddress(const void *pAddr, const size_t Protocol)
{
	if (Protocol == AF_INET6) //IPv6
	{
		in6_addr *Addr = (in6_addr *)pAddr;
	//About this list, see https://en.wikipedia.org/wiki/IPv6_address#Presentation and https://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv6_addresses
		if ((Addr->__in6_u.__u6_addr16[0] == 0 && Addr->__in6_u.__u6_addr16[1] == 0 && Addr->__in6_u.__u6_addr16[2] == 0 && Addr->__in6_u.__u6_addr16[3] == 0 && Addr->__in6_u.__u6_addr16[4] == 0 && 
			((Addr->__in6_u.__u6_addr16[5] == 0 && 
			(((Addr->__in6_u.__u6_addr16[6] == 0 && Addr->__in6_u.__u6_addr16[7] == 0) || //Unspecified address(::, Section 2.5.2 in RFC 4291)
			(Addr->__in6_u.__u6_addr16[6] == 0 && Addr->__in6_u.__u6_addr16[7] == htons(0x0001))) || //Loopback address(::1, Section 2.5.3 in RFC 4291)
			Addr->__in6_u.__u6_addr16[5] == 0)) || //IPv4-Compatible Contrast address(::/96, Section 2.5.5.1 in RFC 4291)
			Addr->__in6_u.__u6_addr16[5] == htons(0xFFFF))) || //IPv4-mapped address(::FFFF:0:0/96, Section 2.5.5 in RFC 4291)
//			Addr->__in6_u.__u6_addr16[0] == htons(0x0064) && Addr->__in6_u.__u6_addr16[1] == htons(0xFF9B) && Addr->__in6_u.__u6_addr16[2] == 0 && Addr->__in6_u.__u6_addr16[3] == 0 && Addr->__in6_u.__u6_addr16[4] == 0 && Addr->__in6_u.__u6_addr16[5] == 0 || //Well Known Prefix(64:FF9B::/96, Section 2.1 in RFC 4773)
			(Addr->__in6_u.__u6_addr16[0] == htons(0x0100) && Addr->__in6_u.__u6_addr16[1] == 0 && Addr->__in6_u.__u6_addr16[1] == 0 && Addr->__in6_u.__u6_addr16[1] == 0 && Addr->__in6_u.__u6_addr16[1] == 0 && Addr->__in6_u.__u6_addr16[1] == 0) || //Discard Prefix(100::/64, Section 4 RFC 6666)
			(Addr->__in6_u.__u6_addr16[0] == htons(0x2001) && 
			(Addr->__in6_u.__u6_addr16[1] == 0 || //Teredo relay/tunnel address(2001::/32, RFC 4380)
			(Addr->__in6_u.__u6_addr8[2] == 0 && Addr->__in6_u.__u6_addr8[3] <= htons(0x07)) || //Sub-TLA IDs assigned to IANA(2001:0000::/29, Section 2 in RFC 4773)
			(Addr->__in6_u.__u6_addr8[2] >= htons(0x01) && Addr->__in6_u.__u6_addr8[3] >= htons(0xF8)) || //Sub-TLA IDs assigned to IANA(2001:01F8::/29, Section 2 in RFC 4773)
			(Addr->__in6_u.__u6_addr8[3] >= htons(0x10) && Addr->__in6_u.__u6_addr8[3] <= htons(0x1F)) || //Overlay Routable Cryptographic Hash IDentifiers/ORCHID address(2001:10::/28 in RFC 4843)
			Addr->__in6_u.__u6_addr16[1] == htons(0x0DB8))) || //Contrast address prefix reserved for documentation(2001:DB8::/32, RFC 3849)
//			Addr->__in6_u.__u6_addr16[0] == htons(0x2002) && Addr->__in6_u.__u6_addr16[1] == 0 || //6to4 relay/tunnel address(2002::/16, Section 2 in RFC 3056)
			(Addr->__in6_u.__u6_addr16[0] == htons(0x3FFE) && Addr->__in6_u.__u6_addr16[1] == 0) || //6bone address(3FFE::/16, RFC 3701)
			Addr->__in6_u.__u6_addr8[0] == htons(0x5F) || //6bone address(5F00::/8, RFC 3701)
//			Addr->__in6_u.__u6_addr8[0] >= htons(0xFC) && Addr->__in6_u.__u6_addr8[0] <= htons(0xFD) || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
			(Addr->__in6_u.__u6_addr8[0] == htons(0xFE) && 
			((Addr->__in6_u.__u6_addr8[1] >= htons(0x80) && Addr->__in6_u.__u6_addr8[1] <= htons(0xBF)) || //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
			Addr->__in6_u.__u6_addr8[1] >= htons(0xC0))) || //Site-Local scoped address(FEC0::/10, RFC 3879)
//			Addr->__in6_u.__u6_addr8[0] == htons(0xFF) || //Multicast address(FF00::/8, Section 2.7 in RFC 4291)
			Addr->__in6_u.__u6_addr16[5] == htons(0x5EFE)) //ISATAP Interface Identifiers(Prefix::5EFE:0:0:0:0/64, Section 6.1 in RFC 5214)
				return true;
	}
	else { //IPv4
		in_addr_Windows *Addr = (in_addr_Windows *)pAddr;
	//About this list, see https://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93#.E8.99.9A.E5.81.87IP.E5.9C.B0.E5.9D.80.
		if (Addr->S_un.S_addr == inet_addr("1.1.1.1") || Addr->S_un.S_addr == inet_addr("4.36.66.178") || Addr->S_un.S_addr == inet_addr("8.7.198.45") || Addr->S_un.S_addr == inet_addr("37.61.54.158") || 
			Addr->S_un.S_addr == inet_addr("46.82.174.68") || Addr->S_un.S_addr == inet_addr("59.24.3.173") || Addr->S_un.S_addr == inet_addr("64.33.88.161") || Addr->S_un.S_addr == inet_addr("64.33.99.47") || 
			Addr->S_un.S_addr == inet_addr("64.66.163.251") || Addr->S_un.S_addr == inet_addr("65.104.202.252") || Addr->S_un.S_addr == inet_addr("65.160.219.113") || Addr->S_un.S_addr == inet_addr("66.45.252.237") || 
			Addr->S_un.S_addr == inet_addr("72.14.205.99") || Addr->S_un.S_addr == inet_addr("72.14.205.104") || Addr->S_un.S_addr == inet_addr("78.16.49.15") || Addr->S_un.S_addr == inet_addr("93.46.8.89") || 
			Addr->S_un.S_addr == inet_addr("128.121.126.139") || Addr->S_un.S_addr == inet_addr("159.106.121.75") || Addr->S_un.S_addr == inet_addr("169.132.13.103") || Addr->S_un.S_addr == inet_addr("192.67.198.6") || 
			Addr->S_un.S_addr == inet_addr("202.106.1.2") || Addr->S_un.S_addr == inet_addr("202.181.7.85") || Addr->S_un.S_addr == inet_addr("203.98.7.65") || Addr->S_un.S_addr == inet_addr("203.161.230.171") || 
			Addr->S_un.S_addr == inet_addr("207.12.88.98") || Addr->S_un.S_addr == inet_addr("208.56.31.43") || Addr->S_un.S_addr == inet_addr("209.36.73.33") || Addr->S_un.S_addr == inet_addr("209.145.54.50") || 
			Addr->S_un.S_addr == inet_addr("209.220.30.174") || Addr->S_un.S_addr == inet_addr("211.94.66.147") || Addr->S_un.S_addr == inet_addr("213.169.251.35") || Addr->S_un.S_addr == inet_addr("216.221.188.182") || 
			Addr->S_un.S_addr == inet_addr("216.234.179.13") || Addr->S_un.S_addr == inet_addr("243.185.187.39") || 
		//About this list, see https://en.wikipedia.org/wiki/IPv4#Special-use_addresses and https://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv4_addresses
			Addr->S_un.S_un_b.s_b1 == 0 || //Current network whick only valid as source address(0.0.0.0/8, Section 3.2.1.3 in RFC 1122)
//			Addr->S_un.S_un_b.s_b1 == 0x0A || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
			Addr->S_un.S_un_b.s_b1 == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
//			Addr->S_un.S_un_b.s_b1 == && Addr->S_un.S_un_b.s_b2 > 0x40 && Addr->S_un.S_un_b.s_b2 < 0x7F || //Carrier-grade NAT(100.64.0.0/10, Section 7 in RFC 6598)
			(Addr->S_un.S_un_b.s_b1 == 0xA9 && Addr->S_un.S_un_b.s_b2 >= 0xFE) || //Link-local address(169.254.0.0/16, Section 1.5 in RFC 3927)
//			Addr->S_un.S_un_b.s_b1 == 0xAC && Addr->S_un.S_un_b.s_b2 >= 0x10 && Addr->S_un.S_un_b.s_b2 <= 0x1F || //Private class B address(172.16.0.0/16, Section 3 in RFC 1918)
			(Addr->S_un.S_un_b.s_b1 == 0xC0 && Addr->S_un.S_un_b.s_b2 == 0 && Addr->S_un.S_un_b.s_b3 == 0 && Addr->S_un.S_un_b.s_b4 >= 0 && Addr->S_un.S_un_b.s_b4 < 0x08) || //DS-Lite transition mechanism(192.0.0.0/29, Section 3 in RFC 6333)
			(Addr->S_un.S_un_b.s_b1 == 0xC0 && (Addr->S_un.S_un_b.s_b2 == 0 && (Addr->S_un.S_un_b.s_b3 == 0 || //Reserved for IETF protocol assignments address(192.0.0.0/24, Section 3 in RFC 5735)
			Addr->S_un.S_un_b.s_b3 == 0x02))) || //TEST-NET-1 address(192.0.2.0/24, Section 3 in RFC 5735)
//			Addr->S_un.S_un_b.s_b2 == 0x58 && Addr->S_un.S_un_b.s_b3 == 0x63 || //6to4 relay/tunnel address(192.88.99.0/24, Section 2.3 in RFC 3068)
//			Addr->S_un.S_un_b.s_b1 == 0xC0 && Addr->S_un.S_un_b.s_b2 == 0xA8 || //Private class C address(192.168.0.0/24, Section 3 in RFC 1918)
			(Addr->S_un.S_un_b.s_b1 == 0xC6 && (Addr->S_un.S_un_b.s_b2 == 0x12 || //Benchmarking Methodology for Network Interconnect Devices address(198.18.0.0/15, Section 11.4.1 in RFC 2544)
			(Addr->S_un.S_un_b.s_b2 == 0x33 && Addr->S_un.S_un_b.s_b3 == 0x64))) || //TEST-NET-2(198.51.100.0/24, Section 3 in RFC 5737)
			(Addr->S_un.S_un_b.s_b1 == 0xCB && Addr->S_un.S_un_b.s_b2 == 0 && Addr->S_un.S_un_b.s_b3 == 0x71) || //TEST-NET-3(203.0.113.0/24, Section 3 in RFC 5737)
//			Addr->S_un.S_un_b.s_b1 == 0xE0 || //Multicast address(224.0.0.0/4, Section 2 in RFC 3171)
			Addr->S_un.S_un_b.s_b1 >= 0xF0) //Reserved for future use address(240.0.0.0/4, Section 4 in RFC 1112) and Broadcast address(255.255.255.255/32, Section 7 in RFC 919/RFC 922)
				return true;
	}

	return false;
}

//Get UDP checksum
uint16_t UDPChecksum(const char *Buffer, const size_t Length, const size_t Protocol)
{
//Initialization
	char *Validation = nullptr;
	try {
		Validation = new char[PACKET_MAXSIZE]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", 0, 0);

		return 0;
	}
	memset(Validation, 0, PACKET_MAXSIZE);
	
//Get checksum
	uint16_t Result = EXIT_FAILURE;
	if (Protocol == AF_INET6 && Length - sizeof(ipv6_hdr) > 0) //IPv6
	{
		ipv6_psd_hdr *psd = (ipv6_psd_hdr *)Validation;
		psd->Dst = ((ipv6_hdr *)Buffer)->Dst;
		psd->Src = ((ipv6_hdr *)Buffer)->Src;
		psd->Length = htonl((uint32_t)(Length - sizeof(ipv6_hdr)));
		psd->Next_Header = IPPROTO_UDP;

		memcpy(Validation + sizeof(ipv6_psd_hdr), Buffer + sizeof(ipv6_hdr), Length - sizeof(ipv6_hdr));
		Result = GetChecksum((uint16_t *)Validation, sizeof(ipv6_psd_hdr) + Length - sizeof(ipv6_hdr));
	}
	else if (Protocol == AF_INET && Length - sizeof(ipv4_hdr) > 0) //IPv4
	{
		ipv4_psd_hdr *psd = (ipv4_psd_hdr *)Validation;
		psd->Dst = ((ipv4_hdr *)Buffer)->Dst;
		psd->Src = ((ipv4_hdr *)Buffer)->Src;
		psd->Length = htons((uint16_t)(Length - sizeof(ipv4_hdr)));
		psd->Protocol = IPPROTO_UDP;

		memcpy(Validation + sizeof(ipv4_psd_hdr), Buffer + sizeof(ipv4_hdr), Length - sizeof(ipv4_hdr));
		Result = GetChecksum((uint16_t *)Validation, sizeof(ipv4_psd_hdr) + Length - sizeof(ipv4_hdr));
	}

	delete[] Validation;
	return Result;
}

//Convert data from unsigned char/UCHAR to DNS query
size_t CharToDNSQuery(const char *FName, char *TName)
{
	int Index[] = {(int)strlen(FName) - 1, 0, 0};
	Index[2] = Index[0] + 1;
	TName[Index[0] + 2] = 0;

	for (;Index[0] >= 0;Index[0]--,Index[2]--)
	{
		if (FName[Index[0]] == 46)
		{
			TName[Index[2]] = Index[1];
			Index[1] = 0;
		}
		else
		{
			TName[Index[2]] = FName[Index[0]];
			Index[1]++;
		}
	}
	TName[Index[2]] = Index[1];

	return strlen(TName) + 1;
}

//Convert data from DNS query to unsigned char/UCHAR
size_t DNSQueryToChar(const char *TName, char *FName)
{
	size_t uIndex = 0;
	int Index[] = {0, 0};

	for(uIndex = 0;uIndex < PACKET_MAXSIZE/8;uIndex++)
	{
		if (uIndex == 0)
		{
			Index[0] = TName[uIndex];
		}
		else if (uIndex == (size_t)(Index[0] + Index[1] + 1))
		{
			Index[0] = TName[uIndex];
			if (Index[0] == 0)
				break;
			Index[1] = (int)uIndex;

			FName[uIndex - 1] = 46;
		}
		else {
			FName[uIndex - 1] = TName[uIndex];
		}
	}

	return uIndex;
}

//Get local address(es)
bool GetLocalAddress(sockaddr_storage &SockAddr, const size_t Protocol)
{
//Initialization
	ifaddrs *List = nullptr, *Item = nullptr;
	if (getifaddrs(&List) == RETURN_ERROR)
	{
		return EXIT_FAILURE;
	}

//List traversal
	for (Item = List;Item->ifa_next != nullptr;Item = Item->ifa_next)
	{
		if (Protocol == AF_INET6 && Item->ifa_addr->sa_family == AF_INET6) //IPv6		
		{
			if (!CheckSpecialAddress(&((sockaddr_in6 *)Item->ifa_addr)->sin6_addr, AF_INET6))
			{
				SockAddr.ss_family = Item->ifa_addr->sa_family;
				((sockaddr_in6 *)&SockAddr)->sin6_addr = ((sockaddr_in6 *)Item->ifa_addr)->sin6_addr;
				freeifaddrs(List);
				return true;
			}
		}
		else if (Protocol == AF_INET && Item->ifa_addr->sa_family == AF_INET) //IPv4
		{
			if (!CheckSpecialAddress(&((sockaddr_in *)Item->ifa_addr)->sin_addr, AF_INET))
			{
				SockAddr.ss_family = Item->ifa_addr->sa_family;
				((sockaddr_in *)&SockAddr)->sin_addr = ((sockaddr_in *)Item->ifa_addr)->sin_addr;
				freeifaddrs(List);
				return true;
			}
		}
	}

	freeifaddrs(List);
	return false;
}

//Convert local address(es) to reply DNS PTR Record(s)
size_t LocalAddressToPTR(const size_t Protocol)
{
//Initialization
	char *Addr = nullptr;
	try {
		Addr = new char[PACKET_MAXSIZE/8]();
	}
	catch(std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", 0, 0);

		return EXIT_FAILURE;
	}
	memset(Addr, 0, PACKET_MAXSIZE/8);
	sockaddr_storage SockAddr = {0};
	std::string Result;

	ssize_t Index = 0;
	size_t Location = 0, Colon = 0;
	while (true)
	{
	//Get localhost address(es)
		memset(&SockAddr, 0, sizeof(sockaddr_storage));
		if (!GetLocalAddress(SockAddr, Protocol))
		{
			delete[] Addr;
			return EXIT_FAILURE;
		}

	//IPv6
		if (Protocol == AF_INET6)
		{
			std::string Temp[2];
			Location = 0;
			Colon = 0;

		//Convert from in6_addr to string
			if (inet_ntop(AF_INET6, &((sockaddr_in6 *)&SockAddr)->sin6_addr, Addr, PACKET_MAXSIZE/8) == nullptr)
			{
				PrintError(Socket_Error, L"Local IPv6 Address format error", errno, 0);

				delete[] Addr;
				return EXIT_FAILURE;
			}
			Temp[0] = Addr;

		//Convert to standard IPv6 address format A part(":0:" -> ":0000:")
			while (Temp[0].find(":0:", Index) != std::string::npos)
			{
				Index = Temp[0].find(":0:", Index);
				Temp[0].replace(Index, 3, ":0000:");
			}

		//Count colon
			for (Index = 0;Index < (ssize_t)Temp[0].length();Index++)
			{
				if (Temp[0].at(Index) == 58)
					Colon++;
			}

		//Convert to standard IPv6 address format B part("::" -> ":0000:...")
			Location = Temp[0].find("::");
			Colon = 8 - Colon;
			Temp[1].append(Temp[0], 0, Location);
			while (Colon != 0)
			{
				Temp[1].append(":0000");
				Colon--;
			}
			Temp[1].append(Temp[0], Location + 1, Temp[0].length() - Location + 1);

			for (std::string::iterator iter = Temp[1].begin();iter != Temp[1].end();iter++)
			{
				if (*iter == 58)
					Temp[1].erase(iter);
			}

		//Convert to DNS PTR Record and copy to Result
			for (Index = (ssize_t)(Temp[1].length() - 1);Index != -1;Index--)
			{
				char Word[] = {0, 0};
				Word[0] = Temp[1].at(Index);
				Result.append(Word);
				Result.append(".");
			}

			Result.append("ip6.arpa");
			LocalhostPTR[0].swap(Result);
			Result.clear();
			Result.resize(0);
		}
	//IPv4
		else {
			char CharAddr[4][4] = {{0}, {0}, {0}, {0}};
			size_t Localtion[] = {0, 0};

		//Convert from in_addr to string
			if (inet_ntop(AF_INET, &((sockaddr_in *)&SockAddr)->sin_addr, Addr, PACKET_MAXSIZE/8) == nullptr)
			{
				PrintError(Socket_Error, L"Local IPv4 Address format error", errno, 0);

				delete[] Addr;
				return EXIT_FAILURE;
			}

		//Detach Address data
			for (Index = 0;(size_t)Index < strlen(Addr);Index++)
			{
				if (Addr[Index] == 46)
				{
					Localtion[1] = 0;
					Localtion[0]++;
				}
				else {
					CharAddr[Localtion[0]][Localtion[1]] = Addr[Index];
					Localtion[1]++;
				}
			}

		//Convert to DNS PTR Record and copy to Result
			Result.clear();
			for (Index = 4;Index > 0;Index--)
			{
				Result.append(CharAddr[Index - 1]);
				Result.append(".");
			}

			Result.append("in-addr.arpa");
			LocalhostPTR[1].swap(Result);
			Result.clear();
			Result.resize(0);
		}

	//Auto-refresh
		if (Parameter.Hosts == 0)
		{
			delete[] Addr;
			return EXIT_SUCCESS;
		}
		else {
			sleep(Parameter.Hosts);
		}
	}

	delete[] Addr;
	return EXIT_SUCCESS;
}

//Make ramdom domains
void RamdomDomain(char *Domain, const size_t Length)
{
	static const char *DomainTable = (".-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"); //Preferred name syntax(Section 2.3.1 in RFC 1035)
	memset(Parameter.DomainTestOptions.DomainTest, 0, PACKET_MAXSIZE/8);
	size_t RamdomLength = 0, Index = 0;

//Make ramdom numbers
//Formula: [M, N] -> rand()%(N-M+1)+M
	srand((u_int)time((time_t *)NULL));
	RamdomLength = rand() % 61 + 3; //Domain length is between 3 and 63(Labels must be 63 characters/bytes or less, Section 2.3.1 in RFC 1035)
	for (Index = 0;Index < RamdomLength;Index++)
		Domain[Index] = DomainTable[rand() % 65];

	return;
}
