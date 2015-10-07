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


#include "PacketData.h"

/* Get Ethernet Frame Check Sequence/FCS
uint32_t __fastcall GetFCS(
	const unsigned char *Buffer, 
	const size_t Length)
{
	uint32_t Table[FCS_TABLE_SIZE] = {0}, Gx = 0x04C11DB7, Temp = 0, CRCTable = 0, Value = 0, UI = 0;
	char ReflectNum[]{8, 32};
	int Index[]{0, 0, 0};

	for (Index[0] = 0;Index[0] <= UINT8_MAX;++Index[0])
	{
		Value = 0;
		UI = Index[0];
		for (Index[1U] = 1;Index[1U] < 9;++Index[1U])
		{
			if (UI & 1)
				Value |= 1 << (ReflectNum[0]-Index[1U]);
			UI >>= 1;
		}
		Temp = Value;
		Table[Index[0]] = Temp << 24U;

		for (Index[2U] = 0;Index[2U] < 8;++Index[2U])
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
		for (Index[1U] = 1;Index[1U] < 33;++Index[1U])
		{
			if (UI & 1)
				Value |= 1 << (ReflectNum[1U] - Index[1U]);
			UI >>= 1;
		}
		Table[Index[0]] = Value;
	}

	uint32_t CRC = UINT32_MAX;
	for (Index[0] = 0;Index[0] < (int)Length;+Index[0])
		CRC = Table[(CRC ^ (*(Buffer + Index[0]))) & UINT8_MAX]^(CRC >> 8U);

	return ~CRC;
}
*/

//Get Checksum
uint16_t __fastcall GetChecksum(
	const uint16_t *Buffer, 
	const size_t Length)
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
uint16_t __fastcall GetChecksum_ICMPv6(
	const unsigned char *Buffer, 
	const size_t Length, 
	const in6_addr &Destination, 
	const in6_addr &Source)
{
	std::shared_ptr<char> Validation(new char[sizeof(ipv6_psd_hdr) + Length]());
	memset(Validation.get(), 0, sizeof(ipv6_psd_hdr) + Length);

//Get checksum
	auto IPv6_Pseudo_Header = (pipv6_psd_hdr)Validation.get();
	IPv6_Pseudo_Header->Destination= Destination;
	IPv6_Pseudo_Header->Source = Source;
	IPv6_Pseudo_Header->Length = htonl((uint32_t)Length);
	IPv6_Pseudo_Header->NextHeader = IPPROTO_ICMPV6;
	memcpy_s(Validation.get() + sizeof(ipv6_psd_hdr), Length, Buffer + sizeof(ipv6_hdr), Length);
	return GetChecksum((PUINT16)Validation.get(), sizeof(ipv6_psd_hdr) + Length);
}

//Get TCP or UDP checksum
uint16_t __fastcall GetChecksum_TCP_UDP(
	const unsigned char *Buffer, 
	const size_t Length, 
	const uint16_t Protocol_Network, 
	const uint16_t Protocol_Transport)
{
//Get checksum.
	uint16_t Result = EXIT_FAILURE;
	if (Protocol_Network == AF_INET6) //IPv6
	{
		std::shared_ptr<char> Validation(new char[sizeof(ipv6_psd_hdr) + Length]());
		memset(Validation.get(), 0, sizeof(ipv6_psd_hdr) + Length);
		auto IPv6_Pseudo_Header = (pipv6_psd_hdr)Validation.get();
		IPv6_Pseudo_Header->Destination= ((pipv6_hdr)Buffer)->Destination;
		IPv6_Pseudo_Header->Source = ((pipv6_hdr)Buffer)->Source;
		IPv6_Pseudo_Header->Length = htonl((uint32_t)Length);
		IPv6_Pseudo_Header->NextHeader = (uint8_t)Protocol_Transport;

		memcpy_s(Validation.get() + sizeof(ipv6_psd_hdr), Length, Buffer + sizeof(ipv6_hdr), Length);
		Result = GetChecksum((PUINT16)Validation.get(), sizeof(ipv6_psd_hdr) + Length);
	}
	else { //IPv4
		auto IPv4_Header = (pipv4_hdr)Buffer;
		std::shared_ptr<char> Validation(new char[sizeof(ipv4_psd_hdr) + Length]());
		memset(Validation.get(), 0, sizeof(ipv4_psd_hdr) + Length);
		auto IPv4_Pseudo_Header = (pipv4_psd_hdr)Validation.get();
		IPv4_Pseudo_Header->Destination= ((pipv4_hdr)Buffer)->Destination;
		IPv4_Pseudo_Header->Source = ((pipv4_hdr)Buffer)->Source;
		IPv4_Pseudo_Header->Length = htons((uint16_t)Length);
		IPv4_Pseudo_Header->Protocol = (uint8_t)Protocol_Transport;

		memcpy_s(Validation.get() + sizeof(ipv4_psd_hdr), Length, Buffer + IPv4_Header->IHL * IPV4_IHL_BYTES_TIMES, Length);
		Result = GetChecksum((PUINT16)Validation.get(), sizeof(ipv4_psd_hdr) + Length);
	}

	return Result;
}

//Add length data to TCP DNS transmission
size_t __fastcall AddLengthDataToHeader(
	PSTR Buffer, 
	const size_t RecvLen, 
	const size_t MaxLen)
{
	if (MaxLen >= RecvLen + sizeof(uint16_t))
	{
		memmove_s(Buffer + sizeof(uint16_t), MaxLen - sizeof(uint16_t), Buffer, RecvLen);
		auto DNS_TCP_Header = (pdns_tcp_hdr)Buffer;
		DNS_TCP_Header->Length = htons((uint16_t)RecvLen);
		return RecvLen + sizeof(uint16_t);
	}

	return EXIT_FAILURE;
}

//Convert data from chars to DNS query
size_t __fastcall CharToDNSQuery(
	const char *FName, 
	PSTR TName)
{
	int Index[]{(int)strnlen_s(FName, DOMAIN_MAXSIZE) - 1, 0, 0};
	Index[2U] = Index[0] + 1;
	TName[Index[0] + 2] = 0;

	for (;Index[0] >= 0;--Index[0], --Index[2U])
	{
		if (FName[Index[0]] == ASCII_PERIOD)
		{
			TName[Index[2U]] = (char)Index[1U];
			Index[1U] = 0;
		}
		else {
			TName[Index[2U]] = FName[Index[0]];
			++Index[1U];
		}
	}

	TName[Index[2U]] = (char)Index[1U];
	return strnlen_s(TName, DOMAIN_MAXSIZE - 1U) + 1U;
}

//Convert data from DNS query to chars
size_t __fastcall DNSQueryToChar(
	const char *TName, 
	PSTR FName)
{
//Initialization
	size_t uIndex = 0;
	int Index[]{0, 0};

//Convert domain.
	for (uIndex = 0;uIndex < DOMAIN_MAXSIZE;++uIndex)
	{
	//Pointer
		if ((UCHAR)TName[uIndex] >= DNS_POINTER_BITS)
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

//Make ramdom domains
void __fastcall MakeRamdomDomain(
	PSTR Buffer)
{
//Ramdom number distribution initialization
	std::uniform_int_distribution<int> RamdomDistribution(1U, DOMAIN_LEVEL_DATA_MAXSIZE);

//Make ramdom domain length.
	size_t RamdomLength = RamdomDistribution(*GlobalRunningStatus.RamdomEngine), Index = 0;
	if (RamdomLength < DOMAIN_RAMDOM_MINSIZE)
		RamdomLength = DOMAIN_RAMDOM_MINSIZE;

//Make ramdom domain.
	if (RamdomLength % 2U == 0)
	{
		for (Index = 0;Index < RamdomLength - 3U;++Index)
		{
			Buffer[Index] = GlobalRunningStatus.DomainTable[RamdomDistribution(*GlobalRunningStatus.RamdomEngine)];
			Buffer[Index] = (char)tolower(Buffer[Index]);
		}

	//Make random domain like a normal Top-Level Domain/TLD.
		Buffer[RamdomLength - 3U] = ASCII_PERIOD;
		Index = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Buffer[RamdomLength - 2U] = GlobalRunningStatus.DomainTable[Index];
		Index = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Buffer[RamdomLength - 1U] = GlobalRunningStatus.DomainTable[Index];
	}
	else {
		for (Index = 0;Index < RamdomLength - 4U;++Index)
		{
			Buffer[Index] = GlobalRunningStatus.DomainTable[RamdomDistribution(*GlobalRunningStatus.RamdomEngine)];
			Buffer[Index] = (char)tolower(Buffer[Index]);
		}

	//Make random domain like a normal Top-level domain/TLD.
		Buffer[RamdomLength - 4U] = ASCII_PERIOD;
		Index = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Buffer[RamdomLength - 3U] = GlobalRunningStatus.DomainTable[Index];
		Index = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Buffer[RamdomLength - 2U] = GlobalRunningStatus.DomainTable[Index];
		Index = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
		if (Index < ASCII_FF)
			Index += 52U;
		else if (Index < ASCII_AMPERSAND)
			Index += 26U;
		Buffer[RamdomLength - 1U] = GlobalRunningStatus.DomainTable[Index];
	}

	return;
}

//Make Domain Case Conversion
void __fastcall MakeDomainCaseConversion(
	PSTR Buffer)
{
//Ramdom number distribution initialization
	std::uniform_int_distribution<int> RamdomDistribution(0, 1U);

//Make Case Conversion.
	if (RamdomDistribution(*GlobalRunningStatus.RamdomEngine) % 2U == 0)
	{
		for (size_t Index = 0;Index < strnlen_s(Buffer, DOMAIN_MAXSIZE);++Index)
		{
			if (Index % 2U == 0)
				*(Buffer + Index) = (char)toupper(*(Buffer + Index));
		}
	}
	else {
		for (size_t Index = 0;Index < strnlen_s(Buffer, DOMAIN_MAXSIZE);++Index)
		{
			if (Index % 2U > 0)
				*(Buffer + Index) = (char)toupper(*(Buffer + Index));
		}
	}

	return;
}

//Add EDNS options to Additional Resource Records in DNS packet
size_t __fastcall AddEDNSLabelToAdditionalRR(
	PSTR Buffer, 
	const size_t Length, 
	const size_t MaxLen, 
	const bool NoHeader)
{
//Initialization
	auto DNS_Header = (pdns_hdr)Buffer;
	if (!NoHeader)
	{
		if (DNS_Header->Additional > 0)
			return Length;
		else 
			DNS_Header->Additional = htons(U16_NUM_ONE);
	}
	size_t DataLength = Length;

//Add a new EDNS/OPT Additional Resource Records.
	if (DataLength + sizeof(dns_record_opt) > MaxLen)
		return DataLength;
	auto DNS_Record_OPT = (pdns_record_opt)(Buffer + DataLength);
	DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
	DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNSPayloadSize);
	DataLength += sizeof(dns_record_opt);

//DNSSEC request
	if (Parameter.DNSSEC_Request)
	{
		if (!NoHeader)
		{
			DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_GET_BIT_AD); //Set Authentic Data bit.
//			DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_GET_BIT_CD); //Set Checking Disabled bit.
		}

		DNS_Record_OPT->Z_Field = htons(ntohs(DNS_Record_OPT->Z_Field) | EDNS_GET_BIT_DO); //Set Accepts DNSSEC security Resource Records bit.
	}

//EDNS client subnet
	if (Parameter.EDNS_ClientSubnet)
	{
		auto DNS_Query = (pdns_qry)(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer));
		if (DNS_Query->Classes == htons(DNS_CLASS_IN))
		{
		//IPv6
			if (DNS_Query->Type == htons(DNS_RECORD_AAAA) && Parameter.LocalhostSubnet.IPv6 != nullptr && 
				Parameter.LocalhostSubnet.IPv6->Address.ss_family > 0 && Parameter.LocalhostSubnet.IPv6->Prefix > 0)
			{
			//Length check
				if (DataLength + sizeof(edns_client_subnet) > MaxLen)
					return DataLength;

			//Make EDNS Subnet header.
				auto EDNS_Subnet_Header = (pedns_client_subnet)(Buffer + DataLength);
				EDNS_Subnet_Header->Code = htons(EDNS_CODE_CSUBNET);
				EDNS_Subnet_Header->Family = htons(ADDRESS_FAMILY_IPV6);
				EDNS_Subnet_Header->Netmask_Source = (uint8_t)Parameter.LocalhostSubnet.IPv6->Prefix;
				DataLength += sizeof(edns_client_subnet);

			//Length check
				if (DataLength + sizeof(in6_addr) > MaxLen)
					return DataLength;

			//Copy subnet address.
				auto Addr = (in6_addr *)(Buffer + DataLength);
				*Addr = ((PSOCKADDR_IN6)&Parameter.LocalhostSubnet.IPv6->Address)->sin6_addr;
				EDNS_Subnet_Header->Length = htons((uint16_t)(sizeof(uint16_t) + sizeof(uint8_t) * 2U + sizeof(in6_addr)));
				DNS_Record_OPT->DataLength = htons(sizeof(edns_client_subnet) + sizeof(in6_addr));
				DataLength += sizeof(in6_addr);
			}
		//IPv4
			else if (DNS_Query->Type == htons(DNS_RECORD_A) && Parameter.LocalhostSubnet.IPv4 != nullptr && 
				Parameter.LocalhostSubnet.IPv4->Address.ss_family > 0 && Parameter.LocalhostSubnet.IPv4->Prefix > 0)
			{
			//Length check
				if (DataLength + sizeof(edns_client_subnet) > MaxLen)
					return DataLength;

			//Make EDNS Subnet header.
				auto EDNS_Subnet_Header = (pedns_client_subnet)(Buffer + DataLength);
				EDNS_Subnet_Header->Code = htons(EDNS_CODE_CSUBNET);
				EDNS_Subnet_Header->Family = htons(ADDRESS_FAMILY_IPV4);
				EDNS_Subnet_Header->Netmask_Source = (uint8_t)Parameter.LocalhostSubnet.IPv4->Prefix;
				DataLength += sizeof(edns_client_subnet);

			//Length check
				if (DataLength + sizeof(in_addr) > MaxLen)
					return DataLength;

			//Copy subnet address.
				auto Addr = (in_addr *)(Buffer + DataLength);
				*Addr = ((PSOCKADDR_IN)&Parameter.LocalhostSubnet.IPv4->Address)->sin_addr;
				EDNS_Subnet_Header->Length = htons((uint16_t)(sizeof(uint16_t) + sizeof(uint8_t) * 2U + sizeof(in_addr)));
				DNS_Record_OPT->DataLength = htons(sizeof(edns_client_subnet) + sizeof(in_addr));
				DataLength += sizeof(in_addr);
			}
		}
	}

	return DataLength;
}

//Make Compression Pointer Mutation
size_t __fastcall MakeCompressionPointerMutation(
	PSTR Buffer, 
	const size_t Length)
{
//Ramdom number distribution initialization
	std::uniform_int_distribution<int> RamdomDistribution(0, 2U);
	size_t Index = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);

//Check Compression Pointer Mutation options.
	switch (Index)
	{
		case 0:
		{
			if (!Parameter.CPM_PointerToHeader)
			{
				if (Parameter.CPM_PointerToRR)
					++Index;
				else //Pointer to Additional(2)
					Index += 2U;
			}
		}break;
		case 1U:
		{
			if (!Parameter.CPM_PointerToRR)
			{
				if (Parameter.CPM_PointerToHeader)
					--Index;
				else //Pointer to Additional(1)
					Index += 1U;
			}
		}break;
		case 2U:
		{
			if (!Parameter.CPM_PointerToAdditional)
			{
				if (Parameter.CPM_PointerToHeader)
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
		*(Buffer + Length - sizeof(dns_qry) - 1U) = DNS_POINTER_BITS_STRING;

	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
			Index = (*GlobalRunningStatus.FunctionPTR_GetTickCount64)() % 4U;
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
		*(Buffer + sizeof(dns_hdr)) = DNS_POINTER_BITS_STRING;
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
				DNS_Record_AAAA->TTL = htonl(RamdomDistribution_Additional(*GlobalRunningStatus.RamdomEngine));
				DNS_Record_AAAA->Length = htons(sizeof(in6_addr));
				for (Index = 0;Index < sizeof(in6_addr) / sizeof(uint16_t);++Index)
					DNS_Record_AAAA->Addr.s6_words[Index] = htons((uint16_t)RamdomDistribution_Additional(*GlobalRunningStatus.RamdomEngine));

				return Length + sizeof(dns_record_aaaa);
			}
			else {
				auto DNS_Record_A = (pdns_record_a)(Buffer + Length);
				DNS_Record_A->Type = htons(DNS_RECORD_A);
				DNS_Record_A->Classes = htons(DNS_CLASS_IN);
				DNS_Record_A->TTL = htonl(RamdomDistribution_Additional(*GlobalRunningStatus.RamdomEngine));
				DNS_Record_A->Length = htons(sizeof(in_addr));
				DNS_Record_A->Addr.s_addr = htonl(RamdomDistribution_Additional(*GlobalRunningStatus.RamdomEngine));

				return Length + sizeof(dns_record_a);
			}
		}
	}

	return EXIT_FAILURE;
}
