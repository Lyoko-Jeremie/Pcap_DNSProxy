// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2018 Chengr28
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
uint32_t GetFCS(
	const uint8_t *Buffer, 
	const size_t Length)
{
	std::array<uint32_t, FCS_TABLE_SIZE> Table_FCS{};
	std::array<uint8_t, 2U> ReflectNum{8U, 32U};
	std::array<int, 3U> Index{};
	uint32_t Gx = 0x04C11DB7, Temp = 0, Table_CRC = 0, Value = 0, UI = 0;
	for (Index.at(0) = 0;Index.at(0) <= UINT8_MAX;++Index.at(0))
	{
		Value = 0;
		UI = Index.at(0);

		for (Index.at(1U) = 1;Index.at(1U) < 9;++Index.at(1U))
		{
			if (UI & 1)
				Value |= 1 << (ReflectNum.at(0) - Index.at(1U));
			UI >>= 1;
		}

		Temp = Value;
		Table_FCS.at(Index.at(0)) = Temp << 24U;

		for (Index.at(2U) = 0;Index.at(2U) < 8;++Index.at(2U))
		{
			unsigned long int t1 = 0, t2 = 0, Flag = Table_FCS.at(Index.at(0)) & 0x80000000;
			t1 = (Table_FCS.at(Index.at(0)) << 1);
			if (Flag == 0)
				t2 = 0;
			else 
				t2 = Gx;
			Table_FCS.at(Index.at(0)) = t1 ^ t2;
		}

		Table_CRC = Table_FCS.at(Index.at(0));
		UI = Table_FCS.at(Index.at(0));
		Value = 0;

		for (Index.at(1U) = 1;Index.at(1U) < 33;++Index.at(1U))
		{
			if (UI & 1)
				Value |= 1 << (ReflectNum.at(1U) - Index.at(1U));
			UI >>= 1;
		}

		Table_FCS.at(Index.at(0)) = Value;
	}

	uint32_t CRC = UINT32_MAX;
	for (Index.at(0) = 0;Index.at(0) < static_cast<const int>(Length);+Index.at(0))
		CRC = Table_FCS.at((CRC ^ (*(Buffer + Index.at(0)))) & UINT8_MAX) ^ (CRC >> (sizeof(uint8_t) * BYTES_TO_BITS));

	return ~CRC;
}
*/

//Get Internet checksum
uint16_t GetChecksum_Internet(
	const uint16_t *Buffer, 
	const size_t Length)
{
	uint32_t ResultValue = CHECKSUM_SUCCESS;
	auto LoopLength = Length;
	while (LoopLength > 1U)
	{
		ResultValue += *Buffer++;
		LoopLength -= sizeof(uint16_t);
	}

	if (LoopLength)
		ResultValue += *reinterpret_cast<const uint8_t *>(Buffer);
	ResultValue = (ResultValue >> (sizeof(uint16_t) * BYTES_TO_BITS)) + (ResultValue & UINT16_MAX);
	ResultValue += (ResultValue >> (sizeof(uint16_t) * BYTES_TO_BITS));

	return static_cast<const uint16_t>(~ResultValue);
}

//Get ICMPv6 checksum
uint16_t GetChecksum_ICMPv6(
	const ipv6_hdr * const IPv6_Header, 
	const uint8_t * const Buffer, 
	const size_t Length)
{
//Initialization
	const auto Validation = std::make_unique<uint8_t[]>(sizeof(ipv6_psd_hdr) + Length + MEMORY_RESERVED_BYTES);
	memset(Validation.get(), 0, sizeof(ipv6_psd_hdr) + Length + MEMORY_RESERVED_BYTES);

//Get checksum.
	reinterpret_cast<ipv6_psd_hdr *>(Validation.get())->Destination = IPv6_Header->Destination;
	reinterpret_cast<ipv6_psd_hdr *>(Validation.get())->Source = IPv6_Header->Source;
	reinterpret_cast<ipv6_psd_hdr *>(Validation.get())->Length = hton32(static_cast<const uint32_t>(Length));
	reinterpret_cast<ipv6_psd_hdr *>(Validation.get())->NextHeader = IPPROTO_ICMPV6;
	memcpy_s(Validation.get() + sizeof(ipv6_psd_hdr), Length, Buffer, Length);

	return GetChecksum_Internet(reinterpret_cast<const uint16_t *>(Validation.get()), sizeof(ipv6_psd_hdr) + Length);
}

//Get TCP or UDP checksum
uint16_t GetChecksum_TCP_UDP(
	const uint16_t Protocol_Network, 
	const uint16_t Protocol_Transport, 
	const uint8_t * const Buffer, 
	const size_t Length, 
	const size_t DataOffset)
{
//IPv6
	if (Protocol_Network == AF_INET6)
	{
		const auto Validation = std::make_unique<uint8_t[]>(sizeof(ipv6_psd_hdr) + Length - DataOffset + MEMORY_RESERVED_BYTES);
		memset(Validation.get(), 0, sizeof(ipv6_psd_hdr) + Length - DataOffset + MEMORY_RESERVED_BYTES);
		reinterpret_cast<ipv6_psd_hdr *>(Validation.get())->Destination = reinterpret_cast<const ipv6_hdr *>(Buffer)->Destination;
		reinterpret_cast<ipv6_psd_hdr *>(Validation.get())->Source = reinterpret_cast<const ipv6_hdr *>(Buffer)->Source;
		reinterpret_cast<ipv6_psd_hdr *>(Validation.get())->Length = hton32(static_cast<const uint32_t>(Length - DataOffset));
		reinterpret_cast<ipv6_psd_hdr *>(Validation.get())->NextHeader = static_cast<const uint8_t>(Protocol_Transport);
		memcpy_s(Validation.get() + sizeof(ipv6_psd_hdr), Length - DataOffset, Buffer + sizeof(ipv6_hdr) + DataOffset, Length - DataOffset);

		return GetChecksum_Internet(reinterpret_cast<const uint16_t *>(Validation.get()), sizeof(ipv6_psd_hdr) + Length - DataOffset);
	}
//IPv4
	else if (Protocol_Network == AF_INET)
	{
		const auto Validation = std::make_unique<uint8_t[]>(sizeof(ipv4_psd_hdr) + Length + MEMORY_RESERVED_BYTES);
		memset(Validation.get(), 0, sizeof(ipv4_psd_hdr) + Length + MEMORY_RESERVED_BYTES);
		reinterpret_cast<ipv4_psd_hdr *>(Validation.get())->Destination = reinterpret_cast<const ipv4_hdr *>(Buffer)->Destination;
		reinterpret_cast<ipv4_psd_hdr *>(Validation.get())->Source = reinterpret_cast<const ipv4_hdr *>(Buffer)->Source;
		reinterpret_cast<ipv4_psd_hdr *>(Validation.get())->Length = hton16(static_cast<const uint16_t>(Length));
		reinterpret_cast<ipv4_psd_hdr *>(Validation.get())->Protocol = static_cast<const uint8_t>(Protocol_Transport);
		memcpy_s(Validation.get() + sizeof(ipv4_psd_hdr), Length, Buffer + static_cast<const size_t>(reinterpret_cast<const ipv4_hdr *>(Buffer)->IHL) * IPV4_IHL_BYTES_SET, Length);

		return GetChecksum_Internet(reinterpret_cast<const uint16_t *>(Validation.get()), sizeof(ipv4_psd_hdr) + Length);
	}

	return EXIT_FAILURE;
}

//Add length data to TCP DNS transmission
size_t AddLengthDataToHeader(
	uint8_t * const Buffer, 
	const size_t DataLength, 
	const size_t BufferSize)
{
	if (DataLength + sizeof(uint16_t) < BufferSize)
	{
		memmove_s(Buffer + sizeof(uint16_t), BufferSize - sizeof(uint16_t), Buffer, DataLength);
		reinterpret_cast<dns_tcp_hdr *>(Buffer)->Length = hton16(static_cast<const uint16_t>(DataLength));
		return DataLength + sizeof(uint16_t);
	}

	return EXIT_FAILURE;
}

//Convert data from string to DNS query
size_t StringToPacketQuery(
	const uint8_t * const FName, 
	uint8_t * const TName, 
	const size_t BufferSize)
{
//Initialization
	std::array<int, 3U> Index{};
	Index.at(0) = static_cast<const int>(strnlen_s(reinterpret_cast<const char *>(FName), DOMAIN_MAXSIZE));
	if (Index.at(0) > 0)
		--Index.at(0);
	else 
		return 0;
	Index.at(2U) = Index.at(0) + 1;
	if (static_cast<size_t>(Index.at(0)) + 2U >= BufferSize)
		return DOMAIN_MAXSIZE;
	*(TName + Index.at(0) + 2) = 0;

//Convert domain.
	for (;Index.at(0) >= 0;--Index.at(0), --Index.at(2U))
	{
		if (FName[Index.at(0)] == ASCII_PERIOD)
		{
			*(TName + Index.at(2U)) = static_cast<const uint8_t>(Index.at(1U));
			Index.at(1U) = 0;
		}
		else {
			*(TName + Index.at(2U)) = FName[Index.at(0)];
			++Index.at(1U);
		}
	}

	*(TName + Index.at(2U)) = static_cast<const uint8_t>(Index.at(1U));
	return strnlen_s(reinterpret_cast<const char *>(TName), DOMAIN_MAXSIZE - 1U) + NULL_TERMINATE_LENGTH;
}

//Convert data from DNS query to string
size_t PacketQueryToString(
	const uint8_t * const TName, 
	const size_t BufferSize, 
	std::string &FName)
{
//Initialization
	std::array<uint8_t, 2U> StringIter{};
	std::array<int, 2U> MarkIndex{};
	size_t LocateIndex = 0;
	FName.clear();

//Convert domain.
	for (LocateIndex = 0;LocateIndex < BufferSize;++LocateIndex)
	{
	//Domain length check
		if (LocateIndex >= DOMAIN_MAXSIZE)
		{
			return DOMAIN_MAXSIZE;
		}
	//Domain pointer check
		else if (TName[LocateIndex] >= DNS_POINTER_8_BITS)
		{
			return LocateIndex + sizeof(uint16_t);
		}
	//Mark the first label.
		else if (LocateIndex == 0)
		{
			MarkIndex.at(0) = TName[LocateIndex];
		}
	//Mark other labels. 
		else if (LocateIndex == static_cast<const size_t>(MarkIndex.at(0)) + static_cast<const size_t>(MarkIndex.at(1U)) + 1U)
		{
			MarkIndex.at(0) = TName[LocateIndex];
			if (MarkIndex.at(0) == 0)
			{
				break;
			}
			else {
				MarkIndex.at(1U) = static_cast<const int>(LocateIndex);
				FName.append(".");
			}
		}
	//Convert to string.
		else {
			StringIter.at(0) = TName[LocateIndex];
			FName.append(reinterpret_cast<const char *>(StringIter.data()));
		}
	}

	return LocateIndex;
}

//Convert data from compression DNS query to whole DNS query
size_t MarkWholePacketQuery(
	const uint8_t * const WholePacket, 
	const size_t Length, 
	const uint8_t * const TName, 
	const size_t TNameIndex, 
	std::string &FName)
{
//Length and pointer index check
	if (FName.length() >= DOMAIN_MAXSIZE || TNameIndex < sizeof(dns_hdr) || TNameIndex >= Length)
		return 0;

//Initialization
	std::array<uint8_t, 2U> StringIter{};
	std::array<int, 2U> MarkIndex{};
	size_t LocateIndex = 0;

//Convert domain.
	for (LocateIndex = 0;LocateIndex < Length - TNameIndex;++LocateIndex)
	{
	//Domain pointer check
		if (TName[LocateIndex] >= DNS_POINTER_8_BITS)
		{
			const size_t PointerIndex = ntoh16(*reinterpret_cast<const uint16_t *>(TName + LocateIndex)) & DNS_POINTER_BIT_GET_LOCATE;
			if (PointerIndex < TNameIndex)
			{
				if (!FName.empty())
					FName.append(".");

				return MarkWholePacketQuery(WholePacket, Length, WholePacket + PointerIndex, PointerIndex, FName);
			}
			else {
				return LocateIndex;
			}
		}
		else if (LocateIndex == 0)
		{
			MarkIndex.at(0) = TName[LocateIndex];
		}
		else if (LocateIndex == static_cast<const size_t>(MarkIndex.at(0)) + static_cast<const size_t>(MarkIndex.at(1U)) + 1U)
		{
			MarkIndex.at(0) = TName[LocateIndex];
			if (MarkIndex.at(0) == 0)
				break;
			else 
				MarkIndex.at(1U) = static_cast<const int>(LocateIndex);

			FName.append(".");
		}
		else {
			StringIter.at(0) = TName[LocateIndex];
			FName.append(reinterpret_cast<const char *>(StringIter.data()));
		}
	}

	return LocateIndex;
}

//Generate random domain
void GenerateRandomDomain(
	uint8_t * const Buffer, 
	const size_t BufferSize)
{
//Generate random domain length.
	size_t RandomLength = 0, Index = 0;
	GenerateRandomBuffer(&RandomLength, sizeof(RandomLength), nullptr, DOMAIN_RANDOM_MINSIZE, DOMAIN_SINGLE_DATA_MAXSIZE);
	if (RandomLength >= BufferSize)
		return;
	else if (RandomLength < DOMAIN_RANDOM_MINSIZE)
		RandomLength = DOMAIN_RANDOM_MINSIZE;

//Random distribution initialization
	uint8_t *DomainTableTarget = nullptr;
	if (Parameter.DomainCaseConversion)
	{
		DomainTableTarget = GlobalRunningStatus.DomainTable_Upper;
		Index = strnlen_s(reinterpret_cast<const char *>(GlobalRunningStatus.DomainTable_Upper), DOMAIN_SINGLE_DATA_MAXSIZE);
	}
	else {
		DomainTableTarget = GlobalRunningStatus.DomainTable_Normal;
		Index = strnlen_s(reinterpret_cast<const char *>(GlobalRunningStatus.DomainTable_Normal), DOMAIN_SINGLE_DATA_MAXSIZE);
	}
	std::uniform_int_distribution<uint16_t> RandomDistribution_Normal(0, static_cast<const uint16_t>(Index - 2U));
	std::uniform_int_distribution<uint16_t> RandomDistribution_Top(10U, static_cast<const uint16_t>(Index - 3U));

//Generate random domain.
	for (Index = 0;Index < RandomLength;++Index)
	{
	//Generate not including "-".
		if (Index > 0 && Index + DOMAIN_RANDOM_MINSIZE < RandomLength)
			GenerateRandomBuffer(Buffer + Index, sizeof(uint8_t), &RandomDistribution_Normal, 0, 0);
	//Generate not including number, "-", and ".".
		else 
			GenerateRandomBuffer(Buffer + Index, sizeof(uint8_t), &RandomDistribution_Top, 0, 0);

	//Point location of domain table.
		Buffer[Index] = DomainTableTarget[Buffer[Index]];
	}

//Fix domain to follow preferred name syntax.
	for (Index = 0;Index < RandomLength - DOMAIN_RANDOM_MINSIZE;++Index)
	{
		if (Index + 1U < RandomLength - DOMAIN_RANDOM_MINSIZE && Buffer[Index] == ASCII_PERIOD && Buffer[Index + 1U] == ASCII_PERIOD)
		{
			GenerateRandomBuffer(Buffer + Index, sizeof(uint8_t), &RandomDistribution_Top, 0, 0);
			Buffer[Index] = DomainTableTarget[Buffer[Index]];
		}
	}

//Generate like a normal Top-Level Domain/TLD.
	GenerateRandomBuffer(&Index, sizeof(Index), nullptr, 1U, 4U);
	Buffer[RandomLength - DOMAIN_RANDOM_MINSIZE + Index] = ASCII_PERIOD;

	return;
}

//Make Domain Case Conversion
void MakeDomainCaseConversion(
	uint8_t * const Buffer, 
	const size_t BufferSize)
{
//Initialization
	auto DataLength = strnlen_s(reinterpret_cast<const char *>(Buffer), BufferSize);
	if (DataLength <= DOMAIN_MINSIZE || DataLength >= DOMAIN_MAXSIZE)
		return;

//Exclude if no any lower characters in domain name.
	auto IsNeedConvert = false;
	for (size_t Index = 0;Index < DataLength;++Index)
	{
		if (Buffer[Index] >= ASCII_LOWERCASE_A && Buffer[Index] <= ASCII_LOWERCASE_Z)
		{
			IsNeedConvert = true;
			break;
		}
	}

//Stop convert process.
	if (!IsNeedConvert)
		return;

//Convert domain case.
	size_t RandomValue = 0;
	for (size_t Index = 0;Index < DataLength;++Index)
	{
		GenerateRandomBuffer(&RandomValue, sizeof(RandomValue), nullptr, 0, 0);
		if (RandomValue % 2U == 0 && Buffer[Index] >= ASCII_LOWERCASE_A && Buffer[Index] <= ASCII_LOWERCASE_Z)
			Buffer[Index] = static_cast<const uint8_t>(toupper(Buffer[Index]));
	}

//Make sure domain name must have more than one upper character.
	for (size_t Index = 0;Index < DataLength;++Index)
	{
	//Stop if any upper characters.
		if (Buffer[Index] >= ASCII_UPPERCASE_A && Buffer[Index] <= ASCII_UPPERCASE_Z)
		{
			break;
		}
	//Convert the first lower character to upper character.
		else if (Index + 1U == DataLength)
		{
			for (size_t InnerIndex = 0;InnerIndex < DataLength;++InnerIndex)
			{
				if (Buffer[InnerIndex] >= ASCII_LOWERCASE_A && Buffer[InnerIndex] <= ASCII_LOWERCASE_Z)
				{
					Buffer[InnerIndex] = static_cast<const uint8_t>(toupper(Buffer[InnerIndex]));
					break;
				}
			}
		}
	}

	return;
}

//Move any EDNS Label to the end of packet
//Some records like SIG and TSIG need to locate at the end of the DNS packet, but they are only used to transport between DNS servers.
bool Move_EDNS_LabelToEnd(
	DNS_PACKET_DATA * const PacketStructure)
{
//Packet without EDNS Label
	if (PacketStructure->EDNS_Location == 0)
		return true;

//Packet with EDNS Label, but it's already stored at the end of packet.
	if (PacketStructure->EDNS_Location == PacketStructure->Records_Location.back())
	{
	//EDNS version check
		if (reinterpret_cast<const edns_header *>(PacketStructure->Buffer + PacketStructure->EDNS_Location)->Version != EDNS_VERSION_ZERO)
			return false;
		else 
			return true;
	}

//Packet with EDNS Label, but it's not stored at the end of packet.
	for (size_t Index = 0;Index < PacketStructure->Records_Location.size();++Index)
	{
		if (PacketStructure->Records_Location.at(Index) == PacketStructure->EDNS_Location)
		{
		//EDNS version check
			if (reinterpret_cast<const edns_header *>(PacketStructure->Buffer + PacketStructure->EDNS_Location)->Version != EDNS_VERSION_ZERO)
				return false;

		//Initialization
			const auto BufferTemp = std::make_unique<uint8_t[]>(PacketStructure->Length + MEMORY_RESERVED_BYTES);
			memset(BufferTemp.get(), 0, PacketStructure->Length + MEMORY_RESERVED_BYTES);

		//Copy all resource records except EDNS Label and copy EDNS Label to the end of packet.
			memcpy_s(BufferTemp.get(), PacketStructure->Length, PacketStructure->Buffer, PacketStructure->EDNS_Location);
			memcpy_s(BufferTemp.get() + PacketStructure->EDNS_Location, PacketStructure->Length - PacketStructure->EDNS_Location, PacketStructure->Buffer + PacketStructure->EDNS_Location + PacketStructure->EDNS_Length, PacketStructure->Length - PacketStructure->EDNS_Location - PacketStructure->EDNS_Length);
			memcpy_s(BufferTemp.get() + PacketStructure->Length - PacketStructure->EDNS_Length, PacketStructure->EDNS_Length, PacketStructure->Buffer + PacketStructure->EDNS_Location, PacketStructure->EDNS_Length);

		//Rebuild DNS counts.
			if (Index < PacketStructure->Records_AnswerCount)
				--PacketStructure->Records_AnswerCount;
			else if (Index < PacketStructure->Records_AnswerCount + PacketStructure->Records_AuthorityCount)
				--PacketStructure->Records_AuthorityCount;
			else if (Index < PacketStructure->Records_AnswerCount + PacketStructure->Records_AuthorityCount + PacketStructure->Records_AdditionalCount)
				--PacketStructure->Records_AdditionalCount;
			else 
				return true;
			++PacketStructure->Records_AdditionalCount;

		//Rebuild DNS header counts.
			reinterpret_cast<dns_hdr *>(BufferTemp.get())->Answer = hton16(static_cast<const uint16_t>(PacketStructure->Records_AnswerCount));
			reinterpret_cast<dns_hdr *>(BufferTemp.get())->Authority = hton16(static_cast<const uint16_t>(PacketStructure->Records_AuthorityCount));
			reinterpret_cast<dns_hdr *>(BufferTemp.get())->Additional = hton16(static_cast<const uint16_t>(PacketStructure->Records_AdditionalCount));

		//Copy back DNS packet.
			memset(PacketStructure->Buffer, 0, PacketStructure->Length);
			memcpy_s(PacketStructure->Buffer, PacketStructure->Length, BufferTemp.get(), PacketStructure->Length);

		//Move EDNS Label item.
			for (size_t InnerIndex = Index;InnerIndex < PacketStructure->Records_Length.size();++InnerIndex)
				PacketStructure->Records_Length.at(InnerIndex) -= PacketStructure->EDNS_Length;
			PacketStructure->Records_Location.erase(PacketStructure->Records_Location.begin() + Index);
			PacketStructure->Records_Length.erase(PacketStructure->Records_Length.begin() + Index);
			PacketStructure->Records_Location.push_back(PacketStructure->Length - PacketStructure->EDNS_Length);
			PacketStructure->Records_Length.push_back(PacketStructure->EDNS_Length);
			PacketStructure->EDNS_Location = PacketStructure->Length - PacketStructure->EDNS_Length;

			break;
		}
	}

	return true;
}

//Add EDNS label to DNS packet(C-Style string, packet without EDNS Label)
size_t Add_EDNS_LabelToPacket(
	uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize, 
	const SOCKET_DATA * const LocalSocketData)
{
//Initialization
	const auto DNS_Header = reinterpret_cast<dns_hdr *>(Buffer);
	if (DNS_Header->Additional > 0)
		return Length;
	else 
		DNS_Header->Additional = hton16(UINT16_NUM_ONE);
	auto DataLength = Length;

//Add a new EDNS Label/OPT Additional resource records.
	if (DataLength + sizeof(edns_header) >= BufferSize)
		return DataLength;
	const auto EDNS_Header = reinterpret_cast<edns_header *>(Buffer + DataLength);
	EDNS_Header->Type = hton16(DNS_TYPE_OPT);
	EDNS_Header->UDP_PayloadSize = hton16(static_cast<const uint16_t>(Parameter.EDNS_PayloadSize));
	DataLength += sizeof(edns_header);

//DNSSEC request
	if (Parameter.DNSSEC_Request)
	{
		DNS_Header->Flags = hton16(ntoh16(DNS_Header->Flags) | DNS_FLAG_GET_BIT_AD); //Set Authentic Data bit.
//		DNS_Header->Flags = hton16(ntoh16(DNS_Header->Flags) | DNS_FLAG_GET_BIT_CD); //Set Checking Disabled bit.
		EDNS_Header->Z_Field = hton16(ntoh16(EDNS_Header->Z_Field) | EDNS_FLAG_GET_BIT_DO); //Set Accepts DNSSEC security resource records bit.
	}

//EDNS client subnet
	if ((Parameter.EDNS_ClientSubnet_Relay && LocalSocketData != nullptr) || 
		Parameter.LocalMachineSubnet_IPv6 != nullptr || Parameter.LocalMachineSubnet_IPv4 != nullptr)
	{
		const auto DNS_Query = reinterpret_cast<dns_qry *>(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer, BufferSize));

	//Length, DNS Class and DNS record check
		if (DataLength + sizeof(edns_client_subnet) >= BufferSize || (ntoh16(DNS_Query->Type) != DNS_TYPE_AAAA && ntoh16(DNS_Query->Type) != DNS_TYPE_A))
			return DataLength;

		const auto EDNS_Subnet_Header = reinterpret_cast<edns_client_subnet *>(Buffer + DataLength);

	//AAAA record(IPv6)
		if (ntoh16(DNS_Query->Type) == DNS_TYPE_AAAA && 
			((Parameter.EDNS_ClientSubnet_Relay && LocalSocketData != nullptr && LocalSocketData->SockAddr.ss_family == AF_INET6) || 
			Parameter.LocalMachineSubnet_IPv6 != nullptr))
		{
		//Make EDNS Subnet header.
			EDNS_Subnet_Header->Code = hton16(EDNS_CODE_CSUBNET);
			EDNS_Subnet_Header->Family = hton16(EDNS_ADDRESS_FAMILY_IPV6);

		//Mark network prefix.
			in6_addr BinaryAddr;
			memset(&BinaryAddr, 0, sizeof(BinaryAddr));
			if (Parameter.EDNS_ClientSubnet_Relay && LocalSocketData != nullptr && LocalSocketData->SockAddr.ss_family == AF_INET6)
			{
			//Default prefix of IPv6 address, please visit RFC 7871(https://tools.ietf.org/html/rfc7871).
				if (Parameter.LocalMachineSubnet_IPv6 != nullptr)
					EDNS_Subnet_Header->Netmask_Source = static_cast<const uint8_t>(Parameter.LocalMachineSubnet_IPv6->second);
				else 
					EDNS_Subnet_Header->Netmask_Source = EDNS_CLIENT_SUBNET_SOURCE_PREFIX_IPV6;

			//Keep bits of address.
				if (!AddressPrefixReplacing(AF_INET6, &reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData->SockAddr)->sin6_addr, &BinaryAddr, EDNS_Subnet_Header->Netmask_Source))
					return DataLength;
			}
			else {
				EDNS_Subnet_Header->Netmask_Source = static_cast<const uint8_t>(Parameter.LocalMachineSubnet_IPv6->second);
			}

		//Length check
			DataLength += sizeof(edns_client_subnet);
			if (DataLength + sizeof(in6_addr) >= BufferSize)
				return DataLength;

		//Copy subnet address.
			size_t PrefixBytes = 0;
			if (EDNS_Subnet_Header->Netmask_Source % BYTES_TO_BITS > 0)
				PrefixBytes = EDNS_Subnet_Header->Netmask_Source / BYTES_TO_BITS + sizeof(uint8_t);
			else 
				PrefixBytes = EDNS_Subnet_Header->Netmask_Source / BYTES_TO_BITS;
			if (Parameter.EDNS_ClientSubnet_Relay && LocalSocketData != nullptr && LocalSocketData->SockAddr.ss_family == AF_INET6)
				*reinterpret_cast<in6_addr *>(Buffer + DataLength) = BinaryAddr;
			else 
				*reinterpret_cast<in6_addr *>(Buffer + DataLength) = reinterpret_cast<const sockaddr_in6 *>(&Parameter.LocalMachineSubnet_IPv6->first)->sin6_addr;
			EDNS_Subnet_Header->Length = hton16(static_cast<const uint16_t>(sizeof(uint16_t) + sizeof(uint8_t) * 2U + PrefixBytes));
			EDNS_Header->DataLength = hton16(static_cast<const uint16_t>(sizeof(edns_client_subnet) + PrefixBytes));
			DataLength += PrefixBytes;
		}
	//A record(IPv4)
		else if (ntoh16(DNS_Query->Type) == DNS_TYPE_A && 
			((Parameter.EDNS_ClientSubnet_Relay && LocalSocketData != nullptr && LocalSocketData->SockAddr.ss_family == AF_INET) || 
			Parameter.LocalMachineSubnet_IPv4 != nullptr))
		{
		//Make EDNS Subnet header.
			EDNS_Subnet_Header->Code = hton16(EDNS_CODE_CSUBNET);
			EDNS_Subnet_Header->Family = hton16(EDNS_ADDRESS_FAMILY_IPV4);

		//Mark network prefix.
			in_addr BinaryAddr;
			memset(&BinaryAddr, 0, sizeof(BinaryAddr));
			if (Parameter.EDNS_ClientSubnet_Relay && LocalSocketData != nullptr && LocalSocketData->SockAddr.ss_family == AF_INET)
			{
			//Default prefix of IPv4 address, please visit RFC 7871(https://tools.ietf.org/html/rfc7871).
				if (Parameter.LocalMachineSubnet_IPv4 != nullptr)
					EDNS_Subnet_Header->Netmask_Source = static_cast<const uint8_t>(Parameter.LocalMachineSubnet_IPv4->second);
				else 
					EDNS_Subnet_Header->Netmask_Source = EDNS_CLIENT_SUBNET_SOURCE_PREFIX_IPV4;

			//Keep bits of address.
				if (!AddressPrefixReplacing(AF_INET, &reinterpret_cast<const sockaddr_in *>(&LocalSocketData->SockAddr)->sin_addr, &BinaryAddr, EDNS_Subnet_Header->Netmask_Source))
					return DataLength;
			}
			else {
				EDNS_Subnet_Header->Netmask_Source = static_cast<const uint8_t>(Parameter.LocalMachineSubnet_IPv4->second);
			}

		//Length check
			DataLength += sizeof(edns_client_subnet);
			if (DataLength + sizeof(in_addr) >= BufferSize)
				return DataLength;

		//Copy subnet address.
			size_t PrefixBytes = 0;
			if (EDNS_Subnet_Header->Netmask_Source % BYTES_TO_BITS > 0)
				PrefixBytes = EDNS_Subnet_Header->Netmask_Source / BYTES_TO_BITS + sizeof(uint8_t);
			else 
				PrefixBytes = EDNS_Subnet_Header->Netmask_Source / BYTES_TO_BITS;
			if (Parameter.EDNS_ClientSubnet_Relay && LocalSocketData != nullptr && LocalSocketData->SockAddr.ss_family == AF_INET)
				*reinterpret_cast<in_addr *>(Buffer + DataLength) = BinaryAddr;
			else 
				*reinterpret_cast<in_addr *>(Buffer + DataLength) = reinterpret_cast<const sockaddr_in *>(&Parameter.LocalMachineSubnet_IPv4->first)->sin_addr;
			EDNS_Subnet_Header->Length = hton16(static_cast<const uint16_t>(sizeof(uint16_t) + sizeof(uint8_t) * 2U + PrefixBytes));
			EDNS_Header->DataLength = hton16(static_cast<const uint16_t>(sizeof(edns_client_subnet) + PrefixBytes));
			DataLength += PrefixBytes;
		}
	}

	return DataLength;
}

//Add EDNS label to DNS packet(DNS packet structure)
bool Add_EDNS_LabelToPacket(
	DNS_PACKET_DATA * const PacketStructure, 
	const bool IsAlreadyClientSubnet, 
	const bool IsAlreadyCookies, 
	const SOCKET_DATA * const LocalSocketData)
{
//Initialization
	const auto DNS_Header = reinterpret_cast<dns_hdr *>(PacketStructure->Buffer);
	edns_header *EDNS_Header = nullptr;

//EDNS Options check
	size_t EDNS_LabelPrediction = 0;
	auto IsEDNS_ClientSubnet = false;
	if (!IsAlreadyClientSubnet && //EDNS Client Subnet
		(ntoh16(PacketStructure->QueryType) == DNS_TYPE_AAAA || ntoh16(PacketStructure->QueryType) == DNS_TYPE_A || 
		(Parameter.EDNS_ClientSubnet_Relay && LocalSocketData != nullptr) || 
		Parameter.LocalMachineSubnet_IPv6 != nullptr || Parameter.LocalMachineSubnet_IPv4 != nullptr))
	{
		IsEDNS_ClientSubnet = true;
		EDNS_LabelPrediction += sizeof(edns_client_subnet) * 2U + sizeof(in6_addr) + sizeof(in_addr);
	}

/* Under construction(2018-08-11)
	auto IsEDNS_Cookies = false;
	if (!IsAlreadyCookies) //DNS Cookies
	{
		IsEDNS_Cookies = true;
		EDNS_LabelPrediction += sizeof(edns_cookies);
	}
*/

//Packet with EDNS Label
	if (PacketStructure->EDNS_Location > 0)
	{
	//EDNS Label length check
		if (PacketStructure->Length + EDNS_LabelPrediction >= PacketStructure->BufferSize)
			return false;
		else 
			EDNS_Header = reinterpret_cast<edns_header *>(PacketStructure->Buffer + PacketStructure->EDNS_Location);
	}
//Packet without EDNS Label
	else {
	//EDNS Label length check
		EDNS_LabelPrediction += sizeof(edns_header);
		if (PacketStructure->Length + EDNS_LabelPrediction >= PacketStructure->BufferSize)
			return false;

	//Make a new EDNS Label/OPT Additional resource record.
		memset(PacketStructure->Buffer + PacketStructure->Length, 0, PacketStructure->BufferSize - PacketStructure->Length);
		EDNS_Header = reinterpret_cast<edns_header *>(PacketStructure->Buffer + PacketStructure->Length);
		EDNS_Header->Type = hton16(DNS_TYPE_OPT);
		EDNS_Header->UDP_PayloadSize = hton16(static_cast<const uint16_t>(Parameter.EDNS_PayloadSize));

	//Update EDNS Label information.
		PacketStructure->EDNS_Location = PacketStructure->Length;
		PacketStructure->EDNS_Length = sizeof(edns_header);
		PacketStructure->Records_Location.push_back(PacketStructure->Length);
		PacketStructure->Records_Length.push_back(sizeof(edns_header));
		PacketStructure->Length += sizeof(edns_header);

	//Rebuild DNS header counts.
		++PacketStructure->Records_AdditionalCount;
		DNS_Header->Additional = hton16(static_cast<const uint16_t>(PacketStructure->Records_AdditionalCount));
	}

//Modify EDNS Label.
//DNSSEC request
	if (Parameter.DNSSEC_Request)
	{
		DNS_Header->Flags = hton16(ntoh16(DNS_Header->Flags) | DNS_FLAG_GET_BIT_AD); //Set Authentic Data bit.
//		DNS_Header->Flags = hton16(ntoh16(DNS_Header->Flags) | DNS_FLAG_GET_BIT_CD); //Set Checking Disabled bit.
		EDNS_Header->Z_Field = hton16(ntoh16(EDNS_Header->Z_Field) | EDNS_FLAG_GET_BIT_DO); //Set Accepts DNSSEC security resource records bit.
	}

/* Under construction(2018-08-11)
//DNS Cookies
	if (IsEDNS_Cookies)
	{
	//Make Cookies header.
		const auto EDNS_CookiesHeader = reinterpret_cast<edns_cookies *>(PacketStructure->Buffer + PacketStructure->EDNS_Location + PacketStructure->EDNS_Length);
		EDNS_CookiesHeader->Code = hton16(EDNS_CODE_COOKIES);
		GenerateRandomBuffer(&EDNS_CookiesHeader->ClientCookie, sizeof(EDNS_CookiesHeader->ClientCookie), nullptr, 0, 0);

	//Update DNS Cookies information.
		EDNS_CookiesHeader->Length = hton16(static_cast<const uint16_t>(ntoh16(EDNS_CookiesHeader->Length) + sizeof(EDNS_CookiesHeader->ClientCookie)));
		EDNS_Header->DataLength = hton16(static_cast<const uint16_t>(ntoh16(EDNS_Header->DataLength) + sizeof(edns_cookies)));
		PacketStructure->Length += sizeof(edns_cookies);
		PacketStructure->Records_Length.back() += sizeof(edns_cookies);
		PacketStructure->EDNS_Length += sizeof(edns_cookies);
	}
*/

//EDNS Client Subnet
	if (IsEDNS_ClientSubnet)
	{
	//EDNS Client Subnet initialization
		const auto EDNS_ClientSubnetHeader = reinterpret_cast<edns_client_subnet *>(PacketStructure->Buffer + PacketStructure->EDNS_Location + PacketStructure->EDNS_Length);
		auto IsFunctionRelay = false, IsGlobalRelay = false;

	//AAAA record(IPv6)
		if (ntoh16(PacketStructure->QueryType) == DNS_TYPE_AAAA)
		{
			if (Parameter.EDNS_ClientSubnet_Relay && LocalSocketData != nullptr && LocalSocketData->SockAddr.ss_family == AF_INET6)
				IsFunctionRelay = true;
			else if (Parameter.LocalMachineSubnet_IPv6 != nullptr)
				IsGlobalRelay = true;
			if (IsFunctionRelay || IsGlobalRelay)
			{
			//Make EDNS Subnet header.
				EDNS_ClientSubnetHeader->Code = hton16(EDNS_CODE_CSUBNET);
				EDNS_ClientSubnetHeader->Family = hton16(EDNS_ADDRESS_FAMILY_IPV6);

			//Mark network prefix address.
				in6_addr BinaryAddr;
				memset(&BinaryAddr, 0, sizeof(BinaryAddr));
				if (IsFunctionRelay)
				{
				//Default prefix of IPv6 address, please visit RFC 7871(https://tools.ietf.org/html/rfc7871).
					if (Parameter.LocalMachineSubnet_IPv6 != nullptr)
						EDNS_ClientSubnetHeader->Netmask_Source = static_cast<const uint8_t>(Parameter.LocalMachineSubnet_IPv6->second);
					else 
						EDNS_ClientSubnetHeader->Netmask_Source = EDNS_CLIENT_SUBNET_SOURCE_PREFIX_IPV6;

				//Keep bits of address.
					if (!AddressPrefixReplacing(AF_INET6, &reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData->SockAddr)->sin6_addr, &BinaryAddr, EDNS_ClientSubnetHeader->Netmask_Source))
						return false;
				}
				else {
					EDNS_ClientSubnetHeader->Netmask_Source = static_cast<const uint8_t>(Parameter.LocalMachineSubnet_IPv6->second);
				}

			//Copy client subnet address.
				size_t PrefixBytes = 0;
				if (EDNS_ClientSubnetHeader->Netmask_Source % BYTES_TO_BITS > 0)
					PrefixBytes = EDNS_ClientSubnetHeader->Netmask_Source / BYTES_TO_BITS + sizeof(uint8_t);
				else 
					PrefixBytes = EDNS_ClientSubnetHeader->Netmask_Source / BYTES_TO_BITS;
				if (IsFunctionRelay)
					*reinterpret_cast<in6_addr *>(PacketStructure->Buffer + PacketStructure->EDNS_Location + PacketStructure->EDNS_Length + sizeof(edns_client_subnet)) = BinaryAddr;
				else 
					*reinterpret_cast<in6_addr *>(PacketStructure->Buffer + PacketStructure->EDNS_Location + PacketStructure->EDNS_Length + sizeof(edns_client_subnet)) = reinterpret_cast<const sockaddr_in6 *>(&Parameter.LocalMachineSubnet_IPv6->first)->sin6_addr;

			//Update EDNS Client Subnet information.
				EDNS_ClientSubnetHeader->Length = hton16(static_cast<const uint16_t>(ntoh16(EDNS_ClientSubnetHeader->Length) + sizeof(EDNS_ClientSubnetHeader->Family) + sizeof(EDNS_ClientSubnetHeader->Netmask_Source) + sizeof(EDNS_ClientSubnetHeader->Netmask_Scope) + PrefixBytes));
				EDNS_Header->DataLength = hton16(static_cast<const uint16_t>(ntoh16(EDNS_Header->DataLength) + sizeof(edns_client_subnet) + PrefixBytes));
				PacketStructure->Length += sizeof(edns_client_subnet) + PrefixBytes;
				PacketStructure->Records_Length.back() += sizeof(edns_client_subnet) + PrefixBytes;
				PacketStructure->EDNS_Length += sizeof(edns_client_subnet) + PrefixBytes;
			}
		}
	//A record(IPv4)
		else if (ntoh16(PacketStructure->QueryType) == DNS_TYPE_A)
		{
			if (Parameter.EDNS_ClientSubnet_Relay && LocalSocketData != nullptr && LocalSocketData->SockAddr.ss_family == AF_INET)
				IsFunctionRelay = true;
			else if (Parameter.LocalMachineSubnet_IPv4 != nullptr)
				IsGlobalRelay = true;
			if (IsFunctionRelay || IsGlobalRelay)
			{
			//Make EDNS Subnet header.
				EDNS_ClientSubnetHeader->Code = hton16(EDNS_CODE_CSUBNET);
				EDNS_ClientSubnetHeader->Family = hton16(EDNS_ADDRESS_FAMILY_IPV4);

			//Mark network prefix address.
				in_addr BinaryAddr;
				memset(&BinaryAddr, 0, sizeof(BinaryAddr));
				if (IsFunctionRelay)
				{
				//Default prefix of IPv4 address, please visit RFC 7871(https://tools.ietf.org/html/rfc7871).
					if (Parameter.LocalMachineSubnet_IPv4 != nullptr)
						EDNS_ClientSubnetHeader->Netmask_Source = static_cast<const uint8_t>(Parameter.LocalMachineSubnet_IPv4->second);
					else 
						EDNS_ClientSubnetHeader->Netmask_Source = EDNS_CLIENT_SUBNET_SOURCE_PREFIX_IPV4;

				//Keep bits of address.
					if (!AddressPrefixReplacing(AF_INET, &reinterpret_cast<const sockaddr_in *>(&LocalSocketData->SockAddr)->sin_addr, &BinaryAddr, EDNS_ClientSubnetHeader->Netmask_Source))
						return false;
				}
				else {
					EDNS_ClientSubnetHeader->Netmask_Source = static_cast<const uint8_t>(Parameter.LocalMachineSubnet_IPv4->second);
				}

			//Copy client subnet address.
				size_t PrefixBytes = 0;
				if (EDNS_ClientSubnetHeader->Netmask_Source % BYTES_TO_BITS > 0)
					PrefixBytes = EDNS_ClientSubnetHeader->Netmask_Source / BYTES_TO_BITS + sizeof(uint8_t);
				else 
					PrefixBytes = EDNS_ClientSubnetHeader->Netmask_Source / BYTES_TO_BITS;
				if (IsFunctionRelay)
					*reinterpret_cast<in_addr *>(PacketStructure->Buffer + PacketStructure->EDNS_Location + PacketStructure->EDNS_Length + sizeof(edns_client_subnet)) = BinaryAddr;
				else 
					*reinterpret_cast<in_addr *>(PacketStructure->Buffer + PacketStructure->EDNS_Location + PacketStructure->EDNS_Length + sizeof(edns_client_subnet)) = reinterpret_cast<const sockaddr_in *>(&Parameter.LocalMachineSubnet_IPv4->first)->sin_addr;

			//Update EDNS Client Subnet information.
				EDNS_ClientSubnetHeader->Length = hton16(static_cast<const uint16_t>(ntoh16(EDNS_ClientSubnetHeader->Length) + sizeof(EDNS_ClientSubnetHeader->Family) + sizeof(EDNS_ClientSubnetHeader->Netmask_Source) + sizeof(EDNS_ClientSubnetHeader->Netmask_Scope) + PrefixBytes));
				EDNS_Header->DataLength = hton16(static_cast<const uint16_t>(ntoh16(EDNS_Header->DataLength) + sizeof(edns_client_subnet) + PrefixBytes));
				PacketStructure->Length += sizeof(edns_client_subnet) + PrefixBytes;
				PacketStructure->Records_Length.back() += sizeof(edns_client_subnet) + PrefixBytes;
				PacketStructure->EDNS_Length += sizeof(edns_client_subnet) + PrefixBytes;
			}
		}
	}

	return true;
}

//Make Compression Pointer Mutation
size_t MakeCompressionPointerMutation(
	uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize)
{
//Initialization
	size_t Index = 0;
	GenerateRandomBuffer(&Index, sizeof(Index), nullptr, 0, 2U);

//Check Compression Pointer Mutation options.
	switch (Index)
	{
		case CPM_POINTER_TYPE_HEADER:
		{
			if (!Parameter.CPM_PointerToHeader)
			{
				if (Parameter.CPM_PointerToRR)
					Index = CPM_POINTER_TYPE_RR;
				else //Pointer to Additional(2)
					Index = CPM_POINTER_TYPE_ADDITIONAL;
			}
		}break;
		case CPM_POINTER_TYPE_RR:
		{
			if (!Parameter.CPM_PointerToRR)
			{
				if (Parameter.CPM_PointerToHeader)
					Index = CPM_POINTER_TYPE_HEADER;
				else //Pointer to Additional(2)
					Index = CPM_POINTER_TYPE_ADDITIONAL;
			}
		}break;
		case CPM_POINTER_TYPE_ADDITIONAL:
		{
			if (!Parameter.CPM_PointerToAdditional)
			{
				if (Parameter.CPM_PointerToHeader)
					Index = CPM_POINTER_TYPE_HEADER;
				else //Pointer to RR
					Index = CPM_POINTER_TYPE_RR;
			}
		}break;
		default:
		{
			return EXIT_FAILURE;
		}
	}

//Make Compression Pointer Mutation.
	if (Index == CPM_POINTER_TYPE_HEADER) //Pointer to header, like "<DNS Header><Domain><Pointer><Query>" and point to <DNS Header>.
	{
		memmove_s(Buffer + Length - sizeof(dns_qry) + NULL_TERMINATE_LENGTH, sizeof(dns_qry), Buffer + Length - sizeof(dns_qry), sizeof(dns_qry));
		*(Buffer + Length - sizeof(dns_qry) - 1U) = static_cast<const uint8_t>(DNS_POINTER_8_BIT_STRING);

	//Choose a random one.
		Index = GetCurrentSystemTime() % 4U;
		switch (Index)
		{
			case 0:
			{
				*(Buffer + Length - sizeof(dns_qry)) = ('\x04');
			}break;
			case 1U:
			{
				*(Buffer + Length - sizeof(dns_qry)) = ('\x06');
			}break;
			case 2U:
			{
				*(Buffer + Length - sizeof(dns_qry)) = ('\x08');
			}break;
			case 3U:
			{
				*(Buffer + Length - sizeof(dns_qry)) = ('\x0A');
			}break;
			default:
			{
				return EXIT_FAILURE;
			}
		}

		return Length + 1U;
	}
	else {
		dns_qry DNS_Query;
		memset(&DNS_Query, 0, sizeof(dns_qry));
		memcpy_s(&DNS_Query, sizeof(dns_qry), Buffer + DNS_PACKET_QUERY_LOCATE(Buffer, BufferSize), sizeof(DNS_Query));
		memmove_s(Buffer + sizeof(dns_hdr) + sizeof(uint16_t) + sizeof(dns_qry), BufferSize - sizeof(dns_hdr) - sizeof(uint16_t) - sizeof(dns_qry), Buffer + sizeof(dns_hdr), strnlen_s(reinterpret_cast<const char *>(Buffer) + sizeof(dns_hdr), Length - sizeof(dns_hdr)) + 1U);
		memcpy_s(Buffer + sizeof(dns_hdr) + sizeof(uint16_t), BufferSize - sizeof(dns_hdr) - sizeof(uint16_t), &DNS_Query, sizeof(DNS_Query));
		*(Buffer + sizeof(dns_hdr)) = static_cast<const uint8_t>(DNS_POINTER_8_BIT_STRING);
		*(Buffer + sizeof(dns_hdr) + 1U) = ('\x12');

	//Pointer to RR, like "<DNS Header><Pointer><Query><Domain>" and point to <Domain>.
		if (Index == CPM_POINTER_TYPE_RR)
		{
			return Length + 2U;
		}
	//Pointer to Additional, like "<DNS Header><Pointer><Query><Additional>" and point domain to <Additional>.
		else {
		//Make records.
			reinterpret_cast<dns_hdr *>(Buffer)->Additional = hton16(UINT16_NUM_ONE);
			if (ntoh16(DNS_Query.Type) == DNS_TYPE_AAAA)
			{
				const auto DNS_Record_AAAA = reinterpret_cast<dns_record_aaaa *>(Buffer + Length);
				DNS_Record_AAAA->Type = hton16(DNS_TYPE_AAAA);
				DNS_Record_AAAA->Classes = hton16(DNS_CLASS_INTERNET);
				GenerateRandomBuffer(&DNS_Record_AAAA->TTL, sizeof(DNS_Record_AAAA->TTL), nullptr, 0, 0);
				DNS_Record_AAAA->Length = hton16(sizeof(DNS_Record_AAAA->Address));
				GenerateRandomBuffer(&DNS_Record_AAAA->Address, sizeof(DNS_Record_AAAA->Address), nullptr, 0, 0);

				return Length + sizeof(dns_record_aaaa);
			}
//			else if (ntoh16(DNS_Query.Type) == DNS_TYPE_A)
			else { //A record
				const auto DNS_Record_A = reinterpret_cast<dns_record_a *>(Buffer + Length);
				DNS_Record_A->Type = hton16(DNS_TYPE_A);
				DNS_Record_A->Classes = hton16(DNS_CLASS_INTERNET);
				GenerateRandomBuffer(&DNS_Record_A->TTL, sizeof(DNS_Record_A->TTL), nullptr, 0, 0);
				DNS_Record_A->Length = hton16(sizeof(DNS_Record_A->Address));
				GenerateRandomBuffer(&DNS_Record_A->Address, sizeof(DNS_Record_A->Address), nullptr, 0, 0);

				return Length + sizeof(dns_record_a);
			}
		}
	}

	return EXIT_FAILURE;
}

//Mark responses to domain cache
bool MarkDomainCache(
	const uint8_t * const Buffer, 
	const size_t Length, 
	const SOCKET_DATA * const LocalSocketData)
{
//Check conditions.
	const auto DNS_Header = reinterpret_cast<const dns_hdr *>(Buffer);
	if (
	//Not a response packet
		(ntoh16(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RESPONSE) == 0 || 
	//Question resource records must be set one.
		ntoh16(DNS_Header->Question) != UINT16_NUM_ONE || 
	//Not any Answer resource records
		(DNS_Header->Answer == 0 && DNS_Header->Authority == 0) || 
//		&& DNS_Header->Additional == 0) || 
	//OPCode must be set Query/0.
		(ntoh16(DNS_Header->Flags) & DNS_FLAG_GET_BIT_OPCODE) != DNS_OPCODE_QUERY || 
	//Truncated bit must not be set.
		(ntoh16(DNS_Header->Flags) & DNS_FLAG_GET_BIT_TC) > 0 || 
	//RCode must be set No Error or Non-Existent Domain.
		((ntoh16(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RCODE) != DNS_RCODE_NOERROR && 
		(ntoh16(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RCODE) != DNS_RCODE_NXDOMAIN))
			return false;

//Initialization(A part)
	DNS_CACHE_DATA DNSCacheDataTemp;
	DNSCacheDataTemp.Length = 0;
	DNSCacheDataTemp.ClearCacheTime = 0;
	DNSCacheDataTemp.RecordType = reinterpret_cast<const dns_qry *>(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer, Length))->Type;
	memset(&DNSCacheDataTemp.ForAddress, 0, sizeof(DNSCacheDataTemp.ForAddress));
	uint32_t ResponseTTL = 0;

//Mark DNS A records and AAAA records only.
	if (DNSCacheDataTemp.RecordType == hton16(DNS_TYPE_AAAA) || DNSCacheDataTemp.RecordType == hton16(DNS_TYPE_A))
	{
		size_t DataLength = DNS_PACKET_RR_LOCATE(Buffer, Length), TTL_Counts = 0;

	//Scan all Answers resource records.
		for (size_t Index = 0;Index < ntoh16(DNS_Header->Answer);++Index)
		{
		//Domain pointer check
			if (DataLength + sizeof(uint16_t) < Length && Buffer[DataLength] >= DNS_POINTER_8_BITS)
			{
				const uint16_t DNS_Pointer = ntoh16(*reinterpret_cast<const uint16_t *>(Buffer + DataLength)) & DNS_POINTER_BIT_GET_LOCATE;
				if (DNS_Pointer >= Length || DNS_Pointer < sizeof(dns_hdr) || DNS_Pointer == DataLength || DNS_Pointer == DataLength + 1U)
					return false;
			}

		//Resource records domain name check
			DataLength += CheckQueryNameLength(Buffer + DataLength, Length - DataLength) + NULL_TERMINATE_LENGTH;
			if (DataLength + sizeof(dns_record_standard) > Length)
				break;

		//Standard resource record length check
			auto DNS_Record_Standard = reinterpret_cast<const dns_record_standard *>(Buffer + DataLength);
			DataLength += sizeof(dns_record_standard);
			if (DataLength > Length || DataLength + ntoh16(DNS_Record_Standard->Length) > Length)
				break;

		//Resource records data check
			if (DNS_Record_Standard->TTL > 0 && 
				((ntoh16(DNS_Record_Standard->Type) == DNS_TYPE_AAAA && ntoh16(DNS_Record_Standard->Length) == sizeof(in6_addr)) || 
				(ntoh16(DNS_Record_Standard->Type) == DNS_TYPE_A && ntoh16(DNS_Record_Standard->Length) == sizeof(in_addr))))
			{
				ResponseTTL += ntoh32(DNS_Record_Standard->TTL);
				++TTL_Counts;
			}

			DataLength += ntoh16(DNS_Record_Standard->Length);
		}

	//Calculate average TTL.
		if (TTL_Counts > 0)
			ResponseTTL = ResponseTTL / static_cast<const uint32_t>(TTL_Counts) + ResponseTTL % static_cast<const uint32_t>(TTL_Counts);
	}

//Set cache TTL.
	if (ResponseTTL == 0 && DNS_Header->Authority == 0) //Only mark A and AAAA records.
	{
		return false;
	}
	else {
	//Timer mode
		if (Parameter.DNS_CacheType == DNS_CACHE_TYPE::TIMER)
		{
		//Cache time is <TTL> seconds when Cache Parameter is 0.
		//Cache time is <Cache Parameter> seconds when TTL is shorter than Cache Parameter.
		//Cache time is <TTL + Cache Parameter> seconds when TTL is longer than Cache Parameter.
			if (Parameter.DNS_CacheParameter > 0)
			{
				if (ResponseTTL <= Parameter.DNS_CacheParameter)
					ResponseTTL = static_cast<const uint32_t>(Parameter.DNS_CacheParameter);
				else 
					ResponseTTL += static_cast<const uint32_t>(Parameter.DNS_CacheParameter);
			}
		}
	//Both mode
		else if (Parameter.DNS_CacheType == DNS_CACHE_TYPE::BOTH)
		{
		//Cache time is <TTL> seconds when Cache Parameter is 0.
		//Cache time is <Default TTL> seconds when TTL is shorter than Default TTL.
		//Cache time is <TTL + Default TTL> seconds when TTL is longer than Default TTL.
			if (Parameter.HostsDefaultTTL > 0)
			{
				if (ResponseTTL <= Parameter.HostsDefaultTTL)
					ResponseTTL = static_cast<const uint32_t>(Parameter.HostsDefaultTTL);
				else 
					ResponseTTL += static_cast<const uint32_t>(Parameter.HostsDefaultTTL);
			}
		}
	}

//Initialization(B part)
	if (Length <= DOMAIN_MAXSIZE)
	{
		auto DNSCacheDataBufferTemp = std::make_unique<uint8_t[]>(DOMAIN_MAXSIZE + MEMORY_RESERVED_BYTES);
		memset(DNSCacheDataBufferTemp.get(), 0, DOMAIN_MAXSIZE + MEMORY_RESERVED_BYTES);
		std::swap(DNSCacheDataTemp.Response, DNSCacheDataBufferTemp);
	}
	else {
		auto DNSCacheDataBufferTemp = std::make_unique<uint8_t[]>(Length + MEMORY_RESERVED_BYTES);
		memset(DNSCacheDataBufferTemp.get(), 0, Length + MEMORY_RESERVED_BYTES);
		std::swap(DNSCacheDataTemp.Response, DNSCacheDataBufferTemp);
	}

//Mark domain.
	DNSCacheDataTemp.Length = PacketQueryToString(Buffer + sizeof(dns_hdr), Length - sizeof(dns_hdr), DNSCacheDataTemp.Domain);
	if (DNSCacheDataTemp.Length <= DOMAIN_MINSIZE || DNSCacheDataTemp.Length >= DOMAIN_MAXSIZE)
		return false;

//Make insensitive domain.
	CaseConvert(DNSCacheDataTemp.Domain, false);
	memcpy_s(DNSCacheDataTemp.Response.get(), Length - sizeof(uint16_t), Buffer + sizeof(uint16_t), Length - sizeof(uint16_t));
	DNSCacheDataTemp.Length = Length - sizeof(uint16_t);
	DNSCacheDataTemp.ClearCacheTime = GetCurrentSystemTime() + static_cast<const uint64_t>(ResponseTTL) * SECOND_TO_MILLISECOND;

//Single address single cache
	if (LocalSocketData != nullptr) //Some network test thread do not need to mark request address, put them in default queue.
	{
	//IPv6
		if (Parameter.DNS_CacheSinglePrefix_IPv6 > 0 && LocalSocketData->SockAddr.ss_family == AF_INET6 && 
			!OperationModeFilter(AF_INET6, &reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData->SockAddr)->sin6_addr, LISTEN_MODE::PRIVATE)) //Put private network addessses in default queue.
		{
			DNSCacheDataTemp.ForAddress.Storage.ss_family = AF_INET6;
			if (!AddressPrefixReplacing(AF_INET6, &reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData->SockAddr)->sin6_addr, &DNSCacheDataTemp.ForAddress.IPv6.sin6_addr, Parameter.DNS_CacheSinglePrefix_IPv6))
				return false;
		}
	//IPv4
		else if (Parameter.DNS_CacheSinglePrefix_IPv4 > 0 && LocalSocketData->SockAddr.ss_family == AF_INET && 
			!OperationModeFilter(AF_INET, &reinterpret_cast<const sockaddr_in *>(&LocalSocketData->SockAddr)->sin_addr, LISTEN_MODE::PRIVATE)) //Put private network addessses in default queue.
		{
			DNSCacheDataTemp.ForAddress.Storage.ss_family = AF_INET;
			if (!AddressPrefixReplacing(AF_INET, &reinterpret_cast<const sockaddr_in *>(&LocalSocketData->SockAddr)->sin_addr, &DNSCacheDataTemp.ForAddress.IPv4.sin_addr, Parameter.DNS_CacheSinglePrefix_IPv4))
				return false;
		}
	//Default queue, single address single cache has been shutdown or request protocol is not supported.
//		else {
//			;
//		}
	}

//Remove old cache, mark cache data to global list and global index list.
	std::lock_guard<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	RemoveExpiredDomainCache();
	DNSCacheList.push_front(std::move(DNSCacheDataTemp));
	DNSCacheIndexList.insert(std::make_pair(DNSCacheList.front().Domain, DNSCacheList.begin()));

	return true;
}

//Check domain cache and make response
size_t CheckDomainCache(
	uint8_t * const ResultBuffer, 
	const size_t ResultSize, 
	const std::string &Domain, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData)
{
//Single address single cache(Part 1)
	in6_addr AddrPartIPv6;
	in_addr AddrPartIPv4;
	memset(&AddrPartIPv6, 0, sizeof(AddrPartIPv6));
	memset(&AddrPartIPv4, 0, sizeof(AddrPartIPv4));
	if (Parameter.DNS_CacheSinglePrefix_IPv6 > 0 && LocalSocketData.SockAddr.ss_family == AF_INET6) //IPv6
	{
		if (!AddressPrefixReplacing(AF_INET6, &reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData.SockAddr)->sin6_addr, &AddrPartIPv6, Parameter.DNS_CacheSinglePrefix_IPv6))
			return EXIT_FAILURE;
	}
	else if (Parameter.DNS_CacheSinglePrefix_IPv4 > 0 && LocalSocketData.SockAddr.ss_family == AF_INET) //IPv4
	{
		if (!AddressPrefixReplacing(AF_INET, &reinterpret_cast<const sockaddr_in *>(&LocalSocketData.SockAddr)->sin_addr, &AddrPartIPv4, Parameter.DNS_CacheSinglePrefix_IPv4))
			return EXIT_FAILURE;
	}

//Make insensitive domain.
	std::string InsensitiveDomain(Domain);
	CaseConvert(InsensitiveDomain, false);

//Find all matched domain cache.
	std::lock_guard<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	RemoveExpiredDomainCache();
	if (DNSCacheIndexList.find(InsensitiveDomain) != DNSCacheIndexList.end())
	{
		const auto CacheMapRange = DNSCacheIndexList.equal_range(InsensitiveDomain);
		for (auto CacheMapItem = CacheMapRange.first;CacheMapItem != CacheMapRange.second;++CacheMapItem)
		{
		//Single address single cache(Part 2, IPv6)
			if (CacheMapItem->second->ForAddress.Storage.ss_family == AF_INET6)
			{
				if (LocalSocketData.SockAddr.ss_family != AF_INET6 || 
					(Parameter.DNS_CacheSinglePrefix_IPv6 > 0 && memcmp(&AddrPartIPv6, &CacheMapItem->second->ForAddress.IPv6.sin6_addr, sizeof(AddrPartIPv6)) != 0))
						continue;
			}
		//Single address single cache(Part 2, IPv4)
			else if (CacheMapItem->second->ForAddress.Storage.ss_family == AF_INET)
			{
			//Check if the request protocol is not matched.
				if (LocalSocketData.SockAddr.ss_family != AF_INET || 
					(Parameter.DNS_CacheSinglePrefix_IPv4 > 0 && memcmp(&AddrPartIPv4, &CacheMapItem->second->ForAddress.IPv4.sin_addr, sizeof(AddrPartIPv4)) != 0))
						continue;
			}
		//Single address single cache(Part 2, default queue or single address single cache has been shutdown are always pass)
//			else {
//				;
//			}

		//Scan cache data.
			if (CacheMapItem->second->RecordType == QueryType)
			{
			//Copy cache to result.
				memset(ResultBuffer + sizeof(uint16_t), 0, ResultSize - sizeof(uint16_t));
				memcpy_s(ResultBuffer + sizeof(uint16_t), ResultSize - sizeof(uint16_t), CacheMapItem->second->Response.get(), CacheMapItem->second->Length);

			//Copy requester Question to result.
				const auto ResultValue = strnlen_s(reinterpret_cast<const char *>(ResultBuffer + sizeof(dns_hdr)), DOMAIN_MAXSIZE) + NULL_TERMINATE_LENGTH;
				if (ResultValue < DOMAIN_MAXSIZE + NULL_TERMINATE_LENGTH && 
					StringToPacketQuery(reinterpret_cast<const uint8_t *>(Domain.c_str()), ResultBuffer + sizeof(dns_hdr), ResultSize - sizeof(dns_hdr)) == ResultValue)
				{
					return sizeof(uint16_t) + CacheMapItem->second->Length;
				}
				else {
					memset(ResultBuffer, 0, ResultSize);
					return EXIT_FAILURE;
				}
			}
		}
	}

	return EXIT_SUCCESS;
}

//Remove expired domain cache
void RemoveExpiredDomainCache(
	void)
{
//Timer mode
	if (Parameter.DNS_CacheType == DNS_CACHE_TYPE::TIMER)
	{
	//Expired check
		for (auto DNS_CacheDataItem = DNSCacheList.begin();DNS_CacheDataItem != DNSCacheList.end();)
		{
			if (DNS_CacheDataItem->ClearCacheTime <= GetCurrentSystemTime())
			{
			//Remove from domain cache index list.
				if (DNSCacheIndexList.find(DNS_CacheDataItem->Domain) != DNSCacheIndexList.end())
				{
					const auto CacheMapRange = DNSCacheIndexList.equal_range(DNS_CacheDataItem->Domain);
					for (auto CacheMapItem = CacheMapRange.first;CacheMapItem != CacheMapRange.second;++CacheMapItem)
					{
						if (CacheMapItem->second == DNS_CacheDataItem)
						{
							DNSCacheIndexList.erase(CacheMapItem);
							break;
						}
					}
				}

			//Remove from domain cache data list.
				DNS_CacheDataItem = DNSCacheList.erase(DNS_CacheDataItem);
			}
			else {
				++DNS_CacheDataItem;
			}
		}
	}
//Queue mode
	else if (Parameter.DNS_CacheType == DNS_CACHE_TYPE::QUEUE)
	{
	//Queue length check
		while (DNSCacheList.size() > Parameter.DNS_CacheParameter)
		{
		//Remove from domain cache index list.
			if (DNSCacheIndexList.find(DNSCacheList.back().Domain) != DNSCacheIndexList.end())
			{
				auto DNS_CacheListItem = DNSCacheList.end();
				--DNS_CacheListItem;
				const auto CacheMapRange = DNSCacheIndexList.equal_range(DNSCacheList.back().Domain);
				for (auto CacheMapItem = CacheMapRange.first;CacheMapItem != CacheMapRange.second;++CacheMapItem)
				{
					if (CacheMapItem->second == DNS_CacheListItem)
					{
						DNSCacheIndexList.erase(CacheMapItem);
						break;
					}
				}
			}

		//Remove from domain cache data list.
			DNSCacheList.pop_back();
		}
	}
//Both mode(Timer + Queue)
	else if (Parameter.DNS_CacheType == DNS_CACHE_TYPE::BOTH)
	{
	//Expired check
		for (auto DNS_CacheDataItem = DNSCacheList.begin();DNS_CacheDataItem != DNSCacheList.end();)
		{
			if (DNS_CacheDataItem->ClearCacheTime <= GetCurrentSystemTime())
			{
			//Remove from domain cache index list.
				if (DNSCacheIndexList.find(DNS_CacheDataItem->Domain) != DNSCacheIndexList.end())
				{
					const auto CacheMapRange = DNSCacheIndexList.equal_range(DNS_CacheDataItem->Domain);
					for (auto CacheMapItem = CacheMapRange.first;CacheMapItem != CacheMapRange.second;++CacheMapItem)
					{
						if (CacheMapItem->second == DNS_CacheDataItem)
						{
							DNSCacheIndexList.erase(CacheMapItem);
							break;
						}
					}
				}

			//Remove from domain cache data list.
				DNS_CacheDataItem = DNSCacheList.erase(DNS_CacheDataItem);
			}
			else {
				++DNS_CacheDataItem;
			}
		}

	//Queue length check
		while (DNSCacheList.size() > Parameter.DNS_CacheParameter)
		{
		//Remove from domain cache index list.
			if (DNSCacheIndexList.find(DNSCacheList.back().Domain) != DNSCacheIndexList.end())
			{
				auto DNS_CacheListItem = DNSCacheList.end();
				--DNS_CacheListItem;
				const auto CacheMapRange = DNSCacheIndexList.equal_range(DNSCacheList.back().Domain);
				for (auto CacheMapItem = CacheMapRange.first;CacheMapItem != CacheMapRange.second;++CacheMapItem)
				{
					if (CacheMapItem->second == DNS_CacheListItem)
					{
						DNSCacheIndexList.erase(CacheMapItem);
						break;
					}
				}
			}

		//Remove from domain cache data list.
			DNSCacheList.pop_back();
		}
	}

	return;
}
