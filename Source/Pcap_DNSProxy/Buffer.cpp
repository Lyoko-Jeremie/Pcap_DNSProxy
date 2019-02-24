// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on packet capturing
// Copyright (C) 2012-2019 Chengr28
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


#include "Buffer.h"

//Check empty buffer
bool CheckEmptyBuffer(
	const void * const Buffer, 
	const size_t Length)
{
//Null pointer
	if (Buffer == nullptr)
		return false;

//Scan all data.
	for (size_t Index = 0;Index < Length;++Index)
	{
		if (*(reinterpret_cast<const uint8_t *>(Buffer) + Index) != 0)
			return false;
	}

	return true;
}

//Generate random bytes to buffer
void GenerateRandomBuffer(
	void * const BufferPointer, 
	const size_t BufferSize, 
	const void * Distribution, 
	const uint64_t Lower, 
	const uint64_t Upper)
{
//Buffer check
	if (BufferPointer == nullptr || BufferSize == 0)
		return;

//Clean buffer before generating.
	memset(BufferPointer, 0, BufferSize);

//Fill size_t value.
	if (BufferSize == sizeof(size_t) && (Distribution != nullptr || Lower + Upper > 0))
	{
		if (Distribution != nullptr)
		{
			*reinterpret_cast<size_t *>(BufferPointer) = (*const_cast<std::uniform_int_distribution<size_t> *>(reinterpret_cast<const std::uniform_int_distribution<size_t> *>(Distribution)))(*GlobalRunningStatus.RandomEngine);
		}
		else {
			std::uniform_int_distribution<size_t> RandomDistribution(static_cast<const size_t>(Lower), static_cast<const size_t>(Upper));
			*reinterpret_cast<size_t *>(BufferPointer) = RandomDistribution(*GlobalRunningStatus.RandomEngine);
		}
	}
//Fill a 64 bits value.
	else if (BufferSize == sizeof(uint64_t) && (Distribution != nullptr || Lower + Upper > 0))
	{
		if (Distribution != nullptr)
		{
			*reinterpret_cast<uint64_t *>(BufferPointer) = (*const_cast<std::uniform_int_distribution<uint64_t> *>(reinterpret_cast<const std::uniform_int_distribution<uint64_t> *>(Distribution)))(*GlobalRunningStatus.RandomEngine);
		}
		else {
			std::uniform_int_distribution<uint64_t> RandomDistribution(Lower, Upper);
			*reinterpret_cast<uint64_t *>(BufferPointer) = RandomDistribution(*GlobalRunningStatus.RandomEngine);
		}
	}
//Fill a 32 bits value.
	else if (BufferSize == sizeof(uint32_t) && (Distribution != nullptr || Lower + Upper > 0))
	{
		if (Distribution != nullptr)
		{
			*reinterpret_cast<uint32_t *>(BufferPointer) = (*const_cast<std::uniform_int_distribution<uint32_t> *>(reinterpret_cast<const std::uniform_int_distribution<uint32_t> *>(Distribution)))(*GlobalRunningStatus.RandomEngine);
		}
		else {
			std::uniform_int_distribution<uint32_t> RandomDistribution(static_cast<const uint32_t>(Lower), static_cast<const uint32_t>(Upper));
			*reinterpret_cast<uint32_t *>(BufferPointer) = RandomDistribution(*GlobalRunningStatus.RandomEngine);
		}
	}
//Fill a 16 bits value.
	else if (BufferSize == sizeof(uint16_t) && (Distribution != nullptr || Lower + Upper > 0))
	{
		if (Distribution != nullptr)
		{
			*reinterpret_cast<uint16_t *>(BufferPointer) = (*const_cast<std::uniform_int_distribution<uint16_t> *>(reinterpret_cast<const std::uniform_int_distribution<uint16_t> *>(Distribution)))(*GlobalRunningStatus.RandomEngine);
		}
		else {
			std::uniform_int_distribution<uint16_t> RandomDistribution(static_cast<const uint16_t>(Lower), static_cast<const uint16_t>(Upper));
			*reinterpret_cast<uint16_t *>(BufferPointer) = RandomDistribution(*GlobalRunningStatus.RandomEngine);
		}
	}
//Fill a 8 bits value.
	else if (BufferSize == sizeof(uint8_t) && (Distribution != nullptr || Lower + Upper > 0))
	{
		if (Distribution != nullptr)
		{
			*reinterpret_cast<uint8_t *>(BufferPointer) = static_cast<const uint8_t>((*const_cast<std::uniform_int_distribution<uint16_t> *>(reinterpret_cast<const std::uniform_int_distribution<uint16_t> *>(Distribution)))(*GlobalRunningStatus.RandomEngine));
		}
		else {
			std::uniform_int_distribution<uint16_t> RandomDistribution(static_cast<const uint8_t>(Lower), static_cast<const uint8_t>(Upper));
			*reinterpret_cast<uint8_t *>(BufferPointer) = static_cast<const uint8_t>(RandomDistribution(*GlobalRunningStatus.RandomEngine));
		}
	}
//Fill a random sequence.
	else {
	#if defined(ENABLE_LIBSODIUM)
	//Generate a random sequence by LibSodium.
		for (size_t Index = 0;Index < LOOP_MAX_TIMES;++Index)
		{
		//Generate a random 32 bits or sequence.
			if (BufferSize == sizeof(uint32_t))
				*reinterpret_cast<uint32_t *>(BufferPointer) = randombytes_random();
			else 
				randombytes_buf(BufferPointer, BufferSize);

		//Must not a empty buffer after generating.
			if (!CheckEmptyBuffer(BufferPointer, BufferSize))
				return;
		}
	#endif

	//Generate a random sequence by C++ STL.
		if (CheckEmptyBuffer(BufferPointer, BufferSize))
		{
			std::uniform_int_distribution<uint16_t> RandomDistribution(1U, UINT8_MAX); //Not including empty bytes.
			for (size_t Index = 0;Index < BufferSize;Index += sizeof(uint8_t))
				*(reinterpret_cast<uint8_t *>(BufferPointer) + Index * sizeof(uint8_t)) = static_cast<const uint8_t>(RandomDistribution(*GlobalRunningStatus.RandomEngine));
		}
	}

	return;
}

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

//Get domain name length
size_t GetDomainNameLength(
	const uint8_t * const NameBuffer, 
	const size_t MaxSize)
{
//Name is ROOT.
	if (MaxSize > 0 && NameBuffer[0] == 0)
		return sizeof(uint8_t);

//Scan name data.
	for (size_t Index = 0;Index < MaxSize;++Index)
	{
	//Maximum length check
		if (Index >= DOMAIN_WHOLE_MAXSIZE)
		{
			return DOMAIN_WHOLE_MAXSIZE;
		}
	//End of name
		else if (NameBuffer[Index] == 0)
		{
			if (Index + sizeof(uint8_t) > DOMAIN_WHOLE_MAXSIZE)
				return 0;
			else 
				return Index + sizeof(uint8_t);
		}
	//Compression pointer
		else if (NameBuffer[Index] >= DNS_POINTER_8_BITS)
		{
			if (Index + sizeof(uint16_t) > DOMAIN_WHOLE_MAXSIZE)
				return 0;
			else 
				return Index + sizeof(uint16_t);
		}
	}

	return 0;
}

//Convert data from packet to string
bool PacketQueryToString(
	const uint8_t * const PacketBuffer, 
	const size_t PacketLength, 
	const uint8_t * const PacketName, 
	const size_t NameLength, 
	std::vector<uint16_t> * PointerAlreadyUse, 
	std::string &StringName)
{
//Initialization
	std::vector<uint16_t> PointerUseList;
	if (PointerAlreadyUse == nullptr)
		PointerAlreadyUse = &PointerUseList;
	uint16_t PointerOffset = 0;
	ssize_t LabelLength = 0;

//Convert packet data to string.
	for (size_t Index = 0;Index < NameLength;++Index)
	{
	//End of name
		if (PacketName[Index] == 0)
		{
			break;
		}
	//Message compression pointer
		else if (PacketName[Index] >= DNS_POINTER_8_BITS)
		{
		//Compression pointer length check
			if (Index + sizeof(uint8_t) >= NameLength)
				return false;

		//Locate pointer.
			PointerOffset = ntoh16(*reinterpret_cast<const uint16_t *>(PacketName + Index));
			PointerOffset &= DNS_POINTER_BIT_GET_LOCATE;
			if (PointerOffset < sizeof(dns_hdr) || PointerOffset + sizeof(uint8_t) > PacketLength)
				return false;

		//Circular reference pointer check
			for (const auto &PointerItem:*PointerAlreadyUse)
			{
				if (PointerItem == PointerOffset)
					return false;
			}
			PointerAlreadyUse->push_back(PointerOffset);

		//Continue to copy data from pointer.
			if (GetDomainNameLength(PacketBuffer + PointerOffset, PacketLength - PointerOffset) == 0)
				return false;
			else 
				return PacketQueryToString(PacketBuffer, PacketLength, PacketBuffer + PointerOffset, GetDomainNameLength(PacketBuffer + PointerOffset, PacketLength - PointerOffset), PointerAlreadyUse, StringName);
		}
	//Label sign
		else if (LabelLength <= 0)
		{
			if (!StringName.empty())
				StringName.push_back(ASCII_PERIOD);
			LabelLength = PacketName[Index];
		}
	//Name data
		else {
			StringName.push_back(PacketName[Index]);
			--LabelLength;
		}
	}

	return true;
}

//Get size of converting string to domain name
size_t GetStringToDomainSize(
	const size_t StringLength)
{
	if (StringLength == 0)
		return sizeof(uint8_t);
	else 
		return StringLength + STRING_TO_DOMAIN_EXPAND_SIZE;
}

//Convert data from string to packet
size_t StringToPacketQuery(
	const std::string &StringName, 
	uint8_t * const PacketBuffer, 
	const size_t PacketSize)
{


	return true;
}
