// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2016 Chengr28
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


#include "FileHash.h"

#if defined(ENABLE_LIBSODIUM)
//Global variables
extern size_t HashFamilyID;

//Checksum update process
uint32_t __fastcall Checksum_Update(
	uint32_t Checksum, 
	const uint16_t *Buffer, 
	const size_t Length)
{
	size_t InnerLength = Length;
	while (InnerLength > 1U)
	{ 
		Checksum += *Buffer++;
		InnerLength -= sizeof(uint16_t);
	}
	
	return Checksum;
}

//Finish checksum hash process
uint16_t __fastcall Checksum_Final(
	uint32_t Checksum, 
	const uint16_t *Buffer, 
	const size_t Length)
{
	if (Length)
		Checksum += *(uint8_t *)Buffer;
	Checksum = (Checksum >> (sizeof(uint16_t) * BYTES_TO_BITS)) + (Checksum & UINT16_MAX);
	Checksum += (Checksum >> (sizeof(uint16_t) * BYTES_TO_BITS));

	return (uint16_t)(~Checksum);
}

//Internet protocol checksum hash function
bool __fastcall Checksum_Hash(
	FILE *Input)
{
//Parameters check
	if (HashFamilyID != HASH_ID_CHECKSUM || Input == nullptr)
	{
		fwprintf_s(stderr, L"Parameters error.\n");
		return false;
	}

//Initialization
	std::shared_ptr<char> Buffer(new char[FILE_BUFFER_SIZE]());
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	size_t ReadLength = 0;
	uint16_t Checksum16 = 0;
	uint32_t Checksum32 = 0;

//Hash process
	while (!feof(Input))
	{
		memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
		_set_errno(0);
		ReadLength = fread_s(Buffer.get(), FILE_BUFFER_SIZE, sizeof(char), FILE_BUFFER_SIZE, Input);
		if (ReadLength == 0)
		{
			fwprintf_s(stderr, L"Hash process error");
			if (errno > 0)
				fwprintf_s(stderr, L", error code is %d.\n", errno);
			else 
				fwprintf_s(stderr, L".\n");

			return false;
		}
		else {
			Checksum32 = Checksum_Update(Checksum32, (uint16_t *)Buffer.get(), ReadLength);
		}
	}

//Binary to hex
	Checksum16 = Checksum_Final(Checksum32, (uint16_t *)(Buffer.get() + ReadLength - ReadLength % sizeof(uint16_t)), ReadLength % sizeof(uint16_t));
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	if (sodium_bin2hex(Buffer.get(), FILE_BUFFER_SIZE, (const unsigned char *)&Checksum16, sizeof(uint16_t)) == nullptr)
	{
		fwprintf_s(stderr, L"Convert binary to hex error.\n");
		return false;
	}
	else {
	//Print to screen.
		std::string HashResult = Buffer.get();
		CaseConvert(true, HashResult);
		for (size_t Index = 0;Index < HashResult.length();++Index)
			fwprintf_s(stderr, L"%c", HashResult.c_str()[Index]);
		fwprintf_s(stderr, L"\n");
	}

	return true;
}
#endif
