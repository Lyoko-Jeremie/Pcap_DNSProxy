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


#include "Base.h"

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;

//Check empty buffer
bool CheckEmptyBuffer(
	const void *Buffer, 
	const size_t Length)
{
//Null pointer
	if (Buffer == nullptr)
	{
		return false;
	}
	else {
	//Scan all data.
		for (size_t Index = 0;Index < Length;++Index)
		{
			if (((uint8_t *)Buffer)[Index] != 0)
				return false;
		}
	}

	return true;
}

//Convert host values to network byte order with 16 bits(Force)
uint16_t hton16_Force(
	const uint16_t Value)
{
	return (uint16_t)(((uint8_t *)&Value)[0] << (sizeof(uint8_t) * BYTES_TO_BITS) | ((uint8_t *)&Value)[1U]);
}

/* Redirect to hton16_Force.
//Convert network byte order to host values with 16 bits(Force)
uint16_t ntoh16_Force(
	const uint16_t Value)
{
	return (uint16_t)(((uint8_t *)&Value)[0] << (sizeof(uint8_t) * BYTES_TO_BITS) | ((uint8_t *)&Value)[1U]);
}
*/

//Convert host values to network byte order with 32 bits(Force)
uint32_t hton32_Force(
	const uint32_t Value)
{
	return (uint32_t)(((uint8_t *)&Value)[0] << ((sizeof(uint16_t) + sizeof(uint8_t)) * BYTES_TO_BITS) | 
		((uint8_t *)&Value)[1U] << (sizeof(uint16_t) * BYTES_TO_BITS) | ((uint8_t *)&Value)[2U] << (sizeof(uint8_t) * BYTES_TO_BITS) | ((uint8_t *)&Value)[3U]);
}

/* Redirect to hton32_Force.
//Convert network byte order to host values with 32 bits(Force)
uint32_t ntoh32_Force(
	const uint32_t Value)
{
	return (uint32_t)(((uint8_t *)&Value)[0] << ((sizeof(uint16_t) + sizeof(uint8_t)) * BYTES_TO_BITS) | 
		((uint8_t *)&Value)[1U] << (sizeof(uint16_t) * BYTES_TO_BITS) | ((uint8_t *)&Value)[2U] << (sizeof(uint8_t) * BYTES_TO_BITS) | ((uint8_t *)&Value)[3U]);
}
*/

//Convert host values to network byte order with 64 bits
uint64_t hton64(
	const uint64_t Value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return (((uint64_t)htonl((int32_t)((Value << (sizeof(uint32_t) * BYTES_TO_BITS)) >> (sizeof(uint32_t) * BYTES_TO_BITS)))) << (sizeof(uint32_t) * BYTES_TO_BITS)) | 
		(uint32_t)htonl((int32_t)(Value >> (sizeof(uint32_t) * BYTES_TO_BITS)));
#else //BIG_ENDIAN
	return Value;
#endif
}

/* Redirect to hton64.
//Convert network byte order to host values with 64 bits
uint64_t ntoh64(const uint64_t Value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return (((uint64_t)ntohl((int32_t)((Value << (sizeof(uint32_t) * BYTES_TO_BITS)) >> (sizeof(uint32_t) * BYTES_TO_BITS)))) << (sizeof(uint32_t) * BYTES_TO_BITS)) | 
		(uint32_t)ntohl((int32_t)(Value >> (sizeof(uint32_t) * BYTES_TO_BITS)));
#else //BIG_ENDIAN
	return Value;
#endif
}
*/

//Convert multiple bytes to wide char string
bool MBSToWCSString(
	const uint8_t *Buffer, 
	const size_t MaxLen, 
	std::wstring &Target)
{
//Check buffer.
	Target.clear();
	if (Buffer == nullptr || MaxLen == 0)
		return false;
	size_t Length = strnlen_s((const char *)Buffer, MaxLen);
	if (Length == 0 || CheckEmptyBuffer(Buffer, Length))
		return false;

//Convert string.
	std::shared_ptr<wchar_t> TargetPTR(new wchar_t[Length + PADDING_RESERVED_BYTES]());
	wmemset(TargetPTR.get(), 0, Length + PADDING_RESERVED_BYTES);
#if defined(PLATFORM_WIN)
	if (MultiByteToWideChar(CP_ACP, 0, (LPCCH)Buffer, MBSTOWCS_NULLTERMINATE, TargetPTR.get(), (int)(Length + PADDING_RESERVED_BYTES)) == 0)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (mbstowcs(TargetPTR.get(), (const char *)Buffer, Length + PADDING_RESERVED_BYTES) == (size_t)RETURN_ERROR)
#endif
	{
		return false;
	}
	else {
		if (wcsnlen_s(TargetPTR.get(), Length + PADDING_RESERVED_BYTES) == 0)
			return false;
		else 
			Target = TargetPTR.get();
	}

	return true;
}

//Convert wide char string to multiple bytes
bool WCSToMBSString(
	const wchar_t *Buffer, 
	const size_t MaxLen, 
	std::string &Target)
{
//Check buffer.
	Target.clear();
	if (Buffer == nullptr || MaxLen == 0)
		return false;
	size_t Length = wcsnlen_s(Buffer, MaxLen);
	if (Length == 0 || CheckEmptyBuffer(Buffer, sizeof(wchar_t) * Length))
		return false;

//Convert string.
	std::shared_ptr<uint8_t> TargetPTR(new uint8_t[Length + PADDING_RESERVED_BYTES]());
	memset(TargetPTR.get(), 0, Length + PADDING_RESERVED_BYTES);
#if defined(PLATFORM_WIN)
	if (WideCharToMultiByte(CP_ACP, 0, Buffer, MBSTOWCS_NULLTERMINATE, (LPSTR)TargetPTR.get(), (int)(Length + PADDING_RESERVED_BYTES), nullptr, nullptr) == 0)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (wcstombs((char *)TargetPTR.get(), Buffer, Length + PADDING_RESERVED_BYTES) == (size_t)RETURN_ERROR)
#endif
	{
		return false;
	}
	else {
		if (strnlen_s((const char *)TargetPTR.get(), Length + PADDING_RESERVED_BYTES) == 0)
			return false;
		else 
			Target = (const char *)TargetPTR.get();
	}

	return true;
}

//Convert lowercase/uppercase words to uppercase/lowercase words(C-Style version)
void CaseConvert(
	const bool IsLowerToUpper, 
	uint8_t *Buffer, 
	const size_t Length)
{
//Null pointer
	if (Buffer == nullptr)
	{
		return;
	}
	else {
	//Convert words.
		for (size_t Index = 0;Index < Length;++Index)
		{
		//Lowercase to uppercase
			if (IsLowerToUpper)
				Buffer[Index] = (uint8_t)toupper(Buffer[Index]);
		//Uppercase to lowercase
			else 
				Buffer[Index] = (uint8_t)tolower(Buffer[Index]);
		}
	}

	return;
}

//Convert lowercase/uppercase words to uppercase/lowercase words(C++ string version)
void CaseConvert(
	const bool IsLowerToUpper, 
	std::string &Buffer)
{
	for (auto &StringIter:Buffer)
	{
	//Lowercase to uppercase
		if (IsLowerToUpper)
			StringIter = (char)toupper(StringIter);
	//Uppercase to lowercase
		else 
			StringIter = (char)tolower(StringIter);
	}

	return;
}

//Sort compare(IPFilter)
bool SortCompare_IPFilter(
	const DIFFERNET_FILE_SET_IPFILTER &Begin, 
	const DIFFERNET_FILE_SET_IPFILTER &End)
{
	return Begin.FileIndex < End.FileIndex;
}

//Sort compare(Hosts)
bool SortCompare_Hosts(
	const DIFFERNET_FILE_SET_HOSTS &Begin, 
	const DIFFERNET_FILE_SET_HOSTS &End)
{
	return Begin.FileIndex < End.FileIndex;
}

//Base64 encoding or decoding is from https://github.com/zhicheng/base64.
//Base64 encode
size_t Base64_Encode(
	uint8_t *Input, 
	const size_t Length, 
	uint8_t *Output, 
	const size_t OutputSize)
{
//Initialization
	size_t Index[]{0, 0, 0};
	memset(Output, 0, OutputSize);

//Convert from binary to Base64.
	for (Index[0] = Index[1U] = 0;Index[0] < Length;++Index[0])
	{
	//From 6/gcd(6, 8)
		Index[2U] = Index[0] % 3U;
		switch (Index[2U])
		{
			case 0:
			{
				Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[(Input[Index[0]] >> 2U) & 0x3F];
				continue;
			}
			case 1U:
			{
				Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[((Input[Index[0] - 1U] & 0x3) << 4U) + ((Input[Index[0]] >> 4U) & 0xF)];
				continue;
			}
			case 2U:
			{
				Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[((Input[Index[0] - 1U] & 0xF) << 2U) + ((Input[Index[0]] >> 6U) & 0x3)];
				Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[Input[Index[0]] & 0x3F];
			}
		}
	}

//Move back.
	Index[0] -= 1U;

//Check the last and add padding.
	if ((Index[0] % 3U) == 0)
	{
		Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[(Input[Index[0]] & 0x3) << 4U];
		Output[Index[1U]++] = BASE64_PAD;
		Output[Index[1U]++] = BASE64_PAD;
	}
	else if ((Index[0] % 3U) == 1U)
	{
		Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[(Input[Index[0]] & 0xF) << 2U];
		Output[Index[1U]++] = BASE64_PAD;
	}

	return strnlen_s((const char *)Output, OutputSize);
}

/* Base64 decode
size_t Base64_Decode(
	uint8_t *Input, 
	const size_t Length, 
	uint8_t *Output, 
	const size_t OutputSize)
{
//Initialization
	memset(Output, 0, OutputSize);
	size_t Index[]{0, 0, 0};
	int StringIter = 0;

//Convert from Base64 to binary.
	for (Index[0] = Index[1U] = 0;Index[0] < Length;++Index[0])
	{
	//From 6/gcd(6, 8)
		StringIter = 0;
		Index[2U] = Index[0] % 4U;
		if (Input[Index[0]] == (uint8_t)BASE64_PAD)
			return strnlen_s(Output, OutputSize);
		if (Input[Index[0]] < BASE64_DE_FIRST || Input[Index[0]] > BASE64_DE_LAST || 
			(StringIter = GlobalRunningStatus.Base64_DecodeTable[Input[Index[0]] - BASE64_DE_FIRST]) == -1)
				return 0;
		switch (Index[2U])
		{
			case 0:
			{
				Output[Index[1U]] = (uint8_t)(StringIter << 2U);
				continue;
			}
			case 1U:
			{
				Output[Index[1U]++] += (StringIter >> 4U) & 0x3;

			//If not last char with padding
				if (Index[0] < (Length - 3U) || Input[Length - 2U] != (uint8_t)BASE64_PAD)
					Output[Index[1U]] = (StringIter & 0xF) << 4U;
				continue;
			}
			case 2U:
			{
				Output[Index[1U]++] += (StringIter >> 2U) & 0xF;

			//If not last char with padding
				if (Index[0] < (Length - 2U) || Input[Length - 1U] != (uint8_t)BASE64_PAD)
					Output[Index[1U]] = (StringIter & 0x3) << 6U;
				continue;
			}
			case 3U:
			{
				Output[Index[1U]++] += (uint8_t)StringIter;
			}
		}
	}

	return strnlen_s(Output, OutputSize);
}
*/
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
uint64_t GetCurrentSystemTime(
	void)
{
	timeval CurrentTime;
	memset(&CurrentTime, 0, sizeof(CurrentTime));
	if (gettimeofday(&CurrentTime, nullptr) == 0)
		return (uint64_t)CurrentTime.tv_sec * SECOND_TO_MILLISECOND + (uint64_t)CurrentTime.tv_usec / MICROSECOND_TO_MILLISECOND;

	return 0;
}
#endif
