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
//Check empty buffer
bool __fastcall CheckEmptyBuffer(
	_In_opt_ const void *Buffer, 
	_In_ const size_t Length)
{
//Null pointer
	if (Buffer == nullptr)
		return false;

//Scan all data.
	for (size_t Index = 0;Index < Length;++Index)
	{
		if (((uint8_t *)Buffer)[Index] != 0)
			return false;
	}

	return true;
}

//Convert host values to network byte order with 64 bits
uint64_t __fastcall hton64(
	_In_ const uint64_t Value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return (((uint64_t)htonl((int32_t)((Value << (sizeof(uint32_t) * BYTES_TO_BITS)) >> (sizeof(uint32_t) * BYTES_TO_BITS)))) << (sizeof(uint32_t) * BYTES_TO_BITS)) | (uint32_t)htonl((int32_t)(Value >> (sizeof(uint32_t) * BYTES_TO_BITS)));
#else //BIG_ENDIAN
	return Value;
#endif
}

/* Redirect to hton64.
//Convert network byte order to host values with 64 bits
uint64_t __fastcall ntoh64(const uint64_t Value)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	return (((uint64_t)ntohl((int32_t)((Value << (sizeof(uint32_t) * BYTES_TO_BITS)) >> (sizeof(uint32_t) * BYTES_TO_BITS)))) << (sizeof(uint32_t) * BYTES_TO_BITS)) | (uint32_t)ntohl((int32_t)(Value >> (sizeof(uint32_t) * BYTES_TO_BITS)));
#else //BIG_ENDIAN
	return Value;
#endif
}
*/

//Convert multiple bytes to wide char string
bool __fastcall MBSToWCSString(
	_In_opt_ const char *Buffer, 
	_In_ const size_t MaxLen, 
	_Out_ std::wstring &Target)
{
//Check buffer.
	Target.clear();
	if (Buffer == nullptr || MaxLen == 0)
		return false;
	size_t Length = strnlen_s(Buffer, MaxLen);
	if (Length == 0 || CheckEmptyBuffer(Buffer, Length))
		return false;

//Convert string.
	std::shared_ptr<wchar_t> TargetPTR(new wchar_t[Length + 1U]());
	wmemset(TargetPTR.get(), 0, Length + 1U);
#if defined(PLATFORM_WIN)
	if (MultiByteToWideChar(CP_ACP, 0, Buffer, MBSTOWCS_NULLTERMINATE, TargetPTR.get(), (int)(Length + 1U)) == 0)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (mbstowcs(TargetPTR.get(), Buffer, Length + 1U) == (size_t)RETURN_ERROR)
#endif
	{
		return false;
	}
	else {
		Target = TargetPTR.get();
		if (Target.empty())
			return false;
	}

	return true;
}

#if defined(PLATFORM_WIN)
//Convert lowercase/uppercase words to uppercase/lowercase words(C++ wide string version)
void __fastcall CaseConvert(
	_In_ const bool IsLowerToUpper, 
	_Inout_opt_ std::wstring &Buffer)
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
#endif

//Convert lowercase/uppercase words to uppercase/lowercase words(C++ string version)
void __fastcall CaseConvert(
	_In_ const bool IsLowerToUpper, 
	_Inout_opt_ std::string &Buffer)
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
#endif
