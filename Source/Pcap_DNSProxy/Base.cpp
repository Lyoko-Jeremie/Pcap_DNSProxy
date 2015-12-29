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


#include "Base.h"

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;

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

//Convert host values to network byte order with 16 bits(Force)
uint16_t __fastcall hton16_Force(
	_In_ const uint16_t Value)
{
	return (uint16_t)(((uint8_t *)&Value)[0] << 8U | ((uint8_t *)&Value)[1U]);
}

/* Redirect to hton16_Force.
//Convert network byte order to host values with 16 bits(Force)
uint16_t __fastcall ntoh16_Force(
	const uint16_t Value)
{
	return (uint16_t)(((uint8_t *)&Value)[0] << 8U | ((uint8_t *)&Value)[1U]);
}
*/

//Convert host values to network byte order with 32 bits(Force)
uint32_t __fastcall hton32_Force(
	_In_ const uint32_t Value)
{
	return (uint32_t)(((uint8_t *)&Value)[0] << 24U | ((uint8_t *)&Value)[1U] << 16U | ((uint8_t *)&Value)[2U] << 8U | ((uint8_t *)&Value)[3U]);
}

/* Redirect to hton32_Force.
//Convert network byte order to host values with 32 bits(Force)
uint32_t __fastcall ntoh32_Force(
	const uint32_t Value)
{
	return (uint32_t)(((uint8_t *)&Value)[0] << 24U | ((uint8_t *)&Value)[1U] << 16U | ((uint8_t *)&Value)[2U] << 8U | ((uint8_t *)&Value)[3U]);
}
*/

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

//Convert lowercase/uppercase words to uppercase/lowercase words(C-Style version)
void __fastcall CaseConvert(
	_In_ const bool IsLowerToUpper, 
	_Inout_ char *Buffer, 
	_In_ const size_t Length)
{
	for (size_t Index = 0;Index < Length;++Index)
	{
	//Lowercase to uppercase
		if (IsLowerToUpper)
			Buffer[Index] = (char)toupper(Buffer[Index]);
	//Uppercase to lowercase
		else 
			Buffer[Index] = (char)tolower(Buffer[Index]);
	}

	return;
}

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

//Sort compare(IPFilter)
bool __fastcall SortCompare_IPFilter(
	_In_ const DIFFERNET_FILE_SET_IPFILTER &Begin, 
	_In_ const DIFFERNET_FILE_SET_IPFILTER &End)
{
	return Begin.FileIndex < End.FileIndex;
}

//Sort compare(Hosts)
bool __fastcall SortCompare_Hosts(
	_In_ const DIFFERNET_FILE_SET_HOSTS &Begin, 
	_In_ const DIFFERNET_FILE_SET_HOSTS &End)
{
	return Begin.FileIndex < End.FileIndex;
}

//Base64 encode or decode is from https://github.com/zhicheng/base64.
//Base64 encode
size_t __fastcall Base64_Encode(
	_In_ uint8_t *Input, 
	_In_ const size_t Length, 
	_Out_ char *Output, 
	_In_ const size_t OutputSize)
{
//Initialization
	memset(Output, 0, OutputSize);
	size_t Index[]{0, 0, 0};

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

	return strnlen_s(Output, OutputSize);
}

/* Base64 decode
size_t __fastcall Base64_Decode(
	_In_ char *Input, 
	_In_ const size_t Length, 
	_Out_ uint8_t *Output, 
	_In_ const size_t OutputSize)
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
		if (Input[Index[0]] == '=')
			return strnlen_s(Output, OutputSize);
		if (Input[Index[0]] < BASE64_DE_FIRST || Input[Index[0]] > BASE64_DE_LAST || (StringIter = GlobalRunningStatus.Base64_DecodeTable[Input[Index[0]] - BASE64_DE_FIRST]) == -1)
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
				if (Index[0] < (Length - 3U) || Input[Length - 2U] != '=')
					Output[Index[1U]] = (StringIter & 0xF) << 4U;
				continue;
			}
			case 2U:
			{
				Output[Index[1U]++] += (StringIter >> 2U) & 0xF;

			//If not last char with padding
				if (Index[0] < (Length - 2U) || Input[Length - 1U] != '=')
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
//Linux and Mac OS X compatible with GetTickCount64
uint64_t GetCurrentSystemTime(
	void)
{
	auto CurrentTime = std::make_shared<timeval>();
	memset(CurrentTime.get(), 0, sizeof(timeval));
	if (gettimeofday(CurrentTime.get(), nullptr) == 0)
		return (uint64_t)CurrentTime->tv_sec * SECOND_TO_MILLISECOND + (uint64_t)CurrentTime->tv_usec / MICROSECOND_TO_MILLISECOND;

	return 0;
}

//Windows XP with SP3 support
#elif (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
//Verify version of system(Greater than Windows Vista)
BOOL WINAPI IsGreaterThanVista(
	void)
{
	auto OSVI = std::make_shared<OSVERSIONINFOEXW>();
	memset(OSVI.get(), 0, sizeof(OSVERSIONINFOEXW));
	DWORDLONG dwlConditionMask = 0;

//Initialization
	OSVI->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	OSVI->dwMajorVersion = 6U; //Greater than Windows Vista.
	OSVI->dwMinorVersion = 0;

//System Major version > dwMajorVersion
	VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER);
	if (VerifyVersionInfoW(OSVI.get(), VER_MAJORVERSION, dwlConditionMask))
		return TRUE;

//Sytem Major version = dwMajorVersion and Minor version > dwMinorVersion
	VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_EQUAL);
	VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_GREATER);
	return VerifyVersionInfoW(OSVI.get(), VER_MAJORVERSION|VER_MINORVERSION, dwlConditionMask);
}

//Try to load library to get pointers of functions
BOOL WINAPI GetFunctionPointer(
	_In_ const size_t FunctionType)
{
//GetTickCount64() function
	if (FunctionType == FUNCTION_GETTICKCOUNT64)
	{
		GlobalRunningStatus.FunctionLibrary_GetTickCount64 = LoadLibraryW(L"Kernel32.dll");
		if (GlobalRunningStatus.FunctionLibrary_GetTickCount64 != nullptr)
		{
			GlobalRunningStatus.FunctionPTR_GetTickCount64 = (FunctionType_GetTickCount64)GetProcAddress(GlobalRunningStatus.FunctionLibrary_GetTickCount64, "GetTickCount64");
			if (GlobalRunningStatus.FunctionPTR_GetTickCount64 == nullptr)
			{
				FreeLibrary(GlobalRunningStatus.FunctionLibrary_GetTickCount64);
				GlobalRunningStatus.FunctionLibrary_GetTickCount64 = nullptr;
			}
			else {
				return TRUE;
			}
		}
	}
//inet_ntop() function
	else if (FunctionType == FUNCTION_INET_NTOP)
	{
		GlobalRunningStatus.FunctionLibrary_InetNtop = LoadLibraryW(L"ws2_32.dll");
		if (GlobalRunningStatus.FunctionLibrary_InetNtop != nullptr)
		{
			GlobalRunningStatus.FunctionPTR_InetNtop = (FunctionType_InetNtop)GetProcAddress(GlobalRunningStatus.FunctionLibrary_InetNtop, "inet_ntop");
			if (GlobalRunningStatus.FunctionPTR_InetNtop == nullptr)
			{
				FreeLibrary(GlobalRunningStatus.FunctionLibrary_InetNtop);
				GlobalRunningStatus.FunctionLibrary_InetNtop = nullptr;
			}
			else {
				return TRUE;
			}
		}
	}
//inet_pton() function
	else if (FunctionType == FUNCTION_INET_PTON)
	{
		GlobalRunningStatus.FunctionLibrary_InetPton = LoadLibraryW(L"ws2_32.dll");
		if (GlobalRunningStatus.FunctionLibrary_InetPton != nullptr)
		{
			GlobalRunningStatus.FunctionPTR_InetPton = (FunctionType_InetPton)GetProcAddress(GlobalRunningStatus.FunctionLibrary_InetPton, "inet_pton");
			if (GlobalRunningStatus.FunctionPTR_InetPton == nullptr)
			{
				FreeLibrary(GlobalRunningStatus.FunctionLibrary_InetPton);
				GlobalRunningStatus.FunctionLibrary_InetPton = nullptr;
			}
			else {
				return TRUE;
			}
		}
	}

	return FALSE;
}
#endif
