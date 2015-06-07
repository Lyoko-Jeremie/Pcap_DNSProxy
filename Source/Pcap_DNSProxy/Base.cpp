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

extern CONFIGURATION_TABLE Parameter;

//Check empty buffer
bool __fastcall CheckEmptyBuffer(const void *Buffer, const size_t Length)
{
	if (Buffer == nullptr)
		return true;

	for (size_t Index = 0;Index < Length;++Index)
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

//Convert multiple bytes to wide char string
void __fastcall MBSToWCSString(std::wstring &Target, const char *Buffer)
{
	std::shared_ptr<wchar_t> TargetPTR(new wchar_t[strnlen(Buffer, LARGE_PACKET_MAXSIZE) + 1U]());
	wmemset(TargetPTR.get(), 0, strnlen(Buffer, LARGE_PACKET_MAXSIZE) + 1U);
#if defined(PLATFORM_WIN)
	MultiByteToWideChar(CP_ACP, 0, Buffer, MBSTOWCS_NULLTERMINATE, TargetPTR.get(), (int)strnlen(Buffer, LARGE_PACKET_MAXSIZE));
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	mbstowcs(TargetPTR.get(), Buffer, strnlen(Buffer, LARGE_PACKET_MAXSIZE));
#endif
	Target = TargetPTR.get();

	return;
}

//Convert lowercase/uppercase words to uppercase/lowercase words
void __fastcall CaseConvert(const bool IsLowerUpper, PSTR Buffer, const size_t Length)
{
	for (size_t Index = 0;Index < Length;++Index)
	{
	//Lowercase to uppercase
		if (IsLowerUpper)
			Buffer[Index] = (char)toupper(Buffer[Index]);
	//Uppercase to lowercase
		else 
			Buffer[Index] = (char)tolower(Buffer[Index]);
	}

	return;
}

#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Linux and Mac OS X compatible with GetTickCount64
uint64_t GetTickCount64(void)
{
	std::shared_ptr<timeval> CurrentTime(new timeval());
	memset(CurrentTime.get(), 0, sizeof(timeval));
	gettimeofday(CurrentTime.get(), nullptr);
	return (uint64_t)CurrentTime->tv_sec * SECOND_TO_MILLISECOND + (uint64_t)CurrentTime->tv_usec / MICROSECOND_TO_MILLISECOND;
}

//Windows XP with SP3 support
#elif (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
//Verify version of system(Greater than Windows Vista)
BOOL WINAPI IsGreaterThanVista(void)
{
	std::shared_ptr<OSVERSIONINFOEXW> OSVI(new OSVERSIONINFOEXW());
	memset(OSVI.get(), 0, sizeof(OSVERSIONINFOEXW));
	DWORDLONG dwlConditionMask = 0;

//Initialization
	ZeroMemory(OSVI.get(), sizeof(OSVERSIONINFOEXW));
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
BOOL WINAPI GetFunctionPointer(const size_t FunctionType)
{
//GetTickCount64() function
	if (FunctionType == FUNCTION_GETTICKCOUNT64)
	{
		Parameter.GetTickCount64_DLL = LoadLibraryW(L"Kernel32.dll");
		if (Parameter.GetTickCount64_DLL != nullptr)
		{
			Parameter.GetTickCount64_PTR = (GetTickCount64Function)GetProcAddress(Parameter.GetTickCount64_DLL, "GetTickCount64");
			if (Parameter.GetTickCount64_PTR == nullptr)
			{
				FreeLibrary(Parameter.GetTickCount64_DLL);
				return FALSE;
			}
		}
	}
//inet_ntop() function
	else if (FunctionType == FUNCTION_INET_NTOP)
	{
		Parameter.Inet_Ntop_DLL = LoadLibraryW(L"ws2_32.dll");
		if (Parameter.Inet_Ntop_DLL != nullptr)
		{
			Parameter.Inet_Ntop_PTR = (Inet_Ntop_Function)GetProcAddress(Parameter.Inet_Ntop_DLL, "inet_ntop");
			if (Parameter.Inet_Ntop_PTR == nullptr)
			{
				FreeLibrary(Parameter.Inet_Ntop_DLL);
				return FALSE;
			}
		}
	}

	return TRUE;
}
#endif
