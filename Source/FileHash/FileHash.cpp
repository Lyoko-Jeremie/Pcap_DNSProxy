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


#include "FileHash.h"

#if defined(ENABLE_LIBSODIUM)
//Global variables
size_t HashFamilyID = DEFAULT_HASH_ID;
#endif

//Main function of program
#if defined(PLATFORM_WIN)
int wmain(
	_In_ int argc, 
	_In_ wchar_t* argv[])
{
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
int main(int argc, char *argv[])
{
#endif

#if defined(ENABLE_LIBSODIUM)
//Initialization(Part 1)
#if defined(PLATFORM_WIN)
	std::wstring FileName;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string FileName;
#endif

//Read commands.
	if (argc < 2)
	{
		fwprintf_s(stderr, L"Commands error.\n");
		return EXIT_FAILURE;
	}
	else if (argc == 2) //File name only, use default hash function.
	{
		FileName = argv[1U];
	}
	else if (argc == 3) //File name with hash function command
	{
	//File name
		FileName = argv[2U];

	//Commands check
	#if defined(PLATFORM_WIN)
		std::wstring Command(argv[1U]);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		std::string Command(argv[1U]);
	#endif
		if (Command.length() < 3U)
		{
			fwprintf_s(stderr, L"Commands error.\n");
			return EXIT_FAILURE;
		}
		else {
			CaseConvert(true, Command);
		}

	//SHA-1 family
		if (Command.find(COMMAND_SHA1) == 0)
		{
			HashFamilyID = HASH_ID_SHA1;
		}
	//SHA-2 family
		else if (Command == COMMAND_SHA2_384 || Command.find(COMMAND_SHA2_512) == 0 || Command.find(COMMAND_SHA2) == 0)
		{
			HashFamilyID = HASH_ID_SHA2;
			if (!ReadCommand_SHA2(Command))
				return EXIT_FAILURE;
		}
	//SHA-3 family
		else if (Command == COMMAND_SHA || Command.find(COMMAND_SHA3) == 0)
		{
			HashFamilyID = HASH_ID_SHA3;
			if (!ReadCommand_SHA3(Command))
				return EXIT_FAILURE;
		}
	//Commands error
		else {
			fwprintf_s(stderr, L"Commands error.\n");
			return EXIT_FAILURE;
		}
	}
	else {
		fwprintf_s(stderr, L"Commands error.\n");
		return EXIT_FAILURE;
	}

//Open file.
	FILE *Input = nullptr;
#if defined(PLATFORM_WIN)
	if (_wfopen_s(&Input, FileName.c_str(), L"rb") != 0 || Input == nullptr)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Input = fopen(FileName.c_str(), "rb");
	if (Input == nullptr)
#endif
	{
		fwprintf_s(stderr, L"Open file error.\n");
		return EXIT_FAILURE;
	}
	else {
		if (HashFamilyID == HASH_ID_SHA1 && !SHA1_Hash(Input) || //SHA-1 family
			HashFamilyID == HASH_ID_SHA2 && !SHA2_Hash(Input) || //SHA-2 family
			HashFamilyID == HASH_ID_SHA3 && !SHA3_Hash(Input)) //SHA-3 family
		{
			fclose(Input);
			return EXIT_FAILURE;
		}
	}

	fclose(Input);
#else
	#if defined(PLATFORM_WIN)
		fwprintf_s(stderr, L"LibSodium is disable.\n\n");
		system("PAUSE");
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		fwprintf(stderr, L"LibSodium is disable.\n\n");
	#endif
#endif

	return EXIT_SUCCESS;
}

#if defined(ENABLE_LIBSODIUM)
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
