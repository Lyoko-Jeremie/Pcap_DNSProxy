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
size_t HashFamilyID = DEFAULT_HASH_ID;
#endif

//Main function of program
#if defined(PLATFORM_WIN)
int wmain(
	int argc, 
	wchar_t* argv[])
{
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
int main(int argc, char *argv[])
{
#endif

#if defined(ENABLE_LIBSODIUM)
//Initialization(Part 1)
#if defined(PLATFORM_WIN)
	std::wstring FileName, Command;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string FileName, Command;
#endif

//Read commands.
	if (argc < 2)
	{
		PrintDescription();
		return EXIT_SUCCESS;
	}
	else if (argc == 2) //File name only, use default hash function.
	{
	//Commands check
		Command = argv[1U];
		CaseConvert(true, Command);
		if (Command == COMMAND_LONG_PRINT_VERSION || Command == COMMAND_SHORT_PRINT_VERSION)
		{
			fwprintf_s(stderr, L"FileHash ");
			fwprintf_s(stderr, FULL_VERSION);
			fwprintf_s(stderr, L"\n");

			return EXIT_SUCCESS;
		}
		else if (Command == COMMAND_LONG_HELP || Command == COMMAND_SHORT_HELP || Command == COMMAND_SIGN_HELP)
		{
			PrintDescription();
			return EXIT_SUCCESS;
		}
		else if (Command == COMMAND_LIB_VERSION)
		{
			std::wstring LibVersion;
			if (MBSToWCSString(SODIUM_VERSION_STRING, strlen(SODIUM_VERSION_STRING), LibVersion))
				fwprintf_s(stderr, L"LibSodium version %ls\n", LibVersion.c_str());

			return EXIT_SUCCESS;
		}
		else { //Mark filename.
			FileName = argv[1U];
		}
	}
	else if (argc == 3) //File name with hash function command
	{
		Command = argv[1U];
		FileName = argv[2U];

	//Commands check
		if (Command.length() < 3U)
		{
			fwprintf_s(stderr, L"Commands error.\n");
			return EXIT_FAILURE;
		}
		else {
			CaseConvert(true, Command);
		}

	//CRC family
		if (Command.find(HASH_COMMAND_CRC) == 0)
		{
			HashFamilyID = HASH_ID_CRC;
			if (!ReadCommand_CRC(Command))
				return EXIT_FAILURE;
		}
	//Internet Protocol Checksum
		else if (Command == HASH_COMMAND_CHECKSUM)
		{
			HashFamilyID = HASH_ID_CHECKSUM;
		}
	//MD2
		else if (Command == HASH_COMMAND_MD2)
		{
			HashFamilyID = HASH_ID_MD2;
		}
	//MD4 family
		else if (Command == HASH_COMMAND_MD4)
		{
			HashFamilyID = HASH_ID_MD4;
		}
		else if (Command == HASH_COMMAND_ED2K)
		{
			HashFamilyID = HASH_ID_ED2K;
		}
	//MD5
		else if (Command == HASH_COMMAND_MD || Command == HASH_COMMAND_MD5)
		{
			HashFamilyID = HASH_ID_MD5;
		}
	//SHA-1
		else if (Command.find(HASH_COMMAND_SHA1) == 0)
		{
			HashFamilyID = HASH_ID_SHA1;
		}
	//SHA-2 family
		else if (Command == HASH_COMMAND_SHA2_384 || Command.find(HASH_COMMAND_SHA2_512) == 0 || Command.find(HASH_COMMAND_SHA2) == 0)
		{
			HashFamilyID = HASH_ID_SHA2;
			if (!ReadCommand_SHA2(Command))
				return EXIT_FAILURE;
		}
	//SHA-3 family
		else if (Command == HASH_COMMAND_SHA || Command.find(HASH_COMMAND_SHA3) == 0)
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

	Command.clear();
	Command.shrink_to_fit();

//Open file.
	FILE *FileHandle = nullptr;
#if defined(PLATFORM_WIN)
	if (_wfopen_s(&FileHandle, FileName.c_str(), L"rb") != 0 || FileHandle == nullptr)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	FileHandle = fopen(FileName.c_str(), "rb");
	if (FileHandle == nullptr)
#endif
	{
		fwprintf_s(stderr, L"Open file error.\n");
		return EXIT_FAILURE;
	}
	else {
		if ((HashFamilyID == HASH_ID_CRC && !CRC_Hash(FileHandle)) ||                                     //CRC family
			(HashFamilyID == HASH_ID_CHECKSUM && !Checksum_Hash(FileHandle)) ||                           //Internet Protocol Checksum
			(HashFamilyID == HASH_ID_MD2 && !MD2_Hash(FileHandle)) ||                                     //MD2
			((HashFamilyID == HASH_ID_MD4 || HashFamilyID == HASH_ID_ED2K) && !MD4_Hash(FileHandle)) ||   //MD4 family
			(HashFamilyID == HASH_ID_MD5 && !MD5_Hash(FileHandle)) ||                                     //MD5
			(HashFamilyID == HASH_ID_SHA1 && !SHA1_Hash(FileHandle)) ||                                   //SHA-1
			(HashFamilyID == HASH_ID_SHA2 && !SHA2_Hash(FileHandle)) ||                                   //SHA-2 family
			(HashFamilyID == HASH_ID_SHA3 && !SHA3_Hash(FileHandle)))                                     //SHA-3 family
		{
			fclose(FileHandle);
			return EXIT_FAILURE;
		}
	}

	fclose(FileHandle);
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
//Print description to screen
void __fastcall PrintDescription(
	void)
{
	fwprintf_s(stderr, L"\n");

//Description
	fwprintf_s(stderr, L"--------------------------------------------------\n");
	fwprintf_s(stderr, L"FileHash ");
	fwprintf_s(stderr, FULL_VERSION);
#if defined(PLATFORM_WIN)
	fwprintf_s(stderr, L"(Windows)\n");
#elif defined(PLATFORM_LINUX)
	fwprintf(stderr, L"(Linux)\n");
#elif defined(PLATFORM_MACX)
	fwprintf(stderr, L"(Mac)\n");
#endif
	fwprintf_s(stderr, COPYRIGHT_MESSAGE);
	fwprintf_s(stderr, L"\n--------------------------------------------------\n");

//Usage
	fwprintf_s(stderr, L"\nUsage: FileHash [-option]\n");
	fwprintf_s(stderr, L"       FileHash [-algorithm] Filename\n");
	fwprintf_s(stderr, L"  e.g. FileHash -SHA3 filename\n");

//Options
	fwprintf_s(stderr, L"\nOptions:\n");
	fwprintf_s(stderr, L"   -v/--version:     Print current version on screen.\n");
	fwprintf_s(stderr, L"   --lib-version:    Print current version of libraries on screen.\n");
	fwprintf_s(stderr, L"   -?/-h/--help      Print description.\n");
	fwprintf_s(stderr, L"   -algorithm        Select a supported hash algorithm.\n");

//Supported hash algorithm list
	fwprintf_s(stderr, L"\nSupported hash algorithms:\n");
	fwprintf_s(stderr, L"   * CRC family:     -CRC                        = -CRC32\n");
	fwprintf_s(stderr, L"                     -CRC8                       CRC 8 bits\n");
	fwprintf_s(stderr, L"                     -CRC8_ITU                   CRC 8 bits ITU\n");
	fwprintf_s(stderr, L"                     -CRC8_ATM                   CRC 8 bits ATM\n");
	fwprintf_s(stderr, L"                     -CRC8_CCITT                 CRC 8 bits CCITT\n");
	fwprintf_s(stderr, L"                     -CRC8_MAXIM                 CRC 8 bits Maxim\n");
	fwprintf_s(stderr, L"                     -CRC8_ICODE                 CRC 8 bits Icode\n");
	fwprintf_s(stderr, L"                     -CRC8_J1850                 CRC 8 bits J1850\n");
	fwprintf_s(stderr, L"                     -CRC8_WCDMA                 CRC 8 bits WCDMA\n");
	fwprintf_s(stderr, L"                     -CRC8_ROHC                  CRC 8 bits Rohc\n");
	fwprintf_s(stderr, L"                     -CRC8_DARC                  CRC 8 bits Darc\n");
	fwprintf_s(stderr, L"                     -CRC16                      CRC 16 bits\n");
	fwprintf_s(stderr, L"                     -CRC16_BUYPASS              CRC 16 bits Buypass\n");
	fwprintf_s(stderr, L"                     -CRC16_DDS_110              CRC 16 bits DDS 110\n");
	fwprintf_s(stderr, L"                     -CRC16_EN_13757             CRC 16 bits EN 13757\n");
	fwprintf_s(stderr, L"                     -CRC16_TELEDISK             CRC 16 bits Teledisk\n");
	fwprintf_s(stderr, L"                     -CRC16_MODBUS               CRC 16 bits Modbus\n");
	fwprintf_s(stderr, L"                     -CRC16_MAXIM                CRC 16 bits Maxim\n");
	fwprintf_s(stderr, L"                     -CRC16_USB                  CRC 16 bits USB\n");
	fwprintf_s(stderr, L"                     -CRC16_T10_DIF              CRC 16 bits T10 DIF\n");
	fwprintf_s(stderr, L"                     -CRC16_DECT_X               CRC 16 bits DECT X\n");
	fwprintf_s(stderr, L"                     -CRC16_DECT_R               CRC 16 bits DECT R\n");
	fwprintf_s(stderr, L"                     -CRC16_SICK                 CRC 16 bits Sick\n");
	fwprintf_s(stderr, L"                     -CRC16_DNP                  CRC 16 bits DNP\n");
	fwprintf_s(stderr, L"                     -CRC16_CCITT_XMODEM         CRC 16 bits CCITT Xmodem\n");
	fwprintf_s(stderr, L"                     -CRC16_CCITT_FFFF           CRC 16 bits CCITT FFFF\n");
	fwprintf_s(stderr, L"                     -CRC16_CCITT_1D0F           CRC 16 bits CCITT 1D0F\n");
	fwprintf_s(stderr, L"                     -CRC16_GENIBUS              CRC 16 bits Genibus\n");
	fwprintf_s(stderr, L"                     -CRC16_KERMIT               CRC 16 bits Kermit\n");
	fwprintf_s(stderr, L"                     -CRC16_X25                  CRC 16 bits X25\n");
	fwprintf_s(stderr, L"                     -CRC16_MCRF4XX              CRC 16 bits MCRF4XX\n");
	fwprintf_s(stderr, L"                     -CRC16_RIELLO               CRC 16 bits Riello\n");
	fwprintf_s(stderr, L"                     -CRC16_FLETCHER             CRC 16 bits Fletcher\n");
	fwprintf_s(stderr, L"                     -CRC24                      = -CRC24_R64\n");
	fwprintf_s(stderr, L"                     -CRC24_FLEXRAY_A            CRC 24 bits Flexray A\n");
	fwprintf_s(stderr, L"                     -CRC24_FLEXRAY_B            CRC 24 bits Flexray B\n");
	fwprintf_s(stderr, L"                     -CRC24_R64                  CRC 24 bits R64\n");
	fwprintf_s(stderr, L"                     -CRC32                      CRC 32 bits\n");
	fwprintf_s(stderr, L"                     -CRC32_JAM                  CRC 32 bits JamCRC\n");
	fwprintf_s(stderr, L"                     -CRC32C                     CRC 32 bits C\n");
	fwprintf_s(stderr, L"                     -CRC32D                     CRC 32 bits D\n");
	fwprintf_s(stderr, L"                     -CRC32_BZIP2                CRC 32 bits BZIP2\n");
	fwprintf_s(stderr, L"                     -CRC32_MPEG2                CRC 32 bits MPEG2\n");
	fwprintf_s(stderr, L"                     -CRC32_POSIX                CRC 32 bits POSIX\n");
	fwprintf_s(stderr, L"                     -CRC32K                     CRC 32 bits K\n");
	fwprintf_s(stderr, L"                     -CRC32Q                     CRC 32 bits Q\n");
	fwprintf_s(stderr, L"                     -CRC40                      CRC 40 bits\n");
	fwprintf_s(stderr, L"                     -CRC64                      CRC 64 bits\n");
	fwprintf_s(stderr, L"                     -CRC64_1B                   CRC 64 bits 1B\n");
	fwprintf_s(stderr, L"                     -CRC64_WE                   CRC 64 bits WE\n");
	fwprintf_s(stderr, L"                     -CRC64_JONES                CRC 64 bits JONES\n");
	fwprintf_s(stderr, L"   * Checksum:       -CHECKSUM                   Internet protocol checksum\n");
	fwprintf_s(stderr, L"   * MD2:            -MD2\n");
	fwprintf_s(stderr, L"   * MD4 family:     -MD4\n");
	fwprintf_s(stderr, L"                     -ED2K                       eDonkey/eMule hash algorithm\n");
	fwprintf_s(stderr, L"   * MD5:            -MD5\n");
	fwprintf_s(stderr, L"   * SHA-1:          -SHA1\n");
	fwprintf_s(stderr, L"   * SHA-2 family:   -SHA2                       = -SHA2_256\n");
	fwprintf_s(stderr, L"                     -SHA224/-SHA2_224           SHA-2 224 bits\n");
	fwprintf_s(stderr, L"                     -SHA256/-SHA2_256           SHA-2 256 bits\n");
	fwprintf_s(stderr, L"                     -SHA384/-SHA2_384           SHA-2 384 bits\n");
	fwprintf_s(stderr, L"                     -SHA512/-SHA2_512           SHA-2 512 bits\n");
	fwprintf_s(stderr, L"                     -SHA512_224/-SHA2_512_224   SHA-2 512/224 bits truncated\n");
	fwprintf_s(stderr, L"                     -SHA512_256/-SHA2_512_256   SHA-2 512/256 bits truncated\n");
	fwprintf_s(stderr, L"   * SHA-3 family:   -SHA3                       = -SHA3_256\n");
	fwprintf_s(stderr, L"                     -SHA3_224                   SHA-3 224 bits\n");
	fwprintf_s(stderr, L"                     -SHA3_256                   SHA-3 256 bits\n");
	fwprintf_s(stderr, L"                     -SHA3_384                   SHA-3 384 bits\n");
	fwprintf_s(stderr, L"                     -SHA3_512                   SHA-3 512 bits\n");
	fwprintf_s(stderr, L"                     -SHA3_SHAKE                 = -SHA3_SHAKE_128\n");
	fwprintf_s(stderr, L"                     -SHA3_SHAKE=Size            = -SHA3_SHAKE_128=Size\n");
	fwprintf_s(stderr, L"                     -SHA3_SHAKE_128=Size        SHA-3 SHAKE 128 bits\n");
	fwprintf_s(stderr, L"                                                 Size = Digest output length\n");
	fwprintf_s(stderr, L"                     -SHA3_SHAKE_256=Size        SHA-3 SHAKE 256 bits\n");
	fwprintf_s(stderr, L"                                                 Size = Digest output length\n");

#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	fwprintf_s(stderr, L"\n");
#endif
	return;
}
#endif
