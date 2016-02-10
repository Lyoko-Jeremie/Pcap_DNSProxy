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


#include "KeyPairGenerator.h"

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
//Libsodium initialization
	if (sodium_init() == LIBSODIUM_ERROR)
	{
		fwprintf_s(stderr, L"Libsodium initialization error.\n\n");
	#if defined(PLATFORM_WIN)
		system("PAUSE");
	#endif

		return EXIT_FAILURE;
	}

//Output.
	FILE *Output = nullptr;
#if defined(PLATFORM_WIN)
	_wfopen_s(&Output, L"KeyPair.txt", L"w+,ccs=UTF-8");
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Output = fopen("KeyPair.txt", "w+");
#endif
	if (Output != nullptr)
	{
	//Initialization and make keypair.
		std::shared_ptr<char> Buffer(new char[KEYPAIR_MESSAGE_LEN]());
		sodium_memzero(Buffer.get(), KEYPAIR_MESSAGE_LEN);
		DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> SecretKey(crypto_box_SECRETKEYBYTES);
		uint8_t PublicKey[crypto_box_PUBLICKEYBYTES] = {0};
		size_t Index = 0;
		crypto_box_keypair(PublicKey, SecretKey.Buffer);

	//Write public key.
		sodium_memzero(Buffer.get(), KEYPAIR_MESSAGE_LEN);
		if (sodium_bin2hex(Buffer.get(), KEYPAIR_MESSAGE_LEN, PublicKey, crypto_box_PUBLICKEYBYTES) == nullptr)
			fwprintf_s(stderr, L"Create ramdom key pair failed, please try again.\n");
		CaseConvert(true, Buffer.get(), KEYPAIR_MESSAGE_LEN);
		fwprintf_s(Output, L"Client Public Key = ");
		for (Index = 0;Index < strnlen_s(Buffer.get(), KEYPAIR_MESSAGE_LEN);++Index)
		{
			if (Index > 0 && Index % KEYPAIR_INTERVAL == 0 && Index + 1U < strnlen_s(Buffer.get(), KEYPAIR_MESSAGE_LEN))
				fwprintf_s(Output, L":");

			fwprintf_s(Output, L"%c", Buffer.get()[Index]);
		}
		sodium_memzero(Buffer.get(), KEYPAIR_MESSAGE_LEN);
		fwprintf_s(Output, L"\n");

	//Write secret key.
		if (sodium_bin2hex(Buffer.get(), KEYPAIR_MESSAGE_LEN, SecretKey.Buffer, crypto_box_SECRETKEYBYTES) == nullptr)
			fwprintf_s(stderr, L"Create ramdom key pair failed, please try again.\n");
		CaseConvert(true, Buffer.get(), KEYPAIR_MESSAGE_LEN);
		fwprintf_s(Output, L"Client Secret Key = ");
		for (Index = 0;Index < strnlen_s(Buffer.get(), KEYPAIR_MESSAGE_LEN);++Index)
		{
			if (Index > 0 && Index % KEYPAIR_INTERVAL == 0 && Index + 1U < strnlen_s(Buffer.get(), KEYPAIR_MESSAGE_LEN))
				fwprintf_s(Output, L":");

			fwprintf_s(Output, L"%c", Buffer.get()[Index]);
		}
		fwprintf_s(Output, L"\n");

	//Close file.
		fclose(Output);
	}
	else {
		fwprintf_s(stderr, L"Cannot create target file(KeyPair.txt)\n\n");
	#if defined(PLATFORM_WIN)
		system("PAUSE");
	#endif

		return EXIT_FAILURE;
	}

	fwprintf_s(stderr, L"Create ramdom key pair success, please check KeyPair.txt.\n\n");
#if defined(PLATFORM_WIN)
	system("PAUSE");
#endif
#else
	#if defined(PLATFORM_WIN)
		fwprintf(stderr, L"LibSodium is disable.\n\n");
		system("PAUSE");
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		fwprintf(stderr, L"LibSodium is disable.\n\n");
	#endif
#endif

	return EXIT_SUCCESS;
}

#if defined(ENABLE_LIBSODIUM)
//Convert lowercase/uppercase words to uppercase/lowercase words(Character version)
void __fastcall CaseConvert(
	const bool IsLowerToUpper, 
	char *Buffer, 
	const size_t Length)
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
#endif
