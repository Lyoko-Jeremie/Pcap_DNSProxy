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


#include "KeyPairGenerator.h"

//Main function of program
#if defined(PLATFORM_WIN)
int wmain(int argc, wchar_t* argv[])
{
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
int main(int argc, char *argv[])
{
#endif

#if defined(ENABLE_LIBSODIUM)
//Libsodium initialization
	if (sodium_init() != EXIT_SUCCESS)
	{
		wprintf_s(L"Libsodium initialization error\n");
#if defined(PLATFORM_WIN)
		system("Pause");
#endif

		return EXIT_FAILURE;
	}

	FILE *Output = nullptr;
//Output.
#if defined(PLATFORM_WIN)
	_wfopen_s(&Output, L"KeyPair.txt", L"w+,ccs=UTF-8");
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Output = fopen("KeyPair.txt", "w+");
#endif
	if (Output != nullptr)
	{
	//Initialization and make keypair.
		size_t Index = 0;
		std::shared_ptr<char> Buffer(new char[KEYPAIR_MESSAGE_LEN]());
		std::shared_ptr<uint8_t> PublicKey(new uint8_t[crypto_box_PUBLICKEYBYTES]()), SecretKey(new uint8_t[crypto_box_SECRETKEYBYTES]());
		memset(Buffer.get(), 0, KEYPAIR_MESSAGE_LEN);
		memset(PublicKey.get(), 0, crypto_box_PUBLICKEYBYTES);
		memset(SecretKey.get(), 0, crypto_box_SECRETKEYBYTES);
		crypto_box_keypair(PublicKey.get(), SecretKey.get());

	//Write public key.
		memset(Buffer.get(), 0, KEYPAIR_MESSAGE_LEN);
		if (sodium_bin2hex(Buffer.get(), KEYPAIR_MESSAGE_LEN, PublicKey.get(), crypto_box_PUBLICKEYBYTES) == nullptr)
			wprintf_s(L"Create ramdom key pair failed, please try again.\n");
		CaseConvert(true, Buffer.get(), KEYPAIR_MESSAGE_LEN);
		fwprintf_s(Output, L"Client Public Key = ");
		for (Index = 0;Index < strnlen_s(Buffer.get(), KEYPAIR_MESSAGE_LEN);++Index)
		{
			if (Index > 0 && Index % KEYPAIR_INTERVAL == 0 && Index + 1U < strnlen_s(Buffer.get(), KEYPAIR_MESSAGE_LEN))
				fwprintf_s(Output, L":");

			fwprintf_s(Output, L"%c", Buffer.get()[Index]);
		}
		memset(Buffer.get(), 0, KEYPAIR_MESSAGE_LEN);
		fwprintf_s(Output, L"\n");

	//Write secret key.
		if (sodium_bin2hex(Buffer.get(), KEYPAIR_MESSAGE_LEN, SecretKey.get(), crypto_box_SECRETKEYBYTES) == nullptr)
			wprintf_s(L"Create ramdom key pair failed, please try again.\n");
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
		wprintf_s(L"Cannot create target file(KeyPair.txt)\n");
	#if defined(PLATFORM_WIN)
		system("Pause");
	#endif

		return EXIT_FAILURE;
	}

	wprintf_s(L"Create ramdom key pair success, please check KeyPair.txt.\n\n");
#if defined(PLATFORM_WIN)
	system("Pause");
#endif
#else
	#if defined(PLATFORM_WIN)
		wprintf_s(L"LibSodium is disable.\n\n");
		system("Pause");
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		wprintf(L"LibSodium is disable.\n\n");
	#endif
#endif

	return EXIT_SUCCESS;
}

//Convert lowercase/uppercase words to uppercase/lowercase words(Character version)
#if defined(ENABLE_LIBSODIUM)
void __fastcall CaseConvert(const bool IsLowerToUpper, PSTR Buffer, const size_t Length)
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
