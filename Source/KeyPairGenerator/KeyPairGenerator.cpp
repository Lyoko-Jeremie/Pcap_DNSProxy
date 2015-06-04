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
		crypto_box_curve25519xsalsa20poly1305_keypair(PublicKey.get(), SecretKey.get());

	//Write public key.
		BinaryToHex(Buffer.get(), KEYPAIR_MESSAGE_LEN, PublicKey.get(), crypto_box_PUBLICKEYBYTES);
		fwprintf_s(Output, L"Public Key: ");
		for (Index = 0;Index < strnlen_s(Buffer.get(), KEYPAIR_MESSAGE_LEN);++Index)
			fwprintf_s(Output, L"%c", Buffer.get()[Index]);
		memset(Buffer.get(), 0, KEYPAIR_MESSAGE_LEN);
		fwprintf_s(Output, L"\n");

	//Write secret key.
		BinaryToHex(Buffer.get(), KEYPAIR_MESSAGE_LEN, SecretKey.get(), crypto_box_SECRETKEYBYTES);
		fwprintf_s(Output, L"Secret Key: ");
		for (Index = 0;Index < strnlen_s(Buffer.get(), KEYPAIR_MESSAGE_LEN);++Index)
			fwprintf_s(Output, L"%c", Buffer.get()[Index]);
		fwprintf_s(Output, L"\n");

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

//Convert binary to hex characters
#if defined(ENABLE_LIBSODIUM)
size_t __fastcall BinaryToHex(PSTR Buffer, const size_t MaxLength, const unsigned char *Binary, const size_t Length)
{
	size_t BufferLength = 0, Colon = 0;
	for (size_t Index = 0;Index < Length;++Index)
	{
		if (BufferLength < MaxLength)
		{
			Buffer[BufferLength] = Binary[Index] >> 4U;
			Buffer[BufferLength + 1U] = Binary[Index] << 4U;
			Buffer[BufferLength + 1U] = Binary[BufferLength + 1U] >> 4U;

		//Convert to ASCII.
			if (Buffer[BufferLength] < ASCII_LF)
				Buffer[BufferLength] += 48U; //Number
			else if (Buffer[BufferLength] <= ASCII_DLE)
				Buffer[BufferLength] += 55U; //Captain letters
			if (Buffer[BufferLength + 1U] < ASCII_LF)
				Buffer[BufferLength + 1U] += 48U; //Number
			else if (Buffer[BufferLength + 1U] <= ASCII_DLE)
				Buffer[BufferLength + 1U] += 55U; //Captain letters

		//Add colons.
			++Colon;
			if (Colon == 2U && Index != Length - 1U)
			{
				Colon = 0;
				Buffer[BufferLength + 2U] = ASCII_COLON;
				BufferLength += 3U;
			}
			else {
				BufferLength += 2U;
			}
		}
		else {
			break;
		}
	}

	return BufferLength;
}
#endif
