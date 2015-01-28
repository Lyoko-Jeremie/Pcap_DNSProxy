// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
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
int wmain(int argc, wchar_t* argv[])
{
//Libsodium initialization
	if (sodium_init() != EXIT_SUCCESS)
	{
		wprintf_s(L"Libsodium initialization error\n");
		system("Pause");

		return EXIT_FAILURE;
	}

	FILE *Output = nullptr;
//Output
	_wfopen_s(&Output, L"KeyPair.txt", L"w+,ccs=UTF-8");
	if (Output != nullptr)
	{
	//Initialization and make keypair.
		std::shared_ptr<char> Buffer(new char[KEYPAIR_MESSAGE_LEN]());
		std::shared_ptr<uint8_t> PublicKey(new uint8_t[crypto_box_PUBLICKEYBYTES]()), SecretKey(new uint8_t[crypto_box_SECRETKEYBYTES]());
		crypto_box_curve25519xsalsa20poly1305_keypair(PublicKey.get(), SecretKey.get());

	//Write public key.
		BinaryToHex(Buffer.get(), KEYPAIR_MESSAGE_LEN, PublicKey.get(), crypto_box_PUBLICKEYBYTES);
/*
		if (sodium_bin2hex(Buffer.get(), KEYPAIR_MESSAGE_LEN, PublicKey.get(), crypto_box_PUBLICKEYBYTES) == nullptr)
		{
			wprintf_s(L"Convert binary to hex overflow.\n");
			return EXIT_FAILURE;
		}
*/
		fwprintf_s(Output, L"Public Key: ");
		for (size_t Index = 0;Index < strlen(Buffer.get());Index++)
			fwprintf_s(Output, L"%c", Buffer.get()[Index]);
		memset(Buffer.get(), 0, KEYPAIR_MESSAGE_LEN);
		fwprintf_s(Output, L"\n");

	//Write secret key.
		BinaryToHex(Buffer.get(), KEYPAIR_MESSAGE_LEN, SecretKey.get(), crypto_box_SECRETKEYBYTES);
/*
		if (sodium_bin2hex(Buffer.get(), KEYPAIR_MESSAGE_LEN, SecretKey.get(), crypto_box_SECRETKEYBYTES) == nullptr)
		{
			wprintf_s(L"Convert binary to hex overflow.\n");
			return EXIT_FAILURE;
		}
*/
		fwprintf_s(Output, L"Secret Key: ");
		for (size_t Index = 0;Index < strlen(Buffer.get());Index++)
			fwprintf_s(Output, L"%c", Buffer.get()[Index]);
		fwprintf_s(Output, L"\n");

		fclose(Output);
	}
	else {
		wprintf_s(L"Cannot create target file(KeyPair.txt)\n");
		system("Pause");

		return EXIT_FAILURE;
	}

	wprintf_s(L"Create ramdom key pair success, please check KeyPair.txt.\n\n");
	system("Pause");

	return EXIT_SUCCESS;
}

//Convert binary to hex characters
inline size_t __fastcall BinaryToHex(PSTR Buffer, const size_t MaxLength, const PUINT8 Binary, const size_t Length)
{
	size_t BufferLength = 0, Colon = 0;
	for (size_t Index = 0;Index < Length;Index++)
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
			Colon++;
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
