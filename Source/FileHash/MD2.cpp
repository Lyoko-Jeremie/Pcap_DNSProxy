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


#include "MD2.h"

#if defined(ENABLE_LIBSODIUM)
//Initialize the hash state
void __fastcall MD2_Init(
	MD2_CTX *md2)
{
	XMEMSET(md2->X, 0, MD2_X_SIZE);
	XMEMSET(md2->C, 0, MD2_BLOCK_SIZE);
	XMEMSET(md2->Buffer, 0, MD2_BLOCK_SIZE);
	md2->Count = 0;

	return;
}

//Update MD2 status
void __fastcall MD2_Update(
	MD2_CTX *md2, 
	const uint8_t *data, 
	uint32_t len)
{
	static const uint8_t S[256U] =
	{
		41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 
		19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 
		76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 
		138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 
		245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63, 
		148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50, 
		39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165, 
		181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 
		150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157, 
		112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27, 
		96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 
		85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 
		234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 
		129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 
		8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233, 
		203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228, 
		166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 
		31, 26, 219, 153, 141, 51, 159, 17, 131, 20
	};

	while (len)
	{
		uint32_t L = (MD2_PAD_SIZE - md2->Count) < len ? (MD2_PAD_SIZE - md2->Count) : len;
		XMEMCPY(md2->Buffer + md2->Count, data, L);
		md2->Count += L;
		data += L;
		len -= L;
		if (md2->Count == MD2_PAD_SIZE)
		{
			int i = 0;
			uint8_t t = 0;

			md2->Count = 0;
			XMEMCPY(md2->X + MD2_PAD_SIZE, md2->Buffer, MD2_PAD_SIZE);
			t = md2->C[15U];
			for (i = 0;i < MD2_PAD_SIZE;++i)
			{
				md2->X[32 + i] = md2->X[MD2_PAD_SIZE + i] ^ md2->X[i];
				t = md2->C[i] ^= S[md2->Buffer[i] ^ t];
			}

			t = 0;
			for (i = 0;i < 18;++i)
			{
				int j;
				for (j = 0;j < MD2_X_SIZE;j += 8)
				{
					t = md2->X[j + 0] ^= S[t];
					t = md2->X[j + 1U] ^= S[t];
					t = md2->X[j + 2U] ^= S[t];
					t = md2->X[j + 3U] ^= S[t];
					t = md2->X[j + 4U] ^= S[t];
					t = md2->X[j + 5U] ^= S[t];
					t = md2->X[j + 6U] ^= S[t];
					t = md2->X[j + 7U] ^= S[t];
				}
				t = (t + i) & 0xFF;
			}
		}
	}

	return;
}

//Finish hash process
void __fastcall MD2_Final(
	MD2_CTX *md2, 
	uint8_t *hash)
{
	uint8_t padding[MD2_BLOCK_SIZE] = {0};
	uint32_t padLen = MD2_PAD_SIZE - md2->Count, i = 0;

	for (i = 0;i < padLen;++i)
		padding[i] = (uint8_t)padLen;

	MD2_Update(md2, padding, padLen);
	MD2_Update(md2, md2->C, MD2_BLOCK_SIZE);
	XMEMCPY(hash, md2->X, MD2_DIGEST_SIZE);

	MD2_Init(md2);
	return;
}

//MD2 hash function
bool __fastcall MD2_Hash(
	FILE *Input)
{
//Parameters check
	if (HashFamilyID != HASH_ID_MD2 || Input == nullptr)
	{
		fwprintf_s(stderr, L"Parameters error.\n");
		return false;
	}

//Initialization
	std::shared_ptr<char> Buffer(new char[FILE_BUFFER_SIZE]()), StringBuffer(new char[FILE_BUFFER_SIZE]());
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	memset(StringBuffer.get(), 0, FILE_BUFFER_SIZE);
	MD2_CTX HashInstance = {0};
	size_t ReadLength = 0;

//MD2 initialization
	MD2_Init(&HashInstance);

//Hash process
	while (!feof(Input))
	{
		memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
		ReadLength = fread_s(Buffer.get(), FILE_BUFFER_SIZE, sizeof(char), FILE_BUFFER_SIZE, Input);
		if (ReadLength == 0 && errno > 0)
		{
			fwprintf_s(stderr, L"Hash process error.\n");
			return false;
		}
		else {
			MD2_Update(&HashInstance, (uint8_t *)Buffer.get(), (uint32_t)ReadLength);
		}
	}

//Binary to hex
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	MD2_Final(&HashInstance, (uint8_t *)Buffer.get());
	if (sodium_bin2hex(StringBuffer.get(), FILE_BUFFER_SIZE, (const unsigned char *)Buffer.get(), MD2_DIGEST_SIZE) == nullptr)
	{
		fwprintf_s(stderr, L"Convert binary to hex error.\n");
		return false;
	}
	else {
	//Print to screen.
		std::string HashResult = StringBuffer.get();
		CaseConvert(true, HashResult);
		for (size_t Index = 0;Index < HashResult.length();++Index)
			fwprintf_s(stderr, L"%c", HashResult.c_str()[Index]);
		fwprintf_s(stderr, L"\n");
	}

	return true;
}
#endif
