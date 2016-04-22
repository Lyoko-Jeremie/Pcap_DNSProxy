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


#include "MD5.h"

#if defined(ENABLE_LIBSODIUM)
//Padding data
uint8_t PADDING[] = 
{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

//Initialize the hash state
void __fastcall MD5_Init(
	MD5_CTX *context)
{
	context->State[0] = 0x67452301;
	context->State[1U] = 0xEFCDAB89;
	context->State[2U] = 0x98BADCFE;
	context->State[3U] = 0x10325476;

	return;
}

//Update MD5 status
void __fastcall MD5_Update(
	MD5_CTX *context, 
	uint8_t *input, 
	unsigned int inputlen)
{
	unsigned int i = 0, index = 0, partlen = 0;
	index = (context->Count[0] >> 3U) & 0x3F;
	partlen = 64U - index;
	context->Count[0] += inputlen << 3U;
	if (context->Count[0] < (inputlen << 3U))
		context->Count[1U]++;
	context->Count[1] += inputlen >> 29U;
	if (inputlen >= partlen)
	{
		memcpy(&context->Buffer[index], input, partlen);
		MD5_Transform(context->State, context->Buffer);
		for (i = partlen;i + 64 <= inputlen;i += 64U)
			MD5_Transform(context->State, &input[i]);
		index = 0;
	}
	else {
		i = 0;
	}
	memcpy(&context->Buffer[index], &input[i], inputlen - i);

	return;
}

//Finish MD5 process
void __fastcall MD5_Final(
	MD5_CTX *context, 
	uint8_t digest[MD5_SIZE_DIGEST])
{
	unsigned int index = 0, padlen = 0;
	uint8_t bits[8U];
	memset(bits, 0, 8U);
	index = (context->Count[0] >> 3U) & 0x3F;
	padlen = (index < 56U) ? (56U - index) : (120U - index);
	MD5_Encode(bits, context->Count, 8U);
	MD5_Update(context, PADDING, padlen);
	MD5_Update(context, bits, 8U);
	MD5_Encode(digest, context->State, MD5_SIZE_DIGEST);

	return;
}

//MD5 encode process
void __fastcall MD5_Encode(
	uint8_t *output, 
	unsigned int *input, 
	unsigned int len)
{
	unsigned int i = 0, j = 0;
	while (j < len)
	{
		output[j] = input[i] & 0xFF;
		output[j + 1U] = (input[i] >> 8U) & 0xFF;
		output[j + 2U] = (input[i] >> 16U) & 0xFF;
		output[j + 3U] = (input[i] >> 24U) & 0xFF;
		i++;
		j += 4;
	}

	return;
}

//MD5 encode process
void __fastcall MD5_Decode(
	unsigned int *output, 
	uint8_t *input, 
	unsigned int len)
{
	unsigned int i = 0, j = 0;
	while (j < len)
	{
		output[i] = (input[j])        |
			(input[j + 1] << 8U)      |
			(input[j + 2] << 16U)     |
			(input[j + 3] << 24U);
		i++;
		j += 4;
	}

	return;
}

//MD5 transform process
void __fastcall MD5_Transform(
	unsigned int state[4U], 
	uint8_t block[MD5_SIZE_BLOCK])
{
	unsigned int a = state[0];
	unsigned int b = state[1U];
	unsigned int c = state[2U];
	unsigned int d = state[3U];
	unsigned int x[64U];
	memset(x, 0, sizeof(unsigned int) * 64U);
	MD5_Decode(x, block, 64U);
	FF(a, b, c, d, x[0], 7, 0xD76AA478);
	FF(d, a, b, c, x[1U], 12, 0xE8C7B756);
	FF(c, d, a, b, x[2U], 17, 0x242070DB);
	FF(b, c, d, a, x[3U], 22, 0xC1BDCEEE);
	FF(a, b, c, d, x[4U], 7, 0xF57C0FAF);
	FF(d, a, b, c, x[5U], 12, 0x4787C62A);
	FF(c, d, a, b, x[6U], 17, 0xA8304613);
	FF(b, c, d, a, x[7U], 22, 0xFD469501);
	FF(a, b, c, d, x[8U], 7, 0x698098D8);
	FF(d, a, b, c, x[9U], 12, 0x8B44F7AF);
	FF(c, d, a, b, x[10U], 17, 0xFFFF5BB1);
	FF(b, c, d, a, x[11U], 22, 0x895CD7BE);
	FF(a, b, c, d, x[12U], 7, 0x6B901122);
	FF(d, a, b, c, x[13U], 12, 0xFD987193);
	FF(c, d, a, b, x[14U], 17, 0xA679438E);
	FF(b, c, d, a, x[15U], 22, 0x49B40821);
	GG(a, b, c, d, x[1U], 5, 0xF61E2562);
	GG(d, a, b, c, x[6U], 9, 0xC040B340);
	GG(c, d, a, b, x[11U], 14, 0x265E5A51);
	GG(b, c, d, a, x[0], 20, 0xE9B6C7AA);
	GG(a, b, c, d, x[5U], 5, 0xD62F105D);
	GG(d, a, b, c, x[10U], 9, 0x2441453);
	GG(c, d, a, b, x[15U], 14, 0xD8A1E681);
	GG(b, c, d, a, x[4U], 20, 0xE7D3FBC8);
	GG(a, b, c, d, x[9U], 5, 0x21E1CDE6);
	GG(d, a, b, c, x[14U], 9, 0xC33707D6);
	GG(c, d, a, b, x[3U], 14, 0xF4D50D87);
	GG(b, c, d, a, x[8U], 20, 0x455A14ED);
	GG(a, b, c, d, x[13U], 5, 0xA9E3E905);
	GG(d, a, b, c, x[2U], 9, 0xFCEFA3F8);
	GG(c, d, a, b, x[7U], 14, 0x676F02D9);
	GG(b, c, d, a, x[12U], 20, 0x8D2A4C8A);
	HH(a, b, c, d, x[5U], 4, 0xFFFA3942);
	HH(d, a, b, c, x[8U], 11, 0x8771F681);
	HH(c, d, a, b, x[11U], 16, 0x6D9D6122);
	HH(b, c, d, a, x[14U], 23, 0xFDE5380C);
	HH(a, b, c, d, x[1U], 4, 0xA4BEEA44);
	HH(d, a, b, c, x[4U], 11, 0x4BDECFA9);
	HH(c, d, a, b, x[7U], 16, 0xF6BB4B60);
	HH(b, c, d, a, x[10U], 23, 0xBEBFBC70);
	HH(a, b, c, d, x[13U], 4, 0x289B7EC6);
	HH(d, a, b, c, x[0], 11, 0xEAA127FA);
	HH(c, d, a, b, x[3U], 16, 0xD4EF3085);
	HH(b, c, d, a, x[6U], 23, 0x4881D05);
	HH(a, b, c, d, x[9U], 4, 0xD9D4D039);
	HH(d, a, b, c, x[12U], 11, 0xE6DB99E5);
	HH(c, d, a, b, x[15U], 16, 0x1FA27CF8);
	HH(b, c, d, a, x[2U], 23, 0xC4AC5665);
	II(a, b, c, d, x[0], 6, 0xF4292244);
	II(d, a, b, c, x[7U], 10, 0x432AFF97);
	II(c, d, a, b, x[14U], 15, 0xAB9423A7);
	II(b, c, d, a, x[5U], 21, 0xFC93A039);
	II(a, b, c, d, x[12U], 6, 0x655B59C3);
	II(d, a, b, c, x[3U], 10, 0x8F0CCC92);
	II(c, d, a, b, x[10U], 15, 0xFFEFF47D);
	II(b, c, d, a, x[1U], 21, 0x85845DD1);
	II(a, b, c, d, x[8U], 6, 0x6FA87E4F);
	II(d, a, b, c, x[15U], 10, 0xFE2CE6E0);
	II(c, d, a, b, x[6U], 15, 0xA3014314);
	II(b, c, d, a, x[13U], 21, 0x4E0811A1);
	II(a, b, c, d, x[4U], 6, 0xF7537E82);
	II(d, a, b, c, x[11U], 10, 0xBD3AF235);
	II(c, d, a, b, x[2U], 15, 0x2AD7D2BB);
	II(b, c, d, a, x[9U], 21, 0xEB86D391);
	state[0] += a;
	state[1U] += b;
	state[2U] += c;
	state[3U] += d;

	return;
}

//MD5 hash function
bool __fastcall MD5_Hash(
	FILE *Input)
{
//Parameters check
	if (HashFamilyID != HASH_ID_MD5 || Input == nullptr)
	{
		fwprintf_s(stderr, L"Parameters error.\n");
		return false;
	}

//Initialization
	std::shared_ptr<char> Buffer(new char[FILE_BUFFER_SIZE]()), StringBuffer(new char[FILE_BUFFER_SIZE]());
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	memset(StringBuffer.get(), 0, FILE_BUFFER_SIZE);
	MD5_CTX HashInstance;
	memset(&HashInstance, 0, sizeof(MD5_CTX));
	size_t ReadLength = 0;

//MD5 initialization
	MD5_Init(&HashInstance);

//Hash process
//n * 512 + 448 + 64 = (n + 1) * 512 bits
	while (!feof(Input))
	{
		memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
		_set_errno(0);
		ReadLength = fread_s(Buffer.get(), FILE_BUFFER_SIZE, sizeof(char), FILE_BUFFER_SIZE, Input);
		if (ReadLength == 0)
		{
			fwprintf_s(stderr, L"Hash process error");
			if (errno > 0)
				fwprintf_s(stderr, L", error code is %d.\n", errno);
			else
				fwprintf_s(stderr, L".\n");

			return false;
		}
		else {
			MD5_Update(&HashInstance, (uint8_t *)Buffer.get(), (unsigned int)ReadLength);
		}
	}

//Binary to hex
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	MD5_Final(&HashInstance, (uint8_t *)Buffer.get());
	if (sodium_bin2hex(StringBuffer.get(), FILE_BUFFER_SIZE, (const unsigned char *)Buffer.get(), MD5_SIZE_DIGEST) == nullptr)
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
