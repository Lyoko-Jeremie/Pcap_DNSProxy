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


#include "SHA-1.h"

#if defined(ENABLE_LIBSODIUM)
//SHA-1 compress process
static void __fastcall SHA1_Compress(
	SHA1_State *sha1, 
	uint8_t *buf)
{
	SHA1_INT32 a = 0, b = 0, c = 0, d = 0, e = 0, W[80U] = {0};
	size_t Index = 0;

 //Copy the state into 512-bits into W[0..15].
	for (Index = 0;Index < 16U;++Index)
		LOAD32H(W[Index], buf + (4U * Index));

//Copy state.
	a = sha1->State[0];
	b = sha1->State[1U];
	c = sha1->State[2U];
	d = sha1->State[3U];
	e = sha1->State[4U];

//Expand it.
	for (Index = 16U;Index < 80U;++Index)
		W[Index] = ROL(W[Index - 3U] ^ W[Index - 8U] ^ W[Index - 14U] ^ W[Index - 16U], 1);

//Compress.
//Round 1
	#define SHA1_FF0(a, b, c, d, e, Index) e = (ROLc(a, 5) + SHA1_F0(b, c, d) + e + W[Index] + 0x5A827999UL); b = ROLc(b, 30);
	#define SHA1_FF1(a, b, c, d, e, Index) e = (ROLc(a, 5) + SHA1_F1(b, c, d) + e + W[Index] + 0x6ED9EBA1UL); b = ROLc(b, 30);
	#define SHA1_FF2(a, b, c, d, e, Index) e = (ROLc(a, 5) + SHA1_F2(b, c, d) + e + W[Index] + 0x8F1BBCDCUL); b = ROLc(b, 30);
	#define SHA1_FF3(a, b, c, d, e, Index) e = (ROLc(a, 5) + SHA1_F3(b, c, d) + e + W[Index] + 0xCA62C1D6UL); b = ROLc(b, 30);
	for (Index = 0;Index < 20U;)
	{
		SHA1_FF0(a, b, c, d, e, Index++);
		SHA1_FF0(e, a, b, c, d, Index++);
		SHA1_FF0(d, e, a, b, c, Index++);
		SHA1_FF0(c, d, e, a, b, Index++);
		SHA1_FF0(b, c, d, e, a, Index++);
	}

//Round 2
	for (;Index < 40U;)
	{
		SHA1_FF1(a, b, c, d, e, Index++);
		SHA1_FF1(e, a, b, c, d, Index++);
		SHA1_FF1(d, e, a, b, c, Index++);
		SHA1_FF1(c, d, e, a, b, Index++);
		SHA1_FF1(b, c, d, e, a, Index++);
	}

//Round 3
	for (;Index < 60U;)
	{
		SHA1_FF2(a, b, c, d, e, Index++);
		SHA1_FF2(e, a, b, c, d, Index++);
		SHA1_FF2(d, e, a, b, c, Index++);
		SHA1_FF2(c, d, e, a, b, Index++);
		SHA1_FF2(b, c, d, e, a, Index++);
	}

//Round 4
	for (;Index < 80U;)
	{
		SHA1_FF3(a, b, c, d, e, Index++);
		SHA1_FF3(e, a, b, c, d, Index++);
		SHA1_FF3(d, e, a, b, c, Index++);
		SHA1_FF3(c, d, e, a, b, Index++);
		SHA1_FF3(b, c, d, e, a, Index++);
	}

	#undef SHA1_FF0
	#undef SHA1_FF1
	#undef SHA1_FF2
	#undef SHA1_FF3

//Store.
	sha1->State[0] = sha1->State[0] + a;
	sha1->State[1U] = sha1->State[1U] + b;
	sha1->State[2U] = sha1->State[2U] + c;
	sha1->State[3U] = sha1->State[3U] + d;
	sha1->State[4U] = sha1->State[4U] + e;

	return;
}

/***
	Initialize the hash state
	@param sha1   The hash state you wish to initialize
*/
void __fastcall SHA1_Init(
	SHA1_State *sha1)
{
	sha1->State[0] = 0x67452301UL;
	sha1->State[1U] = 0xEFCDAB89UL;
	sha1->State[2U] = 0x98BADCFEUL;
	sha1->State[3U] = 0x10325476UL;
	sha1->State[4U] = 0xC3D2E1F0UL;
	sha1->Curlen = 0;
	sha1->Length = 0;

	return;
}

/***
	Process a block of memory though the hash
	@param sha1   The hash state
	@param in     The data to hash
	@param inlen  The length of the data (octets)
*/
void __fastcall SHA1_Process(
	SHA1_State *sha1, 
	const uint8_t *in, 
	unsigned long inlen)
{
	unsigned long n = 0;
	while (inlen > 0) 
	{
		if (sha1->Curlen == 0 && inlen >= SHA1_SIZE_BLOCK)
		{
			SHA1_Compress(sha1, (uint8_t *)in);
			sha1->Length += SHA1_SIZE_BLOCK * 8;
			in += SHA1_SIZE_BLOCK;
			inlen -= SHA1_SIZE_BLOCK;
		}
		else {
			n = MIN(inlen, (SHA1_SIZE_BLOCK - sha1->Curlen));
			memcpy(sha1->Buffer + sha1->Curlen, in, (size_t)n);
			sha1->Curlen += n;
			in += n;
			inlen -= n;
			if (sha1->Curlen == SHA1_SIZE_BLOCK)
			{
				SHA1_Compress(sha1, sha1->Buffer);
				sha1->Length += 8 * SHA1_SIZE_BLOCK;
				sha1->Curlen = 0;
			}
		}
	}

	return;
}

/***
	Terminate the hash to get the digest
	@param sha1  The hash state
	@param out [out] The destination of the hash (20 bytes)
*/
void __fastcall SHA1_Done(
	SHA1_State *sha1, 
	uint8_t *out)
{
//Increase the length of the message.
	sha1->Length += sha1->Curlen * 8;

//Append the '1' bit.
	sha1->Buffer[sha1->Curlen++] = (unsigned char)0x80;

/** if the length is currently above 56 bytes we append zeros
  * then compress.  Then we can fall back to padding zeros and length
  * encoding like normal.
*/
	if (sha1->Curlen > 56)
	{
		while (sha1->Curlen < 64)
			sha1->Buffer[sha1->Curlen++] = (unsigned char)0;
		SHA1_Compress(sha1, sha1->Buffer);
		sha1->Curlen = 0;
	}

//Pad upto 56 bytes of zeroes.
	while (sha1->Curlen < 56)
		sha1->Buffer[sha1->Curlen++] = (unsigned char)0;

//Store length.
	STORE64H(sha1->Length, sha1->Buffer + 56);
	SHA1_Compress(sha1, sha1->Buffer);

//Copy output.
	for (size_t Index = 0;Index < 5U;++Index)
		STORE32H(sha1->State[Index], out + (4U * Index));

	return;
}

//SHA-1 hash function
bool __fastcall SHA1_Hash(
	FILE *Input)
{
//Parameters check
	if (HashFamilyID != HASH_ID_SHA1 || Input == nullptr)
	{
		fwprintf_s(stderr, L"Parameters error.\n");
		return false;
	}

//Initialization
	std::shared_ptr<char> Buffer(new char[FILE_BUFFER_SIZE]()), StringBuffer(new char[FILE_BUFFER_SIZE]());
	auto HashInstance = std::make_shared<SHA1_State>();
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	memset(StringBuffer.get(), 0, FILE_BUFFER_SIZE);
	memset(HashInstance.get(), 0, sizeof(SHA1_State));
	size_t ReadLength = 0;

//SHA-1 initialization
	SHA1_Init(HashInstance.get());

//Hash process
	while (!feof(Input))
	{
		memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
		ReadLength = fread_s(Buffer.get(), FILE_BUFFER_SIZE, sizeof(char), FILE_BUFFER_SIZE, Input);
		if (ReadLength == 0 && errno == EINVAL)
		{
			fwprintf_s(stderr, L"Hash process error.\n");
			return false;
		}
		else {
			SHA1_Process(HashInstance.get(), (uint8_t *)Buffer.get(), (unsigned long)ReadLength);
		}
	}

//Binary to hex
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	SHA1_Done(HashInstance.get(), (uint8_t *)Buffer.get());
	if (sodium_bin2hex(StringBuffer.get(), FILE_BUFFER_SIZE, (const unsigned char *)Buffer.get(), SHA1_SIZE_DIGEST) == nullptr)
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
