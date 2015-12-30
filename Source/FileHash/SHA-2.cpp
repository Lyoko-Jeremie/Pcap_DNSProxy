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


#include "SHA-2.h"

#if defined(ENABLE_LIBSODIUM)
//SHA-2(256) long reverse process
//When run on a little-endian CPU we need to perform byte reversal on an array of longwords.
static void __fastcall SHA2_256_LongReverse(
	_Inout_ SHA_INT32 *buffer, 
	_In_ int byteCount, 
	_In_ int Endianness)
{
	SHA_INT32 value = 0;
	if (Endianness == PCT_BIG_ENDIAN)
		return;

	byteCount /= sizeof(*buffer);
	while (byteCount--)
	{
		value = *buffer;
		value = ((value & 0xFF00FF00L) >> 8U) |   \
			((value & 0x00FF00FFL) << 8U);
		*buffer++ = (value << 16U) | (value >> 16U);
	}

	return;
}

/*
//SHA-2(256) copy process
static void __fastcall SHA2_256_Copy(
	_In_ SHA2_256_Object *src, 
	_Out_ SHA2_256_Object *dest)
{
	dest->Endianness = src->Endianness;
	dest->Local = src->Local;
	dest->DigestSize = src->DigestSize;
	dest->CountLow = src->CountLow;
	dest->CountHigh = src->CountHigh;
	memcpy(dest->Digest, src->Digest, sizeof(src->Digest));
	memcpy(dest->Data, src->Data, sizeof(src->Data));

	return;
}
*/

//Various logical functions
#define ROR(x, y)                                                            \
	(((((unsigned long)(x) & 0xFFFFFFFFUL) >> (unsigned long)((y) & 31)) |   \
	((unsigned long)(x) << (unsigned long)(32 - ((y) & 31)))) & 0xFFFFFFFFUL)
#define Ch(x, y, z)       (z ^ (x & (y ^ z)))
#define Maj(x, y, z)      (((x | y) & z) | (x & y))
#define S(x, n)           ROR((x), (n))
#define R(x, n)           (((x) & 0xFFFFFFFFUL) >> (n))
#define Sigma0(x)         (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)         (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)         (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)         (S(x, 17) ^ S(x, 19) ^ R(x, 10))

//SHA-2(256) transform process
static void __fastcall SHA2_256_Transform(
	_Inout_ SHA2_256_Object *sha_info)
{
	size_t Index = 0;
	SHA_INT32 S[8U] = {0}, W[64U] = {0}, t0 = 0, t1 = 0;

	memcpy(W, sha_info->Data, sizeof(sha_info->Data));
	SHA2_256_LongReverse(W, (int)sizeof(sha_info->Data), sha_info->Endianness);
	for (Index = 16U;Index < 64U;++Index)
		W[Index] = Gamma1(W[Index - 2U]) + W[Index - 7U] + Gamma0(W[Index - 15U]) + W[Index - 16U];
	for (Index = 0;Index < 8U;++Index)
		S[Index] = sha_info->Digest[Index];

//Compress.
#define RND(a, b, c, d, e, f, g, h, i, ki)          \
	t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];   \
	t1 = Sigma0(a) + Maj(a, b, c);                  \
	d += t0;                                        \
	h  = t0 + t1;

	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 0, 0x428A2F98);
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 1, 0x71374491);
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 2, 0xB5C0FBCF);
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 3, 0xE9B5DBA5);
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 4, 0x3956C25B);
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 5, 0x59F111F1);
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 6, 0x923F82A4);
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 7, 0xAB1C5ED5);
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 8, 0xD807AA98);
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 9, 0x12835B01);
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 10, 0x243185BE);
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 11, 0x550C7DC3);
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 12, 0x72BE5D74);
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 13, 0x80DEB1FE);
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 14, 0x9BDC06A7);
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 15, 0xC19BF174);
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 16, 0xE49B69C1);
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 17, 0xEFBE4786);
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 18, 0x0FC19DC6);
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 19, 0x240CA1CC);
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 20, 0x2DE92C6F);
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 21, 0x4A7484AA);
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 22, 0x5CB0A9DC);
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 23, 0x76F988DA);
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 24, 0x983E5152);
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 25, 0xA831C66D);
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 26, 0xB00327C8);
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 27, 0xBF597FC7);
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 28, 0xC6E00BF3);
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 29, 0xD5A79147);
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 30, 0x06CA6351);
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 31, 0x14292967);
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 32, 0x27B70A85);
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 33, 0x2E1B2138);
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 34, 0x4D2C6DFC);
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 35, 0x53380D13);
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 36, 0x650A7354);
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 37, 0x766A0ABB);
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 38, 0x81C2C92E);
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 39, 0x92722C85);
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 40, 0xA2BFE8A1);
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 41, 0xA81A664B);
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 42, 0xC24B8B70);
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 43, 0xC76C51A3);
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 44, 0xD192E819);
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 45, 0xD6990624);
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 46, 0xF40E3585);
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 47, 0x106AA070);
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 48, 0x19A4C116);
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 49, 0x1E376C08);
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 50, 0x2748774C);
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 51, 0x34B0BCB5);
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 52, 0x391C0CB3);
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 53, 0x4ED8AA4A);
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 54, 0x5B9CCA4F);
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 55, 0x682E6FF3);
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 56, 0x748F82EE);
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 57, 0x78A5636F);
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 58, 0x84C87814);
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 59, 0x8CC70208);
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 60, 0x90BEFFFA);
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 61, 0xA4506CEB);
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 62, 0xBEF9A3F7);
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 63, 0xC67178F2);

#undef RND

//Feedback.
	for (Index = 0;Index < 8U;++Index)
		sha_info->Digest[Index] = sha_info->Digest[Index] + S[Index];

	return;
}

//Undefine Various logical functions
#undef ROR
#undef Ch
#undef Maj
#undef S
#undef R
#undef Sigma0
#undef Sigma1
#undef Gamma0
#undef Gamma1

//Initialize the SHA digest
static void __fastcall SHA2_256_Init(
	_Inout_ SHA2_256_Object *sha_info)
{
	TestEndianness(sha_info->Endianness)
	sha_info->Digest[0] = 0x6A09E667L;
	sha_info->Digest[1U] = 0xBB67AE85L;
	sha_info->Digest[2U] = 0x3C6EF372L;
	sha_info->Digest[3U] = 0xA54FF53AL;
	sha_info->Digest[4U] = 0x510E527FL;
	sha_info->Digest[5U] = 0x9B05688CL;
	sha_info->Digest[6U] = 0x1F83D9ABL;
	sha_info->Digest[7U] = 0x5BE0CD19L;
	sha_info->CountLow = 0L;
	sha_info->CountHigh = 0L;
	sha_info->Local = 0;
	sha_info->DigestSize = 32;

	return;
}

static void __fastcall SHA2_224_Init(
	_Inout_ SHA2_256_Object *sha_info)
{
	TestEndianness(sha_info->Endianness)
	sha_info->Digest[0] = 0xC1059ED8L;
	sha_info->Digest[1U] = 0x367CD507L;
	sha_info->Digest[2U] = 0x3070DD17L;
	sha_info->Digest[3U] = 0xF70E5939L;
	sha_info->Digest[4U] = 0xFFC00B31L;
	sha_info->Digest[5U] = 0x68581511L;
	sha_info->Digest[6U] = 0x64F98FA7L;
	sha_info->Digest[7U] = 0xBEFA4FA4L;
	sha_info->CountLow = 0L;
	sha_info->CountHigh = 0L;
	sha_info->Local = 0;
	sha_info->DigestSize = 28;

	return;
}

//Update the SHA digest
static void __fastcall SHA2_256_Update(
	_Inout_ SHA2_256_Object *sha_info, 
	_Inout_ SHA2_256_BYTE *buffer, 
	_In_ int count)
{
	int i = 0;
	SHA_INT32 clo = 0;

	clo = sha_info->CountLow + ((SHA_INT32)count << 3U);
	if (clo < sha_info->CountLow)
		++sha_info->CountHigh;
	sha_info->CountLow = clo;
	sha_info->CountHigh += (SHA_INT32)count >> 29U;
	if (sha_info->Local)
	{
		i = SHA2_256_SIZE_BLOCK - sha_info->Local;
		if (i > count)
			i = count;
		memcpy(((SHA2_256_BYTE *)sha_info->Data) + sha_info->Local, buffer, i);
		count -= i;
		buffer += i;
		sha_info->Local += i;
		if (sha_info->Local == SHA2_256_SIZE_BLOCK)
			SHA2_256_Transform(sha_info);
		else 
			return;
	}
	while (count >= SHA2_256_SIZE_BLOCK)
	{
		memcpy(sha_info->Data, buffer, SHA2_256_SIZE_BLOCK);
		buffer += SHA2_256_SIZE_BLOCK;
		count -= SHA2_256_SIZE_BLOCK;
		SHA2_256_Transform(sha_info);
	}
	memcpy(sha_info->Data, buffer, count);
	sha_info->Local = count;

	return;
}

//Finish computing the SHA digest
static void __fastcall SHA2_256_Final(
	_Out_ unsigned char digest[SHA2_256_SIZE_DIGEST], 
	_Inout_ SHA2_256_Object *sha_info)
{
	int count = 0;
	SHA_INT32 lo_bit_count = 0, hi_bit_count = 0;

	lo_bit_count = sha_info->CountLow;
	hi_bit_count = sha_info->CountHigh;
	count = (int)((lo_bit_count >> 3U) & 0x3F);
	((SHA2_256_BYTE *)sha_info->Data)[count++] = 0x80;
	if (count > SHA2_256_SIZE_BLOCK - 8)
	{
		memset(((SHA2_256_BYTE *)sha_info->Data) + count, 0, SHA2_256_SIZE_BLOCK - count);
		SHA2_256_Transform(sha_info);
		memset((SHA2_256_BYTE *)sha_info->Data, 0, SHA2_256_SIZE_BLOCK - 8);
	}
	else {
		memset(((SHA2_256_BYTE *)sha_info->Data) + count, 0, SHA2_256_SIZE_BLOCK - 8 - count);
	}

//GJS: note that we add the hi/lo in big-endian. SHA2_256_Transform will swap these values into host-order.
	sha_info->Data[56U] = (hi_bit_count >> 24U) & 0xFF;
	sha_info->Data[57U] = (hi_bit_count >> 16U) & 0xFF;
	sha_info->Data[58U] = (hi_bit_count >> 8U) & 0xFF;
	sha_info->Data[59U] = (hi_bit_count) & 0xFF;
	sha_info->Data[60U] = (lo_bit_count >> 24U) & 0xFF;
	sha_info->Data[61U] = (lo_bit_count >> 16U) & 0xFF;
	sha_info->Data[62U] = (lo_bit_count >> 8U) & 0xFF;
	sha_info->Data[63U] = (lo_bit_count) & 0xFF;
	SHA2_256_Transform(sha_info);
	digest[0] = (uint8_t)((sha_info->Digest[0] >> 24U) & 0xFF);
	digest[1U] = (uint8_t)((sha_info->Digest[0] >> 16U) & 0xFF);
	digest[2U] = (uint8_t)((sha_info->Digest[0] >> 8U) & 0xFF);
	digest[3U] = (uint8_t)((sha_info->Digest[0]) & 0xFF);
	digest[4U] = (uint8_t)((sha_info->Digest[1U] >> 24U) & 0xFF);
	digest[5U] = (uint8_t)((sha_info->Digest[1U] >> 16U) & 0xFF);
	digest[6U] = (uint8_t)((sha_info->Digest[1U] >> 8U) & 0xFF);
	digest[7U] = (uint8_t)((sha_info->Digest[1U]) & 0xFF);
	digest[8U] = (uint8_t)((sha_info->Digest[2U] >> 24U) & 0xFF);
	digest[9U] = (uint8_t)((sha_info->Digest[2U] >> 16U) & 0xFF);
	digest[10U] = (uint8_t)((sha_info->Digest[2U] >> 8U) & 0xFF);
	digest[11U] = (uint8_t)((sha_info->Digest[2U]) & 0xFF);
	digest[12U] = (uint8_t)((sha_info->Digest[3U] >> 24U) & 0xFF);
	digest[13U] = (uint8_t)((sha_info->Digest[3U] >> 16U) & 0xFF);
	digest[14U] = (uint8_t)((sha_info->Digest[3U] >> 8U) & 0xFF);
	digest[15U] = (uint8_t)((sha_info->Digest[3U]) & 0xFF);
	digest[16U] = (uint8_t)((sha_info->Digest[4U] >> 24U) & 0xFF);
	digest[17U] = (uint8_t)((sha_info->Digest[4U] >> 16U) & 0xFF);
	digest[18U] = (uint8_t)((sha_info->Digest[4U] >> 8U) & 0xFF);
	digest[19U] = (uint8_t)((sha_info->Digest[4U]) & 0xFF);
	digest[20U] = (uint8_t)((sha_info->Digest[5U] >> 24U) & 0xFF);
	digest[21U] = (uint8_t)((sha_info->Digest[5U] >> 16U) & 0xFF);
	digest[22U] = (uint8_t)((sha_info->Digest[5U] >> 8U) & 0xFF);
	digest[23U] = (uint8_t)((sha_info->Digest[5U]) & 0xFF);
	digest[24U] = (uint8_t)((sha_info->Digest[6U] >> 24U) & 0xFF);
	digest[25U] = (uint8_t)((sha_info->Digest[6U] >> 16U) & 0xFF);
	digest[26U] = (uint8_t)((sha_info->Digest[6U] >> 8U) & 0xFF);
	digest[27U] = (uint8_t)((sha_info->Digest[6U]) & 0xFF);
	digest[28U] = (uint8_t)((sha_info->Digest[7U] >> 24U) & 0xFF);
	digest[29U] = (uint8_t)((sha_info->Digest[7U] >> 16U) & 0xFF);
	digest[30U] = (uint8_t)((sha_info->Digest[7U] >> 8U) & 0xFF);
	digest[31U] = (uint8_t)((sha_info->Digest[7U]) & 0xFF);

	return;
}

//Read commands(SHA-2)
bool __fastcall ReadCommand_SHA2(
#if defined(PLATFORM_WIN)
	_In_ std::wstring &Command)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	_In_ std::string &Command)
#endif
{
//Hash function check
	if (Command == COMMAND_SHA2_224 || Command == COMMAND_SHA2_224_UL) //SHA-2 224 bits
	{
		SHA2_HashFunctionID = HASH_ID_SHA2_224;
	}
	else if (Command == COMMAND_SHA2 || Command == COMMAND_SHA2_256 || Command == COMMAND_SHA2_256_UL) //SHA-2 256 bits
	{
		SHA2_HashFunctionID = HASH_ID_SHA2_256;
	}
	else if (Command == COMMAND_SHA2_384 || Command == COMMAND_SHA2_384_UL) //SHA-2 384 bits
	{
		SHA2_HashFunctionID = HASH_ID_SHA2_384;
	}
	else if (Command == COMMAND_SHA2_512 || Command == COMMAND_SHA2_512_UL) //SHA-2 512 bits
	{
		SHA2_HashFunctionID = HASH_ID_SHA2_512;
	}
	else if (Command == COMMAND_SHA2_512_224 || Command == COMMAND_SHA2_512_224_UL) //SHA-2 512/224 bits
	{
		SHA2_HashFunctionID = HASH_ID_SHA2_512_224;
	}
	else if (Command == COMMAND_SHA2_512_256 || Command == COMMAND_SHA2_512_256_UL) //SHA-2 512/256 bits
	{
		SHA2_HashFunctionID = HASH_ID_SHA2_512_256;
	}
	else { //Commands error
		fwprintf_s(stderr, L"Commands error.\n");
		return false;
	}

	return true;
}

//SHA-2 hash function
bool __fastcall SHA2_Hash(
	_In_ FILE *Input)
{
//Parameters check
	if (HashFamilyID != HASH_ID_SHA2 || Input == nullptr)
	{
		fwprintf_s(stderr, L"SHA-2 parameters error.\n");
		return false;
	}

//Initialization
	std::shared_ptr<char> Buffer(new char[FILE_BUFFER_SIZE]()), StringBuffer(new char[FILE_BUFFER_SIZE]());
	auto HashInstance = std::make_shared<SHA2_256_Object>();
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	memset(StringBuffer.get(), 0, FILE_BUFFER_SIZE);
	memset(HashInstance.get(), 0, sizeof(SHA2_256_Object));
	size_t ReadLength = 0, DigestSize = 0;

//SHA-2 initialization
	if (SHA2_HashFunctionID == HASH_ID_SHA2_224) //SHA-2 224 bits
	{
		SHA2_224_Init(HashInstance.get());
		DigestSize = SHA2_224_SIZE_DIGEST;
	}
	else if (SHA2_HashFunctionID == HASH_ID_SHA2_256) //SHA-2 256 bits
	{
		SHA2_256_Init(HashInstance.get());
		DigestSize = SHA2_256_SIZE_DIGEST;
	}
	else {
		return false;
	}

//Hash process
	while (!feof(Input))
	{
		ReadLength = fread_s(Buffer.get(), FILE_BUFFER_SIZE, sizeof(char), FILE_BUFFER_SIZE, Input);
		if (ReadLength == 0 && errno == EINVAL)
		{
			fwprintf_s(stderr, L"SHA-2 hash process error.\n");
			return false;
		}
		else {
			SHA2_256_Update(HashInstance.get(), (unsigned char *)Buffer.get(), (unsigned long)ReadLength);
		}
	}

//Binary to hex
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	SHA2_256_Final((unsigned char *)Buffer.get(), HashInstance.get());
	if (sodium_bin2hex(StringBuffer.get(), FILE_BUFFER_SIZE, (const unsigned char *)Buffer.get(), DigestSize) == nullptr)
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
