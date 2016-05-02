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


#include "SHA-2.h"

#if defined(ENABLE_LIBSODIUM)
//When run on a little-endian CPU we need to perform byte reversal on an array of longwords.
//SHA-2(256) long reverse process
static void __fastcall SHA2_256_LongReverse(
	SHA_INT32 *buffer, 
	int byteCount, 
	int Endianness)
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
	SHA2_256_Object *src, 
	SHA2_256_Object *dest)
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

//SHA-2(256) various logical functions
#define ROR(x, y)                                                  \
	(((((uint64_t)(x) & 0xFFFFFFFFUL) >> (uint64_t)((y) & 31)) |   \
	((uint64_t)(x) << (uint64_t)(32 - ((y) & 31)))) & 0xFFFFFFFFUL)
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
	SHA2_256_Object *sha_info)
{
	size_t Index = 0;
	SHA_INT32 S[8U], W[64U], t0 = 0, t1 = 0;
	memset(S, 0, sizeof(SHA_INT32) * 8U);
	memset(W, 0, sizeof(SHA_INT32) * 64U);

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

//SHA-2(256) undefine Various logical functions
#undef ROR
#undef Ch
#undef Maj
#undef S
#undef R
#undef Sigma0
#undef Sigma1
#undef Gamma0
#undef Gamma1

//Initialize the SHA-2(256) digest
static void __fastcall SHA2_256_Init(
	SHA2_256_Object *sha_info)
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
	sha_info->DigestSize = SHA2_256_SIZE_DIGEST;

	return;
}

//Initialize the SHA-2(224) digest
static void __fastcall SHA2_224_Init(
	SHA2_256_Object *sha_info)
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
	sha_info->DigestSize = SHA2_224_SIZE_DIGEST;

	return;
}

//Update the SHA-2(256) digest
static void __fastcall SHA2_256_Update(
	SHA2_256_Object *sha_info, 
	SHA2_256_BYTE *buffer, 
	int count)
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
	while (count >= (int)SHA2_256_SIZE_BLOCK)
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

//Finish computing the SHA-2(256) digest
static void __fastcall SHA2_256_Final(
	uint8_t digest[SHA2_256_SIZE_DIGEST], 
	SHA2_256_Object *sha_info)
{
	int count = 0;
	SHA_INT32 lo_bit_count = 0, hi_bit_count = 0;

	lo_bit_count = sha_info->CountLow;
	hi_bit_count = sha_info->CountHigh;
	count = (int)((lo_bit_count >> 3U) & 0x3F);
	((SHA2_256_BYTE *)sha_info->Data)[count++] = 0x80;
	if (count > (int)SHA2_256_SIZE_BLOCK - 8)
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

//SHA-2(512) long reverse process
static void __fastcall SHA2_512_LongReverse(
	SHA_INT64 *buffer, 
	int byteCount, 
	int Endianness)
{
	SHA_INT64 value = 0;
	if (Endianness == PCT_BIG_ENDIAN)
		return;

	byteCount /= sizeof(*buffer);
	while (byteCount--)
	{
		value = *buffer;
		((uint8_t *)buffer)[0] = (uint8_t)(value >> 56U) & 0xFF;
		((uint8_t *)buffer)[1U] = (uint8_t)(value >> 48U) & 0xFF;
		((uint8_t *)buffer)[2U] = (uint8_t)(value >> 40U) & 0xFF;
		((uint8_t *)buffer)[3U] = (uint8_t)(value >> 32U) & 0xFF;
		((uint8_t *)buffer)[4U] = (uint8_t)(value >> 24U) & 0xFF;
		((uint8_t *)buffer)[5U] = (uint8_t)(value >> 16U) & 0xFF;
		((uint8_t *)buffer)[6U] = (uint8_t)(value >> 8U) & 0xFF;
		((uint8_t *)buffer)[7U] = (uint8_t)(value)& 0xFF;

		buffer++;
	}

	return;
}

/*
//SHA-2(512) copy process
static void __fastcall SHA2_512_Copy(
	SHA2_512_Object *src, 
	SHA2_512_Object *dest)
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

//SHA-2(512) various logical functions
#define ROR64(x, y) \
	(((((x) & Py_ULL(0xFFFFFFFFFFFFFFFF))>>((uint64_t)(y) & 63)) |   \
	((x) << ((uint64_t)(64 - ((y) & 63))))) & Py_ULL(0xFFFFFFFFFFFFFFFF))
#define Ch(x, y, z)     (z ^ (x & (y ^ z)))
#define Maj(x, y, z)    (((x | y) & z) | (x & y))
#define S(x, n)         ROR64((x), (n))
#define R(x, n)         (((x) & Py_ULL(0xFFFFFFFFFFFFFFFF)) >> ((uint64_t)n))
#define Sigma0(x)       (S(x, 28) ^ S(x, 34) ^ S(x, 39))
#define Sigma1(x)       (S(x, 14) ^ S(x, 18) ^ S(x, 41))
#define Gamma0(x)       (S(x, 1) ^ S(x, 8) ^ R(x, 7))
#define Gamma1(x)       (S(x, 19) ^ S(x, 61) ^ R(x, 6))

//SHA-2(512) transform process
static void __fastcall SHA2_512_Transform(
	SHA2_512_Object *sha_info)
{
	size_t Index = 0;
	SHA_INT64 S[8U], W[80U], t0 = 0, t1 = 0;
	memset(S, 0, sizeof(SHA_INT64) * 8U);
	memset(W, 0, sizeof(SHA_INT64) * 80U);

	memcpy(W, sha_info->Data, sizeof(sha_info->Data));
	SHA2_512_LongReverse(W, (int)sizeof(sha_info->Data), sha_info->Endianness);
	for (Index = 16U;Index < 80U;++Index)
		W[Index] = Gamma1(W[Index - 2U]) + W[Index - 7U] + Gamma0(W[Index - 15U]) + W[Index - 16U];
	for (Index = 0;Index < 8U;++Index)
		S[Index] = sha_info->Digest[Index];

//Compress.
#define RND(a, b, c, d, e, f, g, h, i, ki)          \
	t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];   \
	t1 = Sigma0(a) + Maj(a, b, c);                  \
	d += t0;                                        \
	h  = t0 + t1;

	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 0, Py_ULL(0x428A2F98D728AE22));
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 1, Py_ULL(0x7137449123EF65CD));
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 2, Py_ULL(0xB5C0FBCFEC4D3B2F));
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 3, Py_ULL(0xE9B5DBA58189DBBC));
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 4, Py_ULL(0x3956C25BF348B538));
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 5, Py_ULL(0x59F111F1B605D019));
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 6, Py_ULL(0x923F82A4AF194F9B));
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 7, Py_ULL(0xAB1C5ED5DA6D8118));
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 8, Py_ULL(0xD807AA98A3030242));
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 9, Py_ULL(0x12835B0145706FBE));
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 10, Py_ULL(0x243185BE4EE4B28C));
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 11, Py_ULL(0x550C7DC3D5FFB4E2));
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 12, Py_ULL(0x72BE5D74F27B896F));
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 13, Py_ULL(0x80DEB1FE3B1696B1));
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 14, Py_ULL(0x9BDC06A725C71235));
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 15, Py_ULL(0xC19BF174CF692694));
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 16, Py_ULL(0xE49B69C19EF14AD2));
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 17, Py_ULL(0xEFBE4786384F25E3));
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 18, Py_ULL(0x0FC19DC68B8CD5B5));
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 19, Py_ULL(0x240CA1CC77AC9C65));
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 20, Py_ULL(0x2DE92C6F592B0275));
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 21, Py_ULL(0x4A7484AA6EA6E483));
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 22, Py_ULL(0x5CB0A9DCBD41FBD4));
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 23, Py_ULL(0x76F988DA831153B5));
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 24, Py_ULL(0x983E5152EE66DFAB));
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 25, Py_ULL(0xA831C66D2DB43210));
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 26, Py_ULL(0xB00327C898FB213F));
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 27, Py_ULL(0xBF597FC7BEEF0EE4));
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 28, Py_ULL(0xC6E00BF33DA88FC2));
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 29, Py_ULL(0xD5A79147930AA725));
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 30, Py_ULL(0x06CA6351E003826F));
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 31, Py_ULL(0x142929670A0E6E70));
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 32, Py_ULL(0x27B70A8546D22FFC));
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 33, Py_ULL(0x2E1B21385C26C926));
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 34, Py_ULL(0x4D2C6DFC5AC42AED));
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 35, Py_ULL(0x53380D139D95B3DF));
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 36, Py_ULL(0x650A73548BAF63DE));
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 37, Py_ULL(0x766A0ABB3C77B2A8));
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 38, Py_ULL(0x81C2C92E47EDAEE6));
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 39, Py_ULL(0x92722C851482353B));
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 40, Py_ULL(0xA2BFE8A14CF10364));
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 41, Py_ULL(0xA81A664BBC423001));
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 42, Py_ULL(0xC24B8B70D0F89791));
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 43, Py_ULL(0xC76C51A30654BE30));
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 44, Py_ULL(0xD192E819D6EF5218));
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 45, Py_ULL(0xD69906245565A910));
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 46, Py_ULL(0xF40E35855771202A));
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 47, Py_ULL(0x106AA07032BBD1B8));
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 48, Py_ULL(0x19A4C116B8D2D0C8));
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 49, Py_ULL(0x1E376C085141AB53));
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 50, Py_ULL(0x2748774CDF8EEB99));
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 51, Py_ULL(0x34B0BCB5E19B48A8));
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 52, Py_ULL(0x391C0CB3C5C95A63));
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 53, Py_ULL(0x4ED8AA4AE3418ACB));
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 54, Py_ULL(0x5B9CCA4F7763E373));
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 55, Py_ULL(0x682E6FF3D6B2B8A3));
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 56, Py_ULL(0x748F82EE5DEFB2FC));
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 57, Py_ULL(0x78A5636F43172F60));
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 58, Py_ULL(0x84C87814A1F0AB72));
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 59, Py_ULL(0x8CC702081A6439EC));
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 60, Py_ULL(0x90BEFFFA23631E28));
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 61, Py_ULL(0xA4506CEBDE82BDE9));
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 62, Py_ULL(0xBEF9A3F7B2C67915));
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 63, Py_ULL(0xC67178F2E372532B));
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 64, Py_ULL(0xCA273ECEEA26619C));
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 65, Py_ULL(0xD186B8C721C0C207));
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 66, Py_ULL(0xEADA7DD6CDE0EB1E));
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 67, Py_ULL(0xF57D4F7FEE6ED178));
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 68, Py_ULL(0x06F067AA72176FBA));
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 69, Py_ULL(0x0A637DC5A2C898A6));
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 70, Py_ULL(0x113F9804BEF90DAE));
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 71, Py_ULL(0x1B710B35131C471B));
	RND(S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], 72, Py_ULL(0x28DB77F523047D84));
	RND(S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], 73, Py_ULL(0x32CAAB7B40C72493));
	RND(S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], S[5U], 74, Py_ULL(0x3C9EBE0A15C9BEBC));
	RND(S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], S[4U], 75, Py_ULL(0x431D67C49C100D4C));
	RND(S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], S[3U], 76, Py_ULL(0x4CC5D4BECB3E42B6));
	RND(S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], S[2U], 77, Py_ULL(0x597F299CFC657E2A));
	RND(S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], S[1U], 78, Py_ULL(0x5FCB6FAB3AD6FAEC));
	RND(S[1U], S[2U], S[3U], S[4U], S[5U], S[6U], S[7U], S[0], 79, Py_ULL(0x6C44198C4A475817));

#undef RND

//Feedback.
	for (Index = 0;Index < 8U;++Index)
		sha_info->Digest[Index] = sha_info->Digest[Index] + S[Index];

	return;
}

//SHA-2(512) undefine Various logical functions
#undef ROR64
#undef Ch
#undef Maj
#undef S
#undef R
#undef Sigma0
#undef Sigma1
#undef Gamma0
#undef Gamma1

//Initialize the SHA-2(512) digest
static void __fastcall SHA2_512_Init(
	SHA2_512_Object *sha_info)
{
	TestEndianness(sha_info->Endianness)
		sha_info->Digest[0] = Py_ULL(0x6A09E667F3BCC908);
	sha_info->Digest[1U] = Py_ULL(0xBB67AE8584CAA73B);
	sha_info->Digest[2U] = Py_ULL(0x3C6EF372FE94F82B);
	sha_info->Digest[3U] = Py_ULL(0xA54FF53A5F1D36F1);
	sha_info->Digest[4U] = Py_ULL(0x510E527FADE682D1);
	sha_info->Digest[5U] = Py_ULL(0x9B05688C2B3E6C1F);
	sha_info->Digest[6U] = Py_ULL(0x1F83D9ABFB41BD6B);
	sha_info->Digest[7U] = Py_ULL(0x5BE0CD19137E2179);
	sha_info->CountLow = 0L;
	sha_info->CountHigh = 0L;
	sha_info->Local = 0;
	sha_info->DigestSize = SHA2_512_SIZE_DIGEST;

	return;
}

//Initialize the SHA-2(384) digest
static void __fastcall SHA2_384_Init(
	SHA2_512_Object *sha_info)
{
	TestEndianness(sha_info->Endianness)
		sha_info->Digest[0] = Py_ULL(0xCBBB9D5DC1059ED8);
	sha_info->Digest[1U] = Py_ULL(0x629A292A367CD507);
	sha_info->Digest[2U] = Py_ULL(0x9159015A3070DD17);
	sha_info->Digest[3U] = Py_ULL(0x152FECD8F70E5939);
	sha_info->Digest[4U] = Py_ULL(0x67332667FFC00B31);
	sha_info->Digest[5U] = Py_ULL(0x8EB44A8768581511);
	sha_info->Digest[6U] = Py_ULL(0xDB0C2E0D64F98FA7);
	sha_info->Digest[7U] = Py_ULL(0x47B5481DBEFA4FA4);
	sha_info->CountLow = 0L;
	sha_info->CountHigh = 0L;
	sha_info->Local = 0;
	sha_info->DigestSize = SHA2_384_SIZE_DIGEST;

	return;
}

//Initialize the SHA-2(512/256) digest
static void __fastcall SHA2_512_256_Init(
	SHA2_512_Object *sha_info)
{
	TestEndianness(sha_info->Endianness)
		sha_info->Digest[0] = Py_ULL(0x22312194FC2BF72C);
	sha_info->Digest[1U] = Py_ULL(0x9F555FA3C84C64C2);
	sha_info->Digest[2U] = Py_ULL(0x2393B86B6F53B151);
	sha_info->Digest[3U] = Py_ULL(0x963877195940EABD);
	sha_info->Digest[4U] = Py_ULL(0x96283EE2A88EFFE3);
	sha_info->Digest[5U] = Py_ULL(0xBE5E1E2553863992);
	sha_info->Digest[6U] = Py_ULL(0x2B0199FC2C85B8AA);
	sha_info->Digest[7U] = Py_ULL(0x0EB72DDC81C52CA2);
	sha_info->CountLow = 0L;
	sha_info->CountHigh = 0L;
	sha_info->Local = 0;
	sha_info->DigestSize = SHA2_512_256_SIZE_DIGEST;

	return;
}

//Initialize the SHA-2(512/224) digest
static void __fastcall SHA2_512_224_Init(
	SHA2_512_Object *sha_info)
{
	TestEndianness(sha_info->Endianness)
		sha_info->Digest[0] = Py_ULL(0x8C3D37C819544DA2);
	sha_info->Digest[1U] = Py_ULL(0x73E1996689DCD4D6);
	sha_info->Digest[2U] = Py_ULL(0x1DFAB7AE32FF9C82);
	sha_info->Digest[3U] = Py_ULL(0x679DD514582F9FCF);
	sha_info->Digest[4U] = Py_ULL(0x0F6D2B697BD44DA8);
	sha_info->Digest[5U] = Py_ULL(0x77E36F7304C48942);
	sha_info->Digest[6U] = Py_ULL(0x3F9D85A86A1D36C8);
	sha_info->Digest[7U] = Py_ULL(0x1112E6AD91D692A1);
	sha_info->CountLow = 0L;
	sha_info->CountHigh = 0L;
	sha_info->Local = 0;
	sha_info->DigestSize = SHA2_512_224_SIZE_DIGEST;

	return;
}

//Update the SHA-2(512) digest
static void __fastcall SHA2_512_Update(
	SHA2_512_Object *sha_info, 
	SHA2_512_BYTE *buffer, 
	int count)
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
		i = SHA2_512_SIZE_BLOCK - sha_info->Local;
		if (i > count)
			i = count;
		memcpy(((SHA2_512_BYTE *)sha_info->Data) + sha_info->Local, buffer, i);
		count -= i;
		buffer += i;
		sha_info->Local += i;
		if (sha_info->Local == SHA2_512_SIZE_BLOCK)
			SHA2_512_Transform(sha_info);
		else 
			return;
	}
	while (count >= (int)SHA2_512_SIZE_BLOCK)
	{
		memcpy(sha_info->Data, buffer, SHA2_512_SIZE_BLOCK);
		buffer += SHA2_512_SIZE_BLOCK;
		count -= SHA2_512_SIZE_BLOCK;
		SHA2_512_Transform(sha_info);
	}
	memcpy(sha_info->Data, buffer, count);
	sha_info->Local = count;

	return;
}

//Finish computing the SHA-2(512) digest
static void __fastcall SHA2_512_Final(
	uint8_t digest[SHA2_512_SIZE_DIGEST], 
	SHA2_512_Object *sha_info)
{
	int count = 0;
	SHA_INT32 lo_bit_count = 0, hi_bit_count = 0;

	lo_bit_count = sha_info->CountLow;
	hi_bit_count = sha_info->CountHigh;
	count = (int)((lo_bit_count >> 3U) & 0x7F);
	((SHA2_512_BYTE *)sha_info->Data)[count++] = 0x80;
	if (count > (int)SHA2_512_SIZE_BLOCK - 16)
	{
		memset(((SHA2_512_BYTE *)sha_info->Data) + count, 0, SHA2_512_SIZE_BLOCK - count);
		SHA2_512_Transform(sha_info);
		memset((SHA2_512_BYTE *)sha_info->Data, 0, SHA2_512_SIZE_BLOCK - 16);
	}
	else {
		memset(((SHA2_512_BYTE *)sha_info->Data) + count, 0, SHA2_512_SIZE_BLOCK - 16 - count);
	}

//GJS: note that we add the hi/lo in big-endian. SHA2_512_Transform will swap these values into host-order.
	sha_info->Data[112U] = 0;
	sha_info->Data[113U] = 0;
	sha_info->Data[114U] = 0;
	sha_info->Data[115U] = 0;
	sha_info->Data[116U] = 0;
	sha_info->Data[117U] = 0;
	sha_info->Data[118U] = 0;
	sha_info->Data[119U] = 0;
	sha_info->Data[120U] = (hi_bit_count >> 24U) & 0xFF;
	sha_info->Data[121U] = (hi_bit_count >> 16U) & 0xFF;
	sha_info->Data[122U] = (hi_bit_count >> 8U) & 0xFF;
	sha_info->Data[123U] = (hi_bit_count >> 0) & 0xFF;
	sha_info->Data[124U] = (lo_bit_count >> 24U) & 0xFF;
	sha_info->Data[125U] = (lo_bit_count >> 16U) & 0xFF;
	sha_info->Data[126U] = (lo_bit_count >> 8U) & 0xFF;
	sha_info->Data[127U] = (lo_bit_count >> 0) & 0xFF;
	SHA2_512_Transform(sha_info);
	digest[0] = (uint8_t)((sha_info->Digest[0] >> 56U) & 0xFF);
	digest[1U] = (uint8_t)((sha_info->Digest[0] >> 48U) & 0xFF);
	digest[2U] = (uint8_t)((sha_info->Digest[0] >> 40U) & 0xFF);
	digest[3U] = (uint8_t)((sha_info->Digest[0] >> 32U) & 0xFF);
	digest[4U] = (uint8_t)((sha_info->Digest[0] >> 24U) & 0xFF);
	digest[5U] = (uint8_t)((sha_info->Digest[0] >> 16U) & 0xFF);
	digest[6U] = (uint8_t)((sha_info->Digest[0] >> 8U) & 0xFF);
	digest[7U] = (uint8_t)((sha_info->Digest[0]) & 0xFF);
	digest[8U] = (uint8_t)((sha_info->Digest[1U] >> 56U) & 0xFF);
	digest[9U] = (uint8_t)((sha_info->Digest[1U] >> 48U) & 0xFF);
	digest[10U] = (uint8_t)((sha_info->Digest[1U] >> 40U) & 0xFF);
	digest[11U] = (uint8_t)((sha_info->Digest[1U] >> 32U) & 0xFF);
	digest[12U] = (uint8_t)((sha_info->Digest[1U] >> 24U) & 0xFF);
	digest[13U] = (uint8_t)((sha_info->Digest[1U] >> 16U) & 0xFF);
	digest[14U] = (uint8_t)((sha_info->Digest[1U] >> 8U) & 0xFF);
	digest[15U] = (uint8_t)((sha_info->Digest[1U]) & 0xFF);
	digest[16U] = (uint8_t)((sha_info->Digest[2U] >> 56U) & 0xFF);
	digest[17U] = (uint8_t)((sha_info->Digest[2U] >> 48U) & 0xFF);
	digest[18U] = (uint8_t)((sha_info->Digest[2U] >> 40U) & 0xFF);
	digest[19U] = (uint8_t)((sha_info->Digest[2U] >> 32U) & 0xFF);
	digest[20U] = (uint8_t)((sha_info->Digest[2U] >> 24U) & 0xFF);
	digest[21U] = (uint8_t)((sha_info->Digest[2U] >> 16U) & 0xFF);
	digest[22U] = (uint8_t)((sha_info->Digest[2U] >> 8U) & 0xFF);
	digest[23U] = (uint8_t)((sha_info->Digest[2U]) & 0xFF);
	digest[24U] = (uint8_t)((sha_info->Digest[3U] >> 56U) & 0xFF);
	digest[25U] = (uint8_t)((sha_info->Digest[3U] >> 48U) & 0xFF);
	digest[26U] = (uint8_t)((sha_info->Digest[3U] >> 40U) & 0xFF);
	digest[27U] = (uint8_t)((sha_info->Digest[3U] >> 32U) & 0xFF);
	digest[28U] = (uint8_t)((sha_info->Digest[3U] >> 24U) & 0xFF);
	digest[29U] = (uint8_t)((sha_info->Digest[3U] >> 16U) & 0xFF);
	digest[30U] = (uint8_t)((sha_info->Digest[3U] >> 8U) & 0xFF);
	digest[31U] = (uint8_t)((sha_info->Digest[3U]) & 0xFF);
	digest[32U] = (uint8_t)((sha_info->Digest[4U] >> 56U) & 0xFF);
	digest[33U] = (uint8_t)((sha_info->Digest[4U] >> 48U) & 0xFF);
	digest[34U] = (uint8_t)((sha_info->Digest[4U] >> 40U) & 0xFF);
	digest[35U] = (uint8_t)((sha_info->Digest[4U] >> 32U) & 0xFF);
	digest[36U] = (uint8_t)((sha_info->Digest[4U] >> 24U) & 0xFF);
	digest[37U] = (uint8_t)((sha_info->Digest[4U] >> 16U) & 0xFF);
	digest[38U] = (uint8_t)((sha_info->Digest[4U] >> 8U) & 0xFF);
	digest[39U] = (uint8_t)((sha_info->Digest[4U]) & 0xFF);
	digest[40U] = (uint8_t)((sha_info->Digest[5U] >> 56U) & 0xFF);
	digest[41U] = (uint8_t)((sha_info->Digest[5U] >> 48U) & 0xFF);
	digest[42U] = (uint8_t)((sha_info->Digest[5U] >> 40U) & 0xFF);
	digest[43U] = (uint8_t)((sha_info->Digest[5U] >> 32U) & 0xFF);
	digest[44U] = (uint8_t)((sha_info->Digest[5U] >> 24U) & 0xFF);
	digest[45U] = (uint8_t)((sha_info->Digest[5U] >> 16U) & 0xFF);
	digest[46U] = (uint8_t)((sha_info->Digest[5U] >> 8U) & 0xFF);
	digest[47U] = (uint8_t)((sha_info->Digest[5U]) & 0xFF);
	digest[48U] = (uint8_t)((sha_info->Digest[6U] >> 56U) & 0xFF);
	digest[49U] = (uint8_t)((sha_info->Digest[6U] >> 48U) & 0xFF);
	digest[50U] = (uint8_t)((sha_info->Digest[6U] >> 40U) & 0xFF);
	digest[51U] = (uint8_t)((sha_info->Digest[6U] >> 32U) & 0xFF);
	digest[52U] = (uint8_t)((sha_info->Digest[6U] >> 24U) & 0xFF);
	digest[53U] = (uint8_t)((sha_info->Digest[6U] >> 16U) & 0xFF);
	digest[54U] = (uint8_t)((sha_info->Digest[6U] >> 8U) & 0xFF);
	digest[55U] = (uint8_t)((sha_info->Digest[6U]) & 0xFF);
	digest[56U] = (uint8_t)((sha_info->Digest[7U] >> 56U) & 0xFF);
	digest[57U] = (uint8_t)((sha_info->Digest[7U] >> 48U) & 0xFF);
	digest[58U] = (uint8_t)((sha_info->Digest[7U] >> 40U) & 0xFF);
	digest[59U] = (uint8_t)((sha_info->Digest[7U] >> 32U) & 0xFF);
	digest[60U] = (uint8_t)((sha_info->Digest[7U] >> 24U) & 0xFF);
	digest[61U] = (uint8_t)((sha_info->Digest[7U] >> 16U) & 0xFF);
	digest[62U] = (uint8_t)((sha_info->Digest[7U] >> 8U) & 0xFF);
	digest[63U] = (uint8_t)((sha_info->Digest[7U]) & 0xFF);

	return;
}

//Read commands(SHA-2)
bool __fastcall ReadCommand_SHA2(
#if defined(PLATFORM_WIN)
	std::wstring &Command)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string &Command)
#endif
{
//Hash function check
	if (Command == COMMAND_SHA2_224 || Command == COMMAND_SHA2_224_UL) //SHA-2 224 bits
	{
		SHA2_HashFunctionID = HASH_ID_SHA2_224;
	}
	else if (Command == HASH_COMMAND_SHA2 || Command == COMMAND_SHA2_256 || Command == COMMAND_SHA2_256_UL) //SHA-2 256 bits
	{
		SHA2_HashFunctionID = HASH_ID_SHA2_256;
	}
	else if (Command == HASH_COMMAND_SHA2_384 || Command == COMMAND_SHA2_384_UL) //SHA-2 384 bits
	{
		SHA2_HashFunctionID = HASH_ID_SHA2_384;
	}
	else if (Command == HASH_COMMAND_SHA2_512 || Command == COMMAND_SHA2_512_UL) //SHA-2 512 bits
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
	FILE *Input)
{
//Parameters check
	if (HashFamilyID != HASH_ID_SHA2 || Input == nullptr)
	{
		fwprintf_s(stderr, L"Parameters error.\n");
		return false;
	}

//Initialization
	std::shared_ptr<char> Buffer(new char[FILE_BUFFER_SIZE]()), StringBuffer(new char[FILE_BUFFER_SIZE]());
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	memset(StringBuffer.get(), 0, FILE_BUFFER_SIZE);
	SHA2_256_Object HashInstance256;
	SHA2_512_Object HashInstance512;
	memset(&HashInstance256, 0, sizeof(SHA2_256_Object));
	memset(&HashInstance512, 0, sizeof(SHA2_512_Object));
	size_t ReadLength = 0, DigestSize = 0;

//SHA-2 initialization
	if (SHA2_HashFunctionID == HASH_ID_SHA2_224) //SHA-2 224 bits
	{
		SHA2_224_Init(&HashInstance256);
		DigestSize = SHA2_224_SIZE_DIGEST;
	}
	else if (SHA2_HashFunctionID == HASH_ID_SHA2_256) //SHA-2 256 bits
	{
		SHA2_256_Init(&HashInstance256);
		DigestSize = SHA2_256_SIZE_DIGEST;
	}
	else if (SHA2_HashFunctionID == HASH_ID_SHA2_384) //SHA-2 384 bits
	{
		SHA2_384_Init(&HashInstance512);
		DigestSize = SHA2_384_SIZE_DIGEST;
	}
	else if (SHA2_HashFunctionID == HASH_ID_SHA2_512) //SHA-2 512 bits
	{
		SHA2_512_Init(&HashInstance512);
		DigestSize = SHA2_512_SIZE_DIGEST;
	}
	else if (SHA2_HashFunctionID == HASH_ID_SHA2_512_224) //SHA-2 512/224 bits
	{
		SHA2_512_224_Init(&HashInstance512);
		DigestSize = SHA2_512_224_SIZE_DIGEST;
	}
	else if (SHA2_HashFunctionID == HASH_ID_SHA2_512_256) //SHA-2 512/256 bits
	{
		SHA2_512_256_Init(&HashInstance512);
		DigestSize = SHA2_512_256_SIZE_DIGEST;
	}
	else {
		return false;
	}

//Hash process
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
			if (SHA2_HashFunctionID == HASH_ID_SHA2_224 || SHA2_HashFunctionID == HASH_ID_SHA2_256)
				SHA2_256_Update(&HashInstance256, (uint8_t *)Buffer.get(), (int)ReadLength);
			else if (SHA2_HashFunctionID == HASH_ID_SHA2_384 || SHA2_HashFunctionID == HASH_ID_SHA2_512 || 
				SHA2_HashFunctionID == HASH_ID_SHA2_512_224 || SHA2_HashFunctionID == HASH_ID_SHA2_512_256)
					SHA2_512_Update(&HashInstance512, (uint8_t *)Buffer.get(), (int)ReadLength);
			else 
				return false;
		}
	}

//Binary to hex
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	if (SHA2_HashFunctionID == HASH_ID_SHA2_224 || SHA2_HashFunctionID == HASH_ID_SHA2_256)
		SHA2_256_Final((uint8_t *)Buffer.get(), &HashInstance256);
	else if (SHA2_HashFunctionID == HASH_ID_SHA2_384 || SHA2_HashFunctionID == HASH_ID_SHA2_512 || 
		SHA2_HashFunctionID == HASH_ID_SHA2_512_224 || SHA2_HashFunctionID == HASH_ID_SHA2_512_256)
			SHA2_512_Final((uint8_t *)Buffer.get(), &HashInstance512);
	else 
		return false;
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
