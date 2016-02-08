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
//The MD4 block size and message digest size
#define MD4_SIZE_BLOCK     64U
#define MD4_LENGTH_BLOCK   (MD4_SIZE_BLOCK / 4U)
#define MD4_SIZE_DIGEST    16U
#define MD4_LONG           uint32_t
#define ED2K_SIZE_BLOCK    9728000U

//Code definitions
#define INIT_DATA_A (uint32_t)0x67452301L
#define INIT_DATA_B (uint32_t)0xEFCDAB89L
#define INIT_DATA_C (uint32_t)0x98BADCFEL
#define INIT_DATA_D (uint32_t)0x10325476L
#define HASH_MAKE_STRING(c, s)   do {                         \
	uint32_t ll = 0;                                          \
	ll = (c)->A; (void)HOST_l2c(ll, (s));                     \
	ll = (c)->B; (void)HOST_l2c(ll, (s));                     \
	ll = (c)->C; (void)HOST_l2c(ll, (s));                     \
	ll = (c)->D; (void)HOST_l2c(ll, (s));                     \
	} while (0)
#define HOST_c2l(c, l)   (l = (((uint32_t)(*((c)++)))),       \
	l |= (((uint32_t)(*((c)++))) << 8U),                      \
	l |= (((uint32_t)(*((c)++))) << 16U),                     \
	l |= (((uint32_t)(*((c)++))) << 24U))
#define HOST_l2c(l, c)   (*((c)++)=(uint8_t)(((l)) & 0xFF),   \
	*((c)++) = (uint8_t)(((l) >> 8U) & 0xFF),                 \
	*((c)++) = (uint8_t)(((l) >> 16U) & 0xFF),                \
	*((c)++) = (uint8_t)(((l) >> 24U) & 0xFF),                \
	l)
#define F(b, c, d)   ((((c) ^ (d)) & (b)) ^ (d))   
#define G(b, c, d)   (((b) & (c)) | ((b) & (d)) | ((c) & (d)))   
#define H(b, c, d)   ((b) ^ (c) ^ (d))   
#define R0(a, b, c, d, k, s, t) {                             \
	a += ((k) + (t) + F((b), (c), (d)));                      \
	a = ROTATE(a, s);};
#define R1(a, b, c, d, k, s, t) {                             \
	a += ((k) + (t) + G((b), (c), (d)));                      \
	a = ROTATE(a, s);};
#define R2(a, b, c, d, k, s, t) {                             \
	a += ((k) + (t) + H((b), (c), (d)));                      \
	a = ROTATE(a, s);};
#define ROTATE(a, n)   (((a) << (n)) | (((a) & 0xFFFFFFFF) >> (32 - (n))))   

//The structure for storing MD4 info
typedef struct _md4_state_st_
{
	MD4_LONG       A, B, C, D;
	MD4_LONG       Nl, Nh;
	MD4_LONG       Data[MD4_LENGTH_BLOCK];
	unsigned int   Num;
}MD4_CTX;

//Global variables
extern size_t HashFamilyID;

//Functions
void __fastcall MD4_Init(
	MD4_CTX *c);
void __fastcall MD4_BlockDataOrder(
	MD4_CTX *c, 
	const void *data_, 
	size_t num);
void __fastcall MD4_Update(
	MD4_CTX *c, 
	const void *data_, 
	size_t len);
void __fastcall MD4_Final(
	uint8_t *md, 
	MD4_CTX *c);
#endif
