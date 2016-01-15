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
//The MD5 block size and message digest size
#define MD5_SIZE_BLOCK    64U
#define MD5_SIZE_DIGEST   16U

//The structure for storing MD5 info
typedef struct _md5_ctx_
{
	uint32_t   Count[2U];
	uint32_t   State[4U];
	uint8_t    Buffer[MD5_SIZE_BLOCK];
}MD5_CTX;

//Code definitions
#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))
#define ROTATE_LEFT(x, n) ((x << n) | (x >> (32 - n)))
#define FF(a, b, c, d, x, s, ac)   \
{                                  \
	a += F(b, c, d) + x + ac;      \
	a = ROTATE_LEFT(a, s);         \
	a += b;                        \
}  
#define GG(a, b, c, d, x, s, ac)   \
{                                  \
	a += G(b, c, d) + x + ac;      \
	a = ROTATE_LEFT(a, s);         \
	a += b;                        \
}  
#define HH(a, b, c, d, x, s, ac)   \
{                                  \
	a += H(b, c, d) + x + ac;      \
	a = ROTATE_LEFT(a, s);         \
	a += b; \
}  
#define II(a, b, c, d, x, s, ac)   \
{                                  \
	a += I(b, c, d) + x + ac;      \
	a = ROTATE_LEFT(a, s);         \
	a += b;                        \
}

//Global variables
extern size_t HashFamilyID;

//Functions
void __fastcall MD5_Init(
	_Inout_ MD5_CTX *context);
void __fastcall MD5_Update(
	_Inout_ MD5_CTX *context, 
	_In_ uint8_t *input, 
	_In_ unsigned int inputlen);
void __fastcall MD5_Final(
	_Inout_ MD5_CTX *context, 
	_Inout_ uint8_t digest[MD5_SIZE_DIGEST]);
void __fastcall MD5_Transform(
	_Inout_ unsigned int state[4U], 
	_Inout_ uint8_t block[MD5_SIZE_BLOCK]);
void __fastcall MD5_Encode(
	_Out_ uint8_t *output, 
	_In_ unsigned int *input, 
	_In_ unsigned int len);
void __fastcall MD5_Decode(
	_Out_ unsigned int *output, 
	_In_ uint8_t *input, 
	_In_ unsigned int len);
#endif
