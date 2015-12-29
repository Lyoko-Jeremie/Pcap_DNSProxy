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


#include "FileHash.h"

#if defined(ENABLE_LIBSODIUM)
//The SHA1 block size, message digest sizes in bytes and some useful types.
#define SHA1_SIZE_BLOCK    64U
#define SHA1_SIZE_DIGEST   20U
typedef int32_t            SHA1_INT32;
typedef int64_t            SHA1_INT64;

//The structure for storing SHA1 info
typedef struct _sha1_state_
{
	SHA1_INT64     Length;
	SHA1_INT32     State[5U], Curlen;
	uint8_t        Buffer[SHA1_SIZE_BLOCK];
}SHA1_State;

//Rotate the hard way(platform optimizations could be done).
#define ROL(x, y) ((((unsigned long)(x) << (unsigned long)((y) & 31)) | (((unsigned long)(x) & 0xFFFFFFFFUL) >> (unsigned long)(32 - ((y) & 31)))) & 0xFFFFFFFFUL)
#define ROLc(x, y) ((((unsigned long)(x) << (unsigned long)((y) & 31)) | (((unsigned long)(x) & 0xFFFFFFFFUL) >> (unsigned long)(32 - ((y) & 31)))) & 0xFFFFFFFFUL)

//Endian Neutral macros that work on all platforms
#define STORE32H(x, y)																			\
	{(y)[0] = (unsigned char)(((x) >> 24U) & 255); (y)[1U] = (unsigned char)(((x) >> 16U) & 255);	\
		(y)[2U] = (unsigned char)(((x) >> 8U) & 255); (y)[3U] = (unsigned char)((x) & 255);}

#define LOAD32H(x, y)										\
	{x = ((unsigned long)((y)[0] & 255) << 24U) |			\
		((unsigned long)((y)[1U] & 255) << 16U) |			\
		((unsigned long)((y)[2U] & 255) << 8U)  |			\
		((unsigned long)((y)[3U] & 255));}

#define STORE64H(x, y)																						\
	{(y)[0] = (unsigned char)(((x) >> 56U) & 255); (y)[1U] = (unsigned char)(((x) >> 48U) & 255);			\
		(y)[2U] = (unsigned char)(((x) >> 40U) & 255); (y)[3U] = (unsigned char)(((x) >> 32U) & 255);		\
		(y)[4U] = (unsigned char)(((x) >> 24U) & 255); (y)[5U] = (unsigned char)(((x) >> 16U) & 255);		\
		(y)[6U] = (unsigned char)(((x) >> 8U) & 255); (y)[7U] = (unsigned char)((x) & 255);}

#ifndef MIN
	#define MIN(x, y) (((x)<(y)) ? (x):(y))
#endif

//SHA-1 macros
#define SHA1_F0(x, y, z)   (z ^ (x & (y ^ z)))
#define SHA1_F1(x, y, z)   (x ^ y ^ z)
#define SHA1_F2(x, y, z)   ((x & y) | (z & (x | y)))
#define SHA1_F3(x, y, z)   (x ^ y ^ z)

//Global variables
extern size_t HashFamilyID;

//Functions
static void __fastcall SHA1_Compress(
	_Inout_ SHA1_State *sha1, 
	_Inout_ unsigned char *buf);
void __fastcall SHA1_Init(
	_Inout_ SHA1_State *sha1);
void __fastcall SHA1_Process(
	_Inout_ SHA1_State *sha1,
	_In_ const unsigned char *in,
	_In_ unsigned long inlen);
void __fastcall SHA1_Done(
	_Inout_ SHA1_State *sha1,
	_Out_ unsigned char *out);
#endif
