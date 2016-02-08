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
//The MD2 block size and message digest size
enum {
	MD2 = 6,                //Hash type unique
	MD2_BLOCK_SIZE = 16, 
	MD2_DIGEST_SIZE = 16, 
	MD2_PAD_SIZE = 16, 
	MD2_X_SIZE = 48
};

//Code definitions
#define XMEMSET(b, c, l)    memset((b), (c), (l))
#define XMEMCPY(d, s, l)    memcpy_s((d), (l), (s), (l))

//The structure for storing MD2 info
typedef struct _md2_info_
{
	uint32_t   Count;       //Bytes % PAD_SIZE
	uint8_t    X[MD2_X_SIZE];
	uint8_t    C[MD2_BLOCK_SIZE];
	uint8_t    Buffer[MD2_BLOCK_SIZE];
}MD2_CTX;

//Global variables
extern size_t HashFamilyID;

//Functions
void __fastcall MD2_Init(
	MD2_CTX *md2);
void __fastcall MD2_Update(
	MD2_CTX *md2, 
	const uint8_t *data, 
	uint32_t len);
void __fastcall MD2_Final(
	MD2_CTX *md2, 
	uint8_t *hash);
#endif
