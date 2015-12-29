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
//Hash function ID
#define HASH_ID_SHA3_224           1U
#define HASH_ID_SHA3_256           2U
#define HASH_ID_SHA3_384           3U
#define HASH_ID_SHA3_512           4U
#define HASH_ID_SHA3_SHAKE_128     5U
#define HASH_ID_SHA3_SHAKE_256     6U
#define DEFAULT_HASH_FUNCTION_ID   HASH_ID_SHA3_256

//Size definitions
#define SHA3_SIZE_224              224U
#define SHA3_SIZE_256              256U
#define SHA3_SIZE_384              384U
#define SHA3_SIZE_512              512U

//Commands definitions
#if defined(PLATFORM_WIN)
	#define COMMAND_SHA3_224           L"-SHA3_224"
	#define COMMAND_SHA3_256           L"-SHA3_256"
	#define COMMAND_SHA3_384           L"-SHA3_384"
	#define COMMAND_SHA3_512           L"-SHA3_512"
	#define COMMAND_SHA3_SHAKE         L"-SHA3_SHAKE"
	#define COMMAND_SHA3_SHAKE_SIZE    L"-SHA3_SHAKE="
	#define COMMAND_SHA3_SHAKE_128     L"-SHA3_SHAKE_128="
	#define COMMAND_SHA3_SHAKE_256     L"-SHA3_SHAKE_256="
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define COMMAND_SHA3_224           ("-SHA3_224")
	#define COMMAND_SHA3_256           ("-SHA3_256")
	#define COMMAND_SHA3_384           ("-SHA3_384")
	#define COMMAND_SHA3_512           ("-SHA3_512")
	#define COMMAND_SHA3_SHAKE         ("-SHA3_SHAKE")
	#define COMMAND_SHA3_SHAKE_SIZE    ("-SHA3_SHAKE=")
	#define COMMAND_SHA3_SHAKE_128     ("-SHA3_SHAKE_128=")
	#define COMMAND_SHA3_SHAKE_256     ("-SHA3_SHAKE_256=")
#endif

//Global variables
extern size_t HashFamilyID;
size_t SHA3_HashFunctionID = DEFAULT_HASH_FUNCTION_ID, SHA3_SHAKE_Length = 0;
#endif
