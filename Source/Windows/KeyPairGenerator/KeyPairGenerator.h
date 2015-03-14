// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
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


//////////////////////////////////////////////////
// Base Header
// 
//#include <cstdio>                  //File Input/Output
//#include <cstdlib>                 //Several general purpose functions.
//#include <cstdint>                 //A set of integral type aliases with specific width requirements.
//#include <exception>               //Exception
#include <memory>                  //Manage dynamic memory support
//#include <tchar.h>                 //Unicode(UTF-8/UTF-16)/Wide-Character Support
#include <windows.h>               //Microsoft Windows master include file

//////////////////////////////////////////////////
// Sodium headers
// 
//#include "LibSodium\core.h"
//#include "LibSodium\crypto_box.h"
#include "LibSodium\sodium.h"

//Static libraries
#ifdef _WIN64
	#pragma comment(lib, "LibSodium/Libsodium_x64.lib") //LibSodium library(x64)
#else //x86
	#pragma comment(lib, "LibSodium/libsodium_x86.lib") //LibSodium library(x86)
#endif

//#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup") //Hide console.
//Remember to add "WPCAP" and "HAVE_REMOTE" to preprocessor options!
//Remember to add "SODIUM_STATIC" and "SODIUM_EXPORT=" to preprocessor options!

//////////////////////////////////////////////////
// Base defines
// 
#pragma pack(1)                        //Memory alignment: 1 bytes/8 bits
#define KEYPAIR_MESSAGE_LEN    80U     //Keypair messages length
#define MBSTOWCS_NULLTERMINATE (-1)    //MultiByteToWideChar() find null-terminate.

//ASCII values defines
#define ASCII_LF               10      //"␊"
#define ASCII_DLE              16      //"␐"
#define ASCII_COLON            58      //":"

//Functions
size_t __fastcall BinaryToHex(PSTR Buffer, const size_t MaxLength, const PUINT8 Binary, const size_t Length);
