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
//Hash function ID
#define HASH_ID_CRC_8                 1U
#define HASH_ID_CRC_8_ITU             2U
#define HASH_ID_CRC_8_ATM             3U
#define HASH_ID_CRC_8_CCITT           4U
#define HASH_ID_CRC_8_MAXIM           5U
#define HASH_ID_CRC_8_ICODE           6U
#define HASH_ID_CRC_8_J1850           7U
#define HASH_ID_CRC_8_WCDMA           8U
#define HASH_ID_CRC_8_ROHC            9U
#define HASH_ID_CRC_8_DARC            10U
#define HASH_ID_CRC_16                11U
#define HASH_ID_CRC_16_BUYPASS        12U
#define HASH_ID_CRC_16_DDS_110        13U
#define HASH_ID_CRC_16_EN_13757       14U
#define HASH_ID_CRC_16_TELEDISK       15U
#define HASH_ID_CRC_16_MODBUS         16U
#define HASH_ID_CRC_16_MAXIM          17U
#define HASH_ID_CRC_16_USB            18U
#define HASH_ID_CRC_16_T10_DIF        19U
#define HASH_ID_CRC_16_DECT_X         20U
#define HASH_ID_CRC_16_DECT_R         21U
#define HASH_ID_CRC_16_SICK           22U
#define HASH_ID_CRC_16_DNP            23U
#define HASH_ID_CRC_16_CCITT_XMODEM   24U
#define HASH_ID_CRC_16_CCITT_FFFF     25U
#define HASH_ID_CRC_16_CCITT_1D0F     26U
#define HASH_ID_CRC_16_GENIBUS        27U
#define HASH_ID_CRC_16_KERMIT         28U
#define HASH_ID_CRC_16_X25            29U
#define HASH_ID_CRC_16_MCRF4XX        30U
#define HASH_ID_CRC_16_RIELLO         31U
#define HASH_ID_CRC_16_FLETCHER       32U
#define HASH_ID_CRC_24_FLEXRAY_A      33U
#define HASH_ID_CRC_24_FLEXRAY_B      34U
#define HASH_ID_CRC_24_R64            35U
#define HASH_ID_CRC_24                HASH_ID_CRC_24_R64
#define HASH_ID_CRC_32                36U
#define HASH_ID_CRC_32_JAM            37U
#define HASH_ID_CRC_32_C              38U
#define HASH_ID_CRC_32_D              39U
#define HASH_ID_CRC_32_BZIP2          40U
#define HASH_ID_CRC_32_MPEG2          41U
#define HASH_ID_CRC_32_POSIX          42U
#define HASH_ID_CRC_32_K              43U
#define HASH_ID_CRC_32_Q              44U
#define HASH_ID_CRC_32_XFER           45U
#define HASH_ID_CRC_40                46U
#define HASH_ID_CRC_64                47U
#define HASH_ID_CRC_64_1B             48U
#define HASH_ID_CRC_64_WE             49U
#define HASH_ID_CRC_64_JONES          50U
#define DEFAULT_HASH_FUNCTION_ID   HASH_ID_CRC_32

//Size definitions
#define CRC_TABLE_SIZE             256U
#define CRC8_SIZE_BLOCK            sizeof(uint8_t)
#define CRC16_SIZE_BLOCK           sizeof(uint16_t)
#define CRC24_SIZE_BLOCK           (sizeof(uint32_t) - sizeof(uint8_t))
#define CRC32_SIZE_BLOCK           sizeof(uint32_t)
#define CRC40_SIZE_BLOCK           (sizeof(uint32_t) + sizeof(uint8_t))
#define CRC64_SIZE_BLOCK           sizeof(uint64_t)

//Commands definitions
#if defined(PLATFORM_WIN)
	#define COMMAND_CRC_8                 L"-CRC8"
	#define COMMAND_CRC_8_ITU             L"-CRC8_ITU"
	#define COMMAND_CRC_8_ATM             L"-CRC8_ATM"
	#define COMMAND_CRC_8_CCITT           L"-CRC8_CCITT"
	#define COMMAND_CRC_8_MAXIM           L"-CRC8_MAXIM"
	#define COMMAND_CRC_8_ICODE           L"-CRC8_ICODE"
	#define COMMAND_CRC_8_J1850           L"-CRC8_J1850"
	#define COMMAND_CRC_8_WCDMA           L"-CRC8_WCDMA"
	#define COMMAND_CRC_8_ROHC            L"-CRC8_ROHC"
	#define COMMAND_CRC_8_DARC            L"-CRC8_DARC"
	#define COMMAND_CRC_16                L"-CRC16"
	#define COMMAND_CRC_16_BUYPASS        L"-CRC16_BUYPASS"
	#define COMMAND_CRC_16_DDS_110        L"-CRC16_DDS_110"
	#define COMMAND_CRC_16_EN_13757       L"-CRC16_EN_13757"
	#define COMMAND_CRC_16_TELEDISK       L"-CRC16_TELEDISK"
	#define COMMAND_CRC_16_MODBUS         L"-CRC16_MODBUS"
	#define COMMAND_CRC_16_MAXIM          L"-CRC16_MAXIM"
	#define COMMAND_CRC_16_USB            L"-CRC16_USB"
	#define COMMAND_CRC_16_T10_DIF        L"-CRC16_T10_DIF"
	#define COMMAND_CRC_16_DECT_X         L"-CRC16_DECT_X"
	#define COMMAND_CRC_16_DECT_R         L"-CRC16_DECT_R"
	#define COMMAND_CRC_16_SICK           L"-CRC16_SICK"
	#define COMMAND_CRC_16_DNP            L"-CRC16_DNP"
	#define COMMAND_CRC_16_CCITT_XMODEM   L"-CRC16_CCITT_XMODEM"
	#define COMMAND_CRC_16_CCITT_FFFF     L"-CRC16_CCITT_FFFF"
	#define COMMAND_CRC_16_CCITT_1D0F     L"-CRC16_CCITT_1D0F"
	#define COMMAND_CRC_16_GENIBUS        L"-CRC16_GENIBUS"
	#define COMMAND_CRC_16_KERMIT         L"-CRC16_KERMIT"
	#define COMMAND_CRC_16_X25            L"-CRC16_X25"
	#define COMMAND_CRC_16_MCRF4XX        L"-CRC16_MCRF4XX"
	#define COMMAND_CRC_16_RIELLO         L"-CRC16_RIELLO"
	#define COMMAND_CRC_16_FLETCHER       L"-CRC16_FLETCHER"
	#define COMMAND_CRC_24                L"-CRC24"
	#define COMMAND_CRC_24_FLEXRAY_A      L"-CRC24_FLEXRAY_A"
	#define COMMAND_CRC_24_FLEXRAY_B      L"-CRC24_FLEXRAY_B"
	#define COMMAND_CRC_24_R64            L"-CRC24_R64"
	#define COMMAND_CRC_32                L"-CRC32"
	#define COMMAND_CRC_32_JAM            L"-CRC32_JAM"
	#define COMMAND_CRC_32C               L"-CRC32C"
	#define COMMAND_CRC_32D				  L"-CRC32D"
	#define COMMAND_CRC_32_C              L"-CRC32_C"
	#define COMMAND_CRC_32_D              L"-CRC32_D"
	#define COMMAND_CRC_32_BZIP2          L"-CRC32_BZIP2"
	#define COMMAND_CRC_32_MPEG2          L"-CRC32_MPRG2"
	#define COMMAND_CRC_32_POSIX          L"-CRC32_POSIX"
	#define COMMAND_CRC_32K               L"-CRC32K"
	#define COMMAND_CRC_32Q               L"-CRC32Q"
	#define COMMAND_CRC_32_K              L"-CRC32_K"
	#define COMMAND_CRC_32_Q              L"-CRC32_Q"
	#define COMMAND_CRC_32_XFER           L"-CRC32_XFER"
	#define COMMAND_CRC_40                L"-CRC40"
	#define COMMAND_CRC_64                L"-CRC64"
	#define COMMAND_CRC_64_1B             L"-CRC64_1B"
	#define COMMAND_CRC_64_WE             L"-CRC64_WE"
	#define COMMAND_CRC_64_JONES          L"-CRC64_JONES"
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define COMMAND_CRC_8                 ("-CRC8")
	#define COMMAND_CRC_8_ITU             ("-CRC8_ITU")
	#define COMMAND_CRC_8_ATM             ("-CRC8_ATM")
	#define COMMAND_CRC_8_CCITT           ("-CRC8_CCITT")
	#define COMMAND_CRC_8_MAXIM           ("-CRC8_MAXIM")
	#define COMMAND_CRC_8_ICODE           ("-CRC8_ICODE")
	#define COMMAND_CRC_8_J1850           ("-CRC8_J1850")
	#define COMMAND_CRC_8_WCDMA           ("-CRC8_WCDMA")
	#define COMMAND_CRC_8_ROHC            ("-CRC8_ROHC")
	#define COMMAND_CRC_8_DARC            ("-CRC8_DARC")
	#define COMMAND_CRC_16                ("-CRC16")
	#define COMMAND_CRC_16_BUYPASS        ("-CRC16_BUYPASS")
	#define COMMAND_CRC_16_DDS_110        ("-CRC16_DDS_110")
	#define COMMAND_CRC_16_EN_13757       ("-CRC16_EN_13757")
	#define COMMAND_CRC_16_TELEDISK       ("-CRC16_TELEDISK")
	#define COMMAND_CRC_16_MODBUS         ("-CRC16_MODBUS")
	#define COMMAND_CRC_16_MAXIM          ("-CRC16_MAXIM")
	#define COMMAND_CRC_16_USB            ("-CRC16_USB")
	#define COMMAND_CRC_16_T10_DIF        ("-CRC16_T10_DIF")
	#define COMMAND_CRC_16_DECT_X         ("-CRC16_DECT_X")
	#define COMMAND_CRC_16_DECT_R         ("-CRC16_DECT_R")
	#define COMMAND_CRC_16_SICK           ("-CRC16_SICK")
	#define COMMAND_CRC_16_DNP            ("-CRC16_DNP")
	#define COMMAND_CRC_16_CCITT_XMODEM   ("-CRC16_CCITT_XMODEM")
	#define COMMAND_CRC_16_CCITT_FFFF     ("-CRC16_CCITT_FFFF")
	#define COMMAND_CRC_16_CCITT_1D0F     ("-CRC16_CCITT_1D0F")
	#define COMMAND_CRC_16_GENIBUS        ("-CRC16_GENIBUS")
	#define COMMAND_CRC_16_KERMIT         ("-CRC16_KERMIT")
	#define COMMAND_CRC_16_X25            ("-CRC16_X25")
	#define COMMAND_CRC_16_MCRF4XX        ("-CRC16_MCRF4XX")
	#define COMMAND_CRC_16_RIELLO         ("-CRC16_RIELLO")
	#define COMMAND_CRC_16_FLETCHER       ("-CRC16_FLETCHER")
	#define COMMAND_CRC_24                ("-CRC24")
	#define COMMAND_CRC_24_FLEXRAY_A      ("-CRC24_FLEXRAY_A")
	#define COMMAND_CRC_24_FLEXRAY_B      ("-CRC24_FLEXRAY_B")
	#define COMMAND_CRC_24_R64            ("-CRC24_R64")
	#define COMMAND_CRC_32                ("-CRC32")
	#define COMMAND_CRC_32_JAM            ("-CRC32_JAM")
	#define COMMAND_CRC_32C               ("-CRC32C")
	#define COMMAND_CRC_32D				  ("-CRC32D")
	#define COMMAND_CRC_32_C              ("-CRC32_C")
	#define COMMAND_CRC_32_D              ("-CRC32_D")
	#define COMMAND_CRC_32_BZIP2          ("-CRC32_BZIP2")
	#define COMMAND_CRC_32_MPEG2          ("-CRC32_MPRG2")
	#define COMMAND_CRC_32_POSIX          ("-CRC32_POSIX")
	#define COMMAND_CRC_32K               ("-CRC32K")
	#define COMMAND_CRC_32Q               ("-CRC32Q")
	#define COMMAND_CRC_32_K              ("-CRC32_K")
	#define COMMAND_CRC_32_Q              ("-CRC32_Q")
	#define COMMAND_CRC_32_XFER           ("-CRC32_XFER")
	#define COMMAND_CRC_40                ("-CRC40")
	#define COMMAND_CRC_64                ("-CRC64")
	#define COMMAND_CRC_64_1B             ("-CRC64_1B")
	#define COMMAND_CRC_64_WE             ("-CRC64_WE")
	#define COMMAND_CRC_64_JONES          ("-CRC64_JONES")
#endif

//Global variables
extern size_t HashFamilyID;
size_t CRC_HashFunctionID = HASH_ID_CRC_32;

//Functions
uint8_t __fastcall CRC8_Update(
	const size_t TableType, 
	const uint8_t CRC, 
	const uint8_t Buffer);
uint8_t __fastcall CRC8_Init(
	const size_t TableType);
uint8_t __fastcall CRC8_Calculate(
	uint8_t CRC, 
	const size_t TableType, 
	uint8_t *Buffer, 
	const size_t Length);
uint8_t __fastcall CRC8_Final(
	const uint8_t CRC, 
	const size_t TableType);
uint16_t __fastcall CRC16_Update_Normal(
	const uint16_t *Table, 
	uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_Reflected(
	const uint16_t *Table, 
	uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_Reflected(
	const uint16_t *Table, 
	uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_8005(
	const uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_A001(
	const uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_1021(
	const uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_8408(
	const uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_3D65(
	const uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_DNP(
	const uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_T10_DIF(
	const uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_0589(
	const uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_Teledisk(
	const uint16_t CRC, 
	const uint8_t Buffer);
uint16_t __fastcall CRC16_Update_Sick(
	uint16_t CRC, 
	const uint8_t Buffer, 
	const uint8_t PrevByte);
uint16_t __fastcall CRC16_Init(
	const size_t TableType);
uint16_t __fastcall CRC16_Calculate(
	uint16_t CRC, 
	uint8_t *ParameterA, 
	uint8_t *ParameterB, 
	const size_t TableType, 
	uint8_t *Buffer, 
	const size_t Length);
uint16_t __fastcall CRC16_Final(
	const uint16_t CRC, 
	uint8_t *ParameterA, 
	uint8_t *ParameterB, 
	const size_t TableType);
uint32_t __fastcall CRC24_Update(
	const size_t TableType, 
	const uint32_t CRC, 
	const char c);
uint32_t __fastcall CRC24_Init(
	const size_t TableType);
uint32_t __fastcall CRC24_Calculate(
	uint32_t CRC, 
	const size_t TableType, 
	uint8_t *Buffer, 
	const size_t Length);
uint32_t __fastcall CRC32_Update_Normal(
	const uint32_t *Table, 
	const uint32_t CRC, 
	const uint8_t Buffer);
uint32_t __fastcall CRC32_Update_Reflected(
	const uint32_t *Table, 
	const uint32_t CRC, 
	const uint8_t Buffer);
uint32_t CRC32_Update_Refl(
	const uint32_t CRC, 
	const uint8_t Buffer);
uint32_t CRC32_Update_Norm(
	const uint32_t CRC, 
	const uint8_t Buffer);
uint32_t CRC32_Update_Xfer(
	const uint32_t CRC, 
	const uint8_t Buffer);
uint32_t CRC32_Update_C(
	const uint32_t CRC, 
	const uint8_t Buffer);
uint32_t CRC32_Update_D(
	const uint32_t CRC, 
	const uint8_t Buffer);
uint32_t CRC32_Update_K(
	const uint32_t CRC, 
	const uint8_t Buffer);
uint32_t CRC32_Update_Q(
	const uint32_t CRC, 
	const uint8_t Buffer);
uint32_t __fastcall CRC32_Init(
	const size_t TableType);
uint32_t __fastcall CRC32_Calculate(
	uint32_t CRC, 
	const size_t TableType, 
	uint8_t *Buffer, 
	const size_t Length);
uint32_t __fastcall CRC32_Final(
	const uint32_t CRC, 
	const size_t TableType);
uint64_t __fastcall CRC40_Calculate(
	uint64_t CRC, 
	uint8_t *Buffer, 
	const size_t Length);
uint64_t __fastcall CRC64_Update_Normal(
	const uint64_t *Table, 
	const uint64_t CRC, 
	const uint8_t Buffer);
uint64_t __fastcall CRC64_Update_Reflected(
	const uint64_t *Table, 
	const uint64_t CRC, 
	const uint8_t Buffer);
uint64_t __fastcall CRC64_Update(
	const uint64_t CRC, 
	const uint8_t Buffer);
uint64_t __fastcall CRC64_Update_1B(
	const uint64_t CRC, 
	const uint8_t Buffer);
uint64_t __fastcall CRC64_Update_Jones(
	const uint64_t CRC, 
	const uint8_t Buffer);
uint64_t __fastcall CRC64_Init(
	const size_t TableType);
uint64_t __fastcall CRC64_Calculate(
	uint64_t CRC, 
	const size_t TableType, 
	uint8_t *Buffer, 
	const size_t Length);
uint64_t __fastcall CRC64_Final(
	const uint64_t CRC, 
	const size_t TableType);
#endif
