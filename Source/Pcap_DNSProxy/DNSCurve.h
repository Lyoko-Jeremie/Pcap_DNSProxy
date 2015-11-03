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


#include "Base.h"
#if defined(ENABLE_LIBSODIUM)
//Global variables
	extern CONFIGURATION_TABLE Parameter;
	extern GLOBAL_STATUS GlobalRunningStatus;
	extern ALTERNATE_SWAP_TABLE AlternateSwapList;
	extern DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter;

//Functions
void __fastcall DNSCurvePrintLog(
	_In_ const size_t ServerType, 
	_Out_ std::wstring &Message);
SSIZE_T __fastcall DNSCurvePaddingData(
	_In_ const bool SetPadding, 
	_Inout_ char *Buffer, 
	_In_ const SSIZE_T Length);
size_t __fastcall DNSCurveSelectTargetSocket(
	_Out_ SOCKET_DATA *TargetSocketData, 
	_Outptr_ DNSCURVE_SERVER_DATA **PacketTarget, 
	_Outptr_ bool **IsAlternate, 
	_Outptr_ size_t **AlternateTimeoutTimes, 
	_In_ const uint16_t Protocol);
bool __fastcall DNSCurveSelectTargetSocketMulti(
	_Out_ bool &IsIPv6, 
	_Outptr_ bool **IsAlternate, 
	_In_ const uint16_t Protocol);
bool __fastcall DNSCurvePacketTargetSetting(
	_In_ const size_t ServerType, 
	_Outptr_ DNSCURVE_SERVER_DATA **PacketTarget);
bool __fastcall DNSCurvePrecomputationKeySetting(
	_Out_ uint8_t *PrecomputationKey, 
	_Out_ uint8_t *Client_PublicKey, 
	_In_ const unsigned char *ServerFingerprint);
void __fastcall DNSCurveSocketPrecomputation(
	_In_ const uint16_t Protocol, 
	_In_ const char *OriginalSend, 
	_In_ const size_t SendSize, 
	_In_ const size_t RecvSize, 
	_Outptr_ uint8_t **PrecomputationKey, 
	_Outptr_ uint8_t **Alternate_PrecomputationKey, 
	_Outptr_ DNSCURVE_SERVER_DATA **PacketTarget, 
	_Inout_ std::vector<SOCKET_DATA> &SocketDataList, 
	_Inout_ std::vector<DNSCURVE_SOCKET_SELECTING_DATA> &SocketSelectingList, 
	_Inout_ std::shared_ptr<char> &SendBuffer, 
	_Out_ size_t &DataLength, 
	_Inout_ std::shared_ptr<char> &Alternate_SendBuffer, 
	_Out_ size_t &Alternate_DataLength);
size_t __fastcall DNSCurvePacketEncryption(
	_In_ const uint16_t Protocol, 
	_In_ const char *SendMagicNumber, 
	_In_ const unsigned char *Client_PublicKey, 
	_In_ const unsigned char *PrecomputationKey, 
	_In_ const char *OriginalSend, 
	_In_ const size_t Length, 
	_Inout_ char *SendBuffer, 
	_In_ const size_t SendSize);
SSIZE_T DNSCurvePacketDecryption(
	_In_ const char *ReceiveMagicNumber, 
	_In_ const unsigned char *PrecomputationKey, 
	_Inout_ char *OriginalRecv, 
	_In_ const size_t RecvSize, 
	_In_ const SSIZE_T Length);
SSIZE_T __fastcall DNSCurveSocketSelecting(
	_In_ const uint16_t Protocol, 
	_Inout_ std::vector<SOCKET_DATA> &SocketDataList, 
	_Inout_ std::vector<DNSCURVE_SOCKET_SELECTING_DATA> &SocketSelectingList, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize, 
	_Out_opt_ SSIZE_T *ErrorCode);
SSIZE_T __fastcall DNSCurveSelectingResult(
	_In_ const uint16_t Protocol, 
	_Inout_ std::vector<SOCKET_DATA> &SocketDataList, 
	_Inout_ std::vector<DNSCURVE_SOCKET_SELECTING_DATA> &SocketSelectingList, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize);
bool __fastcall DNSCurveTCPSignatureRequest(
	_In_ const uint16_t Protocol, 
	_In_ const bool IsAlternate);
bool __fastcall DNSCurveUDPSignatureRequest(
	_In_ const uint16_t Protocol, 
	_In_ const bool IsAlternate);
bool __fastcall DNSCruveGetSignatureData(
	_In_ const char *Buffer, 
	_In_ const size_t ServerType);
#endif
