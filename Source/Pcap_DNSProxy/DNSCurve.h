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


#include "Base.h"

#if defined(ENABLE_LIBSODIUM)
//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;
extern ALTERNATE_SWAP_TABLE AlternateSwapList;
extern DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter;
extern std::deque<SOCKET_MARKING_DATA> SocketMarkingList;
extern std::mutex SocketMarkingLock;

//Functions
ssize_t DNSCurvePaddingData(
	const bool SetPadding, 
	uint8_t *Buffer, 
	const ssize_t Length);
size_t DNSCurveSelectTargetSocket(
	SOCKET_DATA *TargetSocketData, 
	DNSCURVE_SERVER_DATA **PacketTarget, 
	bool **IsAlternate, 
	size_t **AlternateTimeoutTimes, 
	const uint16_t Protocol);
bool DNSCurveSelectTargetSocketMultiple(
	bool &IsIPv6, 
	bool **IsAlternate, 
	const uint16_t Protocol);
bool DNSCurvePacketTargetSetting(
	const size_t ServerType, 
	DNSCURVE_SERVER_DATA **PacketTarget);
bool DNSCurvePrecomputationKeySetting(
	uint8_t *PrecomputationKey, 
	uint8_t *Client_PublicKey, 
	const uint8_t *ServerFingerprint);
void DNSCurveSocketPrecomputation(
	const uint16_t Protocol, 
	const uint8_t *OriginalSend, 
	const size_t SendSize, 
	const size_t RecvSize, 
	uint8_t **PrecomputationKey, 
	uint8_t **Alternate_PrecomputationKey, 
	DNSCURVE_SERVER_DATA **PacketTarget, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> &SocketSelectingList, 
	std::shared_ptr<uint8_t> &SendBuffer, 
	size_t &DataLength, 
	std::shared_ptr<uint8_t> &Alternate_SendBuffer, 
	size_t &Alternate_DataLength);
size_t DNSCurvePacketEncryption(
	const uint16_t Protocol, 
	const uint8_t *SendMagicNumber, 
	const uint8_t *Client_PublicKey, 
	const uint8_t *PrecomputationKey, 
	const uint8_t *OriginalSend, 
	const size_t Length, 
	uint8_t *SendBuffer, 
	const size_t SendSize);
ssize_t DNSCurvePacketDecryption(
	const uint8_t *ReceiveMagicNumber, 
	const uint8_t *PrecomputationKey, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize, 
	const ssize_t Length);
ssize_t DNSCurveSocketSelecting(
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> &SocketSelectingList, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize, 
	ssize_t *ErrorCode);
ssize_t DNSCurveSelectingResult(
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> &SocketSelectingList, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize);
bool DNSCurveTCPSignatureRequest(
	const uint16_t Protocol, 
	const bool IsAlternate);
bool DNSCurveUDPSignatureRequest(
	const uint16_t Protocol, 
	const bool IsAlternate);
bool DNSCruveGetSignatureData(
	const uint8_t *Buffer, 
	const size_t ServerType);
#endif
