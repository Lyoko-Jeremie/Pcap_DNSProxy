// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2018 Chengr28
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


#ifndef PCAP_DNSPROXY_CAPTURE_H
#define PCAP_DNSPROXY_CAPTURE_H

#include "Include.h"

#if defined(ENABLE_PCAP)
//Structure definitions
typedef struct _capture_handler_param_
{
	int           DeviceType;
	uint8_t       *Buffer;
	size_t        BufferSize;
}Capture_CallbackHandlerParam, CAPTURE_HANDLER_PARAM;

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;
extern ALTERNATE_SWAP_TABLE AlternateSwapList;
#if defined(ENABLE_LIBSODIUM)
extern DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter;
#endif
extern std::deque<OUTPUT_PACKET_TABLE> OutputPacketList;
extern std::mutex CaptureLock, OutputPacketListLock;

//Local variables
std::string PcapFilterRules;
std::list<std::string> PcapRunningList;

//Functions
bool Capture_FilterRulesInit(
	std::string &FilterRules);
bool Capture_MainProcess(
	const pcap_if * const DriveInterface, 
	const bool IsCaptureList);
void Capture_CallbackHandler(
	uint8_t * const ProcParameter, 
	const pcap_pkthdr * const PacketHeader, 
	const uint8_t * const PacketData);
bool Capture_AnalyzeNetworkLayer(
	const uint16_t Protocol, 
	const uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize);
ssize_t Capture_AnalyzeFragment(
	const uint16_t Protocol, 
	const uint8_t * const Buffer, 
	const size_t Length, 
	bool &IsNeedTruncated);
bool Capture_AnalyzeICMP(
	const uint16_t Protocol, 
	const uint8_t * const Buffer, 
	const size_t Length);
bool Capture_AnalyzeTCP(
	const uint8_t * const Buffer);
bool Capture_AnalyzeDNS(
	const uint8_t * const Buffer, 
	const size_t BufferSize, 
	bool &IsRegisterStatus);
bool Capture_PacketStatusCheck(
	const uint16_t Protocol, 
	const uint8_t * const Buffer, 
	const size_t DNS_DataOffset, 
	const size_t DNS_DataLength, 
	const size_t EDNS_Offset, 
	const size_t EDNS_Length, 
	const bool IsRegisterStatus, 
	DNS_SERVER_DATA * const PacketSource);
bool Capture_MatchPortToSend(
	const uint16_t Protocol, 
	const uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize, 
	const uint16_t Port, 
	const bool IsNeedTruncated, 
	const size_t EDNS_Length_Output);
#endif
#endif
