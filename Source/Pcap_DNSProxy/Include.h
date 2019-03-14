// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2019 Chengr28
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


#ifndef PCAP_DNSPROXY_INCLUDE_H
#define PCAP_DNSPROXY_INCLUDE_H

#include "Template.h"

//////////////////////////////////////////////////
// Main functions
// 
//Base.cpp
bool CheckLibraryVersion(
	void);
bool CheckEmptyBuffer(
	const void * const Buffer, 
	const size_t Length);
bool MBS_To_WCS_String(
	const uint8_t * const Buffer, 
	const size_t BufferSize, 
	std::wstring &Target);
bool WCS_To_MBS_String(
	const wchar_t * const Buffer, 
	const size_t BufferSize, 
	std::string &Target);
void CaseConvert(
	uint8_t * const Buffer, 
	const size_t Length, 
	const bool IsLowerToUpper);
void CaseConvert(
	std::string &Buffer, 
	const bool IsLowerToUpper);
void CaseConvert(
	std::wstring &Buffer, 
	const bool IsLowerToUpper);
void MakeStringReversed(
	std::string &String);
void MakeStringReversed(
	std::wstring &String);
bool CompareStringReversed(
	const std::string &RuleItem, 
	const std::string &TestItem);
bool CompareStringReversed(
	const wchar_t * const RuleItem, 
	const wchar_t * const TestItem);
bool SortCompare_IPFilter(
	const DIFFERNET_FILE_SET_IPFILTER &Begin, 
	const DIFFERNET_FILE_SET_IPFILTER &End);
bool SortCompare_Hosts(
	const DIFFERNET_FILE_SET_HOSTS &Begin, 
	const DIFFERNET_FILE_SET_HOSTS &End);
#if !defined(ENABLE_LIBSODIUM)
size_t Base64_Encode(
	uint8_t * const Input, 
	const size_t Length, 
	uint8_t * const Output, 
	const size_t OutputSize);
size_t Base64_Decode(
	uint8_t *Input, 
	const size_t Length, 
	uint8_t *Output, 
	const size_t OutputSize);
#endif
HUFFMAN_RETURN_TYPE HPACK_HuffmanDecoding(
	uint8_t *HuffmanBuffer, 
	size_t ByteSize, 
	size_t *Consumed, 
	uint8_t *TargetBuffer, 
	size_t Length, 
	size_t *Produced);
void GenerateRandomBuffer(
	void * const BufferPointer, 
	const size_t BufferSize, 
	const void *Distribution, 
	const uint64_t Lower, 
	const uint64_t Upper);
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
uint64_t IncreaseMillisecondTime(
	const uint64_t CurrentTime, 
	const timeval IncreaseTime);
uint64_t GetCurrentSystemTime(
	void);
#endif

//Captrue.h
#if defined(ENABLE_PCAP)
void CaptureInit(
	void);
#endif

//Configuration.h
bool ReadParameter(
	const bool IsFirstRead);
void ReadIPFilter(
	void);
void ReadHosts(
	void);

//DNSCurveControl.h
#if defined(ENABLE_LIBSODIUM)
bool DNSCurve_VerifyKeypair(
	const uint8_t * const PublicKey, 
	const uint8_t * const SecretKey);
DNSCURVE_SERVER_DATA *DNSCurve_SelectSignatureTargetSocket(
	const uint16_t Protocol, 
	const bool IsAlternate, 
	DNSCURVE_SERVER_TYPE &ServerType, 
	std::vector<SOCKET_DATA> &SocketDataList);
bool DNSCurve_PacketTargetSetting(
	const DNSCURVE_SERVER_TYPE ServerType, 
	DNSCURVE_SERVER_DATA ** const PacketTarget);
bool DNSCurve_PrecomputationKeySetting(
	uint8_t * const PrecomputationKey, 
	uint8_t * const Client_PublicKey, 
	const uint8_t * const ServerFingerprint);
void DNSCurve_SocketPrecomputation(
	const uint16_t Protocol, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	const size_t RecvSize, 
	uint8_t ** const PrecomputationKey, 
	uint8_t ** const Alternate_PrecomputationKey, 
	DNSCURVE_SERVER_DATA ** const PacketTarget, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<DNSCURVE_SOCKET_SELECTING_TABLE> &SocketSelectingDataList, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData, 
	std::unique_ptr<uint8_t[]> &SendBuffer, 
	size_t &DataLength, 
	std::unique_ptr<uint8_t[]> &Alternate_SendBuffer, 
	size_t &Alternate_DataLength);
size_t DNSCurve_PacketEncryption(
	const uint16_t Protocol, 
	const uint8_t * const SendMagicNumber, 
	const uint8_t * const Client_PublicKey, 
	const uint8_t * const PrecomputationKey, 
	const uint8_t * const OriginalSend, 
	const size_t Length, 
	uint8_t * const SendBuffer, 
	const size_t SendSize);
ssize_t DNSCurve_PacketDecryption(
	const uint8_t * const ReceiveMagicNumber, 
	const uint8_t * const PrecomputationKey, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const ssize_t Length);
bool DNSCruve_GetSignatureData(
	const uint8_t * const Buffer, 
	const DNSCURVE_SERVER_TYPE ServerType);

//DNSCurveRequest.h
void DNSCurveInit(
	void);
size_t DNSCurve_TCP_RequestSingle(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData);
size_t DNSCurve_TCP_RequestMultiple(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData);
size_t DNSCurve_UDP_RequestSingle(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData);
size_t DNSCurve_UDP_RequestMultiple(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData);
#endif

//Monitor.h
void MonitorLauncher(
	void);
bool MonitorInit(
	void);
bool TCP_AcceptProcess(
	MONITOR_QUEUE_DATA MonitorQueryData, 
	uint8_t * const OriginalRecv, 
	size_t RecvSize);

//Network.h
bool SocketSetting(
	SYSTEM_SOCKET &Socket, 
	const SOCKET_SETTING_TYPE SettingType, 
	const bool IsPrintError, 
	void * const DataPointer);
#if defined(ENABLE_PCAP)
void ReadCallback_SocketSend(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument);
void WriteCallback_SocketSend(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument);
void TimerCallback_SocketSend(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument);
void EventCallback_TransmissionOnce(
	bufferevent *BufferEvent, 
	short EventType, 
	void *Argument);
void ReadCallback_TransmissionOnce(
	bufferevent *BufferEvent, 
	void *Argument);
void WriteCallback_TransmissionOnce(
	bufferevent *BufferEvent, 
	void *Argument);
void TimerCallback_TransmissionOnce(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument);
#endif
uint16_t SelectProtocol_Network(
	const REQUEST_MODE_NETWORK GlobalSpecific, 
	const uint16_t TargetSpecific_IPv6, 
	const uint16_t TargetSpecific_IPv4, 
	const bool IsAccordingType, 
	const uint16_t TypeSpecific, 
	const SOCKET_DATA * const LocalSocketSpecific);
size_t SelectTargetSocketSingle(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	const uint16_t QueryType, 
	const SOCKET_DATA * const LocalSocketData, 
	SOCKET_DATA * const TargetSocketData, 
	bool ** const IsAlternate, 
	size_t ** const AlternateTimeoutTimes, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData, 
	void * DNSCurvePacketServerType, 
	void ** const DNSCurvePacketTarget);
bool SelectTargetSocketMultiple(
	const uint16_t Protocol_Network, 
	const uint16_t Protocol_Transport, 
	const uint16_t QueryType, 
	const SOCKET_DATA * const LocalSocketData, 
	std::vector<SOCKET_DATA> &TargetSocketDataList);
size_t SocketConnecting(
	const uint16_t Protocol, 
	SYSTEM_SOCKET &Socket, 
	const sockaddr * const SockAddr, 
	const socklen_t AddrLen, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize);
ssize_t SocketSelectingOnce(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	void * const OriginalDNSCurveSocketSelectingDataList, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	ssize_t * const ErrorCode, 
	const SOCKET_DATA * const LocalSocketData);
size_t SocketSelectingSerial(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList);
void RegisterPortToList(
	const uint16_t Protocol, 
	const SOCKET_DATA * const LocalSocketData, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	const std::string * const DomainString_Original, 
	const std::string * const DomainString_Request
//	size_t *EDNS_Length
);

//PacketData.h
uint16_t GetChecksum_Internet(
	const uint16_t *Buffer, 
	const size_t Length);
uint16_t GetChecksum_ICMPv6(
	const ipv6_hdr * const IPv6_Header, 
	const uint8_t * const Buffer, 
	const size_t Length);
uint16_t GetChecksum_TCP_UDP(
	const uint16_t Protocol_Network, 
	const uint16_t Protocol_Transport, 
	const uint8_t * const Buffer, 
	const size_t Length, 
	const size_t DataOffset);
size_t AddLengthDataToHeader(
	uint8_t * const Buffer, 
	const size_t DataLength, 
	const size_t BufferSize);
size_t StringToPacketQuery(
	const uint8_t * const FName, 
	uint8_t * const TName, 
	const size_t BufferSize);
size_t PacketQueryToString(
	const uint8_t * const TName, 
	const size_t BufferSize, 
	std::string &FName);
size_t MarkWholePacketQuery(
	const uint8_t * const WholePacket, 
	const size_t Length, 
	const uint8_t * const TName, 
	const size_t TNameIndex, 
	std::string &FName);
void GenerateRandomDomain(
	uint8_t * const Buffer, 
	const size_t BufferSize);
void MakeDomainCaseConversion(
	uint8_t * const Buffer, 
	const size_t BufferSize);
bool Move_EDNS_LabelToEnd(
	DNS_PACKET_DATA * const PacketStructure);
size_t Add_EDNS_LabelToPacket(
	uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize, 
	const SOCKET_DATA * const LocalSocketData);
bool Add_EDNS_LabelToPacket(
	DNS_PACKET_DATA * const PacketStructure, 
	const bool IsAlreadyClientSubnet, 
	const bool IsAlreadyCookies, 
	const SOCKET_DATA * const LocalSocketData);
size_t MakeCompressionPointerMutation(
	uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize);
bool MarkDomainCache(
	const uint8_t * const Buffer, 
	const size_t Length, 
	const SOCKET_DATA * const LocalSocketData);
size_t CheckDomainCache(
	uint8_t * const ResultBuffer, 
	const size_t ResultSize, 
	const std::string &Domain, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData);

//PrintLog.h
bool PrintError(
	const LOG_LEVEL_TYPE ErrorLevel, 
	const LOG_ERROR_TYPE ErrorType, 
	const wchar_t * const Message, 
	const ssize_t ErrorCode, 
	const wchar_t * const FileName, 
	const size_t Line);
void PrintToScreen(
	const bool IsInnerLock, 
	const bool IsStandardOut, 
	const wchar_t * const Format, 
	...
);
void ErrorCodeToMessage(
	const LOG_ERROR_TYPE ErrorType, 
	const ssize_t ErrorCode, 
	std::wstring &Message);
void PrintLog_ReadText(
	const READ_TEXT_TYPE InputType, 
	const size_t FileIndex, 
	const size_t Line);
void PrintLog_HTTP_CONNECT_2(
	const uint32_t ErrorCode, 
	std::wstring &Message);
#if defined(ENABLE_LIBSODIUM)
void PrintLog_DNSCurve(
	const DNSCURVE_SERVER_TYPE ServerType, 
	std::wstring &Message);
#endif

//Process.h
void MonitorRequestProvider(
	const MONITOR_QUEUE_DATA &MonitorQueryData);
void MonitorRequestConsumer(
	void);
bool EnterRequestProcess(
	MONITOR_QUEUE_DATA MonitorQueryData, 
	uint8_t *RecvBuffer, 
	size_t RecvSize);
size_t CheckWhiteBannedHostsProcess(
	const size_t Length, 
	const HostsTable &HostsTableItem, 
	dns_hdr * const DNS_Header, 
	const uint16_t QueryType);
size_t CheckHostsProcess(
	DNS_PACKET_DATA * const PacketStructure, 
	uint8_t * const ResultBuffer, 
	const size_t ResultSize, 
	const SOCKET_DATA &LocalSocketData);
bool SendToRequester(
	const uint16_t Protocol, 
	uint8_t * const RecvBuffer, 
	const size_t RecvSize, 
	const size_t BufferSize, 
	const std::string * const DomainString_Original, 
	const std::string * const DomainString_Request, 
	SOCKET_DATA &LocalSocketData);

//Protocol.h
bool AddressStringToBinary(
	const uint16_t Protocol, 
	const uint8_t * const AddrBuffer, 
	void * const OriginalAddr, 
	ssize_t * const ErrorCode);
bool BinaryToAddressString(
	const uint16_t Protocol, 
	const void * const OriginalAddr, 
	void * const AddrString, 
	const size_t StringSize, 
	ssize_t * const ErrorCode);
bool AddressPrefixReplacing(
	const uint16_t Protocol, 
	const void * const SourceAddr, 
	void * const DestinationAddr, 
	const size_t Prefix);
ADDRESS_COMPARE_TYPE AddressesComparing(
	const uint16_t Protocol, 
	const void * const OriginalAddrBegin, 
	const void * const OriginalAddrEnd);
bool CheckSpecialAddress(
	const uint16_t Protocol, 
	void * const OriginalAddr, 
	const bool IsPrivateUse, 
	const uint8_t * const DomainBuffer);
bool OperationModeFilter(
	const uint16_t Protocol, 
	const void * const OriginalAddr, 
	const LISTEN_MODE OperationMode);
size_t CheckQueryNameLength(
	const uint8_t * const Buffer, 
	const size_t BufferSize);
bool CheckQueryData(
	DNS_PACKET_DATA * const PacketStructure, 
	uint8_t * const SendBuffer, 
	const size_t SendSize, 
	SOCKET_DATA &LocalSocketData);
bool CheckConnectionStreamFin(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint8_t * const Stream, 
	const size_t Length);
size_t CheckResponseData(
	const REQUEST_PROCESS_TYPE ResponseType, 
	uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize, 
	size_t * const PacketEDNS_Offset, 
	size_t * const PacketEDNS_Length);

//Proxy.h
size_t SOCKS_TCP_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::unique_ptr<uint8_t[]> &OriginalRecv, 
	size_t &RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData);
size_t SOCKS_UDP_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::unique_ptr<uint8_t[]> &OriginalRecv, 
	size_t &RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData);
size_t HTTP_CONNECT_TCP_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::unique_ptr<uint8_t[]> &OriginalRecv, 
	size_t &RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData);

//Request.h
#if defined(PLATFORM_WIN)
bool FirewallTest(
	const uint16_t Protocol, 
	ssize_t &ErrorCode);
#endif
#if defined(ENABLE_PCAP)
bool LoadBufferEvent_DomainTest(
	EVENT_TABLE_TRANSMISSION_ONCE *EventArgument_Domain);
bool TestRequest_Domain(
	const uint16_t Protocol);
bool TestRequest_ICMP(
	const uint16_t Protocol);
#endif
size_t TCP_RequestSingle(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData, 
	const uint16_t QueryType, 
	const SOCKET_DATA * const LocalSocketData);
size_t TCP_RequestMultiple(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol_Network, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA * const LocalSocketData);
#if defined(ENABLE_PCAP)
size_t UDP_RequestSingle(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	const uint16_t QueryType, 
	const std::string * const DomainString_Original, 
	const std::string * const DomainString_Request, 
	const SOCKET_DATA * const LocalSocketData
//	size_t *EDNS_Length
);
size_t UDP_RequestMultiple(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol_Network, 
	const uint16_t Protocol_Transport, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	const uint16_t QueryType, 
	const std::string * const DomainString_Original, 
	const std::string * const DomainString_Request, 
	const SOCKET_DATA * const LocalSocketData
//	size_t *EDNS_Length
);
#endif
size_t UDP_CompleteRequestSingle(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData, 
	const uint16_t QueryType, 
	const SOCKET_DATA * const LocalSocketData);
size_t UDP_CompleteRequestMultiple(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA * const LocalSocketData);

//Service.h
bool CheckProcessExists(
	void);
#if defined(PLATFORM_WIN)
BOOL WINAPI SignalHandler(
	const DWORD ControlType);
VOID WINAPI ServiceMain(
	DWORD argc, 
	LPTSTR *argv);
bool FlushDomainCache_MailslotListener(
	void);
bool WINAPI FlushDomainCache_MailslotSender(
	const wchar_t * const Domain);
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
void SignalHandler(
	const int Signal);
bool FlushDomainCache_PipeListener(
	void);
bool FlushDomainCache_PipeSender(
	const uint8_t * const Domain);
#endif
void FlushDomainCache_Main(
	const uint8_t * const Domain);

//TransportSecurity.h
#if defined(ENABLE_TLS)
#if defined(PLATFORM_WIN)
bool SSPI_SChannelInitializtion(
	SSPI_HANDLE_TABLE &SSPI_Handle);
bool SSPI_Handshake(
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList);
bool TLS_TransportSerial(
	const REQUEST_PROCESS_TYPE RequestType, 
	const size_t PacketMinSize, 
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList);
bool SSPI_ShutdownConnection(
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<ssize_t> &ErrorCodeList);
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
void OpenSSL_LibraryInit(
	bool IsLoad);
bool OpenSSL_CTX_Initializtion(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX);
bool OpenSSL_BIO_Initializtion(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX);
bool OpenSSL_Handshake(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX);
bool TLS_TransportSerial(
	const REQUEST_PROCESS_TYPE RequestType, 
	const size_t PacketMinSize, 
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList);
bool OpenSSL_ShutdownConnection(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX);
#endif
#endif
#endif
