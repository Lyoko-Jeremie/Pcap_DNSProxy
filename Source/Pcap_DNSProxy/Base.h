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


#ifndef PCAP_DNSPROXY_BASE_H
#define PCAP_DNSPROXY_BASE_H

#include "Template.h"

//////////////////////////////////////////////////
// Main functions
// 
//Base.cpp
bool CheckEmptyBuffer(
	const void * const Buffer, 
	const size_t Length);
bool MBS_To_WCS_String(
	const uint8_t * const Buffer, 
	const size_t MaxLen, 
	std::wstring &Target);
bool WCS_To_MBS_String(
	const wchar_t * const Buffer, 
	const size_t MaxLen, 
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
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
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

//DNSCurve.h
#if defined(ENABLE_LIBSODIUM)
bool DNSCurveVerifyKeypair(
	const uint8_t * const PublicKey, 
	const uint8_t * const SecretKey);
PDNSCURVE_SERVER_DATA DNSCurveSelectSignatureTargetSocket(
	const uint16_t Protocol, 
	const bool IsAlternate, 
	size_t &ServerType, 
	std::vector<SOCKET_DATA> &SocketDataList);
bool DNSCurvePacketTargetSetting(
	const size_t ServerType, 
	DNSCURVE_SERVER_DATA ** const PacketTarget);
bool DNSCurvePrecomputationKeySetting(
	uint8_t * const PrecomputationKey, 
	uint8_t * const Client_PublicKey, 
	const uint8_t * const ServerFingerprint);
void DNSCurveSocketPrecomputation(
	const uint16_t Protocol, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	const size_t RecvSize, 
	uint8_t ** const PrecomputationKey, 
	uint8_t ** const Alternate_PrecomputationKey, 
	DNSCURVE_SERVER_DATA ** const PacketTarget, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<DNSCURVE_SOCKET_SELECTING_DATA> &SocketSelectingList, 
	std::shared_ptr<uint8_t> &SendBuffer, 
	size_t &DataLength, 
	std::shared_ptr<uint8_t> &Alternate_SendBuffer, 
	size_t &Alternate_DataLength);
size_t DNSCurvePacketEncryption(
	const uint16_t Protocol, 
	const uint8_t * const SendMagicNumber, 
	const uint8_t * const Client_PublicKey, 
	const uint8_t * const PrecomputationKey, 
	const uint8_t * const OriginalSend, 
	const size_t Length, 
	uint8_t * const SendBuffer, 
	const size_t SendSize);
ssize_t DNSCurvePacketDecryption(
	const uint8_t * const ReceiveMagicNumber, 
	const uint8_t * const PrecomputationKey, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const ssize_t Length);
bool DNSCruveGetSignatureData(
	const uint8_t * const Buffer, 
	const size_t ServerType);

//DNSCurveRequest.h
void DNSCurveInit(
	void);
size_t DNSCurve_TCP_RequestSingle(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize);
size_t DNSCurve_TCP_RequestMultiple(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize);
size_t DNSCurve_UDP_RequestSingle(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize);
size_t DNSCurve_UDP_RequestMultiple(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize);
#endif

//Monitor.h
void MonitorLauncher(
	void);
bool MonitorInit(
	void);
bool TCP_ReceiveProcess(
	MONITOR_QUEUE_DATA MonitorQueryData, 
	uint8_t * const OriginalRecv, 
	size_t RecvSize);
void AlternateServerMonitor(
	void);
void NetworkInformationMonitor(
	void);

//Network.h
#if defined(PLATFORM_WIN)
bool FirewallTest(
	const uint16_t Protocol, 
	ssize_t &ErrorCode);
#endif
bool SocketSetting(
	const SYSTEM_SOCKET Socket, 
	const size_t SettingType, 
	const bool IsPrintError, 
	void * const DataPointer);
size_t SelectTargetSocketSingle(
	const size_t RequestType, 
	const uint16_t Protocol, 
	SOCKET_DATA * const TargetSocketData, 
	void ** const DNSCurvePacketTarget, 
	bool ** const IsAlternate, 
	size_t ** const AlternateTimeoutTimes, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData);
bool SelectTargetSocketMultiple(
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &TargetSocketDataList);
size_t SocketConnecting(
	const uint16_t Protocol, 
	const SYSTEM_SOCKET Socket, 
	const sockaddr * const SockAddr, 
	const socklen_t AddrLen, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize);
ssize_t SocketSelectingOnce(
	const size_t RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	void * const OriginalDNSCurveSocketSelectingList, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	ssize_t * const ErrorCode);
size_t SocketSelectingSerial(
	const size_t RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList);
void MarkPortToList(
	const uint16_t Protocol, 
	const SOCKET_DATA * const LocalSocketData, 
	std::vector<SOCKET_DATA> &SocketDataList);

//PacketData.h
uint16_t GetChecksum(
	const uint16_t *Buffer, 
	const size_t Length);
uint16_t GetChecksum_ICMPv6(
	const uint8_t * const Buffer, 
	const size_t Length, 
	const in6_addr &Destination, 
	const in6_addr &Source);
uint16_t GetChecksum_TCP_UDP(
	const uint16_t Protocol_Network, 
	const uint16_t Protocol_Transport, 
	const uint8_t * const Buffer, 
	const size_t Length);
size_t AddLengthDataToHeader(
	uint8_t * const Buffer, 
	const size_t RecvLen, 
	const size_t MaxLen);
size_t StringToPacketQuery(
	const uint8_t * const FName, 
	uint8_t * const TName);
size_t PacketQueryToString(
	const uint8_t * const TName, 
	std::string &FName);
size_t MarkWholePacketQuery(
	const uint8_t * const Packet, 
	const size_t Length, 
	const uint8_t * const TName, 
	const size_t TNameIndex, 
	std::string &FName);
void MakeRamdomDomain(
	uint8_t * const Buffer);
void MakeDomainCaseConversion(
	uint8_t * const Buffer);
size_t Add_EDNS_To_Additional_RR(
	uint8_t * const Buffer, 
	const size_t Length, 
	const size_t MaxLen, 
	const SOCKET_DATA * const LocalSocketData);
bool Add_EDNS_To_Additional_RR(
	DNS_PACKET_DATA * const Packet, 
	const SOCKET_DATA * const LocalSocketData);
size_t MakeCompressionPointerMutation(
	uint8_t * const Buffer, 
	const size_t Length);

//PrintLog.h
bool PrintError(
	const size_t ErrorLevel, 
	const size_t ErrorType, 
	const wchar_t * const Message, 
	const ssize_t ErrorCode, 
	const wchar_t * const FileName, 
	const size_t Line);
void PrintToScreen(
	const bool IsInnerLock, 
	const wchar_t * const Format, 
	...
);
void ErrorCodeToMessage(
	const size_t ErrorType, 
	const ssize_t ErrorCode, 
	std::wstring &Message);
void ReadTextPrintLog(
	const size_t InputType, 
	const size_t FileIndex, 
	const size_t Line);
#if defined(ENABLE_LIBSODIUM)
void DNSCurvePrintLog(
	const size_t ServerType, 
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
	const HostsTable &HostsTableIter, 
	dns_hdr * const DNS_Header, 
	dns_qry * const DNS_Query, 
	bool * const IsLocal);
size_t CheckHostsProcess(
	DNS_PACKET_DATA * const Packet, 
	uint8_t * const Result, 
	const size_t ResultSize, 
	const SOCKET_DATA &LocalSocketData);
bool SendToRequester(
	const uint16_t Protocol, 
	uint8_t * const RecvBuffer, 
	const size_t RecvSize, 
	const size_t MaxLen, 
	const SOCKET_DATA &LocalSocketData);
bool MarkDomainCache(
	const uint8_t * const Buffer, 
	const size_t Length);

//Protocol.h
bool AddressStringToBinary(
	const uint16_t Protocol, 
	const uint8_t * const AddrString, 
	void * const OriginalAddr, 
	ssize_t * const ErrorCode);
bool BinaryToAddressString(
	const uint16_t Protocol, 
	const void * const OriginalAddr, 
	void * const AddressString, 
	const size_t StringSize, 
	ssize_t * const ErrorCode);
size_t AddressesComparing(
	const uint16_t Protocol, 
	const void * const OriginalAddrBegin, 
	const void * const OriginalAddrEnd);
bool CheckSpecialAddress(
	const uint16_t Protocol, 
	void * const Addr, 
	const bool IsPrivateUse, 
	const uint8_t * const Domain);
size_t CheckQueryNameLength(
	const uint8_t * const Buffer);
bool CheckQueryData(
	DNS_PACKET_DATA * const Packet, 
	uint8_t * const SendBuffer, 
	const size_t SendSize, 
	const SOCKET_DATA &LocalSocketData);
bool CheckConnectionStreamFin(
	const size_t RequestType, 
	const uint8_t * const Stream, 
	const size_t Length);
size_t CheckResponseData(
	const size_t ResponseType, 
	uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize, 
	bool * const IsMarkHopLimit);

//Proxy.h
size_t SOCKS_TCP_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::shared_ptr<uint8_t> &OriginalRecv, 
	size_t &RecvSize);
size_t SOCKS_UDP_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::shared_ptr<uint8_t> &OriginalRecv, 
	size_t &RecvSize);
size_t HTTP_CONNECT_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::shared_ptr<uint8_t> &OriginalRecv, 
	size_t &RecvSize);

//Request.h
#if defined(ENABLE_PCAP)
bool DomainTestRequest(
	const uint16_t Protocol);
bool ICMP_TestRequest(
	const uint16_t Protocol);
#endif
size_t TCP_RequestSingle(
	const size_t RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData);
size_t TCP_RequestMultiple(
	const size_t RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize);
#if defined(ENABLE_PCAP)
size_t UDP_RequestSingle(
	const size_t RequestType, 
	const uint16_t Protocol, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA * const LocalSocketData);
size_t UDP_RequestMultiple(
	const size_t RequestType, 
	const uint16_t Protocol, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA * const LocalSocketData);
#endif
size_t UDP_CompleteRequestSingle(
	const size_t RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData);
size_t UDP_CompleteRequestMultiple(
	const size_t RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize);

//Service.h
#if defined(PLATFORM_WIN)
BOOL WINAPI CtrlHandler(
	const DWORD fdwCtrlType);
size_t WINAPI ServiceMain(
	DWORD argc, 
	LPTSTR *argv);
bool Flush_DNS_MailSlotMonitor(
	void);
bool WINAPI Flush_DNS_MailSlotSender(
	const wchar_t * const Domain);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool Flush_DNS_FIFO_Monitor(
	void);
bool Flush_DNS_FIFO_Sender(
	const uint8_t * const Domain);
#endif
void FlushDNSCache(
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
	const size_t PacketMinSize, 
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList);
bool SSPI_ShutdownConnection(
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<ssize_t> &ErrorCodeList);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
void OpenSSL_Library_Init(
	bool IsLoad);
bool OpenSSL_CTX_Initializtion(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX);
bool OpenSSL_BIO_Initializtion(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX);
bool OpenSSL_Handshake(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX);
bool TLS_TransportSerial(
	const size_t RequestType, 
	const size_t PacketMinSize, 
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList);
bool OpenSSL_ShutdownConnection(
	OPENSSL_CONTEXT_TABLE &OpenSSL_CTX);
#endif
#endif
#endif
