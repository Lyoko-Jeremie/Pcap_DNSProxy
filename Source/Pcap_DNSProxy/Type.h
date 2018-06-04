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


#ifndef PCAP_DNSPROXY_TYPE_H
#define PCAP_DNSPROXY_TYPE_H

#include "Definition.h"

//////////////////////////////////////////////////
// Type definitions
// 
typedef enum class _huffman_return_type_
{
	NONE, 
	ERROR_OVERFLOW, 
	ERROR_TRUNCATED, 
	ERROR_EOS, 
	ERROR_BAD_PREFIX
}HUFFMAN_RETURN_TYPE;
typedef enum class _address_compare_type_
{
	NONE, 
	LESS, 
	EQUAL, 
	GREATER
}ADDRESS_COMPARE_TYPE;
typedef enum class _read_text_type_
{
	PARAMETER_NORMAL, 
	PARAMETER_MONITOR, 
	HOSTS, 
	IPFILTER, 
#if defined(ENABLE_LIBSODIUM)
	DNSCURVE_DATABASE, 
	DNSCURVE_MONITOR
#endif
}READ_TEXT_TYPE;
typedef enum class _log_level_type_
{
	LEVEL_0,                                          //Disable log printing
	LEVEL_1,                                          //Failed messages
	LEVEL_2,                                          //Base error messages
	LEVEL_3,                                          //All error messages
//	LEVEL_4,                                          //Reserved
//	LEVEL_5                                           //Reserved
}LOG_LEVEL_TYPE;
#define DEFAULT_LOG_LEVEL                             LOG_LEVEL_TYPE::LEVEL_3
#define LOG_LEVEL_MAXNUM                              LOG_LEVEL_TYPE::LEVEL_3
typedef enum class _log_error_type_
{
	NONE, 
	NOTICE,                                           //Notice Message
	SYSTEM,                                           //System Error
	PARAMETER,                                        //Parameter Error
	IPFILTER,                                         //IPFilter Error
	HOSTS,                                            //Hosts Error
	NETWORK,                                          //Network Error
#if defined(ENABLE_PCAP)
	PCAP,                                             //Pcap Error
#endif
#if defined(ENABLE_LIBSODIUM)
	DNSCURVE,                                         //DNSCurve Error
#endif
	SOCKS,                                            //SOCKS Error
	HTTP_CONNECT,                                     //HTTP CONNECT Error
#if defined(ENABLE_TLS)
	TLS                                               //TLS Error
#endif
}LOG_ERROR_TYPE;
typedef enum _alternate_swap_type_
{
	ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6, 
	ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4, 
	ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV6, 
	ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV4, 
	ALTERNATE_SWAP_TYPE_LOCAL_TCP_IPV6, 
	ALTERNATE_SWAP_TYPE_LOCAL_TCP_IPV4, 
	ALTERNATE_SWAP_TYPE_LOCAL_UDP_IPV6, 
	ALTERNATE_SWAP_TYPE_LOCAL_UDP_IPV4, 
#if defined(ENABLE_LIBSODIUM)
	ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV6, 
	ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV4, 
	ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV6, 
	ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV4
#endif
}ALTERNATE_SWAP_TYPE;
typedef enum class _dns_cache_type_
{
	NONE, 
	BOTH, 
	TIMER, 
	QUEUE
}DNS_CACHE_TYPE;
typedef enum class _hosts_type_
{
	NONE, 
	WHITE, 
	BANNED, 
	NORMAL, 
	LOCAL, 
	CNAME, 
	SOURCE
}HOSTS_TYPE;
typedef enum class _listen_mode_
{
	PROXY, 
	PRIVATE, 
	SERVER, 
	CUSTOM
}LISTEN_MODE;
typedef enum class _listen_protocol_network_
{
	BOTH, 
	IPV6, 
	IPV4
}LISTEN_PROTOCOL_NETWORK;
typedef enum class _listen_protocol_transport_
{
	BOTH, 
	TCP, 
	UDP
}LISTEN_PROTOCOL_TRANSPORT;
typedef enum _network_layer_type_
{
	NETWORK_LAYER_TYPE_IPV6, 
	NETWORK_LAYER_TYPE_IPV4
}NETWORK_LAYER_TYPE;
typedef enum class _request_mode_network_
{
	BOTH, 
	IPV6, 
	IPV4
}REQUEST_MODE_NETWORK;
typedef enum class _request_mode_transport_
{
	UDP, 
	TCP, 
	FORCE_UDP, 
	FORCE_TCP
}REQUEST_MODE_TRANSPORT;
typedef enum class _request_mode_direct_
{
	NONE, 
	BOTH, 
	IPV6, 
	IPV4
}REQUEST_MODE_DIRECT;
typedef enum class _request_mode_test_
{
	BOTH, 
	TCP, 
	UDP
}REQUEST_MODE_TEST;
typedef enum class _socket_setting_type
{
//	CHECKSUM_IPV6, 
	CLOSE, 
	DO_NOT_FRAGMENT, 
	HOP_LIMITS_IPV6, 
	HOP_LIMITS_IPV4, 
	INVALID_CHECK, 
	NON_BLOCKING_MODE, 
	REUSE, 
	TCP_FAST_OPEN, 
	TCP_NO_DELAY, 
//	TCP_KEEP_ALIVE, 
	TIMEOUT, 
	UDP_BLOCK_RESET
}SOCKET_SETTING_TYPE;
typedef enum class _request_process_type_
{
	NONE, 
	LOCAL_NORMAL, 
	LOCAL_IN_WHITE, 
	DIRECT, 
	TCP_NORMAL, 
	TCP_WITHOUT_REGISTER, 
	SOCKS_MAIN, 
	SOCKS_CLIENT_SELECTION, 
	SOCKS_USER_AUTH, 
	SOCKS_4_COMMAND_REPLY, 
	SOCKS_5_COMMAND_REPLY, 
	HTTP_CONNECT_MAIN, 
	HTTP_CONNECT_1, 
	HTTP_CONNECT_2, 
	HTTP_CONNECT_SHUTDOWN, 
#if defined(ENABLE_TLS)
	TLS_HANDSHAKE, 
	TLS_TRANSPORT, 
	TLS_SHUTDOWN, 
#endif
#if defined(ENABLE_LIBSODIUM)
	DNSCURVE_MAIN, 
	DNSCURVE_SIGN, 
#endif
	UDP_NORMAL, 
	UDP_WITHOUT_REGISTER
}REQUEST_PROCESS_TYPE;
#if defined(ENABLE_LIBSODIUM)
typedef enum class _dnscurve_server_type_
{
	NONE, 
	MAIN_IPV6, 
	MAIN_IPV4, 
	ALTERNATE_IPV6, 
	ALTERNATE_IPV4
}DNSCURVE_SERVER_TYPE;
#endif
typedef enum class _http_version_selection_
{
	VERSION_AUTO, 
	VERSION_1, 
	VERSION_2
}HTTP_VERSION_SELECTION;
#if defined(ENABLE_TLS)
typedef enum class _tls_version_selection
{
	VERSION_AUTO, 
	VERSION_1_0, 
	VERSION_1_1, 
	VERSION_1_2, 
	VERSION_1_3
}TLS_VERSION_SELECTION;
#if defined(PLATFORM_WIN)
	#define SSPI_SECURE_BUFFER_NUM                    4U
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	#define OPENSSL_RETURN_FAILURE                    0
	#define OPENSSL_RETURN_SUCCESS                    1
	#define OPENSSL_SET_NON_BLOCKING                  1
	#define OPENSSL_VERSION_1_0_1                     0x10001000L
	#define OPENSSL_VERSION_1_0_2                     0x10002000L
	#define OPENSSL_VERSION_1_1_0                     0x10100000L
	#define OPENSSL_STATIC_BUFFER_SIZE                256U
	#define OPENSSL_CIPHER_LIST_COMPATIBILITY         ("HIGH:!SSLv2:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")
	#define OPENSSL_CIPHER_LIST_STRONG                ("HIGH:!SSLv2:!SSLv3:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")
#endif
#endif


//////////////////////////////////////////////////
// Main structures and classes
// 
//File Data structure
typedef struct _file_data_
{
	std::wstring                         FileName;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::string                          MBS_FileName;
#endif
	time_t                               ModificationTime;
}FileData, FILE_DATA;

//Socket Data structure
typedef struct _socket_data_
{
	SYSTEM_SOCKET                        Socket;
	sockaddr_storage                     SockAddr;
	socklen_t                            AddrLen;
}SocketData, SOCKET_DATA;

//Socket Register Data structure
typedef std::pair<SYSTEM_SOCKET, uint64_t> SocketRegisterData, SOCKET_REGISTER_DATA;

//Address Prefix Block structure
typedef std::pair<sockaddr_storage, size_t> AddressPrefixBlock, ADDRESS_PREFIX_BLOCK;

//Address Union Data structure
typedef union _address_union_data_
{
	sockaddr_storage                     Storage;
	sockaddr_in6                         IPv6;
	sockaddr_in                          IPv4;
}AddressUnionData, ADDRESS_UNION_DATA;

//DNS Server Data structure
typedef struct _dns_server_data_
{
//Server address block
	ADDRESS_UNION_DATA                   AddressData;

//Server packet status block
#if defined(ENABLE_PCAP)
	struct _server_packet_status_
	{
	//Network layer status
		union _network_layer_status_
		{
		//IPv6 header status
			struct _ipv6_header_status_
			{
				uint32_t                             VersionTrafficFlow;
				uint8_t                              HopLimit_StaticLoad;
				uint8_t                              HopLimit_DynamicMark;
			}IPv6_HeaderStatus;

		//IPv4 header status
			struct _ipv4_header_status_
			{
				uint8_t                              IHL;
				uint8_t                              DSCP_ECN;
				uint16_t                             ID;
				uint16_t                             Flags;
				uint8_t                              TTL_StaticLoad;
				uint8_t                              TTL_DynamicMark;
			}IPv4_HeaderStatus;
		}NetworkLayerStatus;

	//Application layer status
		struct _application_layer_status_
		{
			uint16_t                             DNS_Header_Flags;
			bool                                 IsNeedCheck_EDNS;
			uint16_t                             EDNS_UDP_PayloadSize;
			uint8_t                              EDNS_Version;
			uint16_t                             EDNS_Z_Field;
			uint16_t                             EDNS_DataLength;
		}ApplicationLayerStatus;

	//Detail of server
		bool                                 IsMarkDetail;
	}ServerPacketStatus;
#endif
}DNSServerData, DNS_SERVER_DATA;

//Socket Selecting Serial Data structure
typedef struct _socket_selecting_serial_data_
{
	std::unique_ptr<uint8_t[]>           SendBuffer;
	size_t                               SendSize;
	size_t                               SendLen;
	std::unique_ptr<uint8_t[]>           RecvBuffer;
	size_t                               RecvSize;
	size_t                               RecvLen;
	bool                                 IsPacketDone;
	bool                                 IsSendOnly;
}SocketSelectingSerialData, SOCKET_SELECTING_SERIAL_DATA;

//DNS Packet Data structure
typedef struct _dns_packet_data_
{
//Packet attributes block
	uint8_t                                                    *Buffer;
	size_t                                                     BufferSize;
	size_t                                                     Length;
	ADDRESS_UNION_DATA                                         LocalTarget;
	uint16_t                                                   Protocol;
	uint16_t                                                   QueryType;
	bool                                                       IsLocalRequest;
	bool                                                       IsLocalInBlack;
	bool                                                       IsLocalInWhite;
//Packet structure block
	size_t                                                     Records_QuestionLen;
	size_t                                                     Records_AnswerCount;
	size_t                                                     Records_AuthorityCount;
	size_t                                                     Records_AdditionalCount;
	std::vector<size_t>                                        Records_Location;
	std::vector<size_t>                                        Records_Length;
	size_t                                                     EDNS_Location;
	size_t                                                     EDNS_Length;
}DNSPacketData, DNS_PACKET_DATA;

//DNS Cache Data structure
typedef struct _dns_cache_data_
{
	std::string                          Domain;
	std::unique_ptr<uint8_t[]>           Response;
	size_t                               Length;
	uint64_t                             ClearCacheTime;
	uint16_t                             RecordType;
	ADDRESS_UNION_DATA                   ForAddress;
}DNSCacheData, DNS_CACHE_DATA;

//Monitor Queue Data structure
typedef std::pair<DNS_PACKET_DATA, SOCKET_DATA> MonitorQueueData, MONITOR_QUEUE_DATA;

//DNSCurve Server Data structure
#if defined(ENABLE_LIBSODIUM)
typedef struct _dnscurve_server_data_
{
	ADDRESS_UNION_DATA                   AddressData;
	uint8_t                              *ProviderName;          //Server Provider Name
	uint8_t                              *PrecomputationKey;     //DNSCurve Precomputation Keys
	uint8_t                              *ServerPublicKey;       //Server Public Keys
	uint8_t                              *ServerFingerprint;     //Server Fingerprints
	uint8_t                              *ReceiveMagicNumber;    //Receive Magic Number, same as from server
	uint8_t                              *SendMagicNumber;       //Server Magic Number, send to server.
}DNSCurveServerData, DNSCURVE_SERVER_DATA;
#endif

//Class definitions
//Configuration class
typedef class ConfigurationTable
{
//Parameters from configure files
public:
//[Base] block
	size_t                               Version_Major;
	size_t                               Version_Minor;
	size_t                               FileRefreshTime;
	size_t                               LargeBufferSize;
//[Log] block
	LOG_LEVEL_TYPE                       PrintLogLevel;
	size_t                               LogMaxSize;
//[Listen] block
	bool                                 IsProcessUnique;
#if defined(ENABLE_PCAP)
	bool                                 IsPcapCapture;
	std::vector<std::string>             *PcapDevicesBlacklist;
	size_t                               PcapReadingTimeout;
#endif
	LISTEN_MODE                          OperationMode;
	LISTEN_PROTOCOL_NETWORK              ListenProtocol_Network;
	LISTEN_PROTOCOL_TRANSPORT            ListenProtocol_Transport;
	std::vector<uint16_t>                *ListenPort;
	bool                                 IsIPFilterTypePermit;
	size_t                               IPFilterLevel;
	bool                                 IsAcceptTypePermit;
	std::vector<uint16_t>                *AcceptTypeList;
//[DNS] block
	REQUEST_MODE_NETWORK                 RequestMode_Network;
	REQUEST_MODE_TRANSPORT               RequestMode_Transport;
	bool                                 RequestMode_IsAccordingType;
	REQUEST_MODE_DIRECT                  DirectRequest_Protocol;
	DNS_CACHE_TYPE                       DNS_CacheType;
	size_t                               DNS_CacheParameter;
	size_t                               DNS_CacheSinglePrefix_IPv6;
	size_t                               DNS_CacheSinglePrefix_IPv4;
	uint32_t                             HostsDefaultTTL;
//[Local DNS] block
	REQUEST_MODE_NETWORK                 LocalProtocol_Network;
	REQUEST_MODE_TRANSPORT               LocalProtocol_Transport;
	bool                                 LocalProtocol_IsAccordingType;
	bool                                 IsLocalHosts;
	bool                                 IsLocalRouting;
	bool                                 IsLocalForce;
//[Addresses] block
	std::vector<sockaddr_storage>        *ListenAddress_IPv6;
	std::vector<sockaddr_storage>        *ListenAddress_IPv4;
	ADDRESS_PREFIX_BLOCK                 *LocalMachineSubnet_IPv6;
	ADDRESS_PREFIX_BLOCK                 *LocalMachineSubnet_IPv4;
	DNS_SERVER_DATA                      Target_Server_Main_IPv6;
	DNS_SERVER_DATA                      Target_Server_Alternate_IPv6;
	DNS_SERVER_DATA                      Target_Server_Main_IPv4;
	DNS_SERVER_DATA                      Target_Server_Alternate_IPv4;
	ADDRESS_UNION_DATA                   Target_Server_Local_Main_IPv6;
	ADDRESS_UNION_DATA                   Target_Server_Local_Alternate_IPv6;
	ADDRESS_UNION_DATA                   Target_Server_Local_Main_IPv4;
	ADDRESS_UNION_DATA                   Target_Server_Local_Alternate_IPv4;
	std::vector<DNS_SERVER_DATA>         *Target_Server_IPv6_Multiple;
	std::vector<DNS_SERVER_DATA>         *Target_Server_IPv4_Multiple;
//[Values] block
	size_t                               ThreadPoolBaseNum;
	size_t                               ThreadPoolMaxNum;
	size_t                               ThreadPoolResetTime;
	size_t                               QueueResetTime;
	size_t                               EDNS_PayloadSize;
#if defined(PLATFORM_WIN)
	DWORD                                PacketHopLimits_IPv6_Begin;
	DWORD                                PacketHopLimits_IPv6_End;
	DWORD                                PacketHopLimits_IPv4_Begin;
	DWORD                                PacketHopLimits_IPv4_End;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	int                                  PacketHopLimits_IPv6_Begin;
	int                                  PacketHopLimits_IPv6_End;
	int                                  PacketHopLimits_IPv4_Begin;
	int                                  PacketHopLimits_IPv4_End;
#endif
#if defined(ENABLE_PCAP)
	uint8_t                              HopLimitsFluctuation;
#endif
#if defined(PLATFORM_WIN)
	DWORD                                SocketTimeout_Reliable_Once;
	DWORD                                SocketTimeout_Reliable_Serial;
	DWORD                                SocketTimeout_Unreliable_Once;
	DWORD                                SocketTimeout_Unreliable_Serial;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	timeval                              SocketTimeout_Reliable_Once;
	timeval                              SocketTimeout_Reliable_Serial;
	timeval                              SocketTimeout_Unreliable_Once;
	timeval                              SocketTimeout_Unreliable_Serial;
#endif
	size_t                               TCP_FastOpen;
	size_t                               ReceiveWaiting;
	size_t                               AlternateTimes;
	size_t                               AlternateTimeRange;
	size_t                               AlternateResetTime;
	size_t                               MultipleRequestTimes;
//[Switches] block
	bool                                 DomainCaseConversion;
	bool                                 CompressionPointerMutation;
	bool                                 CPM_PointerToHeader;
	bool                                 CPM_PointerToRR;
	bool                                 CPM_PointerToAdditional;
	bool                                 EDNS_Label;
	bool                                 EDNS_Switch_Local;
	bool                                 EDNS_Switch_SOCKS;
	bool                                 EDNS_Switch_HTTP_CONNECT;
	bool                                 EDNS_Switch_Direct;
#if defined(ENABLE_LIBSODIUM)
	bool                                 EDNS_Switch_DNSCurve;
#endif
	bool                                 EDNS_Switch_TCP;
	bool                                 EDNS_Switch_UDP;
	bool                                 EDNS_ClientSubnet_Relay;
	bool                                 DNSSEC_Request;
	bool                                 DNSSEC_ForceRecord;
	bool                                 AlternateMultipleRequest;
	bool                                 DoNotFragment_IPv4;
#if defined(ENABLE_PCAP)
	bool                                 PacketCheck_TCP;
#endif
	bool                                 PacketCheck_DNS;
	bool                                 DataCheck_Blacklist;
	bool                                 DataCheck_RRSetTTL;
//[Data] block
#if defined(ENABLE_PCAP)
	uint16_t                             ICMP_ID;
	uint16_t                             ICMP_Sequence;
	size_t                               ICMP_Speed;
	uint8_t                              *ICMP_PaddingData;
	size_t                               ICMP_PaddingLength;
	REQUEST_MODE_TEST                    DomainTest_Protocol;
	uint16_t                             DomainTest_ID;
	size_t                               DomainTest_Speed;
	uint8_t                              *DomainTest_Data;
#endif
	std::string                          *Local_FQDN_String;
	uint8_t                              *Local_FQDN_Response;
	size_t                               Local_FQDN_Length;
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	uint8_t                              *LocalServer_Response;
	size_t                               LocalServer_Length;
#endif
//[Proxy] block
	bool                                 SOCKS_Proxy;
	size_t                               SOCKS_Version;
	REQUEST_MODE_NETWORK                 SOCKS_Protocol_Network;
	REQUEST_MODE_TRANSPORT               SOCKS_Protocol_Transport;
	bool                                 SOCKS_Protocol_IsAccordingType;
	bool                                 SOCKS_UDP_NoHandshake;
	bool                                 SOCKS_Only;
	ADDRESS_UNION_DATA                   SOCKS_Address_IPv6;
	ADDRESS_UNION_DATA                   SOCKS_Address_IPv4;
	ADDRESS_UNION_DATA                   SOCKS_TargetServer;
	std::string                          *SOCKS_TargetDomain;
	uint16_t                             SOCKS_TargetDomain_Port;
	uint8_t                              *SOCKS_Username;
	size_t                               SOCKS_UsernameLength;
	uint8_t                              *SOCKS_Password;
	size_t                               SOCKS_PasswordLength;
	bool                                 HTTP_CONNECT_Proxy;
	REQUEST_MODE_NETWORK                 HTTP_CONNECT_Protocol;
	bool                                 HTTP_CONNECT_IsAccordingType;
	bool                                 HTTP_CONNECT_Only;
	ADDRESS_UNION_DATA                   HTTP_CONNECT_Address_IPv6;
	ADDRESS_UNION_DATA                   HTTP_CONNECT_Address_IPv4;
#if defined(ENABLE_TLS)
	bool                                 HTTP_CONNECT_TLS_Handshake;
	TLS_VERSION_SELECTION                HTTP_CONNECT_TLS_Version;
	bool                                 HTTP_CONNECT_TLS_Validation;
	std::wstring                         *HTTP_CONNECT_TLS_SNI;
	std::string                          *MBS_HTTP_CONNECT_TLS_SNI;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::string                          *HTTP_CONNECT_TLS_AddressString_IPv6;
	std::string                          *HTTP_CONNECT_TLS_AddressString_IPv4;
#endif
#if !defined(PLATFORM_WIN_XP)
	bool                                 HTTP_CONNECT_TLS_ALPN;
#endif
#endif
	std::string                          *HTTP_CONNECT_TargetDomain;
	HTTP_VERSION_SELECTION               HTTP_CONNECT_Version;
	std::vector<std::string>             *HTTP_CONNECT_HeaderField;
	uint8_t                              *HTTP_CONNECT_ProxyAuthorization;
	size_t                               HTTP_CONNECT_ProxyAuthorizationLength;

//[DNSCurve] block
#if defined(ENABLE_LIBSODIUM)
	bool                                 IsDNSCurve;
#endif

//Redefine operator functions
//	ConfigurationTable() = default;
	ConfigurationTable(const ConfigurationTable &) = delete;
	ConfigurationTable &operator=(const ConfigurationTable &) = delete;

//Member functions(Public)
	ConfigurationTable(
		void);
/* No need copy constructor
	ConfigurationTable(
		const ConfigurationTable &Reference);
	ConfigurationTable & operator=(
		const ConfigurationTable &Reference);
*/
	void SetToMonitorItem(
		void);
	void MonitorItemToUsing(
		ConfigurationTable * const ConfigurationParameter);
	void MonitorItemReset(
		void);
	~ConfigurationTable(
		void);

/* No need copy constructor
//Member functions(Private)
private:
	void CopyMemberOperator(
		const ConfigurationTable &Reference);
*/
}CONFIGURATION_TABLE;

//Global status class
typedef class GlobalStatus
{
public:
//Libraries initialization status
#if defined(PLATFORM_WIN)
	bool                                 IsInitialized_WinSock;
	HANDLE                               Initialized_MutexHandle;
	SECURITY_ATTRIBUTES                  Initialized_MutexSecurityAttributes;
	SECURITY_DESCRIPTOR                  Initialized_MutexSecurityDescriptor;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
#if defined(ENABLE_TLS)
	bool                                 IsInitialized_OpenSSL;
#endif
	int                                  Initialized_MutexHandle;
#endif

//Running status
	time_t                               StartupTime;
#if defined(PLATFORM_WIN)
	bool                                 IsConsole;
#elif defined(PLATFORM_LINUX)
	bool                                 IsDaemon;
#endif
	std::vector<SYSTEM_SOCKET>           *LocalListeningSocket;
	std::default_random_engine           *RandomEngine;
	uint8_t                              *DomainTable;
#if !defined(ENABLE_LIBSODIUM)
	uint8_t                              *Base64_EncodeTable;
	int8_t                               *Base64_DecodeTable;
#endif
	std::atomic<size_t>                  *ThreadRunningNum;
	std::atomic<size_t>                  *ThreadRunningFreeNum;

//Path list and file list status
	std::vector<std::wstring>            *Path_Global;
	std::wstring                         *Path_ErrorLog;
	std::vector<std::wstring>            *FileList_Hosts;
	std::vector<std::wstring>            *FileList_IPFilter;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::vector<std::string>             *MBS_Path_Global;
	std::string                          *MBS_Path_ErrorLog;
	std::vector<std::string>             *MBS_FileList_Hosts;
	std::vector<std::string>             *MBS_FileList_IPFilter;
#endif
	uint64_t                             ConfigFileModifiedTime;

//Network status
	bool                                 GatewayAvailable_IPv6;
	bool                                 GatewayAvailable_IPv4;

//Local address status
	uint8_t                              *LocalAddress_Response[NETWORK_LAYER_PARTNUM];
	size_t                               LocalAddress_Length[NETWORK_LAYER_PARTNUM];
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	std::vector<std::string>             *LocalAddress_PointerResponse[NETWORK_LAYER_PARTNUM];
#endif

//Redefine operator functions
//	GlobalStatus() = default;
	GlobalStatus(const GlobalStatus &) = delete;
	GlobalStatus & operator=(const GlobalStatus &) = delete;

//Member functions(Public)
	GlobalStatus(
		void);
/* No need copy constructor
	GlobalStatus(
		const GlobalStatus &Reference);
	GlobalStatus & operator=(
		const GlobalStatus &Reference);
*/
	~GlobalStatus(
		void);

/* No need copy constructor
//Member functions(Private)
private:
	void CopyMemberOperator(
		const GlobalStatus &Reference);
*/
}GLOBAL_STATUS;

//IP address ranges class
typedef class AddressRangeTable
{
public:
	sockaddr_storage                     Begin;
	sockaddr_storage                     End;
	size_t                               Level;

//Redefine operator functions
//	AddressRangeTable() = default;
//	AddressRangeTable(const AddressRangeTable &) = delete;
//	AddressRangeTable & operator=(const AddressRangeTable &) = delete;

//Member functions
	AddressRangeTable(
		void);
}ADDRESS_RANGE_TABLE;

//Hosts list class
typedef class HostsTable
{
public:
	std::vector<ADDRESS_PREFIX_BLOCK>    SourceList;
	std::vector<ADDRESS_UNION_DATA>      AddrOrTargetList;
	std::regex                           PatternRegex;
	std::string                          PatternOrDomainString;
	std::vector<uint16_t>                RecordTypeList;
	HOSTS_TYPE                           PermissionType;
	bool                                 PermissionOperation;
	bool                                 IsStringMatching;

//Redefine operator functions
//	HostsTable() = default;
//	HostsTable(const HostsTable &) = delete;
//	HostsTable & operator=(const HostsTable &) = delete;

//Member functions
	HostsTable(
		void);
}HOSTS_TABLE;

//Blacklist of results class
typedef class ResultBlacklistTable
{
public:
	std::vector<ADDRESS_RANGE_TABLE>     Addresses;
	std::regex                           PatternRegex;
	std::string                          PatternString;

//Redefine operator functions
//	ResultBlacklistTable() = default; //No need to set default.
//	ResultBlacklistTable(const ResultBlacklistTable &) = delete;
//	ResultBlacklistTable & operator=(const ResultBlacklistTable &) = delete;
}RESULT_BLACKLIST_TABLE;

//Address Hosts class
typedef class AddressHostsTable
{
public:
	std::vector<ADDRESS_PREFIX_BLOCK>    Address_Target;
	std::vector<ADDRESS_RANGE_TABLE>     Address_Source;

//Redefine operator functions
//	AddressHostsTable() = default; //No need to set default.
//	AddressHostsTable(const AddressHostsTable &) = delete;
//	AddressHostsTable & operator=(const AddressHostsTable &) = delete;
}ADDRESS_HOSTS_TABLE;

//Address routing table class
typedef class AddressRoutingTable
{
public:
	std::unordered_map<uint64_t, std::unordered_set<uint64_t>>   AddressRoutingList_IPv6;
	std::unordered_set<uint32_t>                                 AddressRoutingList_IPv4;
	size_t                                                       Prefix;

//Redefine operator functions
//	AddressRoutingTable() = default;
//	AddressRoutingTable(const AddressHostsTable &) = delete;
//	AddressRoutingTable & operator=(const AddressRoutingTable &) = delete;

//Member functions
	AddressRoutingTable(
		void);
}ADDRESS_ROUTING_TABLE;

//Alternate swap table class
typedef class AlternateSwapTable
{
public:
	size_t                               TimeoutTimes[ALTERNATE_SERVER_NUM];
	bool                                 IsSwap[ALTERNATE_SERVER_NUM];

//Redefine operator functions
//	AlternateSwapTable() = default;
	AlternateSwapTable(const AlternateSwapTable &) = delete;
	AlternateSwapTable & operator=(const AlternateSwapTable &) = delete;

//Member functions
	AlternateSwapTable(
		void);
}ALTERNATE_SWAP_TABLE;

//Differnet IPFilter file sets class
typedef class DiffernetFileSetIPFilter
{
public:
	std::vector<ADDRESS_RANGE_TABLE>      AddressRange;
	std::vector<RESULT_BLACKLIST_TABLE>   ResultBlacklist;
	std::vector<ADDRESS_ROUTING_TABLE>    LocalRoutingList;
	size_t                                FileIndex;

//Redefine operator functions
//	DiffernetFileSetIPFilter() = default;
//	DiffernetFileSetIPFilter(const DiffernetFileSetIPFilter &) = delete;
//	DiffernetFileSetIPFilter & operator=(const DiffernetFileSetIPFilter &) = delete;

//Member functions
	DiffernetFileSetIPFilter(
		void);
}DIFFERNET_FILE_SET_IPFILTER;

//Differnet Hosts file sets class
typedef class DiffernetFileSetHosts
{
public:
	std::vector<HOSTS_TABLE>             HostsList_Normal;
	std::vector<HOSTS_TABLE>             HostsList_Local;
	std::vector<HOSTS_TABLE>             HostsList_CNAME;
	std::vector<ADDRESS_HOSTS_TABLE>     AddressHostsList;
	size_t                               FileIndex;

//Redefine operator functions
//	DiffernetFileSetHosts() = default;
//	DiffernetFileSetHosts(const DiffernetFileSetHosts &) = delete;
//	DiffernetFileSetHosts & operator=(const DiffernetFileSetHosts &) = delete;

//Member functions
	DiffernetFileSetHosts(
		void);
}DIFFERNET_FILE_SET_HOSTS;

//Socket Selecting Once table class
typedef class SocketSelectingOnceTable
{
public:
	std::unique_ptr<uint8_t[]>           RecvBuffer;
	size_t                               RecvLen;
	bool                                 IsPacketDone;

//Redefine operator functions
//	SocketSelectingOnceTable() = default;
	SocketSelectingOnceTable(const SocketSelectingOnceTable &) = delete;
	SocketSelectingOnceTable & operator=(const SocketSelectingOnceTable &) = delete;

//Member functions
	SocketSelectingOnceTable(
		void);
}SOCKET_SELECTING_ONCE_TABLE;

#if defined(ENABLE_PCAP)
//Capture device class
typedef class CaptureDeviceTable
{
public:
	std::string                          *DeviceName;
	pcap_t                               *DeviceHandle;
	int                                  DeviceType;
	bpf_program                          BPF_Code;

//Redefine operator functions
//	CaptureDeviceTable() = default;
	CaptureDeviceTable(const CaptureDeviceTable &) = delete;
	CaptureDeviceTable & operator=(const CaptureDeviceTable &) = delete;

//Member functions
	CaptureDeviceTable(
		void);
	~CaptureDeviceTable(
		void);
}CAPTURE_DEVICE_TABLE;

//Port table class
typedef class OutputPacketTable
{
public:
	std::vector<SOCKET_DATA>             SocketData_Output;
	SOCKET_DATA                          SocketData_Input;
	size_t                               ReceiveIndex;
	uint16_t                             Protocol_Network;
	uint16_t                             Protocol_Transport;
	uint64_t                             ClearPortTime;
	size_t                               EDNS_Length;

//Redefine operator functions
//	OutputPacketTable() = default;
//	OutputPacketTable(const OutputPacketTable &) = delete;
//	OutputPacketTable & operator=(const OutputPacketTable &) = delete;

//Member functions
	OutputPacketTable(
		void);
}OUTPUT_PACKET_TABLE;
#endif

#if defined(ENABLE_LIBSODIUM)
//DNSCurve Configuration class
typedef class DNSCurveConfigurationTable
{
public:
//[DNSCurve] block
	size_t                                  DNSCurvePayloadSize;
	REQUEST_MODE_NETWORK                    DNSCurveProtocol_Network;
	REQUEST_MODE_TRANSPORT                  DNSCurveProtocol_Transport;
	bool                                    DNSCurveProtocol_IsAccordingType;
#if defined(PLATFORM_WIN)
	DWORD                                   DNSCurve_SocketTimeout_Reliable;
	DWORD                                   DNSCurve_SocketTimeout_Unreliable;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	timeval                                 DNSCurve_SocketTimeout_Reliable;
	timeval                                 DNSCurve_SocketTimeout_Unreliable;
#endif
	bool                                    IsEncryption;
	bool                                    IsEncryptionOnly;
	bool                                    IsClientEphemeralKey;
	size_t                                  KeyRecheckTime;
//[DNSCurve Database] block
	std::wstring                            *DatabaseName;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::string                             *MBS_DatabaseName;
#endif
	std::string                             *Database_Target_Server_Main_IPv6;
	std::string                             *Database_Target_Server_Alternate_IPv6;
	std::string                             *Database_Target_Server_Main_IPv4;
	std::string                             *Database_Target_Server_Alternate_IPv4;
	std::vector<std::vector<std::string>>   *Database_LineData;
//[DNSCurve Addresses] block
	uint8_t                                 *Client_PublicKey;
	uint8_t                                 *Client_SecretKey;
	DNSCURVE_SERVER_DATA                    DNSCurve_Target_Server_Main_IPv6;
	DNSCURVE_SERVER_DATA                    DNSCurve_Target_Server_Alternate_IPv6;
	DNSCURVE_SERVER_DATA                    DNSCurve_Target_Server_Main_IPv4;
	DNSCURVE_SERVER_DATA                    DNSCurve_Target_Server_Alternate_IPv4;

//Redefine operator functions
//	DNSCurveConfigurationTable() = default;
	DNSCurveConfigurationTable(const DNSCurveConfigurationTable &) = delete;
	DNSCurveConfigurationTable & operator=(const DNSCurveConfigurationTable &) = delete;

//Member functions(Public)
	DNSCurveConfigurationTable(
		void);
/* No need copy constructor
	DNSCurveConfigurationTable(
		const DNSCurveConfigurationTable &Reference);
	DNSCurveConfigurationTable & operator=(
		const DNSCurveConfigurationTable &Reference);
*/
	void SetToMonitorItem(
		void);
	void MonitorItemToUsing(
		DNSCurveConfigurationTable * const DNSCurveConfigurationParameter);
	void MonitorItemReset(
		void);
	~DNSCurveConfigurationTable(
		void);

/* No need copy constructor
//Member functions(Private)
private:
	void CopyMemberOperator(
		const DNSCurveConfigurationTable &Reference);
*/
}DNSCURVE_CONFIGURATION_TABLE;

//DNSCurve Socket Selecting table class
typedef class DNSCurveSocketSelectingTable
{
public:
	DNSCURVE_SERVER_TYPE                 ServerType;
	uint8_t                              *PrecomputationKey;
	uint8_t                              *ReceiveMagicNumber;
	uint8_t                              *SendBuffer;
	size_t                               SendSize;
	std::unique_ptr<uint8_t[]>           RecvBuffer;
	size_t                               RecvLen;
	bool                                 IsPacketDone;

//Redefine operator functions
//	DNSCurveSocketSelectingTable() = default;
/* std::move is used to indicate that an object t may be "moved from", i.e. allowing the efficient transfer of resources from t to another object.
	DNSCurveSocketSelectingTable(const DNSCurveSocketSelectingTable &) = delete;
	DNSCurveSocketSelectingTable & operator=(const DNSCurveSocketSelectingTable &) = delete;
*/

//Member functions
	DNSCurveSocketSelectingTable(
		void);
}DNSCURVE_SOCKET_SELECTING_TABLE;
#endif

#if defined(ENABLE_TLS)
#if defined(PLATFORM_WIN)
//SSPI Handle class
typedef class SSPIHandleTable
{
public:
	CredHandle                           ClientCredentials;
	CtxtHandle                           ContextHandle;
	SecPkgContext_StreamSizes            StreamSizes;
	DWORD                                InputFlags;
	SECURITY_STATUS                      LastReturnValue;

//Redefine operator functions
//	SSPIHandleTable() = default;
	SSPIHandleTable(const SSPIHandleTable &) = delete;
	SSPIHandleTable & operator=(const SSPIHandleTable &) = delete;

//Member functions
	SSPIHandleTable(
		void);
	~SSPIHandleTable(
		void);
}SSPI_HANDLE_TABLE;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//OpenSSL Context class
typedef class OpenSSLContextTable
{
public:
	SSL_CTX                              *MethodContext;
	BIO                                  *SessionBIO;
	SSL                                  *SessionData;
	uint16_t                             Protocol_Network;
	uint16_t                             Protocol_Transport;
	SYSTEM_SOCKET                        Socket;
	std::string                          AddressString;

//Redefine operator functions
//	OpenSSLContextTable() = default;
	OpenSSLContextTable(const OpenSSLContextTable &) = delete;
	OpenSSLContextTable & operator=(const OpenSSLContextTable &) = delete;

//Member functions
	OpenSSLContextTable(
		void);
	~OpenSSLContextTable(
		void);
}OPENSSL_CONTEXT_TABLE;
#endif
#endif
#endif
