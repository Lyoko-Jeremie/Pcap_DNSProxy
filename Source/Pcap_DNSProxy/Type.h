// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on packet capturing
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


#ifndef PCAP_DNSPROXY_TYPE_H
#define PCAP_DNSPROXY_TYPE_H

#include "Definition.h"

//////////////////////////////////////////////////
// Type definition
// 
typedef enum class _arithmetic_compare_type_
{
	NONE, 
	LESS, 
	EQUAL, 
	GREATER
}ARITHMETIC_COMPARE_TYPE;

typedef enum class _huffman_return_type_
{
	NONE, 
	ERROR_OVERFLOW, 
	ERROR_TRUNCATED, 
	ERROR_EOS, 
	ERROR_BAD_PREFIX
}HUFFMAN_RETURN_TYPE;

typedef enum class _dns_record_section_
{
	NONE, 
//	QUESTION, 
	ANSWER, 
	AUTHORITY, 
	ADDITIONAL
}DNS_RECORD_SECTION;

typedef enum class _read_text_type_
{
	PARAMETER_NORMAL, 
	PARAMETER_MONITOR, 
	HOSTS, 
	IPFILTER, 
#if defined(ENABLE_LIBSODIUM)
	DNSCRYPT_DATABASE, 
	DNSCRYPT_MONITOR
#endif
}READ_TEXT_TYPE;

typedef enum class _log_level_type_
{
	LEVEL_0,                                          //Disable log printing
	LEVEL_1,                                          //Failed messages
	LEVEL_2,                                          //Base error messages
	LEVEL_3,                                          //All error messages
	LEVEL_4,                                          //Reserved
	LEVEL_5                                           //Reserved
}LOG_LEVEL_TYPE;
#define DEFAULT_LOG_LEVEL                             LOG_LEVEL_TYPE::LEVEL_3
#define LOG_LEVEL_MAXNUM                              LOG_LEVEL_TYPE::LEVEL_5

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
	DNSCRYPT,                                         //DNSCrypt Error
#endif
	SOCKS,                                            //SOCKS Error
	HTTP_CONNECT,                                     //HTTP CONNECT Error
#if defined(ENABLE_TLS)
	TLS                                               //TLS Error
#endif
}LOG_ERROR_TYPE;

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

typedef enum class _socket_setting_type_
{
	CHECKSUM_IPV6, 
	CLOSE, 
	DO_NOT_FRAGMENT, 
	HOP_LIMITS_IPV6, 
	HOP_LIMITS_IPV4, 
	INVALID_CHECK, 
	NON_BLOCKING_MODE, 
	REUSE, 
	TCP_FAST_OPEN_NORMAL, 
#if defined(PLATFORM_LINUX)
	TCP_FAST_OPEN_CONNECT, 
#endif
	TCP_NO_DELAY, 
	TCP_KEEP_ALIVE, 
	TIMEOUT, 
	UDP_BLOCK_RESET
}SOCKET_SETTING_TYPE;

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

typedef enum class _request_process_type_
{
	NONE, 
	LOCAL_NORMAL, 
	LOCAL_IN_WHITE, 
	DIRECT, 
	TCP_NORMAL, 
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
	DNSCRYPT_MAIN, 
	DNSCRYPT_SIGN, 
#endif
	UDP_NORMAL
}REQUEST_PROCESS_TYPE;

#if defined(ENABLE_LIBSODIUM)
typedef enum class _dnscrypt_server_type_
{
	NONE, 
	MAIN_IPV6, 
	MAIN_IPV4, 
	ALTERNATE_IPV6, 
	ALTERNATE_IPV4
}DNSCRYPT_SERVER_TYPE;
#endif

typedef enum class _http_version_selection_
{
	VERSION_AUTO, 
	VERSION_1, 
	VERSION_2
}HTTP_VERSION_SELECTION;

#if defined(ENABLE_TLS)
typedef enum class _tls_version_selection_
{
	VERSION_AUTO, 
	VERSION_1_0, 
	VERSION_1_1, 
	VERSION_1_2, 
	VERSION_1_3
}TLS_VERSION_SELECTION;
#if defined(PLATFORM_WIN)
	#define SSPI_SECURE_BUFFER_NUM                    4U
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	#define OPENSSL_RETURN_FAILURE                    0
	#define OPENSSL_RETURN_SUCCESS                    1
	#define OPENSSL_SET_NON_BLOCKING                  1
	#define OPENSSL_STATIC_BUFFER_SIZE                256U
	#define OPENSSL_CIPHER_LIST_COMPATIBILITY         ("HIGH:!aNULL:!kRSA:!PSK:!SRP:!SM2:!SM3:!SM4:!SSLv2:!SSLv3:!MD5:!RC4")
	#define OPENSSL_CIPHER_LIST_STRONG                ("HIGH:!aNULL:!kRSA:!PSK:!SRP:!SM2:!SM3:!SM4:!SSLv2:!SSLv3:!MD5:!RC4:!SHA1")
#endif
#endif


//////////////////////////////////////////////////
// Network structure definition
// 
typedef struct _dns_packet_question_
{
	std::string                          QuestionName;
	uint16_t                             QuestionType{0};
	uint16_t                             QuestionClass{0};
}DNS_PACKET_QUESTION;

typedef struct _dns_packet_record_
{
//Parameter of record
	bool                                 IsAfterExtension{false};

//Packet structure
	std::string                          RecordName;
	uint16_t                             RecordType{0};
	uint16_t                             RecordClass{0};
	uint32_t                             RecordTTL{0};
	uint16_t                             RecordLength{0};
	size_t                               RecordDataOffset{0};
}DNS_PACKET_RECORD;

typedef struct _dns_packet_extension_option_
{
	uint16_t                             OptionCode{0};
	uint16_t                             OptionLength{0};
	size_t                               OptionDataOffset{0};
}DNS_PACKET_EXTENSION_OPTION;

typedef struct _dns_packet_extension_record_
{
//Parameter of record
	DNS_RECORD_SECTION                         RecordSection{DNS_RECORD_SECTION::NONE};

//Packet structure
//	std::string                                RecordName;
	uint16_t                                   RecordType{0};
	uint16_t                                   RecordPayloadSize{0};
	uint8_t                                    RecordExtendRCode{0};
	uint8_t                                    RecordVersion{0};
	uint16_t                                   RecordFlags{0};
	uint16_t                                   RecordLength{0};
	std::vector<DNS_PACKET_EXTENSION_OPTION>   RecordData;
}DNS_PACKET_EXTENSION_RECORD;


//////////////////////////////////////////////////
// Internal structure definition
// 
typedef struct _file_data_
{
	std::wstring                         FileName_WCS;
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::string                          FileName_MBS;
#endif
	time_t                               ModificationTime{0};
}FileData, FILE_DATA;

typedef union _address_union_data_
{
	sockaddr_storage                     Storage{0};
	sockaddr_in6                         IPv6;
	sockaddr_in                          IPv4;
}AddressUnionData, ADDRESS_UNION_DATA;

typedef struct _socket_data_
{
	SYSTEM_SOCKET                        Socket{0};
	sockaddr_storage                     SockAddr{0};
	socklen_t                            AddrLen{0};
}SocketData, SOCKET_DATA;

typedef struct _dns_cache_data_
{
	std::string                          Domain;
	std::unique_ptr<uint8_t[]>           Response;
	size_t                               Length{0};
	uint64_t                             ClearCacheTime{0};
	uint16_t                             RecordType{0};
	ADDRESS_UNION_DATA                   ForAddress;
}DNSCacheData, DNS_CACHE_DATA;
#define DNS_CACHE_INDEX_MAP_DOMAIN       first
#define DNS_CACHE_INDEX_MAP_POINTER      second
#endif
