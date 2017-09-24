// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2017 Chengr28
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


#ifndef PCAP_DNSPROXY_DEFINITION_H
#define PCAP_DNSPROXY_DEFINITION_H

#include "Structure.h"

//////////////////////////////////////////////////
// Main definitions
// 
//Base definitions
#define KIBIBYTE_TIMES                                1024U                       //1 KiB = 1,024 bytes
#define MEBIBYTE_TIMES                                1048576U                    //1 MiB = 1,048,576 bytes
#define GIBIBYTE_TIMES                                1073741824U                 //1 GiB = 1,073,741,824 bytes
#define TEBIBYTE_TIMES                                1099511627776U              //1 TiB = 1,099,511,627,776 bytes
#define PEBIBYTE_TIMES                                1125899906842624U           //1 PiB = 1,125,899,906,842,624 bytes
#define EXBIBYTE_TIMES                                1152921504606846976U        //1 EiB = 1,152,921,504,606,846,976 bytes
#define ZEBIBYTE_TIMES                                1180591620717411303424U     //1 ZiB = 1,180,591,620,717,411,303,424 bytes
#define YOBIBYTE_TIMES                                1208925819614629174706176U  //1 YiB = 1,208,925,819,614,629,174,706,176 bytes
#define CODEPAGE_ASCII                                1U                          //Microsoft Windows Codepage of ANSI
#define CODEPAGE_UTF_8                                65001U                      //Microsoft Windows Codepage of UTF-8
#define CODEPAGE_UTF_16_LE                            1200U                       //Microsoft Windows Codepage of UTF-16 Little Endian/LE
#define CODEPAGE_UTF_16_BE                            1201U                       //Microsoft Windows Codepage of UTF-16 Big Endian/BE
#define CODEPAGE_UTF_32_LE                            12000U                      //Microsoft Windows Codepage of UTF-32 Little Endian/LE
#define CODEPAGE_UTF_32_BE                            12001U                      //Microsoft Windows Codepage of UTF-32 Big Endian/BE
#if defined(PLATFORM_WIN)
	#define MBSTOWCS_NULL_TERMINATE                       (-1)                        //MultiByteToWideChar function null-terminate
	#define WCSTOMBS_NULL_TERMINATE                       MBSTOWCS_NULL_TERMINATE     //WideCharToMultiByte function null-terminate
#endif
#if defined(ENABLE_LIBSODIUM)
	#define LIBSODIUM_ERROR                               (-1)
#endif
#define BYTES_TO_BITS                                 8U                          //8 bits = 1 byte
#define U16_NUM_ONE                                   0x0001
#define HEX_PREAMBLE_STRING                           ("0x")                      //Hexadecimal preamble

//Character value definitions
#define ASCII_HT                                      9                           //"?"
#define ASCII_LF                                      0x0A                        //10, Line Feed
#define ASCII_VT                                      0x0B                        //11, Vertical Tab
#define ASCII_FF                                      0x0C                        //12, Form Feed
#define ASCII_CR                                      0x0D                        //13, Carriage Return
#define ASCII_SPACE                                   32                          //" "
#define ASCII_QUOTATION_MARK                          34                          //"\""
#define ASCII_HASHTAG                                 35                          //"#"
#define ASCII_AMPERSAND                               38                          //"&"
#define ASCII_PLUS                                    43                          //"+"
#define ASCII_COMMA                                   44                          //","
#define ASCII_MINUS                                   45                          //"-"
#define ASCII_PERIOD                                  46                          //"."
#define ASCII_SLASH                                   47                          //"/"
#define ASCII_ZERO                                    48                          //"0"
#define ASCII_ONE                                     49                          //"1"
#define ASCII_TWO                                     50                          //"2"
#define ASCII_THREE                                   51                          //"3"
#define ASCII_NINE                                    57                          //"9"
#define ASCII_COLON                                   58                          //":"
#define ASCII_AT                                      64                          //"@"
#define ASCII_UPPERCASE_A                             65                          //"A"
#define ASCII_UPPERCASE_F                             70                          //"F"
#define ASCII_UPPERCASE_Z                             90                          //"Z"
#define ASCII_BRACKETS_LEFT                           91                          //"["
#define ASCII_BACKSLASH                               92                          //"\"
#define ASCII_BRACKETS_RIGHT                          93                          //"]"
#define ASCII_ACCENT                                  96                          //"`"
#define ASCII_LOWERCASE_A                             97                          //"a"
#define ASCII_LOWERCASE_F                             102                         //"f"
#define ASCII_LOWERCASE_X                             120                         //"x"
#define ASCII_LOWERCASE_Z                             122                         //"z"
#define ASCII_BRACES_LEFT                             123                         //"{"
#define ASCII_VERTICAL                                124                         //"|"
#define ASCII_TILDE                                   126                         //"~"
#define ASCII_MAX_NUM                                 0x7F                        //Maximum number of ASCII
#define UNICODE_NEXT_LINE                             0x0085                      //Next Line
#define UNICODE_NO_BREAK_SPACE                        0x00A0                      //No-Break Space
#define UNICODE_OGHAM_SPACE_MARK                      0x1680                      //Ogham Space Mark
#define UNICODE_MONGOLIAN_VOWEL_SEPARATOR             0x180E                      //Mongolian Vowel Separator
#define UNICODE_LINE_SEPARATOR                        0x2028                      //Line Separator
#define UNICODE_PARAGRAPH_SEPARATOR                   0x2029                      //Paragraph Separator
#define UNICODE_EN_SPACE                              0x2002                      //En Space or Nut
#define UNICODE_EM_SPACE                              0x2003                      //Em Space or Mutton
#define UNICODE_THICK_SPACE                           0x2004                      //Three-Per-Em Space/TPES or Thick Space
#define UNICODE_MID_SPACE                             0x2005                      //Four-Per-Em Space/FPES or Mid Space
#define UNICODE_SIX_PER_EM_SPACE                      0x2006                      //Six-Per-Em Space
#define UNICODE_FIGURE_SPACE                          0x2007                      //Figure Space
#define UNICODE_PUNCTUATION_SPACE                     0x2008                      //Punctuation Space
#define UNICODE_THIN_SPACE                            0x2009                      //Thin Space
#define UNICODE_HAIR_SPACE                            0x200A                      //Hair Space
#define UNICODE_ZERO_WIDTH_SPACE                      0x200B                      //Zero Width Space
#define UNICODE_ZERO_WIDTH_NON_JOINER                 0x200C                      //Zero Width Non Joiner
#define UNICODE_ZERO_WIDTH_JOINER                     0x200D                      //Zero Width Joiner
#define UNICODE_NARROW_NO_BREAK_SPACE                 0x202F                      //Narrow No-Break Space
#define UNICODE_MEDIUM_MATHEMATICAL_SPACE             0x205F                      //Medium Mathematical Space
#define UNICODE_WORD_JOINER                           0x2060                      //Word Joiner
#define UNICODE_IDEOGRAPHIC_SPACE                     0x3000                      //Ideographic Space in CJK

//Version definitions
#define CONFIG_VERSION_COUNT                          2U                                    //Version: Major.Minor
#define CONFIG_VERSION_MAJOR                          0                                     //Current configuration file major version(0.45)
#define CONFIG_VERSION_MINOR                          45U                                   //Current configuration file minor version(0.45)
#define COPYRIGHT_MESSAGE                             L"Copyright (C) 2012-2017 Chengr28"   //Copyright message
#define FULL_VERSION                                  L"0.4.9.3"                            //Current full version

//Size and length definitions(Number)
#define ADDRESS_STRING_MAXSIZE                        64U                               //Maximum size of addresses(IPv4/IPv6) words(64 bytes)
#define ALTERNATE_SERVERNUM                           12U                               //Alternate switching of Main(00: TCP/IPv6, 01: TCP/IPv4, 02: UDP/IPv6, 03: UDP/IPv4), Local(04: TCP/IPv6, 05: TCP/IPv4, 06: UDP/IPv6, 07: UDP/IPv4), DNSCurve(08: TCP/IPv6, 09: TCP/IPv4, 10: UDP/IPv6, 11: UDP/IPv4)
#define DEFAULT_LARGE_BUFFER_SIZE                     4096U                             //Default size of large buffer(4KB/4096 bytes)
#define COMMAND_BUFFER_MAXSIZE                        DEFAULT_LARGE_BUFFER_SIZE         //Maximum size of commands buffer
#define COMMAND_MIN_COUNT                             1                                 //Minimum count of commands
#define DEFAULT_LOG_READING_MAXSIZE                   8388608U                          //Default number of maximum log file size(8MB/8388608 bytes)
#define DEFAULT_THREAD_POOL_BASENUM                   24U                               //Default number of base thread pool size
#define DEFAULT_THREAD_POOL_MAXNUM                    256U                              //Default number of maximum thread pool size
#define DIFFERNET_FILE_SET_NUM                        2U                                //Number of different file set
#define DNS_RR_MAX_AAAA_COUNT                         43U                               //Maximum Record Resources size of whole AAAA answers, 28 bytes * 43 records = 1204 bytes
#define DNS_RR_MAX_A_COUNT                            75U                               //Maximum Record Resources size of whole A answers, 16 bytes * 75 records = 1200 bytes
#if defined(ENABLE_LIBSODIUM)
	#define DNSCRYPT_DATABASE_ITEM_MINNUM                 14U                               //Minimum number of item in DNSCrypt database
	#define DNSCRYPT_DATABASE_ADDRESS_LOCATION            10U                               //Location of DNSCurve Address in DNSCrypt database
	#define DNSCRYPT_DATABASE_PROVIDER_NAME_LOCATION      11U                               //Location of Provider Name in DNSCrypt database
	#define DNSCRYPT_DATABASE_PROVIDER_KEY_LOCATION       12U                               //Location of Provider Public Key in DNSCrypt database
	#define DNSCRYPT_KEYPAIR_MESSAGE_LEN                  80U                               //DNScrypt keypair messages length
	#define DNSCRYPT_KEYPAIR_INTERVAL                     4U                                //DNScrypt keypair interval length
	#define DNSCRYPT_RECORD_TXT_LEN                       124U                              //Length of DNScrypt TXT Records
#endif
#define DOMAIN_DATA_MAXSIZE                           253U                              //Maximum data length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_LEVEL_DATA_MAXSIZE                     63U                               //Domain length is between 3 and 63(Labels must be 63 characters/bytes or less, Section 2.3.1 in RFC 1035).
#define DOMAIN_MAXSIZE                                256U                              //Maximum size of whole level domain is 256 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_MINSIZE                                2U                                //Minimum size of whole level domain is 3 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_RAMDOM_MINSIZE                         6U                                //Minimum size of ramdom domain request
#define FILE_BUFFER_SIZE                              DEFAULT_LARGE_BUFFER_SIZE         //Size of file reading buffer
#define FILE_READING_MAXSIZE                          268435456U                        //Maximum size of whole reading file(256 MB/268435456 bytes).
#define HTTP_VERSION_SUPPORT_COUNT                    2U                                //HTTP version 1.1 and 2 which are supported.
#define HTTP_VERSION_MAXSIZE                          3U                                //Maximum size of HTTP version
#define ICMP_PADDING_MAXSIZE                          1484U                             //Length of ICMP padding data must between 18 bytes and 1464 bytes(Ethernet MTU - IPv4 Standard Header - ICMP Header).
#if defined(PLATFORM_LINUX)
	#define ICMP_PADDING_LENGTH_LINUX                     40U
	#define ICMP_STRING_START_NUM_LINUX                   16U
#elif defined(PLATFORM_MACOS)
	#define ICMP_PADDING_LENGTH_MACOS                     48U
	#define ICMP_STRING_START_NUM_MACOS                   8U
#endif
#define IPV4_SHORTEST_ADDR_STRING                     6U                                //The shortest IPv4 address strings(*.*.*.*)
#define IPV6_SHORTEST_ADDR_STRING                     2U                                //The shortest IPv6 address strings(::)
#define LOG_READING_MINSIZE                           DEFAULT_LARGE_BUFFER_SIZE         //Minimum size of whole log file
#define MULTIPLE_REQUEST_MAXNUM                       64U                               //Maximum number of multiple request.
#define NETWORK_LAYER_PARTNUM                         2U                                //Number of network layer protocols(IPv6 and IPv4)
#define NULL_TERMINATE_LENGTH                         1U                                //Length of C style string null
#define ORIGINAL_PACKET_MAXSIZE                       1522U                             //Maximum size of original Ethernet frame, 6 bytes destination MAC + 6 bytes source MAC + 4 bytes 802.1Q tag(optional) + 2 bytes Ethertype + 1500 bytes payload + 4 bytes Frame Check Sequence
#define NORMAL_PACKET_MAXSIZE                         1480U                             //Maximum size of normal Ethernet frame, 1500 bytes maximum payload - 20 bytes IPv4 header(IPv6 header length is longer than IPv4) and ignore all other transport layer protocols.
#define PADDING_RESERVED_BYTES                        2U                                //Padding reserved bytes(2 bytes)
#if defined(ENABLE_PCAP)
	#define PCAP_CAPTURE_STRING_MAXNUM                    256U                        //Maximum length of pcap capture drive name and description
#endif
#if defined(PLATFORM_WIN)
	#define QUERY_SERVICE_CONFIG_BUFFER_MAXSIZE           8192U                       //Buffer maximum size of QueryServiceConfig function(8KB/8192 Bytes)
#endif
#define THREAD_POOL_MAXNUM                            148809524U                  //Number of maximum packet buffer queues, 148809523pps or 148.809Mpps in 100 Gigabit Ethernet
#define THREAD_POOL_MINNUM                            8U                          //Number of minimum packet buffer queues
#define TRANSPORT_LAYER_PARTNUM                       4U                          //Number of transport layer protocols(00: IPv6/UDP, 01: IPv4/UDP, 02: IPv6/TCP, 03: IPv4/TCP)
#define UINT16_MAX_STRING_LENGTH                      6U                          //Maximum number of 16 bits is 65535, its length is 5.
#define UINT32_MAX_STRING_LENGTH                      11U                         //Maximum number of 32 bits is 4294967295, its length is 10.
#define UINT8_MAX_STRING_LENGTH                       4U                          //Maximum number of 8 bits is 255, its length is 3.

//Size and length definitions(Data)
#define DNS_PACKET_MINSIZE                            (sizeof(dns_hdr) + NULL_TERMINATE_LENGTH + sizeof(dns_qry))                              //Minimum DNS packet size(DNS Header + Minimum Domain<ROOT> + DNS Query)
#define EDNS_ADDITIONAL_MAXSIZE                       (sizeof(dns_record_opt) * 2U + sizeof(edns_client_subnet) + sizeof(in6_addr))            //Maximum of EDNS Additional Record Resources size
#if defined(ENABLE_LIBSODIUM)
	#define DNSCRYPT_BUFFER_RESERVED_LEN                  (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES)
	#define DNSCRYPT_BUFFER_RESERVED_TCP_LEN              (sizeof(uint16_t) + DNSCRYPT_BUFFER_RESERVED_LEN)
	#define DNSCRYPT_PACKET_MINSIZE                       (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + DNS_PACKET_MINSIZE)
	#define DNSCRYPT_HEADER_RESERVED_LEN                  (sizeof(ipv6_hdr) + sizeof(udp_hdr) + DNSCRYPT_BUFFER_RESERVED_LEN)
#endif
#define HTTP1_RESPONSE_MINSIZE                        (strlen(" HTTP/") + HTTP_VERSION_MAXSIZE + HTTP_STATUS_CODE_SIZE)

//Code definitions
#define CHECKSUM_SUCCESS                              0                           //Result of getting correct checksum.
#define DYNAMIC_MIN_PORT                              1024U                       //Well-known port is from 1 to 1023.
#if defined(ENABLE_PCAP)
	#define PCAP_LOOP_INFINITY                            (-1)                         //Pcap packets are processed until another ending condition occurs.
	#define PCAP_COMPILE_OPTIMIZE                         1                            //Pcap optimization on the resulting code is performed.
#endif
#if defined(PLATFORM_WIN)
	#define SYSTEM_SOCKET                                 UINT_PTR                     //System Socket defined(WinSock2.h), which is not the same in x86 and x64 platform and defined in WinSock2.h file.
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	#define SYSTEM_SOCKET                                 int
#endif

//Time definitions
#define DEFAULT_ALTERNATE_RANGE_TIME                  10U                         //Default time of checking timeout(10 seconds)
#define DEFAULT_ALTERNATE_RESET_TIME                  180U                        //Default time to reset switching of alternate servers(180 seconds/2 minutes)
#define DEFAULT_ALTERNATE_TIMES                       5U                          //Default times of request timeout(5 times)
#define DEFAULT_DOMAIN_TEST_INTERVAL_TIME             900U                        //Default Domain Test time between every sending(900 seconds/15 minutes)
#define DEFAULT_FILE_REFRESH_TIME                     15000U                      //Default time between files auto-refreshing(15000 ms/15 seconds)
#define DEFAULT_HOSTS_TTL                             900U                        //Default Hosts DNS TTL(900 seconds/15 minutes)
#define DEFAULT_ICMP_TEST_TIME                        900U                        //Default time between ICMP Test(900 seconds/15 minutes)
#if defined(ENABLE_PCAP)
	#define DEFAULT_PCAP_CAPTURE_TIMEOUT                  250U                        //Default Pcap Capture reading timeout(250 ms)
	#define PCAP_CAPTURE_MIN_TIMEOUT                      10U                         //Minimum Pcap Capture reading timeout(10 ms)
#endif
#define DEFAULT_THREAD_POOL_RESET_TIME                120000U                     //Default time to reset thread pool number(120000 ms/120 seconds)
#define DEFAULT_RELIABLE_ONCE_SOCKET_TIMEOUT          3000U                       //Default timeout of reliable once sockets(Such as TCP, 3000 ms/3 seconds)
#define DEFAULT_RELIABLE_SERIAL_SOCKET_TIMEOUT        1500U                       //Default timeout of reliable serial sockets(Such as TCP, 1500 ms/1.5 second)
#define DEFAULT_UNRELIABLE_ONCE_SOCKET_TIMEOUT        2000U                       //Default timeout of unreliable once sockets(Such as ICMP/ICMPv6/UDP, 2000 ms/2 seconds)
#define DEFAULT_UNRELIABLE_SERIAL_SOCKET_TIMEOUT      1000U                       //Default timeout of unreliable serial sockets(Such as ICMP/ICMPv6/UDP, 1000 ms/1 second)
#if defined(ENABLE_LIBSODIUM)
	#define DEFAULT_DNSCURVE_RECHECK_TIME                 1800U                                    //Default DNSCurve keys recheck time(30 minutes/1800 seconds)
	#define DEFAULT_DNSCURVE_RELIABLE_SOCKET_TIMEOUT      DEFAULT_RELIABLE_ONCE_SOCKET_TIMEOUT     //Same as default timeout of reliable sockets
	#define DEFAULT_DNSCURVE_UNRELIABLE_SOCKET_TIMEOUT    DEFAULT_UNRELIABLE_ONCE_SOCKET_TIMEOUT   //Same as default timeout of unreliable sockets
	#define SHORTEST_DNSCURVE_RECHECK_TIME                10U                                      //The shortest DNSCurve keys recheck time(10 seconds)
#endif
#define FLUSH_DNS_CACHE_INTERVAL_TIME                 5U                          //Time between every flushing(5 seconds)
#define LOOP_INTERVAL_TIME_DELAY                      20U                         //Delay mode loop interval time(20 ms)
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	#define LOOP_INTERVAL_TIME_NO_DELAY                   20000U                         //No delay mode loop interval time(20000 us/20 ms)
#endif
#define LOOP_MAX_LITTLE_TIMES                         4U                          //Little maximum of loop times(4 times)
#define LOOP_MAX_LARGE_TIMES                          8U                          //Large maximum of loop times(8 times)
#define MICROSECOND_TO_MILLISECOND                    1000U                       //1000 microseconds(1 ms)
#define SECOND_TO_MILLISECOND                         1000U                       //1000 milliseconds(1 second)
#define SENDING_INTERVAL_TIME                         5000U                       //Time between every sending(5000 ms/5 seconds)
#define SENDING_ONCE_INTERVAL_TIMES                   3U                          //Repeat 3 times between every sending.
#define SHORTEST_ALTERNATE_RANGE_TIME                 5U                          //The shortest time of checking timeout(5 seconds)
#define SHORTEST_ALTERNATE_RESET_TIME                 5U                          //The shortest time to reset switching of alternate servers(5 seconds)
#define SHORTEST_DOMAIN_TEST_INTERVAL_TIME            5U                          //The shortest Domain Test time between every sending(5 seconds)
#define SHORTEST_FILEREFRESH_TIME                     5U                          //The shortest time between files auto-refreshing(5 seconds)
#define SHORTEST_ICMP_TEST_TIME                       5U                          //The shortest time between ICMP Test(5 seconds)
#define SHORTEST_THREAD_POOL_RESET_TIME               5U                          //The shortest time to reset thread pool number(5 seconds)
#define SOCKET_MIN_TIMEOUT                            500U                        //The shortest socket timeout(500 ms)
#define STANDARD_TIMEOUT                              1000U                       //Standard timeout(1000 ms/1 second)
#if defined(PLATFORM_WIN)
	#define UPDATE_SERVICE_TIME                           3000U                       //Update service timeout(3 seconds/3000 ms)
#endif

//Data definitions
#if defined(PLATFORM_WIN)
	#define COMMAND_FIREWALL_TEST                         (L"--first-setup")
	#define COMMAND_FLUSH_DNS                             (L"--flush-dns")
	#define COMMAND_KEYPAIR_GENERATOR                     (L"--keypair-generator")
	#define COMMAND_LIB_VERSION                           (L"--lib-version")
	#define COMMAND_LONG_HELP                             (L"--help")
	#define COMMAND_LONG_PRINT_VERSION                    (L"--version")
	#define COMMAND_LONG_SET_PATH                         (L"--config-file")
	#define COMMAND_SHORT_HELP                            (L"-h")
	#define COMMAND_SHORT_PRINT_VERSION                   (L"-v")
	#define COMMAND_SHORT_SET_PATH                        (L"-c")
	#define CONFIG_FILE_NAME_LIST                         {(L"Config.ini"), (L"Config.conf"), (L"Config.cfg"), (L"Config")}
	#define ERROR_LOG_FILE_NAME                           (L"Error.log")
	#define DEFAULT_ICMP_PADDING_DATA                     ("abcdefghijklmnopqrstuvwabcdefghi")           //Default ICMP padding data(Windows)
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_KEY_PAIR_FILE_NAME                   (L"KeyPair.txt")
#endif
	#define MAILSLOT_MESSAGE_FLUSH_DNS                    (L"Flush Pcap_DNSProxy DNS cache")             //The mailslot message to flush dns cache
	#define MAILSLOT_MESSAGE_FLUSH_DNS_DOMAIN             (L"Flush Pcap_DNSProxy DNS cache: ")           //The mailslot message to flush dns cache(Single domain)
	#define MUTEX_EXISTS_NAME                             (L"Global\\Pcap_DNSProxy Process Exists")      //Global mutex exists name
	#define MAILSLOT_NAME                                 (L"\\\\.\\mailslot\\pcap_dnsproxy_mailslot")   //MailSlot name
	#define SID_ADMINISTRATORS_GROUP                      (L"S-1-5-32-544")                              //Windows Administrators group SID header
	#define SYSTEM_SERVICE_NAME                           (L"PcapDNSProxyService")                       //System service name
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
#if defined(PLATFORM_LINUX)
	#define COMMAND_DISABLE_DAEMON                        ("--disable-daemon")
#endif
	#define COMMAND_FLUSH_DNS                             ("--flush-dns")
	#define COMMAND_KEYPAIR_GENERATOR                     ("--keypair-generator")
	#define COMMAND_LIB_VERSION                           ("--lib-version")
	#define COMMAND_LONG_HELP                             ("--help")
	#define COMMAND_LONG_PRINT_VERSION                    ("--version")
	#define COMMAND_LONG_SET_PATH                         ("--config-file")
	#define COMMAND_SHORT_HELP                            ("-h")
	#define COMMAND_SHORT_PRINT_VERSION                   ("-v")
	#define COMMAND_SHORT_SET_PATH                        ("-c")
	#define CONFIG_FILE_NAME_LIST                         {(L"Config.conf"), (L"Config.ini"), (L"Config.cfg"), (L"Config")}
	#define CONFIG_FILE_NAME_LIST_MBS                     {("Config.conf"), ("Config.ini"), ("Config.cfg"), ("Config")}
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_KEY_PAIR_FILE_NAME                   ("KeyPair.txt")
#endif
	#define ERROR_LOG_FILE_NAME                           (L"Error.log")
	#define ERROR_LOG_FILE_NAME_MBS                       ("Error.log")
	#define FIFO_MESSAGE_FLUSH_DNS                        ("Flush DNS cache of Pcap_DNSProxy")         //The FIFO message to flush dns cache
	#define FIFO_MESSAGE_FLUSH_DNS_DOMAIN                 ("Flush DNS cache of Pcap_DNSProxy: ")       //The FIFO message to flush dns cache(Single domain)
	#define FIFO_PATH_NAME                                ("/tmp/pcap_dnsproxy_fifo")                  //FIFO pathname
#endif
#define DEFAULT_LOCAL_SERVER_NAME                     ("pcap-dnsproxy.server")                     //Default Local DNS server name
#if defined(PLATFORM_MACOS)
	#define DEFAULT_SEQUENCE                               0
#else
	#define DEFAULT_SEQUENCE                               0x0001                                      //Default sequence of protocol
#endif
#define DNS_PACKET_QUERY_LOCATE(Buffer)               (sizeof(dns_hdr) + CheckQueryNameLength(reinterpret_cast<const uint8_t *>(Buffer) + sizeof(dns_hdr)) + NULL_TERMINATE_LENGTH)                     //Location the beginning of DNS Query
#define DNS_PACKET_RR_LOCATE(Buffer)                  (sizeof(dns_hdr) + CheckQueryNameLength(reinterpret_cast<const uint8_t *>(Buffer) + sizeof(dns_hdr)) + NULL_TERMINATE_LENGTH + sizeof(dns_qry))   //Location the beginning of DNS Resource Records
#define DNS_TCP_PACKET_QUERY_LOCATE(Buffer)           (sizeof(dns_tcp_hdr) + CheckQueryNameLength(reinterpret_cast<const uint8_t *>(Buffer) + sizeof(dns_tcp_hdr)) + NULL_TERMINATE_LENGTH)

//Base64 definitions
#define BASE64_PAD                                    ('=')
#define BASE64_DECODE_FIRST                           ('+')
#define BASE64_DECODE_LAST                            ('z')
#define BASE64_DECODE_OUT_SIZE(Message)               (((Message)) / 4U * 3U)
#define BASE64_ENCODE_OUT_SIZE(Message)               (((Message) + 2U) / 3U * 4U)

//Type definitions
typedef enum class _huffman_return_type_
{
	NONE, 
	ERROR_OVERFLOW, 
	ERROR_TRUNCATED, 
	ERROR_EOS, 
	ERROR_BAD_PREFIX, 
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
typedef enum _cpm_pointer_type_
{
	CPM_POINTER_TYPE_HEADER, 
	CPM_POINTER_TYPE_RR, 
	CPM_POINTER_TYPE_ADDITIONAL
}CPM_POINTER_TYPE;
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
//	TCP_KEEP_ALIVE, 
	TIMEOUT, 
	UDP_BLOCK_RESET
}SOCKET_SETTING_TYPE;
typedef enum class _request_process_type_
{
	NONE, 
	LOCAL, 
	DIRECT, 
	TCP_NORMAL, 
	TCP_WITHOUT_MARKING, 
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
	UDP_WITHOUT_MARKING
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
	#define OPENSSL_VERSION_1_0_1                     0x10001000L
	#define OPENSSL_VERSION_1_0_2                     0x10002000L
	#define OPENSSL_VERSION_1_1_0                     0x10100000L
	#define OPENSSL_STATIC_BUFFER_SIZE                256U
	#define OPENSSL_CIPHER_LIST_COMPATIBILITY         ("HIGH:!SSLv2:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")
	#define OPENSSL_CIPHER_LIST_STRONG                ("HIGH:!SSLv2:!SSLv3:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")
#endif
#endif


//////////////////////////////////////////////////
// Function definitions(Part 2)
#define hton16_Force(Value)   (static_cast<const uint16_t>((reinterpret_cast<const uint8_t *>(&(Value)))[0] <<                                     \
								(sizeof(uint8_t) * BYTES_TO_BITS) | (reinterpret_cast<const uint8_t *>(&(Value)))[1U]))
#define ntoh16_Force          hton16_Force
#define hton32_Force(Value)   (static_cast<const uint32_t>((reinterpret_cast<const uint8_t *>(&(Value)))[0] <<                                     \
								((sizeof(uint16_t) + sizeof(uint8_t)) * BYTES_TO_BITS) |                                                           \
								(reinterpret_cast<const uint8_t *>(&(Value)))[1U] << (sizeof(uint16_t) * BYTES_TO_BITS) |                          \
								(reinterpret_cast<const uint8_t *>(&(Value)))[2U] << (sizeof(uint8_t) * BYTES_TO_BITS) |                           \
								(reinterpret_cast<const uint8_t *>(&(Value)))[3U]))
#define ntoh32_Force          hton32_Force
#if BYTE_ORDER == LITTLE_ENDIAN
	#define hton64(Value)         (static_cast<const uint64_t>(((static_cast<const uint64_t>(htonl(static_cast<const uint32_t>                     \
									(((Value) << (sizeof(uint32_t) * BYTES_TO_BITS)) >>                                                            \
									(sizeof(uint32_t) * BYTES_TO_BITS))))) <<                                                                      \
									(sizeof(uint32_t) * BYTES_TO_BITS)) | static_cast<const uint32_t>(htonl(static_cast<const uint32_t>((Value) >> \
									(sizeof(uint32_t) * BYTES_TO_BITS))))))
#else //BIG_ENDIAN
	#define hton64(Value)         (Value)
#endif
#define ntoh64                hton64
#if defined(PLATFORM_WIN)
#if defined(PLATFORM_WIN_XP)
	#define GetCurrentSystemTime   GetTickCount
#else
	#define GetCurrentSystemTime   GetTickCount64
#endif
	#define Sleep(Millisecond)     Sleep(static_cast<const DWORD>(Millisecond))
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	#define Sleep(Millisecond)     usleep(static_cast<const useconds_t>((Millisecond) * MICROSECOND_TO_MILLISECOND))
	#define usleep(Millisecond)    usleep(static_cast<const useconds_t>(Millisecond))
#endif


//////////////////////////////////////////////////
// Main structures and classes
// 
//Huffman Node structure
typedef struct _huffman_node_
{
	uint32_t                             Bits;
	uint8_t                              BitSize;
}HuffmanNode, HUFFMAN_NODE;

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

//Socket Marking Data structure
typedef std::pair<SYSTEM_SOCKET, uint64_t> SocketMarkingData, SOCKET_MARKING_DATA;

//Address Prefix Block structure
typedef std::pair<sockaddr_storage, size_t> AddressPrefixBlock, ADDRESS_PREFIX_BLOCK;

//Address Union Data structure
typedef union _address_union_data_
{
	sockaddr_storage                     Storage;
	sockaddr_in6                         IPv6;
	sockaddr_in                          IPv4;
}AddressUnionData, ADDRESS_UNION_DATA;

//Hop Limits and TTL Data structure
#if defined(ENABLE_PCAP)
typedef union _hop_limits_data_
{
	uint8_t                              TTL;
	uint8_t                              HopLimit;
}HopLimitsUnionData, HOP_LIMITS_UNION_DATA;
#endif

//DNS Server Data structure
typedef struct _dns_server_data_
{
	ADDRESS_UNION_DATA                   AddressData;
#if defined(ENABLE_PCAP)
	HOP_LIMITS_UNION_DATA                HopLimitsData_Assign;
	HOP_LIMITS_UNION_DATA                HopLimitsData_Mark;
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
//Packet structure block
	uint8_t                              *Buffer;
	size_t                               Question;
	size_t                               Answer;
	size_t                               Authority;
	size_t                               Additional;
	size_t                               EDNS_Record;
//Packet attributes block
	size_t                               BufferSize;
	size_t                               Length;
	ADDRESS_UNION_DATA                   LocalTarget;
	uint16_t                             Protocol;
	bool                                 IsLocalRequest;
	bool                                 IsLocalInBlack;
	bool                                 IsLocalInWhite;
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
	uint8_t                              *ReceiveMagicNumber;    //Receive Magic Number(Same from server received)
	uint8_t                              *SendMagicNumber;       //Server Magic Number(Send to server)
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
	REQUEST_MODE_DIRECT                  DirectRequest;
	DNS_CACHE_TYPE                       DNS_CacheType;
	size_t                               DNS_CacheParameter;
	size_t                               DNS_CacheSinglePrefix_IPv6;
	size_t                               DNS_CacheSinglePrefix_IPv4;
	uint32_t                             HostsDefaultTTL;
//[Local DNS] block
	REQUEST_MODE_NETWORK                 LocalProtocol_Network;
	REQUEST_MODE_TRANSPORT               LocalProtocol_Transport;
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
	bool                                 DNSSEC_Validation;
	bool                                 DNSSEC_ForceValidation;
	bool                                 AlternateMultipleRequest;
	bool                                 DoNotFragment;
#if defined(ENABLE_PCAP)
	bool                                 HeaderCheck_IPv4;
	bool                                 HeaderCheck_TCP;
#endif
	bool                                 HeaderCheck_DNS;
	bool                                 DataCheck_Blacklist;
	bool                                 DataCheck_Strict_RR_TTL;
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
	bool                                 SOCKS_UDP_NoHandshake;
	bool                                 SOCKS_Only;
	ADDRESS_UNION_DATA                   SOCKS_Address_IPv6;
	ADDRESS_UNION_DATA                   SOCKS_Address_IPv4;
	ADDRESS_UNION_DATA                   SOCKS_TargetServer;
	std::string                          *SOCKS_TargetDomain;
	uint16_t                             SOCKS_TargetDomain_Port;
	std::string                          *SOCKS_Username;
	std::string                          *SOCKS_Password;
	bool                                 HTTP_CONNECT_Proxy;
	REQUEST_MODE_NETWORK                 HTTP_CONNECT_Protocol;
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
	std::string                          *HTTP_CONNECT_ProxyAuthorization;

//[DNSCurve] block
#if defined(ENABLE_LIBSODIUM)
	bool                                 IsDNSCurve;
#endif

//Member functions
	ConfigurationTable(
		void);
	ConfigurationTable(
		const ConfigurationTable &Reference);
	void SetToMonitorItem(
		void);
	void MonitorItemToUsing(
		ConfigurationTable * const ConfigurationParameter);
	void MonitorItemReset(
		void);
	~ConfigurationTable(
		void);
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
	std::default_random_engine           *RamdomEngine;
	uint8_t                              *DomainTable;
	uint8_t                              *Base64_EncodeTable;
	int8_t                               *Base64_DecodeTable;
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

//Member functions
	GlobalStatus(
		void);
	GlobalStatus(
		const GlobalStatus &Reference);
	~GlobalStatus(
		void);
}GLOBAL_STATUS;

//IPv4/IPv6 address ranges class
typedef class AddressRangeTable
{
public:
	sockaddr_storage                     Begin;
	sockaddr_storage                     End;
	size_t                               Level;

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
}RESULT_BLACKLIST_TABLE;

//Address Hosts class
typedef class AddressHostsTable
{
public:
	std::vector<ADDRESS_PREFIX_BLOCK>    Address_Target;
	std::vector<ADDRESS_RANGE_TABLE>     Address_Source;
}ADDRESS_HOSTS_TABLE;

//Address routing table class
typedef class AddressRoutingTable
{
public:
	std::unordered_map<uint64_t, std::unordered_set<uint64_t>>   AddressRoutingList_IPv6;
	std::unordered_set<uint32_t>                                 AddressRoutingList_IPv4;
	size_t                                                       Prefix;

//Member functions
	AddressRoutingTable(
		void);
}ADDRESS_ROUTING_TABLE;

//Alternate swap table class
typedef class AlternateSwapTable
{
public:
	size_t                               TimeoutTimes[ALTERNATE_SERVERNUM];
	bool                                 IsSwap[ALTERNATE_SERVERNUM];

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

//Member functions
	DiffernetFileSetHosts(
		void);
}DIFFERNET_FILE_SET_HOSTS;

//Socket Selecting Once table class
typedef struct SocketSelectingOnceTable
{
public:
	std::unique_ptr<uint8_t[]>           RecvBuffer;
	size_t                               RecvLen;
	bool                                 IsPacketDone;

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

//Member functions
	DNSCurveConfigurationTable(
		void);
	DNSCurveConfigurationTable(
		const DNSCurveConfigurationTable &Reference);
	void SetToMonitorItem(
		void);
	void MonitorItemToUsing(
		DNSCurveConfigurationTable * const DNSCurveConfigurationParameter);
	void MonitorItemReset(
		void);
	~DNSCurveConfigurationTable(
		void);
}DNSCURVE_CONFIGURATION_TABLE;

//DNSCurve Socket Selecting table class
typedef struct DNSCurveSocketSelectingTable
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

//Member functions
	OpenSSLContextTable(
		void);
	~OpenSSLContextTable(
		void);
}OPENSSL_CONTEXT_TABLE;
#endif
#endif
#endif
