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


#include "Structure.h"

//////////////////////////////////////////////////
// Main definitions
// 
//Base definitions
#define KILOBYTE_TIMES                               1024U                        //1KB = 1,024 bytes
#define MEGABYTE_TIMES                               1048576U                     //1MB = 1,048,576 bytes
#define GIGABYTE_TIMES                               1073741824U                  //1GB = 1,073,741,824 bytes
#define TERABYTE_TIMES                               1099511627776U               //1TB = 1,099,511,627,776 bytes
#define PETABYTE_TIMES                               1125899906842624U            //1PB = 1,125,899,906,842,624 bytes
#define CODEPAGE_ASCII                               1U                           //Microsoft Windows Codepage of ANSI
#define CODEPAGE_UTF_8                               65001U                       //Microsoft Windows Codepage of UTF-8
#define CODEPAGE_UTF_16_LE                           1200U                        //Microsoft Windows Codepage of UTF-16 Little Endian/LE
#define CODEPAGE_UTF_16_BE                           1201U                        //Microsoft Windows Codepage of UTF-16 Big Endian/BE
#define CODEPAGE_UTF_32_LE                           12000U                       //Microsoft Windows Codepage of UTF-32 Little Endian/LE
#define CODEPAGE_UTF_32_BE                           12001U                       //Microsoft Windows Codepage of UTF-32 Big Endian/BE
#if defined(PLATFORM_WIN)
	#define MBSTOWCS_NULLTERMINATE                         (-1)                       //MultiByteToWideChar function find null-terminate.
#endif
#if defined(ENABLE_LIBSODIUM)
	#define LIBSODIUM_ERROR                                (-1)
#endif
#define BYTES_TO_BITS                                 8U
#define U16_NUM_ONE                                   0x0001

//ASCII value definitions
#define ASCII_HT                                      9                           //"?"
#define ASCII_LF                                      0x0A                        //10, Line Feed
#define ASCII_VT                                      0x0B                        //11, Vertical Tab
#define ASCII_FF                                      0x0C                        //12, Form Feed
#define ASCII_CR                                      0x0D                        //13, Carriage Return
#define ASCII_SPACE                                   32                          //" "
#define ASCII_HASHTAG                                 35                          //"#"
#define ASCII_AMPERSAND                               38                          //"&"
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
#define ASCII_MAX_NUM                                 0x7F

//Unicode value definitions
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
#define CONFIG_VERSION                                0.45                                  //Current configuration file version
#define COPYRIGHT_MESSAGE                             L"Copyright (C) 2012-2016 Chengr28"   //Copyright message
#define FULL_VERSION                                  L"0.4.7.8"                            //Current full version

//Size and length definitions(Number)
#define ADDRESS_STRING_MAXSIZE                        64U                         //Maximum size of addresses(IPv4/IPv6) words(64 bytes)
#define ALTERNATE_SERVERNUM                           12U                         //Alternate switching of Main(00: TCP/IPv6, 01: TCP/IPv4, 02: UDP/IPv6, 03: UDP/IPv4), Local(04: TCP/IPv6, 05: TCP/IPv4, 06: UDP/IPv6, 07: UDP/IPv4), DNSCurve(08: TCP/IPv6, 09: TCP/IPv4, 10: UDP/IPv6, 11: UDP/IPv4)
#define BOM_UTF_16_LENGTH                             2U                          //UTF-16 BOM length
#define BOM_UTF_32_LENGTH                             4U                          //UTF-32 BOM length
#define BOM_UTF_8_LENGTH                              3U                          //UTF-8 BOM length
#define DEFAULT_LARGE_BUFFER_SIZE                     4096U                       //Default size of large buffer(4KB/4096 bytes)
#define COMMAND_BUFFER_MAXSIZE                        DEFAULT_LARGE_BUFFER_SIZE   //Maximum size of commands buffer
#define DEFAULT_THREAD_POOL_BASENUM                   24U                         //Default number of base thread pool size
#define DEFAULT_THREAD_POOL_MAXNUM                    256U                        //Default number of maximum thread pool size
#define DNS_RR_MAXCOUNT_AAAA                          43U                         //Maximum Record Resources size of AAAA answers, 28 bytes * 43 = 1204 bytes
#define DNS_RR_MAXCOUNT_A                             75U                         //Maximum Record Resources size of A answers, 16 bytes * 75 = 1200 bytes
#define DNSCRYPT_KEYPAIR_MESSAGE_LEN                  80U                         //DNSCurve/DNScrypt keypair messages length
#define DNSCRYPT_KEYPAIR_INTERVAL                     4U                          //DNSCurve/DNScrypt keypair interval length
#define DNSCRYPT_RECORD_TXT_LEN                       124U                        //Length of DNScrypt TXT Records
#define DOMAIN_DATA_MAXSIZE                           253U                        //Maximum data length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_LEVEL_DATA_MAXSIZE                     63U                         //Domain length is between 3 and 63(Labels must be 63 characters/bytes or less, Section 2.3.1 in RFC 1035).
#define DOMAIN_MAXSIZE                                256U                        //Maximum size of whole level domain is 256 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_MINSIZE                                2U                          //Minimum size of whole level domain is 3 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_RAMDOM_MINSIZE                         6U                          //Minimum size of ramdom domain request
#define FILE_BUFFER_SIZE                              DEFAULT_LARGE_BUFFER_SIZE   //Sizeof file reading buffer
#define FILE_READING_MAXSIZE                          1073741824U                 //Maximum size of whole reading file(1GB/1073741824 bytes).
#define HTTP_VERSION_LENGTH                           2U                          //HTTP version length
#define HTTP_STATUS_CODE_LENGTH                       3U                          //HTTP status code length
#define ICMP_PADDING_MAXSIZE                          1484U                       //Length of ICMP padding data must between 18 bytes and 1464 bytes(Ethernet MTU - IPv4 Standard Header - ICMP Header).
#if defined(PLATFORM_LINUX)
	#define ICMP_PADDING_LENGTH_LINUX                     40U
	#define ICMP_STRING_START_NUM_LINUX                   16U
#elif defined(PLATFORM_MACX)
	#define ICMP_PADDING_LENGTH_MAC                       48U
	#define ICMP_STRING_START_NUM_MAC                     8U
#endif
#define IPV4_SHORTEST_ADDRSTRING                      6U                          //The shortest IPv4 address strings(*.*.*.*).
#define IPV6_SHORTEST_ADDRSTRING                      3U                          //The shortest IPv6 address strings(::).
#define LOG_READING_MAXSIZE                           8388608U                    //Maximum size of whole log file(8MB/8388608 bytes).
#define LOG_READING_MINSIZE                           DEFAULT_LARGE_BUFFER_SIZE   //Minimum size of whole log file(4KB/4096 bytes).
#define MULTIPLE_REQUEST_MAXNUM                       64U                         //Maximum number of multiple request.
#define NETWORK_LAYER_PARTNUM                         2U                          //Number of network layer protocols(IPv6 and IPv4)
#define ORIGINAL_PACKET_MAXSIZE                       1512U                       //Maximum size of original Ethernet II packets(1500 bytes maximum payload length + 8 bytes Ethernet header + 4 bytes FCS)
#define PACKET_MAXSIZE                                1500U                       //Maximum size of packets, Standard MTU of Ethernet II network
#define PADDING_RESERVED_BYTES                        2U                          //Padding reserved bytes(2 bytes)
#define THREAD_POOL_MAXNUM                            1488095U                    //Number of maximum packet buffer queues, 1488095 pps or 1.488Mpps in Gigabit Ethernet
#define THREAD_POOL_MINNUM                            8U                          //Number of minimum packet buffer queues
#define TRANSPORT_LAYER_PARTNUM                       4U                          //Number of transport layer protocols(00: IPv6/UDP, 01: IPv4/UDP, 02: IPv6/TCP, 03: IPv4/TCP)
#define UINT16_MAX_STRING_LENGTH                      6U                          //Maximum number of 16 bits is 65535, its length is 5.
#define UINT32_MAX_STRING_LENGTH                      11U                         //Maximum number of 32 bits is 4294967295, its length is 10.
#define UINT8_MAX_STRING_LENGTH                       4U                          //Maximum number of 8 bits is 255, its length is 3.

//Size and length definitions(Data)
#define DNS_PACKET_MINSIZE                            (sizeof(dns_hdr) + 1U + sizeof(dns_qry))                                          //Minimum DNS packet size(DNS Header + Minimum Domain<ROOT> + DNS Query)
#define EDNS_ADDITIONAL_MAXSIZE                       (sizeof(dns_record_opt) * 2U + sizeof(edns_client_subnet) + sizeof(in6_addr))     //Maximum of EDNS Additional Record Resources size
#define HTTP_TOP_HEADER_LENGTH                        (strlen("HTTP/"))
#define HTTP_RESPONSE_MINSIZE                         (HTTP_TOP_HEADER_LENGTH + HTTP_VERSION_LENGTH + strlen(" ") + HTTP_STATUS_CODE_LENGTH)   //Minimum size of HTTP server response
#define DNSCRYPT_BUFFER_RESERVE_LEN                   (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES)
#define DNSCRYPT_BUFFER_RESERVE_TCP_LEN               (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES)
#define DNSCRYPT_PACKET_MINSIZE                       (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + DNS_PACKET_MINSIZE)
#define DNSCRYPT_RESERVE_HEADER_LEN                   (sizeof(ipv6_hdr) + sizeof(udp_hdr) + DNSCRYPT_BUFFER_RESERVE_LEN)

//Code definitions
#define CHECKSUM_SUCCESS                              0                           //Result of getting correct checksum.
#define DYNAMIC_MIN_PORT                              1024U                       //Well-known port is from 1 to 1023.
#if defined(ENABLE_PCAP)
	#define PCAP_LOOP_INFINITY                            (-1)                         //Pcap packets are processed until another ending condition occurs.
	#define PCAP_COMPILE_OPTIMIZE                         1                            //Pcap optimization on the resulting code is performed.
#endif
#if defined(PLATFORM_WIN)
	#define SYSTEM_SOCKET                                 UINT_PTR                     //System Socket defined(WinSock2.h), which is not the same in x86 and x64 platform and defined in WinSock2.h file.
	#define QUERY_SERVICE_CONFIG_BUFFER_MAXSIZE           8192U                        //Buffer maximum size of QueryServiceConfig function(8KB/8192 Bytes)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define SYSTEM_SOCKET                                 int
#endif

//Time(s) definitions
#define DEFAULT_ALTERNATE_RANGE_TIME                  10U                         //Default time of checking timeout(10 seconds)
#define DEFAULT_ALTERNATE_RESET_TIME                  180U                        //Default time to reset switching of alternate servers(180 seconds/2 minutes)
#define DEFAULT_ALTERNATE_TIMES                       5U                          //Default times of request timeout(5 times)
#define DEFAULT_DOMAIN_TEST_INTERVAL_TIME             900U                        //Default Domain Test time between every sending(900 seconds/15 minutes)
#define DEFAULT_FILEREFRESH_TIME                      15000U                      //Default time between files auto-refreshing(15000 ms/15 seconds)
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
#define DEFAULT_UNRELIABLE_SERIAL_SOCKET_TIMEOUT      1000U                        //Default timeout of unreliable serial sockets(Such as ICMP/ICMPv6/UDP, 1000 ms/1 second)
#if defined(ENABLE_LIBSODIUM)
	#define DEFAULT_DNSCURVE_RECHECK_TIME                 1800U                                    //Default DNSCurve keys recheck time(30 minutes/1800 seconds)
	#define DEFAULT_DNSCURVE_RELIABLE_SOCKET_TIMEOUT      DEFAULT_RELIABLE_ONCE_SOCKET_TIMEOUT     //Same as default timeout of reliable sockets
	#define DEFAULT_DNSCURVE_UNRELIABLE_SOCKET_TIMEOUT    DEFAULT_UNRELIABLE_ONCE_SOCKET_TIMEOUT   //Same as default timeout of unreliable sockets
	#define SHORTEST_DNSCURVE_RECHECK_TIME                10U                                      //The shortset DNSCurve keys recheck time(10 seconds)
#endif
#define FLUSH_DNS_CACHE_INTERVAL_TIME                 5U                          //Time between every flushing(5 seconds)
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define LOOP_INTERVAL_TIME_NO_DELAY                   20000U                         //No delay mode loop interval time(20000 us/20 ms)
#endif
#define LOOP_MAX_TIMES                                16U                         //Maximum of loop times(16 times)
#define MICROSECOND_TO_MILLISECOND                    1000U                       //1000 microseconds(1 ms)
#define SECOND_TO_MILLISECOND                         1000U                       //1000 milliseconds(1 second)
#define SENDING_INTERVAL_TIME                         5000U                       //Time between every sending(5000 ms/5 seconds)
#define SENDING_ONCE_INTERVAL_TIMES                   3U                          //Repeat 3 times between every sending.
#define SHORTEST_ALTERNATE_RANGE_TIME                 5U                          //The shortest time of checking timeout(5 seconds)
#define SHORTEST_ALTERNATE_RESET_TIME                 5U                          //The shortest time to reset switching of alternate servers(5 seconds)
#define SHORTEST_DOMAIN_TEST_INTERVAL_TIME            5U                          //The shortest Domain Test time between every sending(5 seconds)
#define SHORTEST_FILEREFRESH_TIME                     5U                          //The shortset time between files auto-refreshing(5 seconds)
#define SHORTEST_ICMP_TEST_TIME                       5U                          //The shortest time between ICMP Test(5 seconds)
#define SHORTEST_THREAD_POOL_RESET_TIME               5U                          //The shortset time to reset thread pool number(5 seconds)
#define SOCKET_MIN_TIMEOUT                            500U                        //The shortest socket timeout(500 ms)
#define STANDARD_TIMEOUT                              1000U                       //Standard timeout(1000 ms/1 second)
#define UPDATE_SERVICE_TIME                           3000U                       //Update service timeout(3 seconds/3000 ms)

//Data definitions
#if defined(PLATFORM_WIN)
	#define COMMAND_FIREWALL_TEST                         L"--first-setup"
	#define COMMAND_FLUSH_DNS                             L"--flush-dns"
	#define COMMAND_KEYPAIR_GENERATOR                     L"--keypair-generator"
	#define COMMAND_LIB_VERSION                           L"--lib-version"
	#define COMMAND_LONG_HELP                             L"--help"
	#define COMMAND_LONG_PRINT_VERSION                    L"--version"
	#define COMMAND_LONG_SET_PATH                         L"--config-file"
	#define COMMAND_SHORT_HELP                            L"-h"
	#define COMMAND_SHORT_PRINT_VERSION                   L"-v"
	#define COMMAND_SHORT_SET_PATH                        L"-c"
	#define CONFIG_FILE_NAME_LIST                         L"Config.ini", L"Config.conf", L"Config.cfg", L"Config"
	#define ERROR_LOG_FILE_NAME                           L"Error.log"
	#define DEFAULT_ICMP_PADDING_DATA                     ("abcdefghijklmnopqrstuvwabcdefghi")         //Default ICMP padding data in Windows
	#define MAILSLOT_MESSAGE_FLUSH_DNS                    L"Flush Pcap_DNSProxy DNS cache"             //The mailslot message to flush dns cache
	#define MAILSLOT_MESSAGE_FLUSH_DNS_DOMAIN             L"Flush Pcap_DNSProxy DNS cache: "           //The mailslot message to flush dns cache(Single domain)
	#define MAILSLOT_NAME                                 L"\\\\.\\mailslot\\pcap_dnsproxy_mailslot"   //MailSlot name
	#define SID_ADMINISTRATORS_GROUP                      L"S-1-5-32-544"                              //Windows SID of Administrators group
	#define SYSTEM_SERVICE_NAME                           L"PcapDNSProxyService"                       //System service name
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
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
	#define CONFIG_FILE_NAME_LIST                         L"Config.conf", L"Config.ini", L"Config.cfg", L"Config"
	#define CONFIG_FILE_NAME_LIST_STRING                  "Config.conf", "Config.ini", "Config.cfg", "Config"
	#define ERROR_LOG_FILE_NAME                           L"Error.log"
	#define ERROR_LOG_FILE_NAME_STRING                    ("Error.log")
	#define FIFO_MESSAGE_FLUSH_DNS                        ("Flush DNS cache of Pcap_DNSProxy")         //The FIFO message to flush dns cache
	#define FIFO_MESSAGE_FLUSH_DNS_DOMAIN                 ("Flush DNS cache of Pcap_DNSProxy: ")       //The FIFO message to flush dns cache(Single domain)
	#define FIFO_PATH_NAME                                ("/tmp/pcap_dnsproxy_fifo")                  //FIFO pathname
#endif
#define DEFAULT_HTTP_CONNECT_VERSION                  ("1.1")                                      //Default HTTP CONNECT version
#define DEFAULT_LOCAL_SERVERNAME                      ("pcap-dnsproxy.server")                     //Default Local DNS server name
#if defined(PLATFORM_MACX)
	#define DEFAULT_SEQUENCE                               0
#else
	#define DEFAULT_SEQUENCE                               0x0001                                      //Default sequence of protocol
#endif
#define DNS_PACKET_QUERY_LOCATE(Buffer)               (sizeof(dns_hdr) + CheckQueryNameLength(Buffer + sizeof(dns_hdr)) + 1U)                     //Location the beginning of DNS Query
#define DNS_PACKET_RR_LOCATE(Buffer)                  (sizeof(dns_hdr) + CheckQueryNameLength(Buffer + sizeof(dns_hdr)) + 1U + sizeof(dns_qry))   //Location the beginning of DNS Resource Records
#define DNS_TCP_PACKET_QUERY_LOCATE(Buffer)           (sizeof(dns_tcp_hdr) + CheckQueryNameLength(Buffer + sizeof(dns_tcp_hdr)) + 1U)

//Base64 definitions
#define BASE64_PAD                                    ('=')
//#define BASE64_DECODE_FIRST                           ('+')
//#define BASE64_DECODE_LAST                            ('z')
//#define BASE64_DECODE_OUT_SIZE(Message)               (((Message)) / 4U * 3U)
#define BASE64_ENCODE_OUT_SIZE(Message)               (((Message) + 2U) / 3U * 4U)

//Read text input types and Compare addresses definitions
#define ADDRESS_COMPARE_LESS                          1U
#define ADDRESS_COMPARE_EQUAL                         2U
#define ADDRESS_COMPARE_GREATER                       3U
#define READ_TEXT_PARAMETER                           0
#define READ_TEXT_PARAMETER_MONITOR                   1U
#define READ_TEXT_HOSTS                               2U
#define READ_TEXT_IPFILTER                            3U

//Log level and error type definitions
#define LOG_LEVEL_0                                   0                           //Disable log printing
#define LOG_LEVEL_1                                   1U                          //Failed messages
#define LOG_LEVEL_2                                   2U                          //Base error messages
#define LOG_LEVEL_3                                   3U                          //All error messages
#define LOG_LEVEL_4                                   4U                          //Reserved level
#define LOG_LEVEL_5                                   5U                          //Reserved level
#define DEFAULT_LOG_LEVEL                             LOG_LEVEL_3
#define LOG_LEVEL_MAXNUM                              LOG_LEVEL_3
#define LOG_MESSAGE_NOTICE                            1U                          // 01: Notice Message
#define LOG_ERROR_SYSTEM                              2U                          // 02: System Error
#define LOG_ERROR_PARAMETER                           3U                          // 03: Parameter Error
#define LOG_ERROR_IPFILTER                            4U                          // 04: IPFilter Error
#define LOG_ERROR_HOSTS                               5U                          // 05: Hosts Error
#define LOG_ERROR_NETWORK                             6U                          // 06: Network Error
#if defined(ENABLE_PCAP)
	#define LOG_ERROR_PCAP                                7U                          // 07: Pcap Error
#endif
#if defined(ENABLE_LIBSODIUM)
	#define LOG_ERROR_DNSCURVE                            8U                          // 08: DNSCurve Error
#endif
#define LOG_ERROR_SOCKS                               9U                          // 09: SOCKS Error
#define LOG_ERROR_HTTP_CONNECT                        10U                         // 10: HTTP CONNECT Error
#if defined(ENABLE_TLS)
	#define LOG_ERROR_TLS                                 11U                          // 08: TLS Error
#endif

//Codes and types definitions
#define ALTERNATE_TYPE_MAIN_TCP_IPV6                  0
#define ALTERNATE_TYPE_MAIN_TCP_IPV4                  1U
#define ALTERNATE_TYPE_MAIN_UDP_IPV6                  2U
#define ALTERNATE_TYPE_MAIN_UDP_IPV4                  3U
#define ALTERNATE_TYPE_LOCAL_TCP_IPV6                 4U
#define ALTERNATE_TYPE_LOCAL_TCP_IPV4                 5U
#define ALTERNATE_TYPE_LOCAL_UDP_IPV6                 6U
#define ALTERNATE_TYPE_LOCAL_UDP_IPV4                 7U
#if defined(ENABLE_LIBSODIUM)
	#define ALTERNATE_TYPE_DNSCURVE_TCP_IPV6              8U
	#define ALTERNATE_TYPE_DNSCURVE_TCP_IPV4              9U
	#define ALTERNATE_TYPE_DNSCURVE_UDP_IPV6              10U
	#define ALTERNATE_TYPE_DNSCURVE_UDP_IPV4              11U
#endif
#define CACHE_TYPE_NONE                               0
#define CACHE_TYPE_BOTH                               1U
#define CACHE_TYPE_TIMER                              2U
#define CACHE_TYPE_QUEUE                              3U
#define CPM_POINTER_TO_HEADER                         0
#define CPM_POINTER_TO_RR                             1U
#define CPM_POINTER_TO_ADDITIONAL                     2U
#define HOSTS_TYPE_WHITE                              1U
#define HOSTS_TYPE_BANNED                             2U
#define HOSTS_TYPE_NORMAL                             3U
#define HOSTS_TYPE_LOCAL                              4U
#define HOSTS_TYPE_CNAME                              5U
#define HOSTS_TYPE_SOURCE                             6U
#define LISTEN_MODE_PROXY                             0
#define LISTEN_MODE_PRIVATE                           1U
#define LISTEN_MODE_SERVER                            2U
#define LISTEN_MODE_CUSTOM                            3U
#define LISTEN_PROTOCOL_NETWORK_BOTH                  0
#define LISTEN_PROTOCOL_IPV6                          1U
#define LISTEN_PROTOCOL_IPV4                          2U
#define LISTEN_PROTOCOL_TRANSPORT_BOTH                0
#define LISTEN_PROTOCOL_TCP                           1U
#define LISTEN_PROTOCOL_UDP                           2U
#define NETWORK_LAYER_IPV6                            0
#define NETWORK_LAYER_IPV4                            1U
#define REQUEST_MODE_BOTH                             0
#define REQUEST_MODE_IPV6                             1U
#define REQUEST_MODE_IPV4                             2U
#define REQUEST_MODE_UDP                              0
#define REQUEST_MODE_TCP                              1U
#define REQUEST_MODE_DIRECT_NONE                      0
#define REQUEST_MODE_DIRECT_BOTH                      1U
#define REQUEST_MODE_DIRECT_IPV6                      2U
#define REQUEST_MODE_DIRECT_IPV4                      3U
#define SOCKET_SETTING_INVALID_CHECK                  0
#define SOCKET_SETTING_CLOSE                          1U
#define SOCKET_SETTING_TIMEOUT                        2U
#define SOCKET_SETTING_REUSE                          3U
#define SOCKET_SETTING_TCP_FAST_OPEN                  4U
#define SOCKET_SETTING_NON_BLOCKING_MODE              5U
//#define SOCKET_SETTING_TCP_KEEPALIVE                  6U
#define SOCKET_SETTING_UDP_BLOCK_RESET                7U
#define SOCKET_SETTING_HOP_LIMITS_IPV4                8U
#define SOCKET_SETTING_HOP_LIMITS_IPV6                9U
#define SOCKET_SETTING_DO_NOT_FRAGMENT                10U

//Request process type definitions
#define REQUEST_PROCESS_LOCAL                         1U
#define REQUEST_PROCESS_SOCKS_MAIN                    2U
#define REQUEST_PROCESS_HTTP_CONNECT                  3U
#define REQUEST_PROCESS_DIRECT                        4U
#define REQUEST_PROCESS_DNSCURVE_MAIN                 5U
#define REQUEST_PROCESS_DNSCURVE_SIGN                 6U
#define REQUEST_PROCESS_TCP                           7U
#define REQUEST_PROCESS_UDP_NORMAL                    8U
#define REQUEST_PROCESS_UDP_NO_MARKING                9U
#define REQUEST_PROCESS_SOCKS_CLIENT_SELECTION        10U
#define REQUEST_PROCESS_SOCKS_USER_AUTHENTICATION     11U
#define REQUEST_PROCESS_SOCKS_4_COMMAND_REPLY         12U
#define REQUEST_PROCESS_SOCKS_5_COMMAND_REPLY         13U
#if defined(ENABLE_TLS)
	#define REQUEST_PROCESS_TLS_HANDSHAKE                 14U
	#define REQUEST_PROCESS_TLS_TRANSPORT                 15U
	#define REQUEST_PROCESS_TLS_SHUTDOWN                  16U
#endif

//DNSCurve server type definitions(Do NOT define the same with EXIT_SUCCESS == 0 and EXIT_FAILURE == 1U)
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_MAIN_IPV6                        2U                          //DNSCurve Main(IPv6)
	#define DNSCURVE_MAIN_IPV4                        3U                          //DNSCurve Main(IPv4)
	#define DNSCURVE_ALTERNATE_IPV6                   4U                          //DNSCurve Alternate(IPv6)
	#define DNSCURVE_ALTERNATE_IPV4                   5U                          //DNSCurve Alternate(IPv4)
#endif

//TLS type definitions
#if defined(ENABLE_TLS)
	#define TLS_MIN_VERSION                           0x0301                      //TLS 1.0 = SSL 3.1
	#define TLS_VERSION_AUTO                          0
	#define TLS_VERSION_1_0                           10U
	#define TLS_VERSION_1_1                           11U
	#define TLS_VERSION_1_2                           12U
	#define TLS_VERSION_1_3                           13U
	#if defined(PLATFORM_WIN)
		#define SSPI_SECURE_BUFFER_NUM                    4U
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		#define OPENSSL_VERSION_1_0_1                     0x10001000L
		#define OPENSSL_VERSION_1_1_0                     0x10100000L
		#define OPENSSL_STATIC_BUFFER_SIZE                256U
		#define OPENSSL_STRONG_CIPHER_LIST                ("HIGH:!SSLv2:!SSLv3:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4")
	#endif
#endif


//////////////////////////////////////////////////
// Function definitions(Part 2)
#define hton16_Force(Value)   ((uint16_t)(((uint8_t *)&Value)[0] << (sizeof(uint8_t) * BYTES_TO_BITS) | ((uint8_t *)&Value)[1U]))
#define ntoh16_Force          hton16_Force
#define hton32_Force(Value)   ((uint32_t)(((uint8_t *)&Value)[0] << ((sizeof(uint16_t) + sizeof(uint8_t)) * BYTES_TO_BITS) | ((uint8_t *)&Value)[1U] << (sizeof(uint16_t) * BYTES_TO_BITS) | ((uint8_t *)&Value)[2U] << (sizeof(uint8_t) * BYTES_TO_BITS) | ((uint8_t *)&Value)[3U]))
#define ntoh32_Force          hton32_Force
#if BYTE_ORDER == LITTLE_ENDIAN
	#define hton64(Value)         ((uint64_t)((((uint64_t)htonl((uint32_t)((Value << (sizeof(uint32_t) * BYTES_TO_BITS)) >> (sizeof(uint32_t) * BYTES_TO_BITS)))) << (sizeof(uint32_t) * BYTES_TO_BITS)) | (uint32_t)htonl((uint32_t)(Value >> (sizeof(uint32_t) * BYTES_TO_BITS)))))
#else //BIG_ENDIAN
	#define hton64(Value)         Value
#endif
#define ntoh64                hton64
#if defined(PLATFORM_WIN)
	#if defined(PLATFORM_WIN_XP)
		#define GetCurrentSystemTime   GetTickCount
	#else
		#define GetCurrentSystemTime   GetTickCount64
	#endif
	#define Sleep(Millisecond)     Sleep((DWORD)(Millisecond))
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define Sleep(Millisecond)     usleep((useconds_t)((Millisecond) * MICROSECOND_TO_MILLISECOND))
	#define usleep(Millisecond)    usleep((useconds_t)(Millisecond))
#endif


//////////////////////////////////////////////////
// Main structures and classes
// 
//File Data structure
typedef struct _file_data_
{
	std::wstring                         FileName;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string                          sFileName;
#endif
	time_t                               ModificationTime;
}FileData, FILE_DATA, *PFileData, *PFILE_DATA;

//Socket Data structure
typedef struct _socket_data_
{
	SYSTEM_SOCKET                        Socket;
	sockaddr_storage                     SockAddr;
	socklen_t                            AddrLen;
}SocketData, SOCKET_DATA, *PSocketData, *PSOCKET_DATA;

//Socket Marking Data structure
typedef std::pair<SYSTEM_SOCKET, uint64_t> SocketMarkingData, SOCKET_MARKING_DATA, *PSocketMarkingData, *PSOCKET_MARKING_DATA;

//Address Prefix Block structure
typedef std::pair<sockaddr_storage, size_t> AddressPrefixBlock, ADDRESS_PREFIX_BLOCK, *PAddressPrefixBlock, *PADDRESS_PREFIX_BLOCK;

//Address Union Data structure
typedef union _address_union_data_
{
	sockaddr_storage                     Storage;
	sockaddr_in6                         IPv6;
	sockaddr_in                          IPv4;
}AddressUnionData, ADDRESS_UNION_DATA, *PAddressUnionData, *PADDRESS_UNION_DATA;

//Hop Limit and TTL Data structure
typedef union _hoplimit_data_
{
	uint8_t                              TTL;
	uint8_t                              HopLimit;
}HopLimitUnionData, HOP_LIMIT_UNION_DATA, *PHopLimitUnionData, *PHOP_LIMIT_UNION_DATA;

//DNS Server Data structure
typedef struct _dns_server_data_
{
	ADDRESS_UNION_DATA                   AddressData;
#if defined(ENABLE_PCAP)
	HOP_LIMIT_UNION_DATA                 HopLimitData_Assign;
	HOP_LIMIT_UNION_DATA                 HopLimitData_Mark;
#endif
}DNSServerData, DNS_SERVER_DATA, *PDNSServerData, *PDNS_SERVER_DATA;

//Socket Selecting Once Data structure
typedef struct _socket_selecting_once_data_
{
	std::shared_ptr<uint8_t>             RecvBuffer;
	size_t                               RecvLen;
	bool                                 IsPacketDone;
}SocketSelectingOnceData, SOCKET_SELECTING_ONCE_DATA, *PSocketSelectingOnceData, *PSOCKET_SELECTING_ONCE_DATA;

//Socket Selecting Serial Data structure
typedef struct _socket_selecting_serial_data_
{
	std::shared_ptr<uint8_t>             SendBuffer;
	size_t                               SendSize;
	size_t                               SendLen;
	std::shared_ptr<uint8_t>             RecvBuffer;
	size_t                               RecvSize;
	size_t                               RecvLen;
	bool                                 IsPacketDone;
	bool                                 IsSendOnly;
}SocketSelectingSerialData, SOCKET_SELECTING_SERIAL_DATA, *PSocketSelectingSerialData, *PSOCKET_SELECTING_SERIAL_DATA;

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
	uint16_t                             Protocol;
	bool                                 IsLocal;
	ADDRESS_UNION_DATA                   LocalTarget;
}DNSPacketData, DNS_PACKET_DATA, *PDNSPacketData, *PDNS_PACKET_DATA;

//DNS Cache Data structure
typedef struct _dns_cache_data_
{
	std::string                          Domain;
	std::shared_ptr<uint8_t>             Response;
	size_t                               Length;
	uint16_t                             RecordType;
	uint64_t                             ClearCacheTime;
}DNSCacheData, DNS_CACHE_DATA, *PDNSCacheData, *PDNS_CACHE_DATA;

//Monitor Queue Data structure
typedef std::pair<DNS_PACKET_DATA, SOCKET_DATA> MonitorQueueData, MONITOR_QUEUE_DATA, *PMonitorQueueData, *PMONITOR_QUEUE_DATA;

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
}DNSCurveServerData, DNSCURVE_SERVER_DATA, *PDNSCurveServerData, *PDNSCURVE_SERVER_DATA;

//DNSCurve Socket Selecting Data structure
typedef struct _dnscurve_socket_selecting_data_
{
	size_t                               ServerType;
	uint8_t                              *PrecomputationKey;
	uint8_t                              *ReceiveMagicNumber;
	uint8_t                              *SendBuffer;
	size_t                               SendSize;
	std::shared_ptr<uint8_t>             RecvBuffer;
	size_t                               RecvLen;
	bool                                 IsPacketDone;
}DNSCurveSocketSelectingData, DNSCURVE_SOCKET_SELECTING_DATA, *PDNSCurveSocketSelectingData, *PDNSCURVE_SOCKET_SELECTING_DATA;
#endif

//Class definitions
//Configuration class
typedef class ConfigurationTable
{
public:
//Parameters from configure files
//[Base] block
	double                               Version;
	size_t                               FileRefreshTime;
	size_t                               LargeBufferSize;
//[Log] block
	size_t                               PrintLogLevel;
	size_t                               LogMaxSize;
//[Listen] block
#if defined(ENABLE_PCAP)
	bool                                 IsPcapCapture;
	std::vector<std::string>             *PcapDevicesBlacklist;
	size_t                               PcapReadingTimeout;
#endif
	size_t                               OperationMode;
	size_t                               ListenProtocol_Network;
	size_t                               ListenProtocol_Transport;
	std::vector<uint16_t>                *ListenPort;
	bool                                 IPFilterType;
	size_t                               IPFilterLevel;
	bool                                 AcceptType;
	std::vector<uint16_t>                *AcceptTypeList;
//[DNS] block
	size_t                               RequestMode_Network;
	size_t                               RequestMode_Transport;
	size_t                               DirectRequest;
	size_t                               CacheType;
	size_t                               CacheParameter;
	uint32_t                             HostsDefaultTTL;
//[Local DNS] block
	size_t                               LocalProtocol_Network;
	size_t                               LocalProtocol_Transport;
	bool                                 LocalForce;
	bool                                 LocalMain;
	bool                                 LocalHosts;
	bool                                 LocalRouting;
//[Addresses] block
	std::vector<sockaddr_storage>        *ListenAddress_IPv6;
	std::vector<sockaddr_storage>        *ListenAddress_IPv4;
	PADDRESS_PREFIX_BLOCK                LocalMachineSubnet_IPv6;
	PADDRESS_PREFIX_BLOCK                LocalMachineSubnet_IPv4;
	DNS_SERVER_DATA                      Target_Server_IPv6;
	DNS_SERVER_DATA                      Target_Server_Alternate_IPv6;
	DNS_SERVER_DATA                      Target_Server_IPv4;
	DNS_SERVER_DATA                      Target_Server_Alternate_IPv4;
	ADDRESS_UNION_DATA                   Target_Server_Local_IPv6;
	ADDRESS_UNION_DATA                   Target_Server_Alternate_Local_IPv6;
	ADDRESS_UNION_DATA                   Target_Server_Local_IPv4;
	ADDRESS_UNION_DATA                   Target_Server_Alternate_Local_IPv4;
	std::vector<DNS_SERVER_DATA>         *Target_Server_IPv6_Multiple;
	std::vector<DNS_SERVER_DATA>         *Target_Server_IPv4_Multiple;
//[Values] block
	size_t                               ThreadPoolBaseNum;
	size_t                               ThreadPoolMaxNum;
	size_t                               ThreadPoolResetTime;
	size_t                               QueueResetTime;
	size_t                               EDNSPayloadSize;
#if defined(PLATFORM_WIN)
	DWORD                                PacketHopLimits_IPv4_Begin;
	DWORD                                PacketHopLimits_IPv4_End;
	DWORD                                PacketHopLimits_IPv6_Begin;
	DWORD                                PacketHopLimits_IPv6_End;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	int                                  PacketHopLimits_IPv4_Begin;
	int                                  PacketHopLimits_IPv4_End;
	int                                  PacketHopLimits_IPv6_Begin;
	int                                  PacketHopLimits_IPv6_End;
#endif
#if defined(ENABLE_PCAP)
	uint8_t                              HopLimitFluctuation;
#endif
#if defined(PLATFORM_WIN)
	DWORD                                SocketTimeout_Reliable_Once;
	DWORD                                SocketTimeout_Unreliable_Once;
	DWORD                                SocketTimeout_Reliable_Serial;
	DWORD                                SocketTimeout_Unreliable_Serial;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	timeval                              SocketTimeout_Reliable_Once;
	timeval                              SocketTimeout_Unreliable_Once;
	timeval                              SocketTimeout_Reliable_Serial;
	timeval                              SocketTimeout_Unreliable_Serial;
#endif
	size_t                               ReceiveWaiting;
	size_t                               AlternateTimes;
	size_t                               AlternateTimeRange;
	size_t                               AlternateResetTime;
	size_t                               MultipleRequestTimes;
//[Switches] block
	bool                                 TCP_FastOpen;
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
	bool                                 EDNS_Switch_DNSCurve;
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
//[Data] block
#if defined(ENABLE_PCAP)
	uint16_t                             ICMP_ID;
	uint16_t                             ICMP_Sequence;
	size_t                               ICMP_Speed;
	uint8_t                              *ICMP_PaddingData;
	size_t                               ICMP_PaddingLength;
	uint8_t                              *DomainTest_Data;
	uint16_t                             DomainTest_ID;
	size_t                               DomainTest_Speed;
#endif
	std::string                          *LocalFQDN_String;
	uint8_t                              *LocalFQDN_Response;
	size_t                               LocalFQDN_Length;
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	uint8_t                              *LocalServer_Response;
	size_t                               LocalServer_Length;
#endif
//[Proxy] block
	bool                                 SOCKS_Proxy;
	size_t                               SOCKS_Version;
	size_t                               SOCKS_Protocol_Network;
	size_t                               SOCKS_Protocol_Transport;
	bool                                 SOCKS_UDP_NoHandshake;
	bool                                 SOCKS_Only;
	ADDRESS_UNION_DATA                   SOCKS_Address_IPv4;
	ADDRESS_UNION_DATA                   SOCKS_Address_IPv6;
	ADDRESS_UNION_DATA                   SOCKS_TargetServer;
	std::string                          *SOCKS_TargetDomain;
	uint16_t                             SOCKS_TargetDomain_Port;
	std::string                          *SOCKS_Username;
	std::string                          *SOCKS_Password;
	bool                                 HTTP_CONNECT_Proxy;
	size_t                               HTTP_CONNECT_Protocol;
	bool                                 HTTP_CONNECT_Only;
	ADDRESS_UNION_DATA                   HTTP_CONNECT_Address_IPv4;
	ADDRESS_UNION_DATA                   HTTP_CONNECT_Address_IPv6;
#if defined(ENABLE_TLS)
	bool                                 HTTP_CONNECT_TLS_Handshake;
	size_t                               HTTP_CONNECT_TLS_Version;
	bool                                 HTTP_CONNECT_TLS_Validation;
	std::wstring                         *HTTP_CONNECT_TLS_SNI;
	std::string                          *sHTTP_CONNECT_TLS_SNI;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string                          *HTTP_CONNECT_TLS_AddressString_IPv4;
	std::string                          *HTTP_CONNECT_TLS_AddressString_IPv6;
#endif
#endif
	std::string                          *HTTP_CONNECT_TargetDomain;
	std::string                          *HTTP_CONNECT_Version;
	std::string                          *HTTP_CONNECT_HeaderField;
	std::string                          *HTTP_CONNECT_ProxyAuthorization;

//[DNSCurve/DNSCrypt] block
#if defined(ENABLE_LIBSODIUM)
	bool                                 IsDNSCurve;
#endif

//Member functions
	ConfigurationTable(
		void);
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
	bool                                 IsWinSockInitialized;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
#if defined(ENABLE_TLS)
	bool                                 IsOpenSSLInitialized;
#endif
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
//	int8_t                               *Base64_DecodeTable;
	std::atomic<size_t>                  *ThreadRunningNum;
	std::atomic<size_t>                  *ThreadRunningFreeNum;

//Path and file status
	std::vector<std::wstring>            *Path_Global;
	std::wstring                         *Path_ErrorLog;
	std::vector<std::wstring>            *FileList_Hosts;
	std::vector<std::wstring>            *FileList_IPFilter;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::vector<std::string>             *sPath_Global;
	std::string                          *sPath_ErrorLog;
	std::vector<std::string>             *sFileList_Hosts;
	std::vector<std::string>             *sFileList_IPFilter;
#endif

//Network status
	bool                                 GatewayAvailable_IPv6;
	bool                                 GatewayAvailable_IPv4;

//Local address status
	uint8_t                              *LocalAddress_Response[NETWORK_LAYER_PARTNUM];
	size_t                               LocalAddress_Length[NETWORK_LAYER_PARTNUM];
#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
	std::vector<std::string>             *LocalAddress_ResponsePTR[NETWORK_LAYER_PARTNUM];
#endif

//Member functions
	GlobalStatus(
		void);
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

//Hosts lists class
typedef class HostsTable
{
public:
	std::vector<ADDRESS_PREFIX_BLOCK>    SourceList;
	std::vector<ADDRESS_UNION_DATA>      AddrOrTargetList;
	std::regex                           PatternRegex;
	std::string                          PatternOrDomainString;
	std::vector<uint16_t>                RecordTypeList;
	size_t                               PermissionType;
	bool                                 PermissionOperation;
	bool                                 IsStringMatching;

//Member functions
	HostsTable(
		void);
}HOSTS_TABLE;

//Alternate swap table class
typedef class AlternateSwapTable
{
public:
	bool                                 IsSwap[ALTERNATE_SERVERNUM];
	size_t                               TimeoutTimes[ALTERNATE_SERVERNUM];

//Member functions
	AlternateSwapTable(
		void);
}ALTERNATE_SWAP_TABLE;

//Blacklist of results class
typedef class ResultBlacklistTable
{
public:
	std::vector<AddressRangeTable>       Addresses;
	std::regex                           PatternRegex;
	std::string                          PatternString;
}RESULT_BLACKLIST_TABLE;

//Address Hosts class
typedef class AddressHostsTable
{
public:
	std::vector<sockaddr_storage>        Address_Target;
	std::vector<AddressRangeTable>       Address_Source;
}ADDRESS_HOSTS_TABLE;

//Address routing table class
typedef class AddressRoutingTable
{
public:
	size_t                                   Prefix;
	std::map<uint64_t, std::set<uint64_t>>   AddressRoutingList_IPv6;
	std::set<uint32_t>                       AddressRoutingList_IPv4;

//Member functions
	AddressRoutingTable(
		void);
}ADDRESS_ROUTING_TABLE;

//Port table class
#if defined(ENABLE_PCAP)
typedef class OutputPacketTable
{
public:
	std::vector<SOCKET_DATA>             SocketData_Output;
	SOCKET_DATA                          SocketData_Input;
	uint16_t                             Protocol_Network;
	uint16_t                             Protocol_Transport;
	uint64_t                             ClearPortTime;
	size_t                               ReceiveIndex;

//Member functions
	OutputPacketTable(
		void);
}OUTPUT_PACKET_TABLE;
#endif

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

#if defined(ENABLE_LIBSODIUM)
//DNSCurve Configuration class
typedef class DNSCurveConfigurationTable
{
public:
//[DNSCurve] block
	size_t                               DNSCurvePayloadSize;
	size_t                               DNSCurveProtocol_Network;
	size_t                               DNSCurveProtocol_Transport;
#if defined(PLATFORM_WIN)
	DWORD                                DNSCurve_SocketTimeout_Reliable;
	DWORD                                DNSCurve_SocketTimeout_Unreliable;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	timeval                              DNSCurve_SocketTimeout_Reliable;
	timeval                              DNSCurve_SocketTimeout_Unreliable;
#endif
	bool                                 IsEncryption;
	bool                                 IsEncryptionOnly;
	bool                                 IsClientEphemeralKey;
	size_t                               KeyRecheckTime;
//[DNSCurve Addresses] block
	uint8_t                              *Client_PublicKey;
	uint8_t                              *Client_SecretKey;
	DNSCURVE_SERVER_DATA                 DNSCurve_Target_Server_IPv6;
	DNSCURVE_SERVER_DATA                 DNSCurve_Target_Server_Alternate_IPv6;
	DNSCURVE_SERVER_DATA                 DNSCurve_Target_Server_IPv4;
	DNSCURVE_SERVER_DATA                 DNSCurve_Target_Server_Alternate_IPv4;

//Member functions
	DNSCurveConfigurationTable(
		void);
	void SetToMonitorItem(
		void);
	void MonitorItemToUsing(
		DNSCurveConfigurationTable * const DNSCurveConfigurationParameter);
	void MonitorItemReset(
		void);
	~DNSCurveConfigurationTable(
		void);
}DNSCURVE_CONFIGURATION_TABLE;
#endif

#if defined(ENABLE_TLS)
#if defined(PLATFORM_WIN)
//SSPI Handle class
typedef class SSPIHandleTable
{
public:
	CredHandle                           ClientCredentials;
	CtxtHandle                           ContextHandle;
	DWORD                                InputFlags;
	SecPkgContext_StreamSizes            StreamSizes;
	SECURITY_STATUS                      LastReturnValue;

//Member functions
	SSPIHandleTable(
		void);
	~SSPIHandleTable(
		void);
}SSPI_HANDLE_TABLE;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//OpenSSL Context class
typedef class OpenSSLContextTable
{
public:
	SSL_CTX                              *MethodContext;
	BIO                                  *SessionBIO;
	SSL                                  *SessionData;
	std::string                          AddressString;

//Member functions
	OpenSSLContextTable(
		void);
	~OpenSSLContextTable(
		void);
}OPENSSL_CONTEXT_TABLE;
#endif
#endif
