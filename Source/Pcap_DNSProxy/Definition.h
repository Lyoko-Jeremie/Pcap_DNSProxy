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
#define RETURN_ERROR                                  (-1)
#define UINT16_NUM_ONE                                0x0001
#define UNITS_IN_8_OCTETS                             8U                          //8 octets = 1 unit
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
#define CONFIG_VERSION_MAXSIZE                        8U                                    //Maximum size of version
#define COPYRIGHT_MESSAGE                             L"Copyright (C) 2012-2018 Chengr28"   //Copyright message
#define FULL_VERSION                                  L"0.4.9.12"                           //Current full version

//Size and length definitions(Number)
#define ADDRESS_STRING_IPV4_MINSIZE                   6U                                //The shortest IPv4 address strings(*.*.*.*)
#define ADDRESS_STRING_IPV6_MINSIZE                   2U                                //The shortest IPv6 address strings(::)
#define ADDRESS_STRING_MAXSIZE                        64U                               //Maximum size of addresses(IPv6/IPv4) words(64 bytes)
#define ALTERNATE_SERVER_NUM                          12U                               //Alternate switching of Main(00: TCP/IPv6, 01: TCP/IPv4, 02: UDP/IPv6, 03: UDP/IPv4), Local(04: TCP/IPv6, 05: TCP/IPv4, 06: UDP/IPv6, 07: UDP/IPv4), DNSCurve(08: TCP/IPv6, 09: TCP/IPv4, 10: UDP/IPv6, 11: UDP/IPv4)
#define COMMAND_COUNT_MIN                             1                                 //Minimum count of commands
#define DEFAULT_LARGE_BUFFER_SIZE                     4096U                             //Default size of large buffer(4KB/4096 bytes)
#define DEFAULT_LOG_READING_MAXSIZE                   8388608U                          //Default number of maximum log file size(8MB/8388608 bytes)
#define DEFAULT_THREAD_POOL_MAXNUM                    256U                              //Default number of maximum thread pool size
#define DIFFERNET_FILE_SET_NUM                        2U                                //Number of different file set
#define DNS_RECORD_COUNT_AAAA_MAX                     43U                               //Maximum Record Resources size of whole AAAA answers, 28 bytes * 43 records = 1204 bytes
#define DNS_RECORD_COUNT_A_MAX                        75U                               //Maximum Record Resources size of whole A answers, 16 bytes * 75 records = 1200 bytes
#if defined(ENABLE_LIBSODIUM)
	#define DNSCRYPT_DATABASE_ITEM_MIN                    14U                               //Minimum number of item in DNSCrypt database
	#define DNSCRYPT_DATABASE_ADDRESS_LOCATION            10U                               //Location of DNSCurve Address in DNSCrypt database
	#define DNSCRYPT_DATABASE_PROVIDER_NAME_LOCATION      11U                               //Location of Provider Name in DNSCrypt database
	#define DNSCRYPT_DATABASE_PROVIDER_KEY_LOCATION       12U                               //Location of Provider Public Key in DNSCrypt database
	#define DNSCRYPT_KEYPAIR_MESSAGE_LEN                  80U                               //DNScrypt keypair messages length
	#define DNSCRYPT_KEYPAIR_INTERVAL                     4U                                //DNScrypt keypair interval length
	#define DNSCRYPT_RECORD_TXT_LEN                       124U                              //Length of DNScrypt TXT Records
#endif
#define DOMAIN_DATA_MAXSIZE                           253U                              //Maximum data length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_MAXSIZE                                256U                              //Maximum size of whole level domain is 256 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_MINSIZE                                2U                                //Minimum size of whole level domain is 3 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_RANDOM_MINSIZE                         6U                                //Minimum size of random domain request
#define DOMAIN_SINGLE_DATA_MAXSIZE                    63U                               //Domain length is between 3 and 63(Single label must be 63 characters/bytes or less, Section 2.3.1 in RFC 1035).
#define ERROR_MESSAGE_MAXSIZE                         512U                              //Maximum size of log message
#define ERROR_MESSAGE_MINSIZE                         3U                                //Minimum size of log message
#define FILE_BUFFER_SIZE                              DEFAULT_LARGE_BUFFER_SIZE         //Size of file reading buffer
#define FILE_READING_MAXSIZE                          268435456U                        //Maximum size of whole reading file(256 MB/268435456 bytes).
#define HTTP_AUTHORIZATION_MAXSIZE                    DEFAULT_LARGE_BUFFER_SIZE         //Maximum size of HTTP proxy authorization string.
#define HTTP_VERSION_SUPPORT_COUNT                    2U                                //HTTP version 1.1 and 2 which are supported.
#define HTTP_VERSION_MAXSIZE                          3U                                //Maximum size of HTTP version
#define ICMP_PADDING_MAXSIZE                          1464U                             //Length of ICMP padding data must between 18 bytes and 1464 bytes(Ethernet MTU - IPv4 Standard Header - ICMP Header).
#define ICMP_PADDING_MINSIZE                          17U                               //Length of ICMP padding data must between 18 bytes and 1464 bytes(Ethernet MTU - IPv4 Standard Header - ICMP Header).
#if defined(PLATFORM_LINUX)
	#define ICMP_PADDING_LENGTH_LINUX                     40U
	#define ICMP_STRING_START_NUM_LINUX                   16U
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_MACOS))
	#define ICMP_PADDING_LENGTH_MACOS                     48U
	#define ICMP_STRING_START_NUM_MACOS                   8U
#endif
#define LOG_READING_MINSIZE                           DEFAULT_LARGE_BUFFER_SIZE         //Minimum size of whole log file
#define MEMORY_BUFFER_EXPAND_BYTES                    1U                                //Memory buffer expanded bytes(1 bytes)
#define MEMORY_RESERVED_BYTES                         2U                                //Memory buffer reserved bytes(2 bytes)
#define MULTIPLE_REQUEST_MAXNUM                       32U                               //Maximum number of multiple request.
#define NETWORK_LAYER_PARTNUM                         2U                                //Number of network layer protocols(IPv6 and IPv4)
#define NULL_TERMINATE_LENGTH                         1U                                //Length of C style string null
//#define PACKET_ORIGINAL_MAXSIZE                       1522U                             //Maximum size of original Ethernet frame, 6 bytes destination MAC + 6 bytes source MAC + 4 bytes 802.1Q tag(optional) + 2 bytes Ethertype + 1500 bytes payload + 4 bytes FCS/Frame Check Sequence
#define PACKET_ORIGINAL_MAXSIZE                       2048U                             //Some DNS response length exceeds an Ethernet frame maximum payload, extends to 2 KB/2048 bytes.
//#define PACKET_NORMAL_MAXSIZE                         1480U                             //Maximum size of normal Ethernet frame, 1500 bytes maximum payload - 20 bytes IPv4 header(IPv6 header length is longer than IPv4) and ignore all other transport layer protocols.
#define PACKET_NORMAL_MAXSIZE                         PACKET_ORIGINAL_MAXSIZE           //Some DNS response length exceeds an Ethernet frame maximum payload, extends to 2 KB/2048 bytes.
#if defined(ENABLE_PCAP)
	#define PCAP_CAPTURE_STRING_MAXNUM                    256U                        //Maximum length of pcap capture drive name and description
#endif
#if defined(PLATFORM_WIN)
	#define QUERY_SERVICE_CONFIG_BUFFER_MAXSIZE           8192U                       //Buffer maximum size of QueryServiceConfig function(8KB/8192 Bytes)
#endif
#if defined(PLATFORM_WIN)
	#define SERVICE_TABLE_ENTRY_NUM                       2U                          //Service table entry number
#endif
#define THREAD_POOL_MAXNUM                            148809524U                  //Number of maximum packet buffer queues, 148809523pps or 148.809Mpps in 100 Gigabit Ethernet
#define THREAD_POOL_MINNUM                            8U                          //Number of minimum packet buffer queues
#define TRANSPORT_LAYER_PARTNUM                       4U                          //Number of transport layer protocols(00: IPv6/UDP, 01: IPv4/UDP, 02: IPv6/TCP, 03: IPv4/TCP)
#define UINT16_STRING_MAXLEN                          6U                          //Maximum number of 16 bits is 65535, its length is 5.
#define UINT32_STRING_MAXLEN                          11U                         //Maximum number of 32 bits is 4294967295, its length is 10.
#define UINT8_STRING_MAXLEN                           4U                          //Maximum number of 8 bits is 255, its length is 3.

//Size and length definitions(Data)
#define DNS_PACKET_MINSIZE                            (sizeof(dns_hdr) + NULL_TERMINATE_LENGTH + sizeof(dns_qry))                                                           //Minimum DNS packet size(DNS header + Minimum domain<ROOT> + DNS query or EDNS Label)
#define EDNS_RECORD_MAXSIZE                           (sizeof(edns_header) + sizeof(edns_cookies) + sizeof(edns_client_subnet) * 2U + sizeof(in6_addr) + sizeof(in_addr))   //Maximum of EDNS resource record size
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
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	#define SYSTEM_SOCKET                                 int
#endif

//Time definitions
#define DEFAULT_ALTERNATE_RANGE_TIME                  60U                         //Default time of checking timeout(1 minute/60 seconds)
#define DEFAULT_ALTERNATE_RESET_TIME                  300U                        //Default time to reset switching of alternate servers(300 seconds/5 minutes)
#define DEFAULT_ALTERNATE_TIMES                       10U                         //Default times of request timeout(10 times)
#define DEFAULT_DOMAIN_CACHE_PARAMETER                4096U                       //Default parameter of domain cache(4096 size of queue)
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
	#define DNSCURVE_DEFAULT_RECHECK_TIME                 1800U                                    //Default DNSCurve keys recheck time(30 minutes/1800 seconds)
	#define DNSCURVE_DEFAULT_RELIABLE_SOCKET_TIMEOUT      DEFAULT_RELIABLE_ONCE_SOCKET_TIMEOUT     //Same as default timeout of reliable sockets
	#define DNSCURVE_DEFAULT_UNRELIABLE_SOCKET_TIMEOUT    DEFAULT_UNRELIABLE_ONCE_SOCKET_TIMEOUT   //Same as default timeout of unreliable sockets
	#define DNSCURVE_SHORTEST_RECHECK_TIME                10U                                      //The shortest DNSCurve keys recheck time(10 seconds)
#endif
#define FLUSH_DOMAIN_CACHE_INTERVAL_TIME              5U                          //Time between every flushing domain cache(5 seconds)
#define LOOP_INTERVAL_TIME_DELAY                      20U                         //Delay mode loop interval time(20 ms)
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	#define LOOP_INTERVAL_TIME_NO_DELAY                   20000U                         //No delay mode loop interval time(20000 us/20 ms)
#endif
#define LOOP_MAX_LITTLE_TIMES                         4U                          //Little maximum of loop times(4 times)
#define LOOP_MAX_LARGE_TIMES                          8U                          //Large maximum of loop times(8 times)
#define MICROSECOND_TO_MILLISECOND                    1000U                       //1000 microseconds(1 ms)
#define SECOND_TO_MILLISECOND                         1000U                       //1000 milliseconds(1 second)
#define SENDING_INTERVAL_TIME                         5000U                       //Time between every sending(5000 ms/5 seconds)
#define SENDING_ONCE_INTERVAL_TIMES                   3U                          //Repeat times between every sending(3 times).
#define SENDING_MAX_INTERVAL_TIMES                    8U                          //The maximum times of every repeat testing(8 times).
#define SHORTEST_ALTERNATE_RANGE_TIME                 5U                          //The shortest time of checking timeout(5 seconds)
#define SHORTEST_ALTERNATE_RESET_TIME                 5U                          //The shortest time to reset switching of alternate servers(5 seconds)
#define SHORTEST_DOMAIN_TEST_INTERVAL_TIME            5U                          //The shortest Domain Test time between every sending(5 seconds)
#define SHORTEST_FILE_REFRESH_TIME                    5U                          //The shortest time between files auto-refreshing(5 seconds)
#define SHORTEST_ICMP_TEST_TIME                       5U                          //The shortest time between ICMP Test(5 seconds)
#define SHORTEST_QUEUE_RESET_TIME                     5U                          //The shortest time to reset queue limit(5 seconds)
#define SHORTEST_THREAD_POOL_RESET_TIME               5U                          //The shortest time to reset thread pool number(5 seconds)
#define SOCKET_TIMEOUT_MIN                            500U                        //The shortest socket timeout(500 ms)
#define STANDARD_TIMEOUT                              1000U                       //Standard timeout(1000 ms/1 second)
#if defined(PLATFORM_WIN)
	#define UPDATE_SERVICE_TIME                           3000U                       //Update service timeout(3 seconds/3000 ms)
#endif

//Data definitions
#if defined(PLATFORM_WIN)
	#define COMMAND_FIREWALL_TEST                         (L"--first-setup")
	#define COMMAND_FLUSH_DOMAIN_CACHE                    (L"--flush-dns")
	#define COMMAND_KEYPAIR_GENERATOR                     (L"--keypair-generator")
	#define COMMAND_LIB_VERSION                           (L"--lib-version")
	#define COMMAND_LONG_HELP                             (L"--help")
	#define COMMAND_LONG_LOG_FILE                         (L"--log-file")
	#define COMMAND_LONG_PRINT_VERSION                    (L"--version")
	#define COMMAND_LONG_SET_PATH                         (L"--config-path")
	#define COMMAND_SHORT_HELP                            (L"-h")
	#define COMMAND_SHORT_LOG_FILE                        (L"-l")
	#define COMMAND_SHORT_PRINT_VERSION                   (L"-v")
	#define COMMAND_SHORT_SET_PATH                        (L"-c")
	#define CONFIG_FILE_NAME_LIST_WCS                     {(L"Config.ini"), (L"Config.conf"), (L"Config.cfg"), (L"Config")}
	#define DEFAULT_ICMP_PADDING_DATA                     ("abcdefghijklmnopqrstuvwabcdefghi")           //Windows: Default ICMP padding data
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_KEY_PAIR_FILE_NAME                   (L"KeyPair.txt")
#endif
	#define ERROR_LOG_FILE_NAME_WCS                       (L"Error.log")
	#define FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL             (L"Flush Pcap_DNSProxy domain cache")          //The mailslot message to flush domain cache(All)
	#define FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC        (L"Flush Pcap_DNSProxy domain cache: ")        //The mailslot message to flush domain cache(Specific)
	#define FLUSH_DOMAIN_MAILSLOT_NAME                    (L"\\\\.\\mailslot\\pcap_dnsproxy_mailslot")   //The mailslot name to flush domain cache
	#define MUTEX_EXISTS_NAME                             (L"Global\\Pcap_DNSProxy Process Exists")      //Global mutex exists name
	#define SID_ADMINISTRATORS_GROUP                      (L"S-1-5-32-544")                              //Windows Administrators group SID header
	#define SYSTEM_SERVICE_NAME                           (L"PcapDNSProxyService")                       //System service name
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
	#define COMMAND_DISABLE_DAEMON                        ("--disable-daemon")
#endif
	#define COMMAND_FLUSH_DOMAIN_CACHE                    ("--flush-dns")
	#define COMMAND_KEYPAIR_GENERATOR                     ("--keypair-generator")
	#define COMMAND_LIB_VERSION                           ("--lib-version")
	#define COMMAND_LONG_HELP                             ("--help")
	#define COMMAND_LONG_LOG_FILE                         ("--log-file")
	#define COMMAND_LONG_PRINT_VERSION                    ("--version")
	#define COMMAND_LONG_SET_PATH                         ("--config-path")
	#define COMMAND_SHORT_HELP                            ("-h")
	#define COMMAND_SHORT_LOG_FILE                        ("-l")
	#define COMMAND_SHORT_PRINT_VERSION                   ("-v")
	#define COMMAND_SHORT_SET_PATH                        ("-c")
	#define CONFIG_FILE_NAME_LIST_WCS                     {(L"Config.conf"), (L"Config.ini"), (L"Config.cfg"), (L"Config")}
	#define CONFIG_FILE_NAME_LIST_MBS                     {("Config.conf"), ("Config.ini"), ("Config.cfg"), ("Config")}
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_KEY_PAIR_FILE_NAME                   ("KeyPair.txt")
#endif
	#define ERROR_LOG_FILE_NAME_WCS                       (L"Error.log")
	#define ERROR_LOG_FILE_NAME_MBS                       ("Error.log")
	#define FLUSH_DOMAIN_PIPE_MESSAGE_ALL                 ("Flush Pcap_DNSProxy domain cache")         //The FIFO pipe message to flush domain cache(All)
	#define FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC            ("Flush Pcap_DNSProxy domain cache: ")       //The FIFO pipe message to flush domain cache(Specific)
	#define FLUSH_DOMAIN_PIPE_PATH_NAME                   ("/tmp/pcap_dnsproxy_fifo")                  //The FIFO pipe pathname to flush domain cache
#endif
#define DEFAULT_LOCAL_SERVER_NAME                     ("pcap-dnsproxy.server")                     //Default Local DNS server name
#define DNS_PACKET_QUERY_LOCATE(Buffer, BufferSize)   (sizeof(dns_hdr) + CheckQueryNameLength(reinterpret_cast<const uint8_t *>(Buffer) + sizeof(dns_hdr), BufferSize) + NULL_TERMINATE_LENGTH)                     //Locate the beginning of DNS query.
#define DNS_PACKET_RR_LOCATE(Buffer, BufferSize)      (sizeof(dns_hdr) + CheckQueryNameLength(reinterpret_cast<const uint8_t *>(Buffer) + sizeof(dns_hdr), BufferSize) + NULL_TERMINATE_LENGTH + sizeof(dns_qry))   //Locate the beginning of DNS resource records.

#if !defined(ENABLE_LIBSODIUM)
//Base64 definitions
	#define BASE64_PAD                                    ('=')
	#define BASE64_DECODE_FIRST                           ('+')
	#define BASE64_DECODE_LAST                            ('z')
	#define BASE64_DECODE_OUT_SIZE(Message)               (((Message)) / 4U * 3U)
	#define BASE64_ENCODE_OUT_SIZE(Message)               (((Message) + 2U) / 3U * 4U)
#endif


//////////////////////////////////////////////////
// Function definitions(Part 2)
// 
//Byte order function
#define hton16_Force(Value)                           (static_cast<const uint16_t>((reinterpret_cast<const uint8_t *>(&(Value)))[0] <<                                      \
														(sizeof(uint8_t) * BYTES_TO_BITS) | (reinterpret_cast<const uint8_t *>(&(Value)))[1U]))
#define ntoh16_Force                                  hton16_Force
#define hton16                                        htons
#define ntoh16                                        ntohs
#define hton32_Force(Value)                           (static_cast<const uint32_t>((reinterpret_cast<const uint8_t *>(&(Value)))[0] <<                                      \
														((sizeof(uint16_t) + sizeof(uint8_t)) * BYTES_TO_BITS) |                                                            \
														(reinterpret_cast<const uint8_t *>(&(Value)))[1U] << (sizeof(uint16_t) * BYTES_TO_BITS) |                           \
														(reinterpret_cast<const uint8_t *>(&(Value)))[2U] << (sizeof(uint8_t) * BYTES_TO_BITS) |                            \
														(reinterpret_cast<const uint8_t *>(&(Value)))[3U]))
#define ntoh32_Force                                  hton32_Force
#define hton32                                        htonl
#define ntoh32                                        ntohl
#define hton64_Force(Value)                           (static_cast<const uint64_t>(((static_cast<const uint64_t>(hton32(static_cast<const uint32_t>                         \
														(((Value) << (sizeof(uint32_t) * BYTES_TO_BITS)) >>                                                                 \
														(sizeof(uint32_t) * BYTES_TO_BITS))))) <<                                                                           \
														(sizeof(uint32_t) * BYTES_TO_BITS)) | static_cast<const uint32_t>(hton32(static_cast<const uint32_t>((Value) >>     \
														(sizeof(uint32_t) * BYTES_TO_BITS))))))
#define ntoh64_Force                                  hton64_Force
#if defined(PLATFORM_WIN)
#if defined(PLATFORM_WIN_XP)
	#define hton64                                        hton64_Force
	#define ntoh64                                        hton64
#else
	#define hton64                                        htonll
	#define ntoh64                                        ntohll
#endif
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
#if BYTE_ORDER == LITTLE_ENDIAN
	#define hton64(Value)                                 hton64_Force(Value)
#else //BIG_ENDIAN
	#define hton64(Value)                                 (Value)
#endif
	#define ntoh64                                        hton64
#endif

//Time function
#if defined(PLATFORM_WIN)
#if defined(PLATFORM_WIN_XP)
	#define GetCurrentSystemTime                           GetTickCount
#else
	#define GetCurrentSystemTime                           GetTickCount64
#endif
	#define Sleep(Millisecond)                             Sleep(static_cast<const DWORD>(Millisecond))
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	#define Sleep(Millisecond)                             usleep(static_cast<const useconds_t>((Millisecond) * MICROSECOND_TO_MILLISECOND))
	#define usleep(Millisecond)                            usleep(static_cast<const useconds_t>(Millisecond))
#endif
#endif
