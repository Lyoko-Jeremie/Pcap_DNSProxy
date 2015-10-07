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


#include "Structures.h"

//////////////////////////////////////////////////
// Main Header
// 
//Base definitions
#define KILOBYTE_TIMES         1024U         //1KB = 1024 bytes
#define MEGABYTE_TIMES         1048576U      //1MB = 1048576 bytes
#define GIGABYTE_TIMES         1073741824U   //1GB = 1073741824 bytes
#define CODEPAGE_ASCII         1U            //Microsoft Windows Codepage of ANSI
#define CODEPAGE_UTF_8         65001U        //Microsoft Windows Codepage of UTF-8
#define CODEPAGE_UTF_16_LE     1200U         //Microsoft Windows Codepage of UTF-16 Little Endian/LE
#define CODEPAGE_UTF_16_BE     1201U         //Microsoft Windows Codepage of UTF-16 Big Endian/BE
#define CODEPAGE_UTF_32_LE     12000U        //Microsoft Windows Codepage of UTF-32 Little Endian/LE
#define CODEPAGE_UTF_32_BE     12001U        //Microsoft Windows Codepage of UTF-32 Big Endian/BE

#if defined(PLATFORM_WIN)
	#define MBSTOWCS_NULLTERMINATE   (-1)            //MultiByteToWideChar() find null-terminate.
#endif
#if defined(ENABLE_LIBSODIUM)
	#define LIBSODIUM_ERROR          (-1)
#endif
#define BYTES_TO_BITS           8U
#define U16_NUM_ONE             0x0001

//ASCII value definitions
#define ASCII_HT                9                    //"␉"
#define ASCII_LF                0x0A                 //10, Line Feed
#define ASCII_VT                0x0B                 //11, Vertical Tab
#define ASCII_FF                0x0C                 //12, Form Feed
#define ASCII_CR                0x0D                 //13, Carriage Return
#define ASCII_SPACE             32                   //" "
#define ASCII_HASHTAG           35                   //"#"
#define ASCII_AMPERSAND         38                   //"&"
#define ASCII_COMMA             44                   //","
#define ASCII_MINUS             45                   //"-"
#define ASCII_PERIOD            46                   //"."
#define ASCII_SLASH             47                   //"/"
#define ASCII_ZERO              48                   //"0"
#define ASCII_ONE               49                   //"1"
#define ASCII_TWO               50                   //"2"
#define ASCII_THREE             51                   //"3"
#define ASCII_NINE              57                   //"9"
#define ASCII_COLON             58                   //":"
#define ASCII_AT                64                   //"@"
#define ASCII_UPPERCASE_A       65                   //"A"
#define ASCII_UPPERCASE_F       70                   //"F"
#define ASCII_UPPERCASE_Z       90                   //"Z"
#define ASCII_BRACKETS_LEAD     91                   //"["
#define ASCII_BACKSLASH         92                   //"\"
#define ASCII_BRACKETS_TRAIL    93                   //"]"
#define ASCII_ACCENT            96                   //"`"
#define ASCII_LOWERCASE_A       97                   //"a"
#define ASCII_LOWERCASE_F       102                  //"f"
#define ASCII_LOWERCASE_X       120                  //"x"
#define ASCII_LOWERCASE_Z       122                  //"z"
#define ASCII_BRACES_LEAD       123                  //"{"
#define ASCII_VERTICAL          124                  //"|"
#define ASCII_TILDE             126                  //"~"
#define ASCII_MAX_NUM           0x7F
//#define ASCII_UPPER_TO_LOWER    32U                  //Uppercase to lowercase
//#define ASCII_LOWER_TO_UPPER    32U                  //Lowercase to uppercase

//Unicode value definitions
#define UNICODE_NEXT_LINE                   0x0085               //Next Line
#define UNICODE_NO_BREAK_SPACE              0x00A0               //No-Break Space
#define UNICODE_OGHAM_SPACE_MARK            0x1680               //Ogham Space Mark
#define UNICODE_MONGOLIAN_VOWEL_SEPARATOR   0x180E               //Mongolian Vowel Separator
#define UNICODE_LINE_SEPARATOR              0x2028               //Line Separator
#define UNICODE_PARAGRAPH_SEPARATOR         0x2029               //Paragraph Separator
#define UNICODE_EN_SPACE                    0x2002               //En Space or Nut
#define UNICODE_EM_SPACE                    0x2003               //Em Space or Mutton
#define UNICODE_THICK_SPACE                 0x2004               //Three-Per-Em Space/TPES or Thick Space
#define UNICODE_MID_SPACE                   0x2005               //Four-Per-Em Space/FPES or Mid Space
#define UNICODE_SIX_PER_EM_SPACE            0x2006               //Six-Per-Em Space
#define UNICODE_FIGURE_SPACE                0x2007               //Figure Space
#define UNICODE_PUNCTUATION_SPACE           0x2008               //Punctuation Space
#define UNICODE_THIN_SPACE                  0x2009               //Thin Space
#define UNICODE_HAIR_SPACE                  0x200A               //Hair Space
#define UNICODE_ZERO_WIDTH_SPACE            0x200B               //Zero Width Space
#define UNICODE_ZERO_WIDTH_NON_JOINER       0x200C               //Zero Width Non Joiner
#define UNICODE_ZERO_WIDTH_JOINER           0x200D               //Zero Width Joiner
#define UNICODE_NARROW_NO_BREAK_SPACE       0x202F               //Narrow No-Break Space
#define UNICODE_MEDIUM_MATHEMATICAL_SPACE   0x205F               //Medium Mathematical Space
#define UNICODE_WORD_JOINER                 0x2060               //Word Joiner
#define UNICODE_IDEOGRAPHIC_SPACE           0x3000               //Ideographic Space in CJK

//Version definitions
#define CONFIG_VERSION_POINT_THREE   0.3
#define CONFIG_VERSION               0.4                         //Current configuration version
#define FULL_VERSION                 L"0.4.4.1"
#define COPYRIGHT_MESSAGE            L"Copyright (C) 2012-2015 Chengr28"

//Exit code definitions
#define EXIT_CHECK_HOSTS_TYPE_LOCAL                2U   //Type is Local in CheckHostsProcess function.

//Size and length definitions
#define BOM_UTF_8_LENGTH               3U                                         //UTF-8 BOM length
#define BOM_UTF_16_LENGTH              2U                                         //UTF-16 BOM length
#define BOM_UTF_32_LENGTH              4U                                         //UTF-32 BOM length
#define COMMAND_BUFFER_MAXSIZE         4096U                                      //Maximum size of commands buffer(4096 bytes)
#define FILE_BUFFER_SIZE               4096U                                      //Maximum size of file buffer(4KB/4096 bytes)
#define DEFAULT_FILE_MAXSIZE           1073741824U                                //Maximum size of whole reading file(1GB/1073741824 bytes).
#define DEFAULT_LOG_MAXSIZE            8388608U                                   //Maximum size of whole log file(8MB/8388608 bytes).
#define DEFAULT_LOG_MINSIZE            4096U                                      //Minimum size of whole log file(4KB/4096 bytes).
#define PACKET_MAXSIZE                 1500U                                      //Maximum size of packets, Standard MTU of Ethernet II network
#define ORIGINAL_PACKET_MAXSIZE        1512U                                      //Maximum size of original Ethernet II packets(1500 bytes maximum payload length + 8 bytes Ethernet header + 4 bytes FCS)
#define LARGE_PACKET_MAXSIZE           4096U                                      //Maximum size of packets(4KB/4096 bytes) of TCP protocol
#define BUFFER_QUEUE_MAXNUM            1488095U                                   //Number of maximum packet buffer queues, 1488095 pps or 1.488Mpps in Gigabit Ethernet
#define BUFFER_QUEUE_MINNUM            8U                                         //Number of minimum packet buffer queues
#define DEFAULT_BUFFER_QUEUE           64U                                        //Default number of packet buffer queues
#define UINT16_MAX_STRING_LENGTH       6U                                         //Maximum number of 16 bits is 65535, its length is 6.
#define UINT32_MAX_STRING_LENGTH       10U                                        //Maximum number of 32 bits is 4294967295, its length is 10.
#define ADDR_STRING_MAXSIZE            64U                                        //Maximum size of addresses(IPv4/IPv6) words(64 bytes)
#define IPV4_SHORTEST_ADDRSTRING       6U                                         //The shortest IPv4 address strings(*.*.*.*).
#define IPV6_SHORTEST_ADDRSTRING       3U                                         //The shortest IPv6 address strings(::).
#define ICMP_PADDING_MAXSIZE           1484U                                      //Length of ICMP padding data must between 18 bytes and 1464 bytes(Ethernet MTU - IPv4 Standard Header - ICMP Header).
#if defined(PLATFORM_LINUX)
	#define ICMP_STRING_START_NUM_LINUX    16U
	#define ICMP_PADDING_LENGTH_LINUX      40U
#elif defined(PLATFORM_MACX)
	#define ICMP_STRING_START_NUM_MAC      8U
	#define ICMP_PADDING_LENGTH_MAC        48U
#endif
#define MULTI_REQUEST_MAXNUM              64U                                                                             //Maximum number of multi request.
#define NETWORK_LAYER_PARTNUM             2U                                                                              //Number of network layer protocols(IPv6 and IPv4)
#define TRANSPORT_LAYER_PARTNUM           4U                                                                              //Number of transport layer protocols(00: IPv6/UDP, 01: IPv4/UDP, 02: IPv6/TCP, 03: IPv4/TCP)
#define ALTERNATE_SERVERNUM               12U                                                                             //Alternate switching of Main(00: TCP/IPv6, 01: TCP/IPv4, 02: UDP/IPv6, 03: UDP/IPv4), Local(04: TCP/IPv6, 05: TCP/IPv4, 06: UDP/IPv6, 07: UDP/IPv4), DNSCurve(08: TCP/IPv6, 09: TCP/IPv4, 10: UDP/IPv6, 11: UDP/IPv4)
#define DOMAIN_MAXSIZE                    256U                                                                            //Maximum size of whole level domain is 256 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_DATA_MAXSIZE               253U                                                                            //Maximum data length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_LEVEL_DATA_MAXSIZE         63U                                                                             //Domain length is between 3 and 63(Labels must be 63 characters/bytes or less, Section 2.3.1 in RFC 1035).
#define DOMAIN_MINSIZE                    2U                                                                              //Minimum size of whole level domain is 3 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_RAMDOM_MINSIZE             6U                                                                              //Minimum size of ramdom domain request
#define DNS_PACKET_MINSIZE                (sizeof(dns_hdr) + 4U + sizeof(dns_qry))                                        //Minimum DNS packet size(DNS Header + Minimum Domain + DNS Query)
#define DNS_RR_MAXCOUNT_AAAA              43U                                                                             //Maximum Record Resources size of AAAA answers, 28 bytes * 43 = 1204 bytes
#define DNS_RR_MAXCOUNT_A                 75U                                                                             //Maximum Record Resources size of A answers, 16 bytes * 75 = 1200 bytes
#define EDNS_ADDITIONAL_MAXSIZE           (sizeof(dns_record_opt) * 2U + sizeof(edns_client_subnet) + sizeof(in6_addr))   //Maximum of EDNS Additional Record Resources size
#define DNSCRYPT_PACKET_MINSIZE           (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_NONCEBYTES + DNS_PACKET_MINSIZE)
#define DNSCRYPT_RECORD_TXT_LEN           124U                                                                            //Length of DNScrypt TXT Records
#define DNSCRYPT_BUFFER_RESERVE_LEN       (DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES)
#define DNSCRYPT_BUFFER_RESERVE_TCP_LEN   (sizeof(uint16_t) + DNSCURVE_MAGIC_QUERY_LEN + crypto_box_PUBLICKEYBYTES + crypto_box_HALF_NONCEBYTES - crypto_box_BOXZEROBYTES)
#define DNSCRYPT_RESERVE_HEADER_LEN       (sizeof(ipv6_hdr) + sizeof(udp_hdr) + DNSCRYPT_BUFFER_RESERVE_LEN)

//Code definitions
#if defined(PLATFORM_WIN)
	#define QUERY_SERVICE_CONFIG_BUFFER_MAXSIZE   8192U      //Buffer maximum size of QueryServiceConfig() function(8KB/8192 Bytes)
	#define SYSTEM_SOCKET                         UINT_PTR   //System Socket defined(WinSock2.h), which is not the same in x86(unsigned int) and x64(unsigned __int64) platform and defined in WinSock2.h file.
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define SYSTEM_SOCKET                         int
#endif
#if defined(ENABLE_PCAP)
//	#define PCAP_READ_TIMEOUT                     0          //Pcap read timeout with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet.
//	#define PCAP_READ_SUCCESS                     1          //Pcap packets has been read without problems.
	#define PCAP_LOOP_INFINITY                    (-1)       //Pcap packets are processed until another ending condition occurs.
	#define PCAP_COMPILE_OPTIMIZE                 1          //Pcap optimization on the resulting code is performed.
#endif
//#define SHA3_512_SIZE                         64U        //SHA3-512 instance as specified in the FIPS 202(http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), 512 bits/64 bytes.
#define CHECKSUM_SUCCESS                      0          //Result of getting correct checksum.
#define DYNAMIC_MIN_PORT                      1024U      //Well-known port is from 1 to 1023.

//Time(s) definitions
#define SECOND_TO_MILLISECOND                        1000U     //1000 milliseconds(1 second)
#define MICROSECOND_TO_MILLISECOND                   1000U     //1000 microseconds(1 millisecond)
#define STANDARD_TIMEOUT                             1000U     //Standard timeout, 1000 ms(1 second)
#define LOOP_MAX_TIMES                               16U       //Maximum of loop times, 8 times
#define LOOP_INTERVAL_TIME_NO_DELAY                  10U       //Loop interval time(No delay), 10 ms
#define LOOP_INTERVAL_TIME_MONITOR                   10000U    //Loop interval time(Monitor mode), 10000 ms(10 seconds)
#if defined(PLATFORM_WIN)
	#define UPDATE_SERVICE_TIME                      3000U     //Update service timeout, 3000 ms(3 seconds)
#endif
#if defined(ENABLE_PCAP)
	#define PCAP_CAPTURE_MIN_TIMEOUT                     10U       //Minimum Pcap Capture reading timeout, 10 ms
	#define DEFAULT_PCAP_CAPTURE_TIMEOUT                 200U      //Default Pcap Capture reading timeout, 200 ms
#endif
#define SOCKET_MIN_TIMEOUT                           500U      //The shortest socket timeout, 500 ms
#if defined(PLATFORM_WIN)
	#define DEFAULT_RELIABLE_SOCKET_TIMEOUT              3000U     //Default timeout of reliable sockets(Such as TCP, 3 seconds/3000ms)
	#define DEFAULT_UNRELIABLE_SOCKET_TIMEOUT            2000U     //Default timeout of unreliable sockets(Such as ICMP/ICMPv6/UDP, 2 seconds/2000ms)
	#define DEFAULT_SOCKS_RELIABLE_SOCKET_TIMEOUT        6000U     //Default timeout of SOCKS reliable sockets(Such as TCP, 6 seconds/6000ms)
	#define DEFAULT_SOCKS_UNRELIABLE_SOCKET_TIMEOUT      3000U     //Default timeout of SOCKS unreliable sockets(Such as UDP, 3 seconds/3000ms)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define DEFAULT_RELIABLE_SOCKET_TIMEOUT              3U        //Default timeout of reliable sockets(Such as TCP, 3 seconds)
	#define DEFAULT_UNRELIABLE_SOCKET_TIMEOUT            2U        //Default timeout of unreliable sockets(Such as ICMP/ICMPv6/UDP, 2 seconds)
	#define DEFAULT_SOCKS_RELIABLE_SOCKET_TIMEOUT        6U        //Default timeout of SOCKS reliable sockets(Such as TCP, 6 seconds)
	#define DEFAULT_SOCKS_UNRELIABLE_SOCKET_TIMEOUT      3U        //Default timeout of SOCKS unreliable sockets(Such as UDP, 3 seconds)
#endif
#if defined(ENABLE_LIBSODIUM)
	#define DEFAULT_DNSCURVE_RELIABLE_SOCKET_TIMEOUT     DEFAULT_RELIABLE_SOCKET_TIMEOUT     //Same as default timeout of reliable sockets
	#define DEFAULT_DNSCURVE_UNRELIABLE_SOCKET_TIMEOUT   DEFAULT_UNRELIABLE_SOCKET_TIMEOUT   //Same as default timeout of unreliable sockets
#endif
#define DEFAULT_FILEREFRESH_TIME                     10000U    //Default time between files auto-refreshing, 10000 ms(10 seconds)
#define DEFAULT_ICMPTEST_TIME                        5U        //Default time between ICMP Test, 5 seconds
#define DEFAULT_DOMAINTEST_INTERVAL_TIME             900U      //Default Domain Test time between every sending, 15 minutes(900 seconds)
#define DEFAULT_ALTERNATE_TIMES                      5U        //Default times of request timeout, 5 times
#define DEFAULT_ALTERNATE_RANGE                      10U       //Default time of checking timeout, 10 seconds
#define DEFAULT_ALTERNATE_RESET_TIME                 180U      //Default time to reset switching of alternate servers, 180 seconds
#define DEFAULT_HOSTS_TTL                            900U      //Default Hosts DNS TTL, 15 minutes(900 seconds)
#define SHORTEST_FILEREFRESH_TIME                    5U        //The shortset time between files auto-refreshing, 5 seconds
#define SENDING_INTERVAL_TIME                        5000U     //Time between every sending, 5000 ms(5 seconds)
#define SENDING_ONCE_INTERVAL_TIMES                  3U        //Repeat 3 times between every sending.
#if defined(ENABLE_LIBSODIUM)
	#define DEFAULT_DNSCURVE_RECHECK_TIME                1800U     //Default DNSCurve keys recheck time, 1800 seconds
	#define SHORTEST_DNSCURVE_RECHECK_TIME               10U       //The shortset DNSCurve keys recheck time, 10 seconds
#endif

//Data definitions
#define DEFAULT_LOCAL_SERVERNAME              ("pcap-dnsproxy.localhost.server")                                                                                                            //Default Local DNS server name
#if defined(PLATFORM_WIN)
	#define CONFIG_FILE_NAME_LIST                 L"Config.ini", L"Config.conf", L"Config.cfg", L"Config"
	#define COMMAND_LONG_PRINT_VERSION            L"--version"
	#define COMMAND_SHORT_PRINT_VERSION           L"-v"
	#define COMMAND_LONG_HELP                     L"--help"
	#define COMMAND_SHORT_HELP                    L"-h"
	#define COMMAND_FIREWALL_TEST                 L"--first-setup"
	#define COMMAND_FLUSH_DNS                     L"--flush-dns"
	#define COMMAND_LONG_SET_PATH                 L"--config-file"
	#define COMMAND_SHORT_SET_PATH                L"-c"
	#define SID_ADMINISTRATORS_GROUP              L"S-1-5-32-544"                                                                                                                               //Windows SID of Administrators group
	#define MAILSLOT_NAME                         L"\\\\.\\mailslot\\pcap_dnsproxy_mailslot"                                                                                                    //MailSlot name
	#define MAILSLOT_MESSAGE_FLUSH_DNS            L"Flush DNS cache of Pcap_DNSProxy."                                                                                                          //The mailslot message to flush dns cache
	#define SYSTEM_SERVICE_NAME                   L"PcapDNSProxyService"                                                                                                                        //System service name
	#define DEFAULT_ICMP_PADDING_DATA             ("abcdefghijklmnopqrstuvwabcdefghi")                                                                                                          //ICMP padding data on Windows
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define CONFIG_FILE_NAME_LIST                 L"Config.conf", L"Config.ini", L"Config.cfg", L"Config"
	#define CONFIG_FILE_NAME_LIST_STRING          "Config.conf", "Config.ini", "Config.cfg", "Config"
	#define COMMAND_LONG_PRINT_VERSION            ("--version")
	#define COMMAND_SHORT_PRINT_VERSION           ("-v")
	#define COMMAND_LONG_HELP                     ("--help")
	#define COMMAND_SHORT_HELP                    ("-h")
	#define COMMAND_FLUSH_DNS                     ("--flush-dns")
	#define COMMAND_LONG_SET_PATH                 ("--config-file")
	#define COMMAND_SHORT_SET_PATH                ("-c")
	#if defined(PLATFORM_LINUX)
		#define COMMAND_DISABLE_DAEMON                ("--disable-daemon")
	#endif
	#define FIFO_PATH_NAME                        ("/tmp/pcap_dnsproxy_fifo")                                                                                                                   //FIFO pathname
	#define FIFO_MESSAGE_FLUSH_DNS                ("Flush DNS cache of Pcap_DNSProxy.")                                                                                                         //The FIFO message to flush dns cache
#endif
#define RFC_DOMAIN_TABLE                      (".-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")                                                                          //Preferred name syntax(Section 2.3.1 in RFC 1035)
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_TEST_NONCE                   0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23   //DNSCurve Test Nonce, 0x00 - 0x23(ASCII)
#endif
#if defined(PLATFORM_MACX)
	#define DEFAULT_SEQUENCE                      0
#else
	#define DEFAULT_SEQUENCE                      0x0001                                                                                                                                        //Default sequence of protocol
#endif
#define DNS_PACKET_QUERY_LOCATE(Buffer)       (sizeof(dns_hdr) + CheckQueryNameLength(Buffer + sizeof(dns_hdr)) + 1U)                                                                    //Location the beginning of DNS Query
#define DNS_TCP_PACKET_QUERY_LOCATE(Buffer)   (sizeof(dns_tcp_hdr) + CheckQueryNameLength(Buffer + sizeof(dns_tcp_hdr)) + 1U)
#define DNS_PACKET_RR_LOCATE(Buffer)          (sizeof(dns_hdr) + CheckQueryNameLength(Buffer + sizeof(dns_hdr)) + 1U + sizeof(dns_qry))                                                  //Location the beginning of DNS Resource Records

//Function Type definitions
//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	#define FUNCTION_GETTICKCOUNT64        1U
	#define FUNCTION_INET_NTOP             2U
	#define FUNCTION_INET_PTON             3U
#endif

//Compare addresses own definitions
#define ADDRESS_COMPARE_LESS           1U
#define ADDRESS_COMPARE_EQUAL          2U
#define ADDRESS_COMPARE_GREATER        3U

//Error type definitions
#define LOG_MESSAGE_NOTICE             1U            // 01: Notice Message
#define LOG_ERROR_SYSTEM               2U            // 02: System Error
#define LOG_ERROR_PARAMETER            3U            // 03: Parameter Error
#define LOG_ERROR_IPFILTER             4U            // 04: IPFilter Error
#define LOG_ERROR_HOSTS                5U            // 05: Hosts Error
#define LOG_ERROR_NETWORK              6U            // 06: Network Error
#if defined(ENABLE_PCAP)
	#define LOG_ERROR_PCAP                 7U            // 07: Pcap Error
#endif
#if defined(ENABLE_LIBSODIUM)
	#define LOG_ERROR_DNSCURVE             8U            // 08: DNSCurve Error
#endif
#define LOG_ERROR_SOCKS                9U            // 09: SOCKS Error

//Codes and types definitions
#define LISTEN_PROTOCOL_NETWORK_BOTH          0
#define LISTEN_PROTOCOL_IPV6                  1U
#define LISTEN_PROTOCOL_IPV4                  2U
#define LISTEN_PROTOCOL_TRANSPORT_BOTH        0
#define LISTEN_PROTOCOL_TCP                   1U
#define LISTEN_PROTOCOL_UDP                   2U
#define LISTEN_MODE_PROXY                     0
#define LISTEN_MODE_PRIVATE                   1U 
#define LISTEN_MODE_SERVER                    2U
#define LISTEN_MODE_CUSTOM                    3U
#define DIRECT_REQUEST_MODE_NONE              0
#define DIRECT_REQUEST_MODE_BOTH              1U
#define DIRECT_REQUEST_MODE_IPV6              2U
#define DIRECT_REQUEST_MODE_IPV4              3U
#define REQUEST_MODE_NETWORK_BOTH             0
#define REQUEST_MODE_IPV6                     1U
#define REQUEST_MODE_IPV4                     2U
#define REQUEST_MODE_UDP                      0
#define REQUEST_MODE_TCP                      1U
#define HOSTS_TYPE_NORMAL                     1U
#define HOSTS_TYPE_WHITE                      2U
#define HOSTS_TYPE_LOCAL                      3U
#define HOSTS_TYPE_BANNED                     4U
#define CACHE_TYPE_TIMER                      1U
#define CACHE_TYPE_QUEUE                      2U
#define SOCKET_SETTING_INVALID_CHECK          0
#define SOCKET_SETTING_TIMEOUT                1U
#define SOCKET_SETTING_REUSE                  2U
#define SOCKET_SETTING_TCP_FAST_OPEN          3U
#define SOCKET_SETTING_NON_BLOCKING_MODE      4U
//#define SOCKET_SETTING_TCP_KEEPALIVE          5U
#define SOCKET_SETTING_UDP_BLOCK_RESET        6U

//Server type definitions
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_MAIN_IPV6             1U           //DNSCurve Main(IPv6)
	#define DNSCURVE_MAIN_IPV4             2U           //DNSCurve Main(IPv4)
	#define DNSCURVE_ALTERNATE_IPV6        3U           //DNSCurve Alternate(IPv6)
	#define DNSCURVE_ALTERNATE_IPV4        4U           //DNSCurve Alternate(IPv4)
#endif

//Function Pointer definitions
//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	typedef ULONGLONG(CALLBACK *FunctionType_GetTickCount64)(void);
	typedef PCSTR(CALLBACK *FunctionType_InetNtop)(INT, PVOID, PSTR, size_t);
	typedef INT(CALLBACK *FunctionType_InetPton)(INT, PCSTR, PVOID);
#endif


//////////////////////////////////////////////////
// Function definitions(Part 2)
#define ntoh16_Force          hton16_Force
#define ntoh32_Force          hton32_Force
#define ntoh64                hton64
#if defined(PLATFORM_WIN)
	#define Sleep(Millisecond)    Sleep((DWORD)(Millisecond))
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define Sleep(Millisecond)    usleep((useconds_t)((Millisecond) * MICROSECOND_TO_MILLISECOND))
	#define usleep(Millisecond)   usleep((useconds_t)(Millisecond))
	#define GetTickCount64        GetCurrentSystemTime
#endif


//////////////////////////////////////////////////
// Main structures and classes
// 
//File Data structure
typedef struct _file_data_
{
	std::wstring             FileName;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string              sFileName;
#endif
	time_t                   ModificationTime;
}FileData, FILE_DATA, *PFileData, *PFILE_DATA;

//Socket Data structure
typedef struct _socket_data_
{
	SYSTEM_SOCKET            Socket;
	sockaddr_storage         SockAddr;
	socklen_t                AddrLen;
}SocketData, SOCKET_DATA, *PSocketData, *PSOCKET_DATA;

//Address Prefix Block structure
typedef struct _address_prefix_block_
{
	sockaddr_storage         Address;
	size_t                   Prefix;
}AddressPrefixBlock, ADDRESS_PREFIX_BLOCK, *PAddressPrefixBlock, *PADDRESS_PREFIX_BLOCK;

//Address Union Data structure
typedef union _address_union_data_
{
	sockaddr_storage     Storage;
	sockaddr_in6         IPv6;
	sockaddr_in          IPv4;
}AddressUnionData, ADDRESS_UNION_DATA, *PAddressUnionData, *PADDRESS_UNION_DATA;

//DNS Server Data structure
typedef struct _dns_server_data_
{
	AddressUnionData         AddressData;
#if defined(ENABLE_PCAP)
	union _hoplimit_data_ {
		uint8_t              TTL;
		uint8_t              HopLimit;
	}HopLimitData;
#endif
}DNSServerData, DNS_SERVER_DATA, *PDNSServerData, *PDNS_SERVER_DATA;

//Socket Selecting structure
typedef struct _socket_selecting_data_
{
	std::shared_ptr<char>    RecvBuffer;
	size_t                   Length;
	bool                     PacketIsSend;
}SocketSelectingData, SOCKET_SELECTING_DATA, *PSocketSelectingData, *PSOCKET_SELECTING_DATA;

//DNS Cache structure
typedef struct _dnscache_data_
{
	std::string              Domain;
	std::shared_ptr<char>    Response;
	size_t                   Length;
	uint16_t                 RecordType;
	uint64_t                 ClearCacheTime;
}DNSCacheData, DNSCACHE_DATA, *PDNSCacheData, *PDNSCACHE_DATA;

//DNSCurve Server Data structure
#if defined(ENABLE_LIBSODIUM)
typedef struct _dnscurve_server_data_
{
	ADDRESS_UNION_DATA       AddressData;
	PSTR                     ProviderName;           //Server Provider Name
	PUINT8                   PrecomputationKey;      //DNSCurve Precomputation Keys
	PUINT8                   ServerPublicKey;        //Server Public Keys
	PUINT8                   ServerFingerprint;      //Server Fingerprints
	PSTR                     ReceiveMagicNumber;     //Receive Magic Number(Same from server receive)
	PSTR                     SendMagicNumber;        //Server Magic Number(Send to server)
}DNSCurveServerData, DNSCURVE_SERVER_DATA, *PDNSCurveServerData, *PDNSCURVE_SERVER_DATA;

//Socket Selecting structure
typedef struct _dnscurve_socket_selecting_data_
{
	size_t                   ServerType;
	PUINT8                   PrecomputationKey;
	PSTR                     ReceiveMagicNumber;
	PSTR                     SendBuffer;
	size_t                   SendSize;
	std::shared_ptr<char>    RecvBuffer;
	size_t                   Length;
	bool                     PacketIsSend;
}DNSCurveSocketSelectingData, DNSCURVE_SOCKET_SELECTING_DATA, *PDNSCurveSocketSelectingData, *PDNSCURVE_SOCKET_SELECTING_DATA;
#endif

//Class definitions
//Configuration class
typedef class ConfigurationTable {
public:
// Parameters from configure files
//[Base] block
	double                               Version;
	size_t                               FileRefreshTime;
//[Log] block
	bool                                 PrintError;
	size_t                               LogMaxSize;
//[Listen] block
#if defined(ENABLE_PCAP)
	bool                                 PcapCapture;
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
	bool                                 LocalMain;
	bool                                 LocalHosts;
	bool                                 LocalRouting;
//[Addresses] block
	std::vector<sockaddr_storage>        *ListenAddress_IPv6;
	std::vector<sockaddr_storage>        *ListenAddress_IPv4;
	struct _localhost_subnet_ {
		ADDRESS_PREFIX_BLOCK             *IPv6;
		bool                             Setting_IPv6;
		ADDRESS_PREFIX_BLOCK             *IPv4;
		bool                             Setting_IPv4;
	}LocalhostSubnet;
	struct _dns_target_ {
		DNS_SERVER_DATA                  IPv6;
		DNS_SERVER_DATA                  Alternate_IPv6;
		DNS_SERVER_DATA                  IPv4;
		DNS_SERVER_DATA                  Alternate_IPv4;
		ADDRESS_UNION_DATA               Local_IPv6;
		ADDRESS_UNION_DATA               Alternate_Local_IPv6;
		ADDRESS_UNION_DATA               Local_IPv4;
		ADDRESS_UNION_DATA               Alternate_Local_IPv4;
		std::vector<DNS_SERVER_DATA>     *IPv6_Multi;
		std::vector<DNS_SERVER_DATA>     *IPv4_Multi;
	}DNSTarget;
//[Values] block
	size_t                               BufferQueueSize;
	size_t                               QueueResetTime;
	size_t                               EDNSPayloadSize;
#if defined(ENABLE_PCAP)
	uint8_t                              HopLimitFluctuation;
#endif
#if defined(PLATFORM_WIN)
	int                                  SocketTimeout_Reliable;
	int                                  SocketTimeout_Unreliable;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	timeval                              SocketTimeout_Reliable;
	timeval                              SocketTimeout_Unreliable;
#endif
	size_t                               ReceiveWaiting;
	size_t                               AlternateTimes;
	size_t                               AlternateTimeRange;
	size_t                               AlternateResetTime;
	size_t                               MultiRequestTimes;
//[Switches] block
#if defined(PLATFORM_LINUX)
	bool                                 TCP_FastOpen;
#endif
	bool                                 DomainCaseConversion;
	bool                                 CompressionPointerMutation;
	bool                                 CPM_PointerToHeader;
	bool                                 CPM_PointerToRR;
	bool                                 CPM_PointerToAdditional;
	bool                                 EDNS_Label;
	bool                                 EDNS_ClientSubnet;
	bool                                 DNSSEC_Request;
	bool                                 DNSSEC_Validation;
	bool                                 DNSSEC_ForceValidation;
	bool                                 AlternateMultiRequest;
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
	PSTR                                 ICMP_PaddingData;
	size_t                               ICMP_PaddingLength;
	PSTR                                 DomainTest_Data;
	uint16_t                             DomainTest_ID;
	size_t                               DomainTest_Speed;
#endif
	std::string                          *LocalFQDN_String;
	PSTR                                 LocalFQDN_Response;
	size_t                               LocalFQDN_Length;
#if !defined(PLATFORM_MACX)
	PSTR                                 LocalServer_Response;
	size_t                               LocalServer_Length;
#endif
//[Proxy] block
	bool                                 SOCKS;
	size_t                               SOCKS_Version;
	size_t                               SOCKS_Protocol_Network;
	size_t                               SOCKS_Protocol_Transport;
#if defined(PLATFORM_WIN)
	int                                  SOCKS_SocketTimeout_Reliable;
	int                                  SOCKS_SocketTimeout_Unreliable;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	timeval                              SOCKS_SocketTimeout_Reliable;
	timeval                              SOCKS_SocketTimeout_Unreliable;
#endif
	bool                                 SOCKS_UDP_NoHandshake;
	bool                                 SOCKS_Only;
	ADDRESS_UNION_DATA                   SOCKS_Address_IPv4;
	ADDRESS_UNION_DATA                   SOCKS_Address_IPv6;
	ADDRESS_UNION_DATA                   SOCKS_TargetServer;
	PSTR                                 SOCKS_TargetDomain;
	uint16_t                             SOCKS_TargetDomain_Port;
	size_t                               SOCKS_TargetDomain_Length;
	PSTR                                 SOCKS_Username;
	size_t                               SOCKS_Username_Length;
	PSTR                                 SOCKS_Password;
	size_t                               SOCKS_Password_Length;
//[DNSCurve/DNSCrypt] block
#if defined(ENABLE_LIBSODIUM)
	bool                                 DNSCurve;
#endif

//Member functions
	ConfigurationTable(
		void);
	~ConfigurationTable(
		void);
	void SetToMonitorItem(
		void);
	void MonitorItemToUsing(
		ConfigurationTable *ConfigurationParameter);
	void MonitorItemReset(
		void);
}CONFIGURATION_TABLE;

//Global status class
typedef class GlobalStatus {
public:
	time_t                               StartupTime;
#if defined(PLATFORM_WIN)
	bool                                 Console;
#elif defined(PLATFORM_LINUX)
	bool                                 Daemon;
#endif
	std::vector<SYSTEM_SOCKET>           *LocalListeningSocket;
	std::default_random_engine           *RamdomEngine;
	PSTR                                 DomainTable;

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

//Network layer status
	bool                                 GatewayAvailable_IPv6;
	bool                                 GatewayAvailable_IPv4;

//Local address status
	PSTR                                 LocalAddress_Response[NETWORK_LAYER_PARTNUM];
	size_t                               LocalAddress_Length[NETWORK_LAYER_PARTNUM];
#if !defined(PLATFORM_MACX)
	std::vector<std::string>             *LocalAddress_ResponsePTR[NETWORK_LAYER_PARTNUM];
#endif

//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	HINSTANCE                            FunctionLibrary_GetTickCount64;
	HINSTANCE                            FunctionLibrary_InetNtop;
	HINSTANCE                            FunctionLibrary_InetPton;
	FunctionType_GetTickCount64          FunctionPTR_GetTickCount64;
	FunctionType_InetNtop                FunctionPTR_InetNtop;
	FunctionType_InetPton                FunctionPTR_InetPton;
#endif

//Member functions
	GlobalStatus(
		void);
	~GlobalStatus(
		void);
}GLOBAL_STATUS;

//IPv4/IPv6 addresses ranges class
typedef class AddressRangeTable {
public:
	sockaddr_storage         Begin;
	sockaddr_storage         End;
	size_t                   Level;

//Member functions
	AddressRangeTable(void);
}ADDRESS_RANGE_TABLE;

//Hosts lists class
typedef class HostsTable {
public:
	std::shared_ptr<char>    Response;
	std::regex               Pattern;
	std::string              PatternString;
	std::vector<uint16_t>    Type_Record;
	size_t                   Type_Hosts;
	size_t                   Length;
	bool                     Type_Operation;

//Member functions
	HostsTable(
		void);
}HOSTS_TABLE;

//Alternate swap table class
typedef class AlternateSwapTable {
public:
	bool                     IsSwap[ALTERNATE_SERVERNUM];
	size_t                   TimeoutTimes[ALTERNATE_SERVERNUM];

//Member functions
	AlternateSwapTable(
		void);
}ALTERNATE_SWAP_TABLE;

//Blacklist of results class
typedef class ResultBlacklistTable {
public:
	std::vector<AddressRangeTable>   Addresses;
	std::regex                       Pattern;
	std::string                      PatternString;
}RESULT_BLACKLIST_TABLE;

//Address Hosts class
typedef class AddressHostsTable {
public:
	std::vector<sockaddr_storage>    Address_Target;
	std::vector<AddressRangeTable>   Address_Source;
}ADDRESS_HOSTS_TABLE;

//Address routing table(IPv6) class
typedef class AddressRoutingTable_IPv6 {
public:
	size_t                                   Prefix;
	std::map<uint64_t, std::set<uint64_t>>   AddressRoutingList_IPv6;

//Member functions
	AddressRoutingTable_IPv6(
		void);
}ADDRESS_ROUTING_TABLE_IPV6;

//Address routing table(IPv4) class
typedef class AddressRoutingTable_IPv4 {
public:
	size_t                   Prefix;
	std::set<uint32_t>       AddressRoutingList_IPv4;

//Member functions
	AddressRoutingTable_IPv4(
		void);
}ADDRESS_ROUTING_TABLE_IPV4;

//Port table class
#if defined(ENABLE_PCAP)
typedef class OutputPacketTable {
public:
	std::vector<SOCKET_DATA>   SocketData_Output;
	SOCKET_DATA                SocketData_Input;
	uint16_t                   Protocol_Network;
	uint16_t                   Protocol_Transport;
	ULONGLONG                  ClearPortTime;
	size_t                     ReceiveIndex;

//Member functions
	OutputPacketTable(
		void);
}OUTPUT_PACKET_TABLE;
#endif

//Differnet IPFilter file sets structure
typedef class DiffernetIPFilterFileSet
{
public:
	std::vector<ADDRESS_RANGE_TABLE>          AddressRange;
	std::vector<RESULT_BLACKLIST_TABLE>       ResultBlacklist;
	std::vector<ADDRESS_ROUTING_TABLE_IPV6>   LocalRoutingList_IPv6;
	std::vector<ADDRESS_ROUTING_TABLE_IPV4>   LocalRoutingList_IPv4;
	size_t                                    FileIndex;

//Member functions
	DiffernetIPFilterFileSet(
		void);
}DIFFERNET_IPFILTER_FILE_SET;

//Differnet Hosts file sets structure
typedef class DiffernetHostsFileSet
{
public:
	std::vector<HOSTS_TABLE>           HostsList;
	std::vector<ADDRESS_HOSTS_TABLE>   AddressHostsList;
	size_t                             FileIndex;

//Member functions
	DiffernetHostsFileSet(
		void);
}DIFFERNET_HOSTS_FILE_SET;


//DNSCurve Configuration class
#if defined(ENABLE_LIBSODIUM)
typedef class DNSCurveConfigurationTable {
public:
//[DNSCurve] block
	size_t                     DNSCurvePayloadSize;
	size_t                     DNSCurveProtocol_Network;
	size_t                     DNSCurveProtocol_Transport;
#if defined(PLATFORM_WIN)
	int                        DNSCurve_SocketTimeout_Reliable;
	int                        DNSCurve_SocketTimeout_Unreliable;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	timeval                    DNSCurve_SocketTimeout_Reliable;
	timeval                    DNSCurve_SocketTimeout_Unreliable;
#endif
	bool                       IsEncryption;
	bool                       IsEncryptionOnly;
	bool                       ClientEphemeralKey;
	size_t                     KeyRecheckTime;
//[DNSCurve Addresses] block
	PUINT8                     Client_PublicKey;
	PUINT8                     Client_SecretKey;
	struct _dnscurve_target_ {
		DNSCURVE_SERVER_DATA   IPv6;
		DNSCURVE_SERVER_DATA   Alternate_IPv6;
		DNSCURVE_SERVER_DATA   IPv4;
		DNSCURVE_SERVER_DATA   Alternate_IPv4;
	}DNSCurveTarget;

//Member functions
	DNSCurveConfigurationTable(
		void);
	~DNSCurveConfigurationTable(
		void);
	void SetToMonitorItem(
		void);
	void MonitorItemToUsing(
		DNSCurveConfigurationTable *DNSCurveConfigurationParameter);
	void MonitorItemReset(
		void);
}DNSCURVE_CONFIGURATION_TABLE;
#endif


//////////////////////////////////////////////////
// Main functions
// 
//Base.cpp
bool __fastcall CheckEmptyBuffer(
	const void *Buffer, 
	const size_t Length);
uint16_t __fastcall hton16_Force(
	const uint16_t Value);
//uint16_t __fastcall ntoh16_Force(
//	const uint16_t Value);
uint32_t __fastcall hton32_Force(
	const uint32_t Value);
//uint32_t __fastcall ntoh32_Force(
//	const uint32_t Value);
uint64_t __fastcall hton64(
	const uint64_t Value);
//uint64_t __fastcall ntoh64(
//	const uint64_t Value);
bool __fastcall MBSToWCSString(
	std::wstring &Target, 
	const char *Buffer, 
	const size_t MaxLen);
void __fastcall CaseConvert(
	const bool IsLowerToUpper, 
	PSTR Buffer, 
	const size_t Length);
void __fastcall CaseConvert(
	const bool IsLowerToUpper, 
	std::string &Buffer);
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
uint64_t GetCurrentSystemTime(
	void);
#endif
//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
BOOL WINAPI IsGreaterThanVista(
	void);
BOOL WINAPI GetFunctionPointer(
	const size_t FunctionType);
#endif
bool __fastcall SortCompare_IPFilter(
	const DIFFERNET_IPFILTER_FILE_SET &Begin, 
	const DIFFERNET_IPFILTER_FILE_SET &End);
bool __fastcall SortCompare_Hosts(
	const DIFFERNET_HOSTS_FILE_SET &Begin, 
	const DIFFERNET_HOSTS_FILE_SET &End);

//PrintLog.h
bool __fastcall PrintError(
	const size_t ErrorType, 
	const wchar_t *Message, 
	const SSIZE_T ErrorCode, 
	const wchar_t *FileName, 
	const size_t Line);

//PacketData.h
//uint32_t __fastcall GetFCS(
//	const unsigned char *Buffer, 
//	const size_t Length);
uint16_t __fastcall GetChecksum(
	const uint16_t *Buffer, 
	const size_t Length);
uint16_t __fastcall GetChecksum_ICMPv6(
	const unsigned char *Buffer, 
	const size_t Length, 
	const in6_addr &Destination, 
	const in6_addr &Source);
uint16_t __fastcall GetChecksum_TCP_UDP(
	const unsigned char *Buffer, 
	const size_t Length, 
	const uint16_t Protocol_Network, 
	const uint16_t Protocol_Transport);
size_t __fastcall AddLengthDataToHeader(
	PSTR Buffer, 
	const size_t RecvLen, 
	const size_t MaxLen);
size_t __fastcall CharToDNSQuery(
	const char *FName, 
	PSTR TName);
size_t __fastcall DNSQueryToChar(
	const char *TName, 
	PSTR FName);
void __fastcall MakeRamdomDomain(
	PSTR Buffer);
void __fastcall MakeDomainCaseConversion(
	PSTR Buffer);
size_t __fastcall AddEDNSLabelToAdditionalRR(
	PSTR Buffer, 
	const size_t Length, 
	const size_t MaxLen, 
	const bool NoHeader);
size_t __fastcall MakeCompressionPointerMutation(
	PSTR Buffer, 
	const size_t Length);

//Protocol.h
bool __fastcall AddressStringToBinary(
	const char *AddrString, 
	void *OriginalAddr, 
	const uint16_t Protocol, 
	SSIZE_T &ErrorCode);
size_t __fastcall AddressesComparing(
	const void *OriginalAddrBegin, 
	const void *OriginalAddrEnd, 
	const uint16_t Protocol);
bool __fastcall CheckSpecialAddress(
	void *Addr, 
	const uint16_t Protocol, 
	const bool IsPrivateUse, 
	char *Domain);
bool __fastcall CheckAddressRouting(
	const void *Addr, 
	const uint16_t Protocol);
bool __fastcall CheckCustomModeFilter(
	const void *OriginalAddr, 
	const uint16_t Protocol);
size_t __fastcall CheckQueryNameLength(
	const char *Buffer);
size_t __fastcall CheckQueryData(
	PSTR RecvBuffer, 
	PSTR SendBuffer, 
	const size_t Length, 
	const SOCKET_DATA &LocalSocketData, 
	const uint16_t Protocol, 
	bool *IsLocal);
size_t __fastcall CheckResponseData(
	const char *Buffer, 
	const size_t Length, 
	const bool IsLocal, 
	bool *IsMarkHopLimit);

//Configuration.h
bool __fastcall ReadParameter(
	const bool IsFirstRead);
void __fastcall ReadIPFilter(
	void);
void __fastcall ReadHosts(
	void);
void __fastcall GetParameterListData(
	std::vector<std::string> &ListData, 
	const std::string Data, 
	const size_t DataOffset, 
	const size_t Length);

//Monitor.h
bool __fastcall MonitorInit(
	void);
void __fastcall NetworkInformationMonitor(
	void);

//Proxy.h
size_t __fastcall SOCKSTCPRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize);
size_t __fastcall SOCKSUDPRequest(
	const char *OriginalSend,
	const size_t SendSize,
	PSTR OriginalRecv,
	const size_t RecvSize);

//DNSCurve.h
#if defined(ENABLE_LIBSODIUM)
bool __fastcall DNSCurveVerifyKeypair(
	const unsigned char *PublicKey, 
	const unsigned char *SecretKey);
void __fastcall DNSCurveInit(
	void);
size_t __fastcall DNSCurveTCPRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize);
size_t __fastcall DNSCurveTCPRequestMulti(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize);
size_t __fastcall DNSCurveUDPRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize);
size_t __fastcall DNSCurveUDPRequestMulti(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize);
#endif

//Process.h
bool __fastcall EnterRequestProcess(
	const char *OriginalSend, 
	const size_t Length, 
	const SOCKET_DATA LocalSocketData, 
	const uint16_t Protocol, 
	const bool IsLocal);
size_t __fastcall CheckHostsProcess(
	PSTR OriginalRequest, 
	const size_t Length, 
	PSTR Result, 
	const size_t ResultSize);
bool __fastcall SendToRequester(
	PSTR RecvBuffer, 
	const size_t RecvSize, 
	const size_t MaxLen, 
	const uint16_t Protocol, 
	const SOCKET_DATA &LocalSocketData);
bool __fastcall MarkDomainCache(
	const char *Buffer, 
	const size_t Length);

//Captrue.h
#if defined(ENABLE_PCAP)
	void __fastcall CaptureInit(
		void);
#endif

//Network.h
bool __fastcall SocketSetting(
	const SYSTEM_SOCKET Socket, 
	const size_t SettingType, 
	void *DataPointer);
size_t __fastcall SocketConnecting(
	const uint16_t Protocol, 
	const SYSTEM_SOCKET Socket, 
	const PSOCKADDR SockAddr, 
	const socklen_t AddrLen, 
	const char *OriginalSend, 
	const size_t SendSize);
SSIZE_T __fastcall SocketSelecting(
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	const char *SendBuffer, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const bool IsLocal, 
	const bool NoCheck);
#if defined(ENABLE_PCAP)
bool __fastcall DomainTestRequest(
	const uint16_t Protocol);
bool __fastcall ICMPTestRequest(
	const uint16_t Protocol);
#endif
size_t __fastcall TCPRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const bool IsLocal);
size_t __fastcall TCPRequestMulti(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize);
#if defined(ENABLE_PCAP)
size_t __fastcall UDPRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA *LocalSocketData, 
	const uint16_t Protocol);
size_t __fastcall UDPRequestMulti(
	const char *OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA *LocalSocketData, 
	const uint16_t Protocol);
#endif
size_t __fastcall UDPCompleteRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const bool IsLocal);
size_t __fastcall UDPCompleteRequestMulti(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize);

//Service.h
#if defined(PLATFORM_WIN)
BOOL WINAPI CtrlHandler(
	const DWORD fdwCtrlType);
size_t WINAPI ServiceMain(
	DWORD argc, 
	LPTSTR *argv);
bool __fastcall FlushDNSMailSlotMonitor(
	void);
bool WINAPI FlushDNSMailSlotSender(
	void);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
bool FlushDNSFIFOMonitor(
	void);
bool FlushDNSFIFOSender(
	void);
#endif
void __fastcall FlushAllDNSCache(
	void);
