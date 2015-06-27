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
//Base defines
#define KILOBYTE_TIMES         1024U         //1KB = 1024 bytes
#define MEGABYTE_TIMES         1048576U      //1MB = 1048576 bytes
#define GIGABYTE_TIMES         1073741824U   //1GB = 1073741824 bytes
#define CODEPAGE_ANSI          1U            //Microsoft Windows Codepage of ANSI
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

//ASCII value defines
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
#define ASCII_BRACKETS_LEAD     91                   //"["
#define ASCII_BACKSLASH         92                   //"\"
#define ASCII_BRACKETS_TRAIL    93                   //"]"
#define ASCII_ACCENT            96                   //"`"
#define ASCII_LOWERCASE_A       97                   //"a"
#define ASCII_LOWERCASE_F       102                  //"f"
#define ASCII_BRACES_LEAD       123                  //"{"
#define ASCII_VERTICAL          124                  //"|"
#define ASCII_TILDE             126                  //"~"
#define ASCII_MAX_NUM           0x7F
//#define ASCII_UPPER_TO_LOWER    32U                  //Uppercase to lowercase
//#define ASCII_LOWER_TO_UPPER    32U                  //Lowercase to uppercase

//Unicode value defines
#define UNICODE_NEL             0x0085               //Next Line/NEL
#define UNICODE_NBS             0x00A0               //No-Break Space/NBS
#define UNICODE_OSM             0x1680               //Ogham Space Mark/OSM
#define UNICODE_MVS             0x180E               //Mongolian Vowel Separator/MVS
#define UNICODE_LS              0x2028               //Line Separator/LS
#define UNICODE_PS              0x2029               //Paragraph Separator/PS
#define UNICODE_NUT             0x2002               //En Space or Nut
#define UNICODE_MUTTON          0x2003               //Em Space or Mutton
#define UNICODE_TPES            0x2004               //Three-Per-Em Space/TPES or Thick Space
#define UNICODE_FPES            0x2005               //Four-Per-Em Space/FPES or Mid Space
#define UNICODE_SPES            0x2006               //Six-Per-Em Space/SPES
#define UNICODE_FS              0x2007               //Figure Space/FS
#define UNICODE_PCS             0x2008               //Punctuation Space/PS
#define UNICODE_TS              0x2009               //Thin Space/TS
#define UNICODE_HS              0x200A               //Hair Space/HS
#define UNICODE_ZWSP            0x200B               //Zero Width Space/ZWSP
#define UNICODE_ZWNJ            0x200C               //Zero Width Non Joiner/ZWNJ
#define UNICODE_ZWJ             0x200D               //Zero Width Joiner/ZWJ
#define UNICODE_NNBS            0x202F               //Narrow No-Break Space/NNBS
#define UNICODE_MMSP            0x205F               //Medium Mathematical Space/MMSP
#define UNICODE_WJ              0x2060               //Word Joiner/WJ
#define UNICODE_IS              0x3000               //Ideographic Space/IS in CJK

//Version defines
#define CONFIG_VERSION_POINT_THREE   0.3
#define CONFIG_VERSION               0.4             //Current configuration version
#define FULL_VERSION                 L"0.4.2.3"

//Exit code defines
#define EXIT_CHECK_HOSTS_TYPE_LOCAL                2U   //Type is Local in CheckHosts function.
#define EXIT_CHECK_RESPONSE_DATA_MARK_HOP_LIMITS   2U   //Mark Hop Limits in CheckresponseData function.

//Size and length defines
#define BOM_UTF_8_LENGTH               3U                                         //UTF-8 BOM length
#define BOM_UTF_16_LENGTH              2U                                         //UTF-16 BOM length
#define BOM_UTF_32_LENGTH              4U                                         //UTF-32 BOM length
#define COMMAND_BUFFER_MAXSIZE         4096U                                      //Maximum size of commands buffer(4096 bytes)
#define FILE_BUFFER_SIZE               4096U                                      //Maximum size of file buffer(4KB/4096 bytes)
#define DEFAULT_FILE_MAXSIZE           1073741824U                                //Maximum size of whole reading file(1GB/1073741824 bytes).
#define DEFAULT_LOG_MAXSIZE            8388608U                                   //Maximum size of whole log file(8MB/8388608 bytes).
#define DEFAULT_LOG_MINSIZE            4096U                                      //Minimum size of whole log file(4KB/4096 bytes).
#define PACKET_MAXSIZE                 1500U                                      //Maximum size of packets, Standard MTU of Ethernet II network
#define ORIGINAL_PACKET_MAXSIZE        1508U                                      //Maximum size of original Ethernet II packets(1500 bytes maximum payload length + 8 bytes Ethernet header)
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
#define MULTI_REQUEST_TIMES_MAXNUM     8U                                                                              //Maximum times of multi requesting.
#define NETWORK_LAYER_PARTNUM          2U                                                                              //Number of network layer protocols(IPv6 and IPv4)
#define TRANSPORT_LAYER_PARTNUM        4U                                                                              //Number of transport layer protocols(00: IPv6/UDP, 01: IPv4/UDP, 02: IPv6/TCP, 03: IPv4/TCP)
#define ALTERNATE_SERVERNUM            12U                                                                             //Alternate switching of Main(00: TCP/IPv6, 01: TCP/IPv4, 02: UDP/IPv6, 03: UDP/IPv4), Local(04: TCP/IPv6, 05: TCP/IPv4, 06: UDP/IPv6, 07: UDP/IPv4), DNSCurve(08: TCP/IPv6, 09: TCP/IPv4, 10: UDP/IPv6, 11: UDP/IPv4)
#define DOMAIN_MAXSIZE                 256U                                                                            //Maximum size of whole level domain is 256 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_DATA_MAXSIZE            253U                                                                            //Maximum data length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_LEVEL_DATA_MAXSIZE      63U                                                                             //Domain length is between 3 and 63(Labels must be 63 characters/bytes or less, Section 2.3.1 in RFC 1035).
#define DOMAIN_MINSIZE                 2U                                                                              //Minimum size of whole level domain is 3 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_RAMDOM_MINSIZE          6U                                                                              //Minimum size of ramdom domain requesting
#define DNS_PACKET_MINSIZE             (sizeof(dns_hdr) + 4U + sizeof(dns_qry))                                        //Minimum DNS packet size(DNS Header + Minimum Domain + DNS Query)
#define DNS_RR_MAXCOUNT_AAAA           43U                                                                             //Maximum Record Resources size of AAAA answers, 28 bytes * 43 = 1204 bytes
#define DNS_RR_MAXCOUNT_A              75U                                                                             //Maximum Record Resources size of A answers, 16 bytes * 75 = 1200 bytes
#define EDNS_ADDITIONAL_MAXSIZE        (sizeof(dns_record_opt) * 2U + sizeof(edns_client_subnet) + sizeof(in6_addr))   //Maximum of EDNS Additional Record Resources size

//Code defines
#if defined(PLATFORM_WIN)
	#define QUERY_SERVICE_CONFIG_BUFFER_MAXSIZE   8192U      //Buffer maximum size of QueryServiceConfig() function(8KB/8192 Bytes)
	#define SYSTEM_SOCKET                         UINT_PTR   //System Socket defined(WinSock2.h), not the same in x86(unsigned int) and x64(unsigned __int64) platform, which define in WinSock2.h file.
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define SYSTEM_SOCKET                         int
#endif
#if defined(ENABLE_PCAP)
//	#define PCAP_READ_TIMEOUT                     0          //Pcap read timeout with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet.
//	#define PCAP_READ_SUCCESS                     1          //Pcap packets has been read without problems.
	#define PCAP_LOOP_INFINITY                    (-1)       //Pcap packets are processed until another ending condition occurs.
	#define PCAP_COMPILE_OPTIMIZE                 1          //Pcap optimization on the resulting code is performed.
#endif
#define SHA3_512_SIZE                         64U        //SHA3-512 instance as specified in the FIPS 202 draft in April 2014(http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf), 512 bits/64 bytes.
#define CHECKSUM_SUCCESS                      0          //Result of getting correct checksum.
#define DYNAMIC_MIN_PORT                      1024U      //Well-known port is from 1 to 1023.

//Time defines
#define LOOP_MAX_TIMES                     8U        //Maximum of loop times, 8 times
#define LOOP_INTERVAL_TIME                 10U       //Loop interval time, 10 ms
#define STANDARD_TIMEOUT                   1000U     //Standard timeout, 1000 ms(1 second)
#define MONITOR_LOOP_INTERVAL_TIME         10000U    //Monitor loop interval time, 10000 ms(10 seconds)
#define SECOND_TO_MILLISECOND              1000U     //1000 milliseconds(1 second)
#define MICROSECOND_TO_MILLISECOND         1000U     //1000 microseconds(1 millisecond)
#if defined(PLATFORM_WIN)
	#define UPDATE_SERVICE_TIME                3U        //Update service timeout, 3 seconds
#endif
#if defined(ENABLE_PCAP)
	#define PCAP_DEVICES_RECHECK_TIME          10U       //Time between every WinPcap/LibPcap devices recheck, 10 seconds
	#define PCAP_CAPTURE_MIN_TIMEOUT           10U       //Minimum Pcap Capture reading timeout, 10 ms
	#define DEFAULT_PCAP_CAPTURE_TIMEOUT       200U      //Default Pcap Capture reading timeout, 200 ms
#endif
#define SOCKET_MIN_TIMEOUT                 500U      //The shortset socket timeout, 500 ms
#if defined(PLATFORM_WIN)
	#define DEFAULT_RELIABLE_SOCKET_TIMEOUT     3000U     //Default timeout of reliable sockets(Such as TCP, 3 seconds/3000ms)
	#define DEFAULT_UNRELIABLE_SOCKET_TIMEOUT   2000U     //Default timeout of unreliable sockets(Such as ICMP/ICMPv6/UDP, 2 seconds/2000ms)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define DEFAULT_RELIABLE_SOCKET_TIMEOUT     3U        //Default timeout of reliable sockets(Such as TCP, 3 seconds)
	#define DEFAULT_UNRELIABLE_SOCKET_TIMEOUT   2U        //Default timeout of unreliable sockets(Such as ICMP/ICMPv6/UDP, 2 seconds)
#endif
#define DEFAULT_FILEREFRESH_TIME           10U       //Default time between files auto-refreshing, 10 seconds
#define DEFAULT_ICMPTEST_TIME              5U        //Default time between ICMP Test, 5 seconds
#define DEFAULT_DOMAINTEST_INTERVAL_TIME   900U      //Default Domain Test time between every sending, 15 minutes(900 seconds)
#define DEFAULT_ALTERNATE_TIMES            5U        //Default times of requesting timeout, 5 times
#define DEFAULT_ALTERNATE_RANGE            10U       //Default time of checking timeout, 10 seconds
#define DEFAULT_ALTERNATE_RESET_TIME       180U      //Default time to reset switching of alternate servers, 180 seconds
#define DEFAULT_HOSTS_TTL                  900U      //Default Hosts DNS TTL, 15 minutes(900 seconds)
#define SHORTEST_FILEREFRESH_TIME          5U        //The shortset time between files auto-refreshing, 5 seconds
#define SENDING_INTERVAL_TIME              5U        //Time between every sending, 5 seconds
#define SENDING_ONCE_INTERVAL_TIMES        3U        //Repeat 3 times between every sending.
#if defined(ENABLE_LIBSODIUM)
	#define DEFAULT_DNSCURVE_RECHECK_TIME      3600U     //Default DNSCurve keys recheck time, 1 hour(3600 seconds)
	#define SHORTEST_DNSCURVE_RECHECK_TIME     10U       //The shortset DNSCurve keys recheck time, 10 seconds
#endif

//Data defines
#define DEFAULT_LOCAL_SERVERNAME              ("pcap-dnsproxy.localhost.server")                                                                                                            //Default Local DNS server name
#if defined(PLATFORM_WIN)
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
	#define DEFAULT_LOCAL_SERVICE_NAME            L"PcapDNSProxyService"                                                                                                                        //Default service name of system
	#define DEFAULT_PADDINGDATA                   ("abcdefghijklmnopqrstuvwabcdefghi")                                                                                                          //ICMP padding data on Windows
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
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
#define DNS_PACKET_QUERY_LOCATE(Buffer)       (sizeof(dns_hdr) + CheckDNSQueryNameLength(Buffer + sizeof(dns_hdr)) + 1U)                                                                    //Location the beginning of DNS Query
#define DNS_TCP_PACKET_QUERY_LOCATE(Buffer)   (sizeof(dns_tcp_hdr) + CheckDNSQueryNameLength(Buffer + sizeof(dns_tcp_hdr)) + 1U)
#define DNS_PACKET_RR_LOCATE(Buffer)          (sizeof(dns_hdr) + CheckDNSQueryNameLength(Buffer + sizeof(dns_hdr)) + 1U + sizeof(dns_qry))                                                  //Location the beginning of DNS Resource Records

//Function Type defines
//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	#define FUNCTION_GETTICKCOUNT64        1U
	#define FUNCTION_INET_NTOP             2U
#endif

//Compare addresses own defines
#define ADDRESS_COMPARE_LESS           1U
#define ADDRESS_COMPARE_EQUAL          2U
#define ADDRESS_COMPARE_GREATER        3U

//Error type defines
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

//Codes and types defines
#define LISTEN_PROTOCOL_NETWORK_BOTH     0
#define LISTEN_PROTOCOL_IPV6             1U
#define LISTEN_PROTOCOL_IPV4             2U
#define LISTEN_PROTOCOL_TRANSPORT_BOTH   0
#define LISTEN_PROTOCOL_TCP              1U
#define LISTEN_PROTOCOL_UDP              2U
#define LISTEN_MODE_PROXY                0
#define LISTEN_MODE_PRIVATE              1U 
#define LISTEN_MODE_SERVER               2U
#define LISTEN_MODE_CUSTOM               3U
#define REQUEST_MODE_NETWORK_BOTH        0
#define REQUEST_MODE_IPV6                1U
#define REQUEST_MODE_IPV4                2U
#define REQUEST_MODE_UDP                 0
#define REQUEST_MODE_TCP                 1U
#define HOSTS_TYPE_NORMAL                0
#define HOSTS_TYPE_WHITE                 1U
#define HOSTS_TYPE_LOCAL                 2U
#define HOSTS_TYPE_BANNED                3U
#define CACHE_TYPE_TIMER                 1U
#define CACHE_TYPE_QUEUE                 2U
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_REQUEST_MODE_UDP         0
	#define DNSCURVE_REQUEST_MODE_TCP         1U
#endif

//Server type defines
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_MAIN_IPV6             1U           //DNSCurve Main(IPv6)
	#define DNSCURVE_MAIN_IPV4             2U           //DNSCurve Main(IPv4)
	#define DNSCURVE_ALTERNATE_IPV6        3U           //DNSCurve Alternate(IPv6)
	#define DNSCURVE_ALTERNATE_IPV4        4U           //DNSCurve Alternate(IPv4)
#endif

//Function Pointer defines
//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	typedef ULONGLONG(CALLBACK *GetTickCount64Function)(void);
	typedef PCSTR(CALLBACK *Inet_Ntop_Function)(INT, PVOID, PSTR, size_t);
#endif


//////////////////////////////////////////////////
// Function defines(Part 2)
#if defined(PLATFORM_WIN)
	#define Sleep(Millisecond)    Sleep((DWORD)(Millisecond))
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define Sleep(Millisecond)    usleep((useconds_t)((Millisecond) * MICROSECOND_TO_MILLISECOND))
	#define usleep(Millisecond)   usleep((useconds_t)(Millisecond))
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

//DNS Server Data structure
typedef struct _dns_server_data_
{
	union _address_data_ {
		sockaddr_storage     Storage;
		sockaddr_in6         IPv6;
		sockaddr_in          IPv4;
	}AddressData;
#if defined(ENABLE_PCAP)
	union _hoplimit_data_ {
		uint8_t              TTL;
		uint8_t              HopLimit;
	}HopLimitData;
#endif
}DNSServerData, DNS_SERVER_DATA, *PDNSServerData, *PDNS_SERVER_DATA;

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
	union _address_data_ {
		sockaddr_storage     Storage;
		sockaddr_in6         IPv6;
		sockaddr_in          IPv4;
	}AddressData;
	PSTR                     ProviderName;           //Server Provider Name
	PUINT8                   PrecomputationKey;      //DNSCurve Precomputation Keys
	PUINT8                   ServerPublicKey;        //Server Public Keys
	PUINT8                   ServerFingerprint;      //Server Fingerprints
	PSTR                     ReceiveMagicNumber;     //Receive Magic Number(Same from server receive)
	PSTR                     SendMagicNumber;        //Server Magic Number(Send to server)
}DNSCurveServerData, DNSCURVE_SERVER_DATA, *PDNSCurveServerData, *PDNSCURVE_SERVER_DATA;
#endif

//Class defines
//Configuration class
typedef class ConfigurationTable {
public:
// Parameters from configure files
//[Base] block
	double                               Version;
	size_t                               FileRefreshTime;
	size_t                               BufferQueueSize;
	size_t                               QueueResetTime;
//[Log] block
	bool                                 PrintError;
	size_t                               LogMaxSize;
//[DNS] block
	size_t                               RequestMode_Network;
	size_t                               RequestMode_Transport;
	bool                                 HostsOnly;
	bool                                 LocalMain;
	bool                                 LocalHosts;
	bool                                 LocalRouting;
	size_t                               CacheType;
	size_t                               CacheParameter;
	uint32_t                             HostsDefaultTTL;
//[Listen] block
#if defined(ENABLE_PCAP)
	bool                                 PcapCapture;
	size_t                               PcapReadingTimeout;
#endif
	size_t                               OperationMode;
	size_t                               ListenProtocol_Network;
	size_t                               ListenProtocol_Transport;
	std::vector<uint16_t>                *ListenPort;
	bool                                 IPFilterType;
	size_t                               IPFilterLevel;
	bool                                 AcceptType;
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
		DNS_SERVER_DATA                  Local_IPv6;
		DNS_SERVER_DATA                  Alternate_Local_IPv6;
		DNS_SERVER_DATA                  Local_IPv4;
		DNS_SERVER_DATA                  Alternate_Local_IPv4;
		std::vector<DNS_SERVER_DATA>     *IPv6_Multi;
		std::vector<DNS_SERVER_DATA>     *IPv4_Multi;
	}DNSTarget;
//[Values] block
	size_t                               EDNSPayloadSize;
#if defined(ENABLE_PCAP)
	uint8_t                              HopLimitFluctuation;
	uint16_t                             ICMP_ID;
	uint16_t                             ICMP_Sequence;
	size_t                               ICMP_Speed;
//[Data] block(A part)
	PSTR                                 ICMP_PaddingData;
	size_t                               ICMP_PaddingLength;
	PSTR                                 DomainTest_Data;
	uint16_t                             DomainTest_ID;
	size_t                               DomainTest_Speed;
#endif
	size_t                               AlternateTimes;
	size_t                               AlternateTimeRange;
	size_t                               AlternateResetTime;
	size_t                               MultiRequestTimes;
//[Switches] block
	bool                                 TCP_FastOpen;
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
	bool                                 DNSDataCheck;
	bool                                 BlacklistCheck;
//[Data] block(B part)
	std::string                          *LocalFQDN_String;
	PSTR                                 LocalFQDN_Response;
	size_t                               LocalFQDN_Length;
#if !defined(PLATFORM_MACX)
	PSTR                                 LocalServer_Response;
	size_t                               LocalServer_Length;
#endif
//[DNSCurve/DNSCrypt] block
#if defined(ENABLE_LIBSODIUM)
	bool                                 DNSCurve;
#endif

// Global parameters from status
//Global block
#if defined(PLATFORM_WIN)
	bool                                 Console;
#elif defined(PLATFORM_LINUX)
	bool                                 Daemon;
#endif
	std::vector<SYSTEM_SOCKET>           *LocalSocket;
	std::default_random_engine           *RamdomEngine;
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
#if defined(PLATFORM_WIN)
	int                                  SocketTimeout_Reliable;
	int                                  SocketTimeout_Unreliable;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	timeval                              SocketTimeout_Reliable;
	timeval                              SocketTimeout_Unreliable;
#endif
	size_t                               ReceiveWaiting;
	PSTR                                 DomainTable;
	PSTR                                 LocalAddress_Response[NETWORK_LAYER_PARTNUM];
	size_t                               LocalAddress_Length[NETWORK_LAYER_PARTNUM];
#if !defined(PLATFORM_MACX)
	std::vector<std::string>             *LocalAddress_ResponsePTR[NETWORK_LAYER_PARTNUM];
#endif
	std::vector<uint16_t>                *AcceptTypeList;

//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	HINSTANCE                            GetTickCount64_DLL;
	GetTickCount64Function               GetTickCount64_PTR;
	HINSTANCE                            Inet_Ntop_DLL;
	Inet_Ntop_Function                   Inet_Ntop_PTR;
#endif

//IPv6 support block
	bool                                 GatewayAvailable_IPv6;
	bool                                 GatewayAvailable_IPv4;
	bool                                 TunnelAvailable_IPv6;

	ConfigurationTable(void);
	~ConfigurationTable(void);
}CONFIGURATION_TABLE;

//IPv4/IPv6 addresses ranges class
typedef class AddressRangeTable {
public:
	sockaddr_storage         Begin;
	sockaddr_storage         End;
	size_t                   Level;

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

	HostsTable(void);
}HOSTS_TABLE;

//Alternate swap table class
typedef class AlternateSwapTable {
public:
	bool                     IsSwap[ALTERNATE_SERVERNUM];
	size_t                   TimeoutTimes[ALTERNATE_SERVERNUM];

	AlternateSwapTable(void);
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

	AddressRoutingTable_IPv6(void);
}ADDRESS_ROUTING_TABLE_IPV6;

//Address routing table(IPv4) class
typedef class AddressRoutingTable_IPv4 {
public:
	size_t                   Prefix;
	std::set<uint32_t>       AddressRoutingList_IPv4;

	AddressRoutingTable_IPv4(void);
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

	OutputPacketTable(void);
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

	DiffernetIPFilterFileSet(void);
}DIFFERNET_IPFILTER_FILE_SET;

//Differnet Hosts file sets structure
typedef class DiffernetHostsFileSet
{
public:
	std::vector<HOSTS_TABLE>           HostsList;
	std::vector<ADDRESS_HOSTS_TABLE>   AddressHostsList;
	size_t                             FileIndex;

	DiffernetHostsFileSet(void);
}DIFFERNET_HOSTS_FILE_SET;


//DNSCurve Configuration class
#if defined(ENABLE_LIBSODIUM)
typedef class DNSCurveConfigurationTable {
public:
//[DNSCurve] block
	size_t                   DNSCurvePayloadSize;
	size_t                   DNSCurveMode;
	bool                     IsEncryption;
	bool                     IsEncryptionOnly;
	size_t                   KeyRecheckTime;
//[DNSCurve Addresses] block
	PUINT8                   Client_PublicKey;
	PUINT8                   Client_SecretKey;
	struct _dnscurve_target_ {
		DNSCURVE_SERVER_DATA   IPv6;
		DNSCURVE_SERVER_DATA   Alternate_IPv6;
		DNSCURVE_SERVER_DATA   IPv4;
		DNSCURVE_SERVER_DATA   Alternate_IPv4;
	}DNSCurveTarget;

	DNSCurveConfigurationTable(void);
	~DNSCurveConfigurationTable(void);
}DNSCURVE_CONFIGURATON_TABLE;
#endif


//////////////////////////////////////////////////
// Main functions
// 
//Base.cpp
bool __fastcall CheckEmptyBuffer(const void *Buffer, const size_t Length);
uint16_t __fastcall hton16_Force(const uint16_t Value);
uint16_t __fastcall ntoh16_Force(const uint16_t Value);
uint32_t __fastcall hton32_Force(const uint32_t Value);
uint32_t __fastcall ntoh32_Force(const uint32_t Value);
uint64_t __fastcall hton64(const uint64_t Value);
uint64_t __fastcall ntoh64(const uint64_t Value);
void __fastcall MBSToWCSString(std::wstring &Target, const char *Buffer);
void __fastcall CaseConvert(const bool IsLowerToUpper, PSTR Buffer, const size_t Length);
void __fastcall CaseConvert(const bool IsLowerToUpper, std::string &Buffer);
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	uint64_t GetTickCount64(void);
#endif
//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	BOOL WINAPI IsGreaterThanVista(void);
	BOOL WINAPI GetFunctionPointer(const size_t FunctionType);
#endif

//PrintLog.h
size_t __fastcall PrintError(const size_t ErrType, const wchar_t *Message, const SSIZE_T ErrCode, const wchar_t *FileName, const size_t Line);

//PacketData.h
//uint32_t __fastcall GetFCS(const unsigned char *Buffer, const size_t Length);
uint16_t __fastcall GetChecksum(const uint16_t *Buffer, const size_t Length);
uint16_t __fastcall GetICMPv6Checksum(const unsigned char *Buffer, const size_t Length, const in6_addr &Destination, const in6_addr &Source);
uint16_t __fastcall GetTCPUDPChecksum(const unsigned char *Buffer, const size_t Length, const uint16_t Protocol_Network, const uint16_t Protocol_Transport);
size_t __fastcall AddLengthDataToDNSHeader(PSTR Buffer, const size_t RecvLen, const size_t MaxLen);
size_t __fastcall CharToDNSQuery(const char *FName, PSTR TName);
size_t __fastcall DNSQueryToChar(const char *TName, PSTR FName);
void __fastcall MakeRamdomDomain(PSTR Buffer);
void __fastcall MakeDomainCaseConversion(PSTR Buffer);
size_t __fastcall AddEDNS_LabelToAdditionalRR(PSTR Buffer, const size_t Length);
size_t __fastcall MakeCompressionPointerMutation(PSTR Buffer, const size_t Length);

//Protocol.h
bool __fastcall AddressStringToBinary(const char *AddrString, void *OriginalAddr, const uint16_t Protocol, SSIZE_T &ErrCode);
size_t __fastcall AddressesComparing(const void *OriginalAddrBegin, const void *OriginalAddrEnd, const uint16_t Protocol);
bool __fastcall CheckSpecialAddress(void *Addr, const uint16_t Protocol, const bool IsPrivateUse, char *Domain);
bool __fastcall CheckAddressRouting(const void *Addr, const uint16_t Protocol);
bool __fastcall CheckCustomModeFilter(const void *OriginalAddr, const uint16_t Protocol);
size_t __fastcall CheckDNSQueryNameLength(const char *Buffer);
size_t __fastcall CheckResponseData(const char *Buffer, const size_t Length, const bool IsLocal);

//Configuration.h
bool __fastcall ReadParameter(void);
void __fastcall ReadIPFilter(void);
void __fastcall ReadHosts(void);
uint16_t __fastcall ServiceNameToHex(const char *OriginalBuffer);
uint16_t __fastcall DNSTypeNameToHex(const char *OriginalBuffer);

//Monitor.h
bool __fastcall MonitorInit(void);
void __fastcall NetworkInformationMonitor(void);

//DNSCurve.h
#if defined(ENABLE_LIBSODIUM)
	bool __fastcall DNSCurveVerifyKeypair(const unsigned char *PublicKey, const unsigned char *SecretKey);
	void __fastcall DNSCurveInit(void);
	size_t __fastcall DNSCurveTCPRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
	size_t __fastcall DNSCurveTCPRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
	size_t __fastcall DNSCurveUDPRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
	size_t __fastcall DNSCurveUDPRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
#endif

//Process.h
bool __fastcall EnterRequestProcess(const char *OriginalSend, const size_t Length, const SOCKET_DATA LocalSocketData, const uint16_t Protocol);
bool __fastcall MarkDomainCache(const char *Buffer, const size_t Length);

//Captrue.h
#if defined(ENABLE_PCAP)
	void __fastcall CaptureInit(void);
#endif

//Network.h
#if defined(ENABLE_PCAP)
bool __fastcall DomainTestRequest(const uint16_t Protocol);
bool __fastcall ICMPEcho(const uint16_t Protocol);
#endif
size_t __fastcall TCPRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsLocal);
size_t __fastcall TCPRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
#if defined(ENABLE_PCAP)
	size_t __fastcall UDPRequest(const char *OriginalSend, const size_t Length, const SOCKET_DATA *LocalSocketData, const uint16_t Protocol);
	size_t __fastcall UDPRequestMulti(const char *OriginalSend, const size_t Length, const SOCKET_DATA *LocalSocketData, const uint16_t Protocol);
#endif
size_t __fastcall UDPCompleteRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsLocal);
size_t __fastcall UDPCompleteRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);

//Service.h
#if defined(PLATFORM_WIN)
	BOOL WINAPI CtrlHandler(const DWORD fdwCtrlType);
	size_t WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
	bool WINAPI FlushDNSMailSlotMonitor(void);
	bool WINAPI FlushDNSMailSlotSender(void);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	bool FlushDNSFIFOMonitor(void);
	bool FlushDNSFIFOSender(void);
#endif
void __fastcall FlushAllDNSCache(void);
