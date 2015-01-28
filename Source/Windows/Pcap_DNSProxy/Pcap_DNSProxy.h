// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
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


#include "Pcap_DNSProxy_Base.h"

//Base defines
//#define RETURN_ERROR           (-1)
#define MBSTOWCS_NULLTERMINATE   (-1)                  //MultiByteToWideChar() find null-terminate.
//#define PCAP_ERROR               (-1)
#define LIBSODIUM_ERROR          (-1)
#define BYTES_TO_BITS            8U
#define U4_MAXNUM                0x000F                //Maximum value of 4 bits
#define U8_MAXNUM                0x00FF                //Maximum value of uint8_t/8 bits
#define U16_MAXNUM               0xFFFF                //Maximum value of uint16_t/16 bits
#define U32_MAXNUM               0xFFFFFFFF            //Maximum value of uint32_t/32 bits
//#define U64_MAXNUM               0xFFFFFFFFFFFFFFFF   //Maximum value of uint64_t/64 bits
#define HIGHEST_BIT_U16          0x7FFF                //Get highest bit in uint16_t/16 bits data
#define U16_NUM_ONE              0x0001
#define NUM_DECIMAL              10
#define NUM_HEX                  16

//ASCII values defines
#define ASCII_HT                9                    //"␉"
#define ASCII_LF                0x0A                 //10, Line Feed or LF
#define ASCII_FF                12                   //"␌"
#define ASCII_CR                0x0D                 //13, Carriage Return or CR
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
#define ASCII_UPPER_TO_LOWER    32U                  //Uppercase to lowercase
#define ASCII_LOWER_TO_UPPER    32U                  //Lowercase to uppercase

//Version define
#define PRODUCT_VERSION         0.4                     //Current version
//#define IPFILTER_VERSION     0.4                     //Current version of ipfilter file
//#define HOSTS_VERSION        0.4                     //Current version of hosts file

//Compare addresses own defines
#define ADDRESS_COMPARE_LESS      1U
#define ADDRESS_COMPARE_EQUAL     2U
#define ADDRESS_COMPARE_GREATER   3U

//Length defines
#define BOM_UTF_8_LENGTH               3U                                       //Length of UTF-8 BOM
#define BOM_UTF_16_LENGTH              2U                                       //Length of UTF-16 BOM
#define BOM_UTF_32_LENGTH              4U                                       //Length of UTF-32 BOM
#define FILE_BUFFER_SIZE               4096U                                    //Maximum size of file buffer
#define DEFAULT_FILE_MAXSIZE           4294967296U                              //Maximum size of whole reading file(4GB/4294967296 bytes).
#define DEFAULT_LOG_MAXSIZE            8388608U                                 //Maximum size of whole log file(8MB/8388608 bytes).
#define DEFAULT_LOG_MINSIZE            4096U                                    //Minimum size of whole log file(4KB/4096 bytes).
#define PACKET_MAXSIZE                 1512U                                    //Maximum size of packets(1500 bytes maximum payload length + 8 bytes Ethernet header + 4 bytes FCS), Standard MTU of Ethernet network
#define LARGE_PACKET_MAXSIZE           4096U                                    //Maximum size of packets(4KB/4096 bytes) of TCP protocol
#define BUFFER_RING_MAXNUM             64U                                      //Maximum packet buffer number
#define ADDR_STRING_MAXSIZE            64U                                      //Maximum size of addresses(IPv4/IPv6) words
#define ICMP_PADDING_MAXSIZE           1484U                                    //Length of ICMP padding data must between 18 bytes and 1464 bytes(Ethernet MTU - IPv4 Standard Header - ICMP Header).
#define MULTI_REQUEST_TIMES_MAXNUM     16U                                      //Maximum times of multi requesting.
#define QUEUE_MAXLEN                   64U                                      //Maximum length of queue
#define QUEUE_PARTNUM                  4U                                       //Parts of queues(00: IPv6/UDP, 01: IPv4/UDP, 02: IPv6/TCP, 03: IPv4/TCP)
#define ALTERNATE_SERVERNUM            12U                                      //Alternate switching of Main(00: TCP/IPv6, 01: TCP/IPv4, 02: UDP/IPv6, 03: UDP/IPv4), Local(04: TCP/IPv6, 05: TCP/IPv4, 06: UDP/IPv6, 07: UDP/IPv4), DNSCurve(08: TCP/IPv6, 09: TCP/IPv4, 10: UDP/IPv6, 11: UDP/IPv4)
#define DOMAIN_MAXSIZE                 256U                                     //Maximum size of whole level domain is 256 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_DATA_MAXSIZE            253U                                     //Maximum data length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_LEVEL_DATA_MAXSIZE      63U                                      //Domain length is between 3 and 63(Labels must be 63 characters/bytes or less, Section 2.3.1 in RFC 1035).
#define DOMAIN_MINSIZE                 2U                                       //Minimum size of whole level domain is 3 bytes(Section 2.3.1 in RFC 1035).
#define DNS_PACKET_MINSIZE             (sizeof(dns_hdr) + 4U + sizeof(dns_qry)) //Minimum DNS packet size(DNS Header + Minimum Domain + DNS Query)

//Code defines
#define QUERY_SERVICE_CONFIG_BUFFER_MAXSIZE   8192U      //Buffer maximum size of QueryServiceConfig() is 8KB/8192 Bytes.
#define SYSTEM_SOCKET                         UINT_PTR   //System Socket defined(WinSock2.h), not the same in x86(unsigned int) and x64(unsigned __int64) platform, which define in WinSock2.h file.
#define PCAP_COMPILE_OPTIMIZE                 1U         //Pcap optimization on the resulting code is performed.
#define PCAP_OFFLINE_EOF_ERROR                (-2)       //Pcap EOF was reached reading from an offline capture.
#define SHA3_512_SIZE                         64U        //SHA3-512 instance as specified in the FIPS 202 draft in April 2014(http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf), 512 bits/64 bytes.
#define CHECKSUM_SUCCESS                      0          //Result of getting correct checksums.
#define DYNAMIC_MIN_PORT                      1024U      //Well-known port is from 1 to 1023.

//Time defines
#define LOOP_MAX_TIMES                     8U        //Maximum of loop times, 8 times
#define LOOP_INTERVAL_TIME                 10U       //Loop interval time, 10 ms
#define STANDARD_TIMEOUT                   1000U     //Standard timeout, 1000 ms(1 second)
#define SECOND_TO_MILLISECOND              1000U     //1000 milliseconds(1 second)
#define UPDATESERVICE_TIME                 3U        //Update service timeout, 3 seconds
//#define PCAP_FINALLDEVS_RETRY_TIME         90U       //Retry to get device list in 15 minutes(90*10 seconds).
#define PCAP_DEVICESRECHECK_TIME           10U       //Time between every WinPcap/LibPcap devices recheck, 10 seconds
#define PCAP_CAPTURE_TIMEOUT               250U      //Pcap read timeout, 250 ms
#define SOCKET_TIMEOUT_MIN                 500U      //The shortset socket timeout, 500 ms
#define DEFAULT_RELIABLE_SOCKET_TIMEOUT    3000U     //Default timeout of reliable sockets(Such as TCP, 3 seconds/3000ms)
#define DEFAULT_UNRELIABLE_SOCKET_TIMEOUT  2000U     //Default timeout of unreliable sockets(Such as ICMP/ICMPv6/UDP, 2 seconds/2000ms)
#define DEFAULT_FILEREFRESH_TIME           5U        //Default time between files auto-refreshing, 5 seconds
#define DEFAULT_ICMPTEST_TIME              5U        //Default time between ICMP Test, 5 seconds
#define DEFAULT_DOMAINTEST_INTERVAL_TIME   900U      //Default Domain Test time between every sending, 15 minutes(900 seconds)
#define DEFAULT_ALTERNATE_TIMES            5U        //Default times of requesting timeout, 5 times
#define DEFAULT_ALTERNATE_RANGE            10U       //Default time of checking timeout, 10 seconds
#define DEFAULT_ALTERNATERESET_TIME        180U      //Default time to reset switching of alternate servers, 180 seconds
#define DEFAULT_HOSTS_TTL                  900U      //Default Hosts DNS TTL, 15 minutes(900 seconds)
#define DEFAULT_DNSCURVE_RECHECK_TIME      3600U     //Default DNSCurve keys recheck time, 1 hour(3600 seconds)
#define SHORTEST_DOMAINTEST_INTERVAL_TIME  5000U     //The shortset Domain Test time between every sending, 5 seconds(5000 ms)
#define SHORTEST_DNSCURVE_RECHECK_TIME     10U       //The shortset DNSCurve keys recheck time, 10 seconds
#define SENDING_INTERVAL_TIME              5U        //Time between every sending, 5 seconds
#define SENDING_ONCE_INTERVAL_TIMES        3U        //Repeat 3 times between every sending.

//Data defines
#define DEFAULT_LOCAL_SERVICENAME             L"PcapDNSProxyService"                                                                                                                        //Default service name of system
#define DEFAULT_LOCAL_SERVERNAME              ("pcap-dnsproxy.localhost.server")                                                                                                            //Default Local DNS server name
#define DEFAULT_PADDINGDATA                   ("abcdefghijklmnopqrstuvwabcdefghi")                                                                                                          //ICMP padding data(Microsoft Windows Ping)
#define RFC_DOMAIN_TABLE                      (".-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")                                                                          //Preferred name syntax(Section 2.3.1 in RFC 1035)
#define DNSCURVE_TEST_NONCE                   0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23   //DNSCurve Test Nonce, 0x00 - 0x23(ASCII)
#define DEFAULT_SEQUENCE                      0x0001                                                                                                                                        //Default sequence of protocol
#define DNS_PACKET_QUERY_LOCATE(Buffer)       (sizeof(dns_hdr) + CheckDNSQueryNameLength(Buffer + sizeof(dns_hdr)) + 1U)                                                                    //Location of beginning of DNS Query
#define DNS_TCP_PACKET_QUERY_LOCATE(Buffer)   (sizeof(tcp_dns_hdr) + CheckDNSQueryNameLength(Buffer + sizeof(tcp_dns_hdr)) + 1U)
#define DNS_PACKET_RR_LOCATE(Buffer)          (sizeof(dns_hdr) + CheckDNSQueryNameLength(Buffer + sizeof(dns_hdr)) + 1U + sizeof(dns_qry))                                                  //Location of beginning of DNS Resource Records

//Error Type defines
#define LOG_ERROR_SYSTEM     1U                      // 01: System Error
#define LOG_ERROR_PARAMETER  2U                      // 02: Parameter Error
#define LOG_ERROR_IPFILTER   3U                      // 03: IPFilter Error
#define LOG_ERROR_HOSTS      4U                      // 04: Hosts Error
#define LOG_ERROR_WINSOCK    5U                      // 05: Winsock Error
#define LOG_ERROR_WINPCAP    6U                      // 06: WinPcap Error
#define LOG_ERROR_DNSCURVE   7U                      // 07: DNSCurve Error

//Running Status level defines
#define LOG_STATUS_CLOSED    0U
#define LOG_STATUS_LEVEL1    1U
#define LOG_STATUS_LEVEL2    2U
#define LOG_STATUS_LEVEL3    3U

//Codes and types defines
#define LISTEN_IPV4                    0
#define LISTEN_IPV6                    1U
#define LISTEN_IPV4_IPV6               2U
#define LISTEN_PROXYMODE               0
#define LISTEN_PRIVATEMODE             1U 
#define LISTEN_SERVERMODE              2U
#define LISTEN_CUSTOMMODE              3U
#define REQUEST_UDPMODE                0
#define REQUEST_TCPMODE                1U
#define HOSTS_NORMAL                   0
#define HOSTS_WHITE                    1U
#define HOSTS_LOCAL                    2U
#define HOSTS_BANNED                   3U
#define CACHE_TIMER                    1U
#define CACHE_QUEUE                    2U
#define DNSCURVE_REQUEST_UDPMODE       0
#define DNSCURVE_REQUEST_TCPMODE       1U

//Server type defines
#define DNSCURVE_MAINIPV6              0             //DNSCurve Main(IPv6)
#define DNSCURVE_MAINIPV4              1U            //DNSCurve Main(IPv4)
#define DNSCURVE_ALTERNATEIPV6         2U            //DNSCurve Alternate(IPv6)
#define DNSCURVE_ALTERNATEIPV4         3U            //DNSCurve Alternate(IPv4)

//Structure defines
//Socket Data structure
typedef struct _socket_data_
{
	SYSTEM_SOCKET            Socket;
	sockaddr_storage         SockAddr;
	int                      AddrLen;
}SOCKET_Data, SOCKET_DATA;

//File Data structure
typedef struct _file_data_
{
	std::wstring                       FileName;
	bool                               HashAvailable;
	std::shared_ptr<BitSequence>       HashResult;
}FileData, FILE_DATA;

//DNS Server Data structure
typedef struct _dns_server_data_
{
	union _address_data_ {
		sockaddr_storage     Storage;
		sockaddr_in          IPv4;
		sockaddr_in6         IPv6;
	}AddressData;
	union _hoplimit_data_ {
		uint8_t              TTL;
		uint8_t              HopLimit;
	}HopLimitData;
}DNSServerData, DNS_SERVER_DATA;

//DNS Cache structure
typedef struct _dnscache_data_
{
	std::string              Domain;
	std::shared_ptr<char>    Response;
	uint16_t                 Type;
	size_t                   Length;
	size_t                   ClearTime;
}DNSCacheData, DNSCACHE_DATA;

//Address Prefix Block structure
typedef struct _address_prefix_block_
{
	size_t                   FileIndex;
	union _address_data_ {
		sockaddr_storage     Storage;
		sockaddr_in          IPv4;
		sockaddr_in6         IPv6;
	}AddressData;
	size_t Prefix;
}AddressPrefixBlock, ADDRESS_PREFIX_BLOCK;

/* Old version(2014-12-23)
//TCP Request Multithreading Parameter structure
typedef struct _tcpudp_complete_request_multithread_parameter_
{
	PSTR                     Send;
	size_t                   SendSize;
	PSTR                     Recv;
	size_t                   RecvSize;
	SOCKET_DATA              TargetData;
	size_t                   ServerIndex;
	size_t                   ReturnValue;
}TCPUDPCompleteRequestMultithreadParameter, TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER;

//UDP Request Multithreading Parameter structure
typedef struct _udp_request_multithread_parameter_
{
	PSTR                     Send;
	size_t                   Length;
	SOCKET_DATA              TargetData;
	size_t                   Index;
	size_t                   ServerIndex;
}UDPRequestMultithreadParameter, UDP_REQUEST_MULTITHREAD_PARAMETER;
*/

//DNSCurve Server Data structure
typedef struct _dnscurve_server_data_
{
	union _address_data_ {
		sockaddr_storage     Storage;
		sockaddr_in          IPv4;
		sockaddr_in6         IPv6;
	}AddressData;
	PSTR                     ProviderName;           //Server Provider Name
	PUINT8                   PrecomputationKey;      //DNSCurve Precomputation Keys
	PUINT8                   ServerPublicKey;        //Server Public Keys
	PUINT8                   ServerFingerprint;      //Server Fingerprints
	PSTR                     ReceiveMagicNumber;     //Receive Magic Number(Same from server receive)
	PSTR                     SendMagicNumber;        //Server Magic Number(Send to server)
}DNSCurveServerData, DNSCURVE_SERVER_DATA;

/* Old version(2015-01-13)
//DNSCurve TCP Request Multithreading Parameter structure
typedef struct _dnscurve_request_multithread_parameter_
{
	PSTR                     Send;
	size_t                   SendSize;
	PSTR                     Recv;
	size_t                   RecvSize;
	SOCKET_DATA              TargetData;
	bool                     Alternate;
	bool                     Encryption;
	size_t                   ReturnValue;
}DNSCurveRequestMultithreadParameter, DNSCURVE_REQUEST_MULTITHREAD_PARAMETER;
*/

//Class defines
//Configuration class
class ConfigurationTable {
public:
// Parameters from configure files
//[Base] block
	double                           Version;
	size_t                           FileRefreshTime;
	bool                             FileHash;
//[Log] block
	bool                             PrintError;
	size_t                           PrintStatus;
	size_t                           LogMaxSize;
//[DNS] block
	size_t                           RequestMode;
	bool                             HostsOnly;
	bool                             LocalMain;
	bool                             LocalRouting;
	size_t                           CacheType;
	size_t                           CacheParameter;
	uint32_t                         HostsDefaultTTL;
//[Listen] block
	bool                             PcapCapture;
	size_t                           OperationMode;
	size_t                           ListenProtocol;
	uint16_t                         ListenPort;
	bool                             IPFilterType;
	size_t                           IPFilterLevel;
	bool                             AcceptType;
//[Addresses] block
	struct _dns_target_ {
		DNSServerData                IPv4;
		DNSServerData                Alternate_IPv4;
		DNSServerData                IPv6;
		DNSServerData                Alternate_IPv6;
		DNSServerData                Local_IPv4;
		DNSServerData                Alternate_Local_IPv4;
		DNSServerData                Local_IPv6;
		DNSServerData                Alternate_Local_IPv6;
		std::vector<DNSServerData>   *IPv4_Multi;
		std::vector<DNSServerData>   *IPv6_Multi;
	}DNSTarget;
//[Values] block
	size_t                           EDNS0PayloadSize;
	uint8_t                          HopLimitFluctuation;
	uint16_t                         ICMPID;
	uint16_t                         ICMPSequence;
	size_t                           ICMPSpeed;
	//[Data] block(A part)
	PSTR                             ICMPPaddingData;
	size_t                           ICMPPaddingDataLength;
	PSTR                             DomainTestData;
	uint16_t                         DomainTestID;
	size_t                           DomainTestSpeed;
	size_t                           AlternateTimes;
	size_t                           AlternateTimeRange;
	size_t                           AlternateResetTime;
	size_t                           MultiRequestTimes;
//[Switches] block
	bool                             DomainCaseConversion;
	bool                             CompressionPointerMutation;
	bool                             CPMPointerToHeader;
	bool                             CPMPointerToRR;
	bool                             CPMPointerToAdditional;
	bool                             EDNS0Label;
	bool                             DNSSECRequest;
	bool                             AlternateMultiRequest;
	bool                             IPv4DataCheck;
	bool                             TCPDataCheck;
	bool                             DNSDataCheck;
	bool                             Blacklist;
//[Data] block(B part)
	std::string                      *LocalFQDNString;
	PSTR                             LocalFQDN;
	size_t                           LocalFQDNLength;
	PSTR                             LocalServerResponse;
	size_t                           LocalServerResponseLength;
//[DNSCurve/DNSCrypt] block
	bool                             DNSCurve;

// Global parameters from status
//Global block
	bool                             Console;
	SYSTEM_SOCKET                    LocalSocket[QUEUE_PARTNUM];
	std::default_random_engine       *RamdomEngine;
	std::vector<std::wstring>        *Path;
	std::vector<std::wstring>        *HostsFileList;
	std::vector<std::wstring>        *IPFilterFileList;
	std::wstring                     *ErrorLogPath;
	std::wstring                     *RunningLogPath;
	int                              ReliableSocketTimeout;
	int                              UnreliableSocketTimeout;
	PSTR                             DomainTable;
	PSTR                             LocalAddress[QUEUE_PARTNUM / 2U];
	size_t                           LocalAddressLength[QUEUE_PARTNUM / 2U];
	std::vector<std::string>         *LocalAddressPTR[QUEUE_PARTNUM / 2U];
	std::vector<uint16_t>            *AcceptTypeList;

//IPv6 tunnels support block
	bool                             Tunnel_IPv6;
//	std::vector<in_addr>             Tunnel_Teredo;          //Teredo address list
//	bool                             Tunnel_ISATAP;          //6to4, ISATAP and others which using IPv4 Protocol 41

	::ConfigurationTable(void);
	~ConfigurationTable(void);
};

//Hosts lists class
class HostsTable {
public:
	size_t                   FileIndex;
	size_t                   Type;
	uint16_t                 Protocol;
	size_t                   Length;
	std::shared_ptr<char>    Response;
	std::regex               Pattern;
	std::string              PatternString;

	::HostsTable(void);
};

//IP(v4/v6) addresses ranges class
class AddressRange {
public:
	size_t                   FileIndex;
	sockaddr_storage         Begin;
	sockaddr_storage         End;
	size_t                   Level;

	::AddressRange(void);
};

//Blacklist of results class
class ResultBlacklistTable {
public:
	size_t                      FileIndex;
	std::vector<AddressRange>   Addresses;
	std::regex                  Pattern;
	std::string                 PatternString;
};

//System and Request port list class
class PortTable {
public:
	SOCKET_DATA              *RecvData;                                //System receive sockets/Addresses records
	std::vector<SOCKET_DATA> SendData[QUEUE_MAXLEN * QUEUE_PARTNUM];   //Request ports records

	::PortTable(void);
	~PortTable(void);
};

//Alternate swap table class
class AlternateSwapTable {
public:
	bool                     IsSwap[ALTERNATE_SERVERNUM];
	size_t                   TimeoutTimes[ALTERNATE_SERVERNUM];
	size_t                   *PcapAlternateTimeout;

	::AlternateSwapTable(void);
	~AlternateSwapTable(void);
};

//DNSCurve Configuration class
class DNSCurveConfigurationTable {
public:
//[DNSCurve] block
	size_t                   DNSCurvePayloadSize;
	size_t                   DNSCurveMode;
	bool                     IsEncryption;
	bool                     IsEncryptionOnly;
	size_t                   KeyRecheckTime;
//[DNSCurve Addresses]
	PUINT8                   Client_PublicKey;
	PUINT8                   Client_SecretKey;
	struct _dnscurve_target_ {
		DNSCurveServerData   IPv4;
		DNSCurveServerData   Alternate_IPv4;
		DNSCurveServerData   IPv6;
		DNSCurveServerData   Alternate_IPv6;
	}DNSCurveTarget;

	::DNSCurveConfigurationTable(void);
	~DNSCurveConfigurationTable(void);
};

//PrintLog.cpp
size_t __fastcall PrintError(const size_t ErrType, const PWSTR Message, const SSIZE_T ErrCode, const PWSTR FileName, const size_t Line);
size_t __fastcall PrintStatus(const PWSTR Message);
size_t __fastcall PrintParameterList(void);

//Protocol.cpp
bool __fastcall CheckEmptyBuffer(const void *Buffer, const size_t Length);
//uint64_t __fastcall hton64(const uint64_t Val);
//uint64_t __fastcall ntoh64(const uint64_t Val);
size_t __fastcall CaseConvert(bool IsLowerUpper, const PSTR Buffer, const size_t Length);
size_t __fastcall AddressStringToBinary(const PSTR AddrString, void *OriginalAddr, const uint16_t Protocol, SSIZE_T &ErrCode);
PADDRINFOA __fastcall GetLocalAddressList(const uint16_t Protocol);
size_t __fastcall GetLocalAddressInformation(const uint16_t Protocol);
uint16_t __fastcall ServiceNameToHex(const PSTR Buffer);
uint16_t __fastcall DNSTypeNameToHex(const PSTR Buffer);
bool __fastcall CheckSpecialAddress(const void *Addr, const uint16_t Protocol, const PSTR Domain);
bool __fastcall CheckAddressRouting(const void *Addr, const uint16_t Protocol);
bool __fastcall CustomModeFilter(const void *OriginalAddr, const uint16_t Protocol);
//uint32_t __fastcall GetFCS(const PUINT8 Buffer, const size_t Length);
uint16_t __fastcall GetChecksum(const uint16_t *Buffer, const size_t Length);
uint16_t __fastcall ICMPv6Checksum(const PUINT8 Buffer, const size_t Length, const in6_addr Destination, const in6_addr Source);
uint16_t __fastcall TCPUDPChecksum(const PUINT8 Buffer, const size_t Length, const uint16_t NetworkLayer, const uint16_t TransportLayer);
size_t __fastcall AddLengthToTCPDNSHeader(PSTR Buffer, const size_t RecvLen, const size_t MaxLen);
size_t __fastcall CharToDNSQuery(const PSTR FName, PSTR TName);
size_t __fastcall CheckDNSQueryNameLength(const PSTR Buffer);
size_t __fastcall DNSQueryToChar(const PSTR TName, PSTR FName /* , uint16_t &Truncated */);
BOOL WINAPI FlushDNSResolverCache(void);
void __fastcall MakeRamdomDomain(PSTR Buffer);
void __fastcall MakeDomainCaseConversion(PSTR Buffer);
size_t __fastcall MakeCompressionPointerMutation(const PSTR Buffer, const size_t Length);
bool __fastcall CheckResponseData(const PSTR Buffer, const size_t Length, bool IsLocal, bool *MarkHopLimit);

//Sort.cpp
size_t __fastcall CompareAddresses(const void *OriginalAddrBegin, const void *OriginalAddrEnd, const uint16_t Protocol);
bool __fastcall SortResultBlacklistALL(const ResultBlacklistTable& ResultBlacklistTableIter);
bool __fastcall SortHostsListBANNED(const HostsTable& HostsTableIter);
bool __fastcall SortHostsListWHITE(const HostsTable& HostsTableIter);
bool __fastcall SortHostsListNORMAL(const HostsTable& HostsTableIter);

//Configuration.cpp
inline bool __fastcall ReadText(const FILE *Input, const size_t InputType, const size_t FileIndex);
inline size_t __fastcall ReadMultiLineComments(const PSTR Buffer, std::string &Data, bool &LabelComments);
size_t __fastcall ReadParameter(void);
size_t __fastcall ReadParameterData(const PSTR Buffer, const size_t FileIndex, const size_t Line, bool &LabelComments);
size_t __fastcall ReadIPFilter(void);
size_t __fastcall ReadIPFilterData(const PSTR Buffer, const size_t FileIndex, const size_t Line, size_t &LabelType, bool &LabelComments);
inline size_t __fastcall ReadBlacklistData(std::string Data, const size_t FileIndex, const size_t Line);
inline size_t __fastcall ReadLocalRoutingData(std::string Data, const size_t FileIndex, const size_t Line);
inline size_t __fastcall ReadMainIPFilterData(std::string Data, const size_t FileIndex, const size_t Line);
size_t __fastcall ReadHosts(void);
size_t __fastcall ReadHostsData(const PSTR Buffer, const size_t FileIndex, const size_t Line, size_t &LabelType, bool &LabelComments);
inline size_t __fastcall ReadWhitelistAndBannedData(std::string Data, const size_t FileIndex, const size_t Line, const size_t LabelType);
inline size_t __fastcall ReadLocalHostsData(std::string Data, const size_t FileIndex, const size_t Line);
inline size_t __fastcall ReadMainHostsData(std::string Data, const size_t FileIndex, const size_t Line);

//Service.cpp
size_t WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
size_t WINAPI ServiceControl(const DWORD dwControlCode);
BOOL WINAPI ExecuteService(void);
void WINAPI TerminateService(void);
DWORD WINAPI ServiceProc(LPVOID lpParameter);
BOOL WINAPI UpdateServiceStatus(const DWORD dwCurrentState, const DWORD dwWin32ExitCode, const DWORD dwServiceSpecificExitCode, const DWORD dwCheckPoint, const DWORD dwWaitHint);

//Main.cpp
inline size_t __fastcall FileNameInit(const PWSTR OriginalPath);
inline size_t __fastcall FirewallTest(const uint16_t Protocol);

//Monitor.cpp
size_t __fastcall MonitorInit(void);
size_t __fastcall UDPMonitor(const SOCKET_DATA LocalhostData);
size_t __fastcall TCPMonitor(const SOCKET_DATA LocalhostData);
size_t __fastcall TCPReceiveProcess(const SOCKET_DATA TargetData, const size_t ListIndex);
inline void __fastcall AlternateServerMonitor(void);
void __fastcall DNSCacheTimerMonitor(void);

//DNSCurve.cpp
bool __fastcall VerifyKeypair(const PUINT8 PublicKey, const PUINT8 SecretKey);
size_t __fastcall DNSCurveInit(void);
inline size_t LocalSignatureRequest(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
inline bool __fastcall DNSCurveTCPSignatureRequest(const uint16_t NetworkLayer, const bool IsAlternate);
inline bool __fastcall DNSCurveUDPSignatureRequest(const uint16_t NetworkLayer, const bool IsAlternate);
bool __fastcall GetSignatureData(const PSTR Buffer, const size_t ServerType);
size_t __fastcall DNSCurveTCPRequest(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool IsAlternate);
size_t __fastcall DNSCurveTCPRequestMulti(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool IsAlternate);
size_t __fastcall DNSCurveUDPRequest(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool IsAlternate);
size_t __fastcall DNSCurveUDPRequestMulti(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool IsAlternate);

//Process.cpp
size_t __fastcall EnterRequestProcess(const PSTR OriginalSend, const size_t Length, const SOCKET_DATA TargetData, const uint16_t Protocol, const size_t ListIndex);
inline size_t __fastcall CheckHosts(PSTR OriginalRequest, const size_t Length, PSTR Result, const size_t ResultSize, bool &IsLocal);
inline size_t __fastcall LocalRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData);
inline size_t __fastcall DirectRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData);
inline size_t __fastcall DNSCurveRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData);
inline size_t __fastcall TCPRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData);
inline size_t __fastcall UDPRequestProcess(const PSTR OriginalSend, const size_t SendSize, const uint16_t Protocol, const SOCKET_DATA TargetData, const size_t ListIndex);
inline size_t __fastcall SendToRequester(PSTR RecvBuffer, const size_t RecvSize, const uint16_t Protocol, const SOCKET_DATA TargetData);
size_t __fastcall MarkDomainCache(const PSTR Buffer, const size_t Length);

//Captrue.cpp
size_t __fastcall CaptureInit(void);
inline void __fastcall FilterRulesInit(std::string &FilterRules);
size_t __fastcall Capture(const pcap_if *pDrive, const bool IsList);
size_t __fastcall NetworkLayer(const PSTR Recv, const size_t Length, const uint16_t Protocol);
inline bool __fastcall ICMPCheck(const PSTR Buffer, const size_t Length, const uint16_t Protocol);
inline bool __fastcall TCPCheck(const PSTR Buffer);
inline size_t __fastcall DNSMethod(const PSTR Recv, const size_t Length, const uint16_t Protocol);
inline size_t __fastcall MatchPortToSend(const PSTR Buffer, const size_t Length, const uint16_t Port);

//Request.cpp
size_t __fastcall DomainTestRequest(const uint16_t Protocol);
size_t __fastcall ICMPEcho(void);
size_t __fastcall ICMPv6Echo(void);
size_t __fastcall TCPRequest(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool IsLocal, const bool IsAlternate);
size_t __fastcall TCPRequestMulti(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool IsAlternate);
size_t __fastcall UDPRequest(const PSTR OriginalSend, const size_t Length, const SOCKET_DATA TargetData, const size_t ListIndex, const bool IsAlternate);
size_t __fastcall UDPRequestMulti(const PSTR OriginalSend, const size_t Length, const SOCKET_DATA TargetData, const size_t ListIndex, const bool IsAlternate);
size_t __fastcall UDPCompleteRequest(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool IsLocal, const bool IsAlternate);
size_t __fastcall UDPCompleteRequestMulti(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool IsAlternate);

//Console.cpp
BOOL WINAPI CtrlHandler(const DWORD fdwCtrlType);
