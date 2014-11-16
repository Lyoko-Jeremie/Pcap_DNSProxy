// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
// Copyright (C) 2012-2014 Chengr28
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
#define U8_MAXNUM            0x00FF                  //Maximum value of uint8_t/8 bits
#define U16_MAXNUM           0xFFFF                  //Maximum value of uint16_t/16 bits
//#define U32_MAXNUM           0xFFFFFFFF              //Maximum value of uint32_t/32 bits
//#define U64_MAXNUM           0xFFFFFFFFFFFFFFFF      //Maximum value of uint64_t/64 bits
#define U16_NUM_1            0x0001
#define NUM_DECIMAL          10
#define NUM_HEX              16

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
#define ASCII_NINE              57                   //"9"
#define ASCII_COLON             58                   //":"
#define ASCII_AT                64                   //"@"
#define ASCII_UPPERCASE_A       65                   //"A"
#define ASCII_UPPERCASE_F       70                   //"F"
#define ASCII_BRACKETS_LEAD     91                   //"["
#define ASCII_BRACKETS_TRAIL    93                   //"]"
#define ASCII_ACCENT            96                   //"`"
#define ASCII_LOWERCASE_A       97                   //"a"
#define ASCII_LOWERCASE_F       102                   //"f"
#define ASCII_BRACES_LEAD       123                  //"{"
#define ASCII_VERTICAL          124                  //"|"

//Version define
#define INI_VERSION          0.4                     //Current version of configuration file
#define IPFILTER_VERSION     0.4                     //Current version of ipfilter file
#define HOSTS_VERSION        0.4                     //Current version of hosts file

//Length defines
//BOM length defines
#define BOM_UTF_8_LENGTH               3U            //Length of UTF-8 BOM
#define BOM_UTF_16_LENGTH              2U            //Length of UTF-16 BOM
#define BOM_UTF_32_LENGTH              4U            //Length of UTF-32 BOM
#define FILE_BUFFER_SIZE               4096U         //Maximum size of file buffer
#define DEFAULT_FILE_MAXSIZE           4294967296U   //Maximum size of whole reading file(4GB/4294967296 bytes).
#define DEFAULT_LOG_MAXSIZE            8388608U      //Maximum size of whole log file(8MB/8388608 bytes).
#define DEFAULT_LOG_MINSIZE            4096U         //Minimum size of whole log file(4KB/4096 bytes).
#define PACKET_MAXSIZE                 1512U         //Maximum size of packets(1500 bytes maximum payload length + 8 bytes Ethernet header + 4 bytes FCS), Standard MTU of Ethernet network
#define LARGE_PACKET_MAXSIZE           4096U         //Maximum size of packets(4KB/4096 bytes) of TCP protocol
#define BUFFER_RING_MAXNUM             64U           //Maximum packet buffer number
#define ADDR_STRING_MAXSIZE            64U           //Maximum size of addresses(IPv4/IPv6) words
#define ICMP_PADDING_MAXSIZE           1484U         //Length of ICMP padding data must between 18 bytes and 1464 bytes(Ethernet MTU - IPv4 Standard Header - ICMP Header).
#define MULTI_REQUEST_TIMES_MAXNUM     16U           //Maximum times of multi requesting.
#define QUEUE_MAXLEN                   64U           //Maximum length of queue
#define QUEUE_PARTNUM                  4U            //Parts of queues(00: IPv6/UDP, 01: IPv4/UDP, 02: IPv6/TCP, 03: IPv4/TCP)
#define ALTERNATE_SERVERNUM            12U           //Alternate switching of Main(00: TCP/IPv6, 01: TCP/IPv4, 02: UDP/IPv6, 03: UDP/IPv4), Local(04: TCP/IPv6, 05: TCP/IPv4, 06: UDP/IPv6, 07: UDP/IPv4), DNSCurve(08: TCP/IPv6, 09: TCP/IPv4, 10: UDP/IPv6, 11: UDP/IPv4)
#define DOMAIN_MAXSIZE                 256U          //Maximum size of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).

//Code defines
#define RETURN_ERROR                          -1
#define BYTES_TO_BITS                         8U
#define MBSTOWCS_NULLTERMINATE                -1         //MultiByteToWideChar() find null-terminate.
#define QUERY_SERVICE_CONFIG_BUFFER_MAXSIZE   8192U      //Buffer maximum size of QueryServiceConfig() is 8KB/8192 Bytes.
#define SYSTEM_SOCKET                         UINT_PTR   //System Socket defined(WinSock2.h), not the same in x86(unsigned int) and x64(unsigned __int64) platform, which define in WinSock2.h file.
#define SHA3_512_SIZE                         64U        //SHA3-512 instance as specified in the FIPS 202 draft in April 2014(http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf), 512 bits/64 bytes.
#define CHECKSUM_SUCCESS                      0          //Result of getting correct checksums.

//Time(s) defines
#define STANDARD_TIMEOUT                   1000U     //Standard timeout, 1000 ms(1 second)
#define SECOND_TO_MILLISECOND              1000U     //1000 milliseconds(1 second)
#define UPDATESERVICE_TIME                 3U        //Update service timeout, 3 seconds
//#define PCAP_FINALLDEVS_RETRY_TIME         90U       //Retry to get device list in 15 minutes(90*10 seconds).
#define PCAP_DEVICESRECHECK_TIME           10U       //Time between every WinPcap/LibPcap devices recheck, 10 seconds
#define PCAP_CAPTURE_TIMEOUT               250U      //Pcap read timeout, 250 ms
#define RELIABLE_SOCKET_TIMEOUT            5000U     //Timeout of reliable sockets(Such as TCP, 5 seconds/5000ms)
#define UNRELIABLE_SOCKET_TIMEOUT          2000U     //Timeout of unreliable sockets(Such as ICMP/ICMPv6/UDP, 2 seconds/2000ms)
#define DEFAULT_FILEREFRESH_TIME           5U        //Default time between file(s) auto-refreshing, 5 seconds
#define DEFAULT_ICMPTEST_TIME              5U        //Default time between ICMP Test, 5 seconds
#define DEFAULT_DOMAINTEST_INTERVAL_TIME   900U      //Default Domain Test time between every sending, 15 minutes(900 seconds)
#define DEFAULT_ALTERNATE_TIMES            5U        //Default times of requesting timeout, 5 times
#define DEFAULT_ALTERNATE_RANGE            10U       //Default time of checking timeout, 10 seconds
#define DEFAULT_ALTERNATERESET_TIME        180U      //Default time to reset switching of alternate servers, 180 seconds
#define DEFAULT_HOSTS_TTL                  900U      //Default Hosts DNS TTL, 15 minutes(900 seconds)
#define DEFAULT_DNSCURVE_RECHECK_TIME      3600U     //Default DNSCurve key(s) recheck time, 1 hour(3600 seconds)
#define SHORTEST_DOMAINTEST_INTERVAL_TIME  5000U     //The shortset Domain Test time between every sending, 5 seconds(5000 ms)
#define SHORTEST_DNSCURVE_RECHECK_TIME     10U       //The shortset DNSCurve key(s) recheck time, 10 seconds
#define SENDING_INTERVAL_TIME              5U        //Time between every sending, 5 seconds
#define SENDING_ONCE_INTERVAL_TIMES        3U        //Repeat 3 times between every sending.

//Data defines
#define DEFAULT_LOCAL_SERVICENAME   L"PcapDNSProxyService"                                                 //Default service name of system
#define DEFAULT_LOCAL_SERVERNAME    ("pcap-dnsproxy.localhost.server")                                     //Default Local DNS server name
#define DEFAULT_PADDINGDATA         ("abcdefghijklmnopqrstuvwabcdefghi")                                   //ICMP padding data(Microsoft Windows Ping)
#define RFC_DOMAIN_TABLE            (".-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")   //Preferred name syntax(Section 2.3.1 in RFC 1035)
#define DNSCURVE_TEST_NONCE         0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23 //DNSCurve Test Nonce, 0x00 - 0x23(ASCII)
#define DEFAULT_SEQUENCE            0x0001

//Error Type defines
#define LOG_ERROR_SYSTEM     1U                      // 01: System Error
#define LOG_ERROR_PARAMETER  2U                      // 02: Parameter Error
#define LOG_ERROR_IPFILTER   3U                      // 03: IPFilter Error
#define LOG_ERROR_HOSTS      4U                      // 04: Hosts Error
#define LOG_ERROR_WINSOCK    5U                      // 05: Winsock Error
#define LOG_ERROR_WINPCAP    6U                      // 06: WinPcap Error
#define LOG_ERROR_DNSCURVE   7U                      // 07: DNSCurve Error

//Running Status level defines
#define LOG_STATUS_CLOSED    0U                      //
#define LOG_STATUS_LEVEL1    1U                      //
#define LOG_STATUS_LEVEL2    2U                      //
#define LOG_STATUS_LEVEL3    3U                      //

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
//#define PREFERRED_SERVER               0             //Main
//#define ALTERNATE_SERVER               1U            //Alternate
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
typedef struct _file_data_ {
	bool                               Available;
	std::wstring                       FileName;
	std::shared_ptr<BitSequence>       Result;
}FileData, FILE_DATA;

//DNS Server Data structure
typedef struct _dns_server_data_ {
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
typedef struct _dnscache_data_ {
	std::string              Domain;
	std::shared_ptr<char>    Response;
	uint16_t                 Protocol;
	size_t                   Length;
	size_t                   Time;
}DNSCacheData, DNSCACHE_DATA;

//TCP Request Multithreading Parameter structure
typedef struct _tcpudp_complete_request_multithread_parameter_ {
	PSTR                     Send;
	size_t                   SendSize;
	PSTR                     Recv;
	size_t                   RecvSize;
	SOCKET_DATA              TargetData;
	size_t                   ServerIndex;
	size_t                   ReturnValue;
}TCPUDPCompleteRequestMultithreadParameter, TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER;

//UDP Request Multithreading Parameter structure
typedef struct _udp_request_multithread_parameter_ {
	PSTR                     Send;
	size_t                   Length;
	SOCKET_DATA              TargetData;
	size_t                   Index;
	size_t                   ServerIndex;
}UDPRequestMultithreadParameter, UDP_REQUEST_MULTITHREAD_PARAMETER;

//DNSCurve Server Data structure
typedef struct _dnscurve_server_data_ {
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

//Class defines
//DNSCurve TCP Request Multithreading Parameter structure
typedef struct _dnscurve_request_multithread_parameter_ {
	PSTR                     Send;
	size_t                   SendSize;
	PSTR                     Recv;
	size_t                   RecvSize;
	SOCKET_DATA              TargetData;
	bool                     Alternate;
	bool                     Encryption;
	size_t                   ReturnValue;
}DNSCurveRequestMultithreadParameter, DNSCURVE_REQUEST_MULTITHREAD_PARAMETER;

//Configuration class
class Configuration {
public:
// Parameters from configure files
//[Base] block
	double                   Version;
	size_t                   FileRefreshTime;
	bool                     FileHash;
//[Log] block
	bool                     PrintError;
	size_t                   PrintStatus;
	size_t                   LogMaxSize;
//[DNS] block
	size_t                   RquestMode;
	bool                     HostsOnly;
	bool                     LocalMain;
	size_t                   CacheType;
	size_t                   CacheParameter;
//[Listen] block
	bool                     PcapCapture;
	size_t                   OperationMode;
	size_t                   ListenProtocol;
	uint16_t                 ListenPort;
	struct _ipfilter_options_ {
		bool                 Type;
		size_t               IPFilterLevel;
	}IPFilterOptions;
	bool                     AcceptType;
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
	size_t                   EDNS0PayloadSize;
	uint8_t                  HopLimitFluctuation;
	struct _icmp_options_ {
		uint16_t             ICMPID;
		uint16_t             ICMPSequence;
		size_t               ICMPSpeed;
	//[Data] block(A part)
		PSTR                 PaddingData;
		size_t               PaddingDataLength;
	}ICMPOptions;
	struct _domaintest_options_ {
		PSTR                 DomainTestData;
		uint16_t             DomainTestID;
		size_t               DomainTestSpeed;
	}DomainTestOptions;
	struct _alternate_options_ {
		size_t               AlternateTimes;
		size_t               AlternateTimeRange;
		size_t               AlternateResetTime;
	}AlternateOptions;
	size_t                   MultiRequestTimes;
//[Switches] block
	bool                     DomainCaseConversion;
	bool                     CompressionPointerMutation;
	bool                     EDNS0Label;
	bool                     DNSSECRequest;
	bool                     AlternateMultiRequest;
	bool                     IPv4DataCheck;
	bool                     TCPDataCheck;
	bool                     DNSDataCheck;
	bool                     Blacklist;
//[Data] block(B part)
	struct _local_server_options_ {
		std::string          LocalFQDNString;
		PSTR                 LocalFQDN;
		size_t               LocalFQDNLength;
		PSTR                 LocalPTRResponse;
		size_t               LocalPTRResponseLength;
	}LocalServerOptions;
//[DNSCurve/DNSCrypt] block
	bool                     DNSCurve;

// Global parameters from states
//Global block
	bool                     Console;
	SYSTEM_SOCKET            LocalSocket[QUEUE_PARTNUM];
	std::wstring             *Path, *ErrorLogPath, *RunningLogPath;
	int                      ReliableSocketTimeout, UnreliableSocketTimeout;
	PSTR                     DomainTable;
	struct _local_address_options_ {
		PSTR                     LocalAddress[QUEUE_PARTNUM / 2U];
		size_t                   LocalAddressLength[QUEUE_PARTNUM / 2U];
		std::vector<std::string> LocalAddressPTR[QUEUE_PARTNUM / 2U];
	}LocalAddressOptions;
//Hosts file(s) block
	uint32_t                 HostsDefaultTTL;
//IPv6 tunnels support block
//	std::vector<in_addr>     Tunnel_Teredo;          //Teredo address list
//	bool                     Tunnel_IPv6;            //6to4, ISATAP and others which using IPv4 Protocol 41
	bool                     Tunnel_IPv6;

	::Configuration(void);
	~Configuration(void);
};

//Hosts lists class
class HostsTable {
public:
	size_t                   Type;
	uint16_t                 Protocol;
	size_t                   Length;
	std::shared_ptr<char>    Response;
	std::regex               Pattern;
	std::string              PatternString;

	HostsTable(void);
};

//IP(v4/v6) addresses ranges class
class AddressRange {
public:
	sockaddr_storage         Begin, End;
	size_t                   Level;

	AddressRange(void);
};

//Blacklist of results class
class ResultBlacklistTable {
public:
	std::vector<sockaddr_storage>         Addresses;
	std::regex                            Pattern;
	std::string                           PatternString;
};

//System&Request port list class
class PortTable {
public:
	std::vector<SOCKET_DATA> SendData[QUEUE_MAXLEN * QUEUE_PARTNUM];   //Request ports records
	SOCKET_DATA              *RecvData;                                //System receive sockets/Addresses records

	PortTable(void);
	~PortTable(void);
};

//Alternate swap table class
class AlternateSwapTable {
public:
	bool                     Swap[ALTERNATE_SERVERNUM];
	size_t                   TimeoutTimes[ALTERNATE_SERVERNUM];
	size_t                   *PcapAlternateTimeout;

	AlternateSwapTable(void);
	~AlternateSwapTable(void);
};

//DNSCurve Configuration class
class DNSCurveConfiguration {
public:
//[DNSCurve] block
	size_t                   DNSCurvePayloadSize;
	size_t                   DNSCurveMode;
	bool                     Encryption;
	bool                     EncryptionOnly;
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

	::DNSCurveConfiguration(void);
	~DNSCurveConfiguration(void);
};

//PrintLog.cpp
size_t __fastcall PrintError(const size_t Type, const PWSTR Message, const SSIZE_T ErrCode, const PWSTR FileName, const size_t Line);
size_t __fastcall PrintStatus( /* const size_t Level, */ const PWSTR Message /* , const PWSTR Message_B */ );
size_t __fastcall PrintParameterList(void);

//Protocol.cpp
bool __fastcall CheckEmptyBuffer(const void *Buffer, const size_t Length);
//uint64_t __fastcall hton64(const uint64_t Val);
//uint64_t __fastcall ntoh64(const uint64_t Val);
size_t __fastcall CaseConvert(bool LowerUpper, const PSTR Buffer, const size_t Length);
size_t __fastcall AddressStringToBinary(const PSTR AddrString, void *pAddr, const uint16_t Protocol, SSIZE_T &ErrCode);
PADDRINFOA __fastcall GetLocalAddressList(const uint16_t Protocol);
size_t __fastcall GetLocalAddressInformation(const uint16_t Protocol);
uint16_t __fastcall ServiceNameToPort(const PSTR Buffer);
uint16_t __fastcall DNSTypeNameToID(const PSTR Buffer);
bool __fastcall CheckSpecialAddress(const void *Addr, const uint16_t Protocol, const PSTR Domain);
bool __fastcall CustomModeFilter(const void *pAddr, const uint16_t Protocol);
//uint32_t __fastcall GetFCS(const PUINT8 Buffer, const size_t Length);
uint16_t __fastcall GetChecksum(const uint16_t *Buffer, const size_t Length);
uint16_t __fastcall ICMPv6Checksum(const PUINT8 Buffer, const size_t Length, const in6_addr Destination, const in6_addr Source);
uint16_t __fastcall TCPUDPChecksum(const PUINT8 Buffer, const size_t Length, const uint16_t NetworkLayer, const uint16_t TransportLayer);
size_t __fastcall AddLengthToTCPDNSHeader(PSTR Buffer, const size_t RecvLen, const size_t MaxLen);
size_t __fastcall CharToDNSQuery(const PSTR FName, PSTR TName);
size_t __fastcall DNSQueryToChar(const PSTR TName, PSTR FName);
BOOL WINAPI FlushDNSResolverCache(void);
void __fastcall MakeRamdomDomain(PSTR Domain);
void __fastcall DomainCaseConversion(PSTR Buffer);
void __fastcall MakeCompressionPointerMutation(const PSTR Buffer, const size_t Length);
bool __fastcall CheckDNSLastResult(const PSTR Buffer, const size_t Length);

//Configuration.cpp
inline bool __fastcall ReadText(const FILE *Input, const size_t InputType, const PWSTR FileName);
size_t __fastcall ReadParameter(void);
size_t __fastcall ReadParameterData(const PSTR Buffer, const PWSTR FileName, const size_t Line, bool &Comments);
size_t __fastcall ReadIPFilter(void);
size_t __fastcall ReadIPFilterData(const PSTR Buffer, const PWSTR FileName, const size_t Line, bool &Comments, bool &Blacklist, bool &TempStop);
size_t __fastcall ReadHosts(void);
size_t __fastcall ReadHostsData(const PSTR Buffer, const PWSTR FileName, const size_t Line, bool &Comments, bool &Local, bool &TempStop);
//inline bool __fastcall ReadNextLineType(const PSTR Buffer, const size_t Length, size_t &Encoding, size_t &NextLineType);
inline size_t __fastcall CompareAddresses(const void *vAddrBegin, const void *vAddrEnd, const uint16_t Protocol);
//inline size_t __fastcall HexToBinary(PUINT8 Binary, const PSTR Buffer, const size_t Length);

//Service.cpp
size_t WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
size_t WINAPI ServiceControl(const DWORD dwControlCode);
BOOL WINAPI ExecuteService(void);
void WINAPI TerminateService(void);
DWORD WINAPI ServiceProc(LPVOID lpParameter);
BOOL WINAPI UpdateServiceStatus(const DWORD dwCurrentState, const DWORD dwWin32ExitCode, const DWORD dwServiceSpecificExitCode, const DWORD dwCheckPoint, const DWORD dwWaitHint);

//Main.cpp
inline size_t __fastcall FileInit(const PWSTR wPath);
inline size_t __fastcall FirewallTest(const uint16_t Protocol);

//Monitor.cpp
size_t __fastcall MonitorInit(void);
size_t __fastcall UDPMonitor(const SOCKET_DATA LocalhostData);
size_t __fastcall TCPMonitor(const SOCKET_DATA LocalhostData);
size_t __fastcall TCPReceiveProcess(const SOCKET_DATA FunctionData, const size_t Index);
inline void __fastcall AlternateServerSwitcher(void);
void __fastcall DNSCacheTimerMonitor(const size_t CacheType);

//DNSCurve.cpp
bool __fastcall VerifyKeypair(const PUINT8 PublicKey, const PUINT8 SecretKey);
size_t __fastcall DNSCurveInit(void);
inline size_t LocalSignatureRequest(const PSTR Send, const size_t SendSize, PSTR Recv, const size_t RecvSize);
inline bool __fastcall DNSCurveTCPSignatureRequest(const uint16_t NetworkLayer, const bool Alternate);
inline bool __fastcall DNSCurveUDPSignatureRequest(const uint16_t NetworkLayer, const bool Alternate);
bool __fastcall GetSignatureData(const PSTR Buffer, const size_t ServerType);
size_t __fastcall DNSCurveTCPRequest(const PSTR Send, const size_t SendSize, PSTR Recv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool Alternate, const bool Encryption);
size_t __fastcall DNSCurveTCPRequestMulti(DNSCURVE_REQUEST_MULTITHREAD_PARAMETER &DNSCurveTCPRequestParameter, std::mutex &Mutex);
size_t __fastcall DNSCurveUDPRequest(const PSTR Send, const size_t SendSize, PSTR Recv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool Alternate, const bool Encryption);
size_t __fastcall DNSCurveUDPRequestMulti(DNSCURVE_REQUEST_MULTITHREAD_PARAMETER &DNSCurveTCPRequestParameter, std::mutex &Mutex);

//Process.cpp
size_t __fastcall RequestProcess(const PSTR Send, const size_t Length, const SOCKET_DATA FunctionData, const uint16_t Protocol, const size_t Index);
inline size_t __fastcall CheckHosts(PSTR Request, const size_t Length, PSTR Result, const size_t ResultSize, bool &Local);
inline size_t __fastcall LocalRequestProcess(const PSTR Send, const size_t SendSize, PSTR Recv, const uint16_t Protocol, const SOCKET_DATA FunctionData);
inline size_t __fastcall DirectRequestProcess(const PSTR Send, const size_t SendSize, PSTR Recv, const uint16_t Protocol, const SOCKET_DATA FunctionData);
inline size_t __fastcall DNSCurveRequestProcess(const PSTR Send, const size_t SendSize, PSTR Recv, const uint16_t Protocol, const SOCKET_DATA FunctionData);
inline size_t __fastcall TCPRequestProcess(const PSTR Send, const size_t SendSize, PSTR Recv, const uint16_t Protocol, const SOCKET_DATA FunctionData);
inline size_t __fastcall UDPRequestProcess(const PSTR Send, const size_t SendSize, const uint16_t Protocol, const SOCKET_DATA FunctionData, const size_t Index);
inline size_t __fastcall SendToRequester( /* const PSTR SendBuffer, const size_t SendSize, */ PSTR RecvBuffer, const size_t RecvSize, const uint16_t Protocol, const SOCKET_DATA TargetData);
size_t __fastcall MarkDomainCache(const PSTR Buffer, const size_t Length);

//Captrue.cpp
size_t __fastcall CaptureInit(void);
inline void __fastcall FilterRulesInit(std::string &FilterRules);
size_t __fastcall Capture(const pcap_if *pDrive, const bool List);
size_t __fastcall NetworkLayer(const PSTR Recv, const size_t Length, const uint16_t Protocol);
inline bool __fastcall ICMPCheck(const PSTR Buffer, const size_t Length, const uint16_t Protocol);
inline bool __fastcall TCPCheck(const PSTR Buffer);
inline bool __fastcall DTDNSDCheck(const PSTR Buffer, /* const size_t Length, */ bool &SignHopLimit);
inline size_t __fastcall DNSMethod(const PSTR Recv, const size_t Length, const uint16_t Protocol);
inline size_t __fastcall MatchPortToSend(const PSTR Buffer, const size_t Length, const uint16_t Port);

//Request.cpp
size_t __fastcall DomainTestRequest(const uint16_t Protocol);
size_t __fastcall ICMPEcho(void);
size_t __fastcall ICMPv6Echo(void);
size_t __fastcall TCPRequest(const PSTR Send, const size_t SendSize, PSTR Recv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool Local, const bool Alternate);
size_t __fastcall TCPRequestMulti(TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER &TCPRequestParameter, std::mutex &Mutex);
size_t __fastcall UDPRequest(const PSTR Send, const size_t Length, const SOCKET_DATA TargetData, const size_t Index, const bool Alternate);
size_t __fastcall UDPRequestMulti(UDP_REQUEST_MULTITHREAD_PARAMETER UDPRequestParameter);
size_t __fastcall UDPCompleteRequest(const PSTR Send, const size_t SendSize, PSTR Recv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool Local, const bool Alternate);
size_t __fastcall UDPCompleteRequestMulti(TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER &UDPRequestParameter, std::mutex &Mutex);

//Console.cpp
BOOL WINAPI CtrlHandler(const DWORD fdwCtrlType);
