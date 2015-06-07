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


#include "Base.h"

//Base defines
//Read Texts input and Label types defines
#define READ_TEXT_PARAMETER                   0
#define READ_TEXT_HOSTS                       1U
#define READ_TEXT_IPFILTER                    2U
#define LABEL_STOP                            1U
#define LABEL_IPFILTER                        2U
#define LABEL_IPFILTER_BLACKLIST              3U
#define LABEL_IPFILTER_LOCAL_ROUTING          4U
#define LABEL_HOSTS                           5U
#define LABEL_HOSTS_TYPE_LOCAL                6U
#define LABEL_HOSTS_TYPE_WHITELIST            7U
#define LABEL_HOSTS_TYPE_BANNED               8U
#define LABEL_HOSTS_TYPE_BANNED_TYPE          9U
#define LABEL_HOSTS_ADDRESS                   10U

//Length defines
#define READ_DATA_MINSIZE                     4U
#define READ_TEXT_MINSIZE                     2U
#define READ_PARAMETER_MINSIZE                8U
#define READ_HOSTS_MINSIZE                    3U
#define READ_HOSTS_ADDRESS_MINSIZE            5U
#define READ_IPFILTER_MINSIZE                 5U
#define READ_IPFILTER_BLACKLIST_MINSIZE       3U
#define READ_IPFILTER_LOCAL_ROUTING_MINSIZE   4U

//Global variables
extern CONFIGURATION_TABLE Parameter;
#if defined(ENABLE_LIBSODIUM)
	extern DNSCURVE_CONFIGURATON_TABLE DNSCurveParameter;
#endif
extern std::vector<std::wstring> ConfigFileList;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	extern std::vector<std::string> sConfigFileList;
#endif
extern std::vector<FILE_DATA> FileList_IPFilter, FileList_Hosts;
extern std::vector<DIFFERNET_IPFILTER_FILE_SET> *IPFilterFileSetUsing, *IPFilterFileSetModificating;
extern std::vector<DIFFERNET_HOSTS_FILE_SET> *HostsFileSetUsing, *HostsFileSetModificating;
extern std::mutex HostsListLock, AddressRangeLock, ResultBlacklistLock, AddressHostsListLock, LocalRoutingListLock;

//Functions in Configuration.cpp
bool __fastcall ReadText(const FILE *Input, const size_t InputType, const size_t FileIndex);
bool __fastcall ReadMultiLineComments(const char *Buffer, std::string &Data, bool &IsLabelComments);
void __fastcall ClearListData(const size_t ClearType, const size_t FileIndex);

//Functions in ReadParameter.cpp
bool __fastcall ParameterCheckAndSetting(const size_t FileIndex);
bool __fastcall ReadParameterData(const char *Buffer, const size_t FileIndex, const size_t Line, bool &IsLabelComments);
#if defined(PLATFORM_WIN)
	void __fastcall ReadFileName(std::string Data, const size_t DataOffset, std::vector<std::wstring> *ListData);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	void ReadFileName(std::string Data, const size_t DataOffset, std::vector<std::wstring> *ListData, std::vector<std::string> *sListData);
#endif
bool __fastcall ReadListenAddress(std::string Data, const size_t DataOffset, const uint16_t Protocol, const size_t FileIndex, const size_t Line);
bool __fastcall ReadSingleAddress(std::string Data, const size_t DataOffset, sockaddr_storage &SockAddr, const uint16_t Protocol, const size_t FileIndex, const size_t Line);
bool __fastcall ReadMultipleAddresses(std::string Data, const size_t DataOffset, sockaddr_storage &SockAddr, const uint16_t Protocol, const size_t FileIndex, const size_t Line);
#if defined(ENABLE_PCAP)
	bool __fastcall ReadHopLimitData(std::string Data, const size_t DataOffset, uint8_t &HopLimit, const uint16_t Protocol, const size_t FileIndex, const size_t Line);
#endif
#if defined(ENABLE_LIBSODIUM)
	bool __fastcall ReadDNSCurveProviderName(std::string Data, const size_t DataOffset, PSTR ProviderNameData, const size_t FileIndex, const size_t Line);
	bool __fastcall ReadDNSCurveKey(std::string Data, const size_t DataOffset, PUINT8 KeyData, const size_t FileIndex, const size_t Line);
#endif
bool __fastcall ReadMagicNumber(std::string Data, const size_t DataOffset, PSTR MagicNumber, const size_t FileIndex, const size_t Line);

//Functions in ReadIPFilter.cpp
bool __fastcall ReadIPFilterData(const char *Buffer, const size_t FileIndex, const size_t Line, size_t &LabelType, bool &IsLabelComments);
bool __fastcall ReadBlacklistData(std::string Data, const size_t FileIndex, const size_t Line);
bool __fastcall ReadLocalRoutingData(std::string Data, const size_t FileIndex, const size_t Line);
bool __fastcall ReadAddressPrefixBlock(std::string OriginalData, const size_t DataOffset, const size_t FileIndex, const size_t Line);
bool __fastcall ReadMainIPFilterData(std::string Data, const size_t FileIndex, const size_t Line);

//Functions in ReadHosts.cpp
bool __fastcall ReadHostsData(const char *Buffer, const size_t FileIndex, const size_t Line, size_t &LabelType, bool &IsLabelComments);
bool __fastcall ReadWhitelistAndBannedData(std::string Data, const size_t FileIndex, const size_t Line, const size_t LabelType);
bool __fastcall ReadLocalHostsData(std::string Data, const size_t FileIndex, const size_t Line);
bool __fastcall ReadAddressHostsData(std::string Data, const size_t FileIndex, const size_t Line);
bool __fastcall ReadMainHostsData(std::string Data, const size_t FileIndex, const size_t Line);
