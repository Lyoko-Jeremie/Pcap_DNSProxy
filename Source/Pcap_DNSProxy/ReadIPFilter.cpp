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


#include "Configuration.h"

//Read ipfilter data from files
bool __fastcall ReadIPFilterData(
	std::string Data, 
	const size_t FileIndex, 
	size_t &LabelType, 
	const size_t Line, 
	bool &IsLabelComments)
{
//Convert horizontal tab/HT to space and delete spaces before or after data.
	for (auto &StringIter:Data)
	{
		if (StringIter == ASCII_HT)
			StringIter = ASCII_SPACE;
	}
	while (!Data.empty() && Data.at(0) == ASCII_SPACE)
		Data.erase(0, 1U);
	while (!Data.empty() && Data.back() == ASCII_SPACE)
		Data.pop_back();
	while (!Data.empty() && Data.find("  ") != std::string::npos)
		Data.erase(Data.find("  "), 1U);

//Multi-line comments check, delete spaces, horizontal tab/HT, check comments(Number Sign/NS and double slashs) and check minimum length of ipfilter items.
	if (!ReadMultiLineComments(Data, IsLabelComments) || Data.find(ASCII_HASHTAG) == 0 || Data.find(ASCII_SLASH) == 0)
		return true;

//[Base] block
	if (Data.find("[Base]") == 0 || Data.find("[base]") == 0 || 
		Data.find("Version = ") == 0 || Data.find("version = ") == 0 || 
		Data.find("Default TTL = ") == 0 || Data.find("default ttl = ") == 0)
			return true;

//[Local Routing] block(A part)
	if (LabelType == 0 && (Parameter.DNSTarget.Local_IPv4.Storage.ss_family > 0 || Parameter.DNSTarget.Local_IPv6.Storage.ss_family > 0) && 
	#if defined(PLATFORM_WIN) //Case-insensitive in Windows
		(FileList_IPFilter.at(FileIndex).FileName.rfind(L"chnrouting.txt") != std::wstring::npos && 
		FileList_IPFilter.at(FileIndex).FileName.length() > wcslen(L"chnrouting.txt") && 
		FileList_IPFilter.at(FileIndex).FileName.rfind(L"chnrouting.txt") + wcslen(L"chnrouting.txt") == FileList_IPFilter.at(FileIndex).FileName.length() || 
		FileList_IPFilter.at(FileIndex).FileName.rfind(L"chnroute.txt") != std::wstring::npos && 
		FileList_IPFilter.at(FileIndex).FileName.length() > wcslen(L"chnroute.txt") && 
		FileList_IPFilter.at(FileIndex).FileName.rfind(L"chnroute.txt") + wcslen(L"chnroute.txt") == FileList_IPFilter.at(FileIndex).FileName.length()))
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		(FileList_IPFilter.at(FileIndex).FileName.rfind(L"chnrouting.txt") != std::wstring::npos && 
		FileList_IPFilter.at(FileIndex).FileName.length() > wcslen(L"chnrouting.txt") && 
		FileList_IPFilter.at(FileIndex).FileName.rfind(L"chnrouting.txt") + wcslen(L"chnrouting.txt") == FileList_IPFilter.at(FileIndex).FileName.length() || 
		FileList_IPFilter.at(FileIndex).FileName.rfind(L"chnroute.txt") != std::wstring::npos && 
		FileList_IPFilter.at(FileIndex).FileName.length() > wcslen(L"chnroute.txt") && 
		FileList_IPFilter.at(FileIndex).FileName.rfind(L"chnroute.txt") + wcslen(L"chnroute.txt") == FileList_IPFilter.at(FileIndex).FileName.length()))
	#endif
			LabelType = LABEL_IPFILTER_LOCAL_ROUTING;

//[IPFilter] block
	if (Data.find("[IPFilter]") == 0 || Data.find("[IPfilter]") == 0 || Data.find("[ipfilter]") == 0)
	{
		LabelType = LABEL_IPFILTER;
		return true;
	}

//[Blacklist] block(A part)
	else if (Data.find("[BlackList]") == 0 || Data.find("[Blacklist]") == 0 || Data.find("[blacklist]") == 0)
	{
		LabelType = LABEL_IPFILTER_BLACKLIST;
		return true;
	}

//[Local Routing] block(B part)
	else if (Data.find("[Local Routing]") == 0 || Data.find("[Local routing]") == 0 || Data.find("[local routing]") == 0)
	{
		LabelType = LABEL_IPFILTER_LOCAL_ROUTING;
		return true;
	}

//Temporary stop read.
	else if (Data.find("[Stop]") == 0 || Data.find("[stop]") == 0)
	{
		LabelType = LABEL_STOP;
		return true;
	}
	if (LabelType == LABEL_STOP)
		return true;

//[Blacklist] block(B part)
	if (LabelType == LABEL_IPFILTER && Data.find(ASCII_MINUS) == std::string::npos)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"Data format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Multi-line comments check, delete comments(Number Sign/NS and double slashs) and check minimum length.
	else if (Data.rfind(" //") != std::string::npos)
	{
		Data.erase(Data.rfind(" //"), Data.length() - Data.rfind(" //"));
	}
	else if (Data.rfind(" #") != std::string::npos)
	{
		Data.erase(Data.rfind(" #"), Data.length() - Data.rfind(" #"));
	}

//Blacklist items
	if (Parameter.DataCheck_Blacklist && LabelType == LABEL_IPFILTER_BLACKLIST)
	{
	//Delete spaces before or after verticals.
		while (Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
		{
			if (Data.find(" |") != std::string::npos)
				Data.erase(Data.find(" |"), strlen(" "));
			if (Data.find("| ") != std::string::npos)
				Data.erase(Data.find("| ") + 1U, strlen("|"));
		}

		return ReadBlacklistData(Data, FileIndex, Line);
	}
//Local Routing items
	else if (Parameter.LocalRouting && LabelType == LABEL_IPFILTER_LOCAL_ROUTING)
	{
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);
		if (Data.length() >= READ_IPFILTER_LOCAL_ROUTING_MINSIZE)
			return ReadLocalRoutingData(Data, FileIndex, Line);
	}
//Main IPFilter items
	else if (Parameter.OperationMode == LISTEN_MODE_CUSTOM && LabelType == LABEL_IPFILTER)
	{
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);
		if (Data.length() >= READ_IPFILTER_MINSIZE)
			return ReadMainIPFilterData(Data, FileIndex, Line);
	}

	return true;
}

//Read Blacklist items in IPFilter file from data
bool __fastcall ReadBlacklistData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line)
{
//Mark separated location.
	size_t Separated = 0;
	if (Data.find(ASCII_COMMA) != std::string::npos)
	{
	//Delete spaces before or after commas.
		while (Data.find(" ,") != std::string::npos)
			Data.erase(Data.find(" ,"), strlen(" "));
		while (Data.find(ASCII_SPACE) != std::string::npos && Data.find(ASCII_SPACE) > Data.find(ASCII_COMMA))
			Data.erase(Data.find(ASCII_SPACE), 1U);

	//Common format
		if (Data.find(ASCII_SPACE) != std::string::npos)
		{
			Separated = Data.find(ASCII_SPACE);
		}
	//Comma-Separated Values/CSV, RFC 4180(https://tools.ietf.org/html/rfc4180), Common Format and MIME Type for Comma-Separated Values (CSV) Files.
		else {
			Separated = Data.find(ASCII_COMMA);
			Data.erase(Separated, 1U);
		}
	}
//Common format
	else if (Data.find(ASCII_SPACE) != std::string::npos)
	{
		Separated = Data.find(ASCII_SPACE);
	}
	else {
		PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"Data format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//String length check.
	if (Data.length() < READ_IPFILTER_BLACKLIST_MINSIZE || 
		Data.find(ASCII_MINUS) != std::string::npos && Data.find(ASCII_VERTICAL) != std::string::npos && 
		Data.find(ASCII_MINUS) < Separated && Data.find(ASCII_VERTICAL) < Separated && Data.find(ASCII_MINUS) < Data.find(ASCII_VERTICAL))
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"Data format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Initialization
	RESULT_BLACKLIST_TABLE ResultBlacklistTableTemp;
	ADDRESS_RANGE_TABLE AddressRangeTableTemp;
	char Addr[ADDR_STRING_MAXSIZE];
	memset(Addr, 0, ADDR_STRING_MAXSIZE);
	std::vector<std::string> ListData;
	GetParameterListData(ListData, Data, 0, Separated);
	SSIZE_T Result = 0;

//Mark all data in list.
	for (auto StringIter:ListData)
	{
	//AAAA records(IPv6)
		if (StringIter.find(ASCII_COLON) != std::string::npos)
		{
		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Range check
				if (StringIter.length() + 1U <= StringIter.find(ASCII_MINUS))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Convert address(Begin).
				memset(Addr, 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr, ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(Addr, AF_INET6, &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET6;

			//Convert address(End).
				memset(Addr, 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr, ADDR_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(Addr, AF_INET6, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET6;

			//Check address range.
				if (AddressesComparing(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv6 address range error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert address.
				memset(Addr, 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr, ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.length());
				if (!AddressStringToBinary(Addr, AF_INET6, &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Check repeating items.
				if (CheckSpecialAddress(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, false, nullptr))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"Repeating items error, this item is not available", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET6;
				AddressRangeTableTemp.End.ss_family = AF_INET6;
				((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr = ((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr;
			}

			ResultBlacklistTableTemp.Addresses.push_back(AddressRangeTableTemp);
			memset(&AddressRangeTableTemp, 0, sizeof(ADDRESS_RANGE_TABLE));
		}
	//A records(IPv4)
		else {
		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Range check
				if (StringIter.length() + 1U <= StringIter.find(ASCII_MINUS))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Convert address(Begin).
				memset(Addr, 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr, ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(Addr, AF_INET, &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET;

			//Convert address(End).
				memset(Addr, 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr, ADDR_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(Addr, AF_INET, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET;

			//Check address range.
				if (AddressesComparing(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv4 address range error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert address.
				memset(Addr, 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr, ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.length());
				if (!AddressStringToBinary(Addr, AF_INET, &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Check repeating items.
				if (CheckSpecialAddress(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, false, nullptr))
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"Repeating items error, this item is not available", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET;
				AddressRangeTableTemp.End.ss_family = AF_INET;
				((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr = ((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr;
			}

			ResultBlacklistTableTemp.Addresses.push_back(AddressRangeTableTemp);
			memset(&AddressRangeTableTemp, 0, sizeof(ADDRESS_RANGE_TABLE));
		}
	}

//Block these IP addresses from all request.
	ResultBlacklistTableTemp.PatternString.append(Data, Separated, Data.length() - Separated);
	if (ResultBlacklistTableTemp.PatternString == ("ALL") || ResultBlacklistTableTemp.PatternString == ("All") || ResultBlacklistTableTemp.PatternString == ("all"))
	{
		ResultBlacklistTableTemp.PatternString.clear();
		ResultBlacklistTableTemp.PatternString.shrink_to_fit();
	}
//Other request
	else {
		try {
			std::regex PatternTemp(ResultBlacklistTableTemp.PatternString);
			ResultBlacklistTableTemp.Pattern.swap(PatternTemp);
		}
		catch (std::regex_error& Error)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"Regular expression pattern error", Error.code(), FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Add to global ResultBlacklistTable.
	for (auto &IPFilterFileSetIter:*IPFilterFileSetModificating)
	{
		if (IPFilterFileSetIter.FileIndex == FileIndex)
		{
			IPFilterFileSetIter.ResultBlacklist.push_back(ResultBlacklistTableTemp);
			break;
		}
	}


	return true;
}

//Read Local Routing items in IPFilter file from data
bool __fastcall ReadLocalRoutingData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line)
{
//Check format of items.
	if (Data.find("/") == std::string::npos || Data.rfind("/") < 3U || Data.rfind("/") == Data.length() - 1U)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Address Prefix Block format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
		return false;
	}
	for (auto StringIter:Data)
	{
		if (StringIter < ASCII_PERIOD || StringIter > ASCII_COLON && 
			StringIter < ASCII_UPPERCASE_A || StringIter > ASCII_UPPERCASE_F && StringIter < ASCII_LOWERCASE_A || StringIter > ASCII_LOWERCASE_F)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Address Prefix Block format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Initialization
	AddressRoutingTable AddressRoutingTableTemp;
	char Addr[ADDR_STRING_MAXSIZE];
	memset(Addr, 0, ADDR_STRING_MAXSIZE);
	memcpy_s(Addr, ADDR_STRING_MAXSIZE, Data.c_str(), Data.find("/"));
	SSIZE_T Result = 0;

//IPv6
	if (Data.find(":") != std::string::npos) 
	{
		in6_addr BinaryAddr;
		memset(&BinaryAddr, 0, sizeof(in6_addr));
		Data.erase(0, Data.find("/") + 1U);

	//Convert address.
		if (!AddressStringToBinary(Addr, AF_INET6, &BinaryAddr, &Result))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Mark network prefix.
		Result = strtoul(Data.c_str(), nullptr, 0);
		if (Result <= 0 || Result > (SSIZE_T)(sizeof(in6_addr) * BYTES_TO_BITS))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv6 prefix error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			AddressRoutingTableTemp.Prefix = (size_t)Result;
		}

	//Add to global LocalRoutingList(IPv6).
		std::map<uint64_t, std::set<uint64_t>>::iterator AddressRoutingListIter;
		std::set<uint64_t> AddrBackSet;
		for (auto &IPFilterFileSetIter:*IPFilterFileSetModificating)
		{
			if (IPFilterFileSetIter.FileIndex == FileIndex)
			{
			//Local routing list is empty.
				if (IPFilterFileSetIter.LocalRoutingList.empty())
					goto AddToGlobalList_IPv6;

			//Scan all local routing items to add or insert.
				for (auto LocalRoutingTableIter = IPFilterFileSetIter.LocalRoutingList.begin();LocalRoutingTableIter != IPFilterFileSetIter.LocalRoutingList.end();++LocalRoutingTableIter)
				{
					if (LocalRoutingTableIter->Prefix == AddressRoutingTableTemp.Prefix)
					{
						AddressRoutingListIter = LocalRoutingTableIter->AddressRoutingList_IPv6.find(hton64(*(PUINT64)&BinaryAddr) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressRoutingTableTemp.Prefix)));
						if (AddressRoutingListIter != LocalRoutingTableIter->AddressRoutingList_IPv6.end())
						{
							if (AddressRoutingListIter->second.count(hton64(*(PUINT64)((uint8_t *)&BinaryAddr + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix))) == 0)
								AddressRoutingListIter->second.insert(hton64(*(PUINT64)((uint8_t *)&BinaryAddr + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));
						}
						else {
							AddrBackSet.clear();
							if (AddressRoutingTableTemp.Prefix < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
							{
								AddrBackSet.insert(0);
								LocalRoutingTableIter->AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::set<uint64_t>>(hton64(*(PUINT64)&BinaryAddr) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressRoutingTableTemp.Prefix)), AddrBackSet));
							}
							else {
								AddrBackSet.insert(hton64(*(PUINT64)((uint8_t *)&BinaryAddr + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));
								LocalRoutingTableIter->AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::set<uint64_t>>(hton64(*(PUINT64)&BinaryAddr), AddrBackSet));
							}
						}

						return true;
					}
				}

			//Jump here to add new item to global list.
			AddToGlobalList_IPv6:
				AddrBackSet.clear();
				if (AddressRoutingTableTemp.Prefix < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
				{
					AddrBackSet.insert(0);
					AddressRoutingTableTemp.AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::set<uint64_t>>(hton64(*(PUINT64)&BinaryAddr) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressRoutingTableTemp.Prefix)), AddrBackSet));
				}
				else {
					AddrBackSet.insert(hton64(*(PUINT64)((uint8_t *)&BinaryAddr + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));
					AddressRoutingTableTemp.AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::set<uint64_t>>(hton64(*(PUINT64)&BinaryAddr), AddrBackSet));
				}
				IPFilterFileSetIter.LocalRoutingList.push_back(AddressRoutingTableTemp);
				break;
			}
		}
	}
//IPv4
	else {
		in_addr BinaryAddr;
		memset(&BinaryAddr, 0, sizeof(in_addr));
		Data.erase(0, Data.find("/") + 1U);

	//Convert address.
		if (!AddressStringToBinary(Addr, AF_INET, &BinaryAddr, &Result))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Mark network prefix.
		Result = strtoul(Data.c_str(), nullptr, 0);
		if (Result <= 0 || Result > (SSIZE_T)(sizeof(in_addr) * BYTES_TO_BITS))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv4 prefix error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			AddressRoutingTableTemp.Prefix = (size_t)Result;
		}

	//Add to global LocalRoutingTable(IPv4).
		for (auto &IPFilterFileSetIter:*IPFilterFileSetModificating)
		{
			if (IPFilterFileSetIter.FileIndex == FileIndex)
			{
			//Local routing list is empty.
				if (IPFilterFileSetIter.LocalRoutingList.empty())
					goto AddToGlobalList_IPv4;

			//Scan all local routing items to add or insert.
				for (auto LocalRoutingTableIter = IPFilterFileSetIter.LocalRoutingList.begin();LocalRoutingTableIter != IPFilterFileSetIter.LocalRoutingList.end();++LocalRoutingTableIter)
				{
					if (LocalRoutingTableIter->Prefix == AddressRoutingTableTemp.Prefix)
					{
						if (LocalRoutingTableIter->AddressRoutingList_IPv4.count(htonl(BinaryAddr.s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix))) == 0)
							LocalRoutingTableIter->AddressRoutingList_IPv4.insert(htonl(BinaryAddr.s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));

						return true;
					}
				}

			//Jump here to add new item to global list.
			AddToGlobalList_IPv4:
				AddressRoutingTableTemp.AddressRoutingList_IPv4.insert(htonl(BinaryAddr.s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));
				IPFilterFileSetIter.LocalRoutingList.push_back(AddressRoutingTableTemp);
				break;
			}
		}
	}

	return true;
}

//Read Address Prefix Block data
bool __fastcall ReadAddressPrefixBlock(
	std::string OriginalData, 
	const size_t DataOffset, 
	const uint16_t Protocol, 
	ADDRESS_PREFIX_BLOCK *AddressPrefix, 
	const size_t FileIndex, 
	const size_t Line)
{
	std::string Data(OriginalData, DataOffset);

//Check format of items.
	if (Data.find("/") == std::string::npos || Data.rfind("/") < 3U || Data.rfind("/") == Data.length() - 1U)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Address Prefix Block format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		return false;
	}
	for (auto StringIter:Data)
	{
		if (StringIter < ASCII_PERIOD || StringIter > ASCII_COLON && 
			StringIter < ASCII_UPPERCASE_A || StringIter > ASCII_UPPERCASE_F && StringIter < ASCII_LOWERCASE_A || StringIter > ASCII_LOWERCASE_F)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"Address Prefix Block format error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Initialization
	char Addr[ADDR_STRING_MAXSIZE];
	memset(Addr, 0, ADDR_STRING_MAXSIZE);
	memcpy_s(Addr, ADDR_STRING_MAXSIZE, Data.c_str(), Data.find("/"));
	Data.erase(0, Data.find("/") + 1U);
	SSIZE_T Result = 0;

//IPv6
	if (Protocol == AF_INET6)
	{
	//Convert address.
		if (!AddressStringToBinary(Addr, AF_INET6, &((PSOCKADDR_IN6)&AddressPrefix->Address)->sin6_addr, &Result))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 address format error", Result, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Mark network prefix.
		Result = strtoul(Data.c_str(), nullptr, 0);
		if (Result <= 0 || Result > (SSIZE_T)(sizeof(in6_addr) * BYTES_TO_BITS))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv6 prefix error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			AddressPrefix->Prefix = (size_t)Result;

		//Mark prefix block.
			if (AddressPrefix->Prefix < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
				*(PUINT64)&((PSOCKADDR_IN6)&AddressPrefix->Address)->sin6_addr = hton64(ntoh64(*(PUINT64)&((PSOCKADDR_IN6)&AddressPrefix->Address)->sin6_addr) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressPrefix->Prefix)));
			else 
				*(PUINT64)((uint8_t *)&((PSOCKADDR_IN6)&AddressPrefix->Address)->sin6_addr + sizeof(in6_addr) / 2U) = hton64(ntoh64(*(PUINT64)((uint8_t *)&((PSOCKADDR_IN6)&AddressPrefix->Address)->sin6_addr + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressPrefix->Prefix)));
		}

		AddressPrefix->Address.ss_family = AF_INET6;
	}
//IPv4
	else {
	//Convert address.
		if (!AddressStringToBinary(Addr, AF_INET, &((PSOCKADDR_IN)&AddressPrefix->Address)->sin_addr, &Result))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 address format error", Result, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Mark network prefix.
		Result = strtoul(Data.c_str(), nullptr, 0);
		if (Result <= 0 || Result > (SSIZE_T)(sizeof(in_addr) * BYTES_TO_BITS))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_PARAMETER, L"IPv4 prefix error", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			AddressPrefix->Prefix = (size_t)Result;

		//Mark prefix block.
			((PSOCKADDR_IN)&AddressPrefix->Address)->sin_addr.s_addr = htonl(ntohl(((PSOCKADDR_IN)&AddressPrefix->Address)->sin_addr.s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - AddressPrefix->Prefix)));
		}

		AddressPrefix->Address.ss_family = AF_INET;
	}

	return true;
}

//Read Main IPFilter items in IPFilter file from data
bool __fastcall ReadMainIPFilterData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line)
{
//Initialization
	ADDRESS_RANGE_TABLE AddressRangeTableTemp;
	SSIZE_T Result = 0;
	size_t Index = 0;

//Check format of items.
	if (Data.find(ASCII_COMMA) != std::string::npos && Data.find(ASCII_COMMA) > Data.find(ASCII_MINUS)) //IPFilter.dat
	{
	//IPv4 spacial delete
		if (Data.find(ASCII_PERIOD) != std::string::npos)
		{
		//Delete all zeros before data.
			for (Index = 0;Index < Data.find(ASCII_MINUS);++Index)
			{
				if (Data.at(Index) == ASCII_ZERO)
				{
					Data.erase(Index, 1U);
					--Index;
				}
				else {
					break;
				}
			}

		//Delete all zeros before minus or after commas in addresses range.
			while (Data.find(".0") != std::string::npos)
				Data.replace(Data.find(".0"), strlen(".0"), ("."));
			while (Data.find("-0") != std::string::npos)
				Data.replace(Data.find("-0"), strlen("-0"), ("-"));
			while (Data.find("..") != std::string::npos)
				Data.replace(Data.find(".."), strlen(".."), (".0."));
			if (Data.find(".-") != std::string::npos)
				Data.replace(Data.find(".-"), strlen(".-"), (".0-"));
			if (Data.find("-.") != std::string::npos)
				Data.replace(Data.find("-."), strlen("-."), ("-0."));
			if (Data.at(0) == ASCII_PERIOD)
				Data.replace(0, 1U, ("0."));
		}

	//Delete all zeros before minus or after commas in ipfilter level.
		while (Data.find(",000,") != std::string::npos)
			Data.replace(Data.find(",000,"), strlen(",000,"), (",0,"));
		while (Data.find(",00,") != std::string::npos)
			Data.replace(Data.find(",00,"), strlen(",00,"), (",0,"));
		while (Data.find(",00") != std::string::npos)
			Data.replace(Data.find(",00"), strlen(",00"), (","));
		if (Data.find(",0") != std::string::npos && Data.at(Data.find(",0") + 2U) != ASCII_COMMA)
			Data.replace(Data.find(",0"), strlen(",0"), (","));

	//Mark ipfilter level.
		char Level[ADDR_STRING_MAXSIZE];
		memset(Level, 0, ADDR_STRING_MAXSIZE);
		memcpy_s(Level, ADDR_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_COMMA) + 1U, Data.find(ASCII_COMMA, Data.find(ASCII_COMMA) + 1U) - Data.find(ASCII_COMMA) - 1U);
		_set_errno(0);
		Result = strtoul(Level, nullptr, 0);
		if (Result == 0 && errno == 0 || Result > 0 && Result < UINT16_MAX)
		{
			AddressRangeTableTemp.Level = (size_t)Result;
		}
		else {
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"Level error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Delete all data except addresses range.
		Data.erase(Data.find(ASCII_COMMA));
		if (Data.at(Data.length() - 1U) == ASCII_PERIOD)
			Data.append("0");
	}
//PeerGuardian Text Lists(P2P) Format(Guarding.P2P), also a little part of IPFilter.dat without level.
	else {
	//IPv4 IPFilter.dat data without level
		if (Data.find(ASCII_COLON) == std::string::npos)
		{
		//Delete all zeros before data.
			for (Index = 0;Index < Data.find(ASCII_MINUS);++Index)
			{
				if (Data.at(Index) == ASCII_ZERO)
				{
					Data.erase(Index, 1U);
					--Index;
				}
				else {
					break;
				}
			}

		//Delete all zeros before minus or after commas in addresses range.
			while (Data.find(".0") != std::string::npos)
				Data.replace(Data.find(".0"), strlen(".0"), ("."));
			while (Data.find("-0") != std::string::npos)
				Data.replace(Data.find("-0"), strlen("-0"), ("-"));
			while (Data.find("..") != std::string::npos)
				Data.replace(Data.find(".."), strlen(".."), (".0."));
			if (Data.find(".-") != std::string::npos)
				Data.replace(Data.find(".-"), strlen(".-"), (".0-"));
			if (Data.find("-.") != std::string::npos)
				Data.replace(Data.find("-."), strlen("-."), ("-0."));
			if (Data.at(0) == ASCII_PERIOD)
				Data.replace(0, 1U, ("0."));
			if (Data.at(Data.length() - 1U) == ASCII_PERIOD)
				Data.append("0");
		}
		else {
		//PeerGuardian Text Lists(P2P) Format(Guarding.P2P)
			if (Data.find(ASCII_COLON) == Data.rfind(ASCII_COLON))
			{
				Data.erase(0, Data.find(ASCII_COLON) + 1U);

			//Delete all zeros before data.
				for (Index = 0;Index < Data.find(ASCII_MINUS);++Index)
				{
					if (Data.at(Index) == ASCII_ZERO)
					{
						Data.erase(Index, 1U);
						--Index;
					}
					else {
						break;
					}
				}

			//Delete all zeros before minus or after commas in addresses range.
				while (Data.find(".0") != std::string::npos)
					Data.replace(Data.find(".0"), strlen(".0"), ("."));
				while (Data.find("-0") != std::string::npos)
					Data.replace(Data.find("-0"), strlen("-0"), ("-"));
				while (Data.find("..") != std::string::npos)
					Data.replace(Data.find(".."), strlen(".."), (".0."));
				if (Data.find(".-") != std::string::npos)
					Data.replace(Data.find(".-"), strlen(".-"), (".0-"));
				if (Data.find("-.") != std::string::npos)
					Data.replace(Data.find("-."), strlen("-."), ("-0."));
				if (Data.at(0) == ASCII_PERIOD)
					Data.replace(0, 1U, ("0."));
				if (Data.at(Data.length() - 1U) == ASCII_PERIOD)
					Data.append("0");
			}
		}
	}

//Read data.
	char Addr[ADDR_STRING_MAXSIZE];
	memset(Addr, 0, ADDR_STRING_MAXSIZE);
	if (Data.find(ASCII_COLON) != std::string::npos) //IPv6
	{
	//Begin address
		AddressRangeTableTemp.Begin.ss_family = AF_INET6;
		memcpy_s(Addr, ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_MINUS));
		if (!AddressStringToBinary(Addr, AF_INET6, &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &Result))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//End address
		memset(Addr, 0, ADDR_STRING_MAXSIZE);
		AddressRangeTableTemp.End.ss_family = AF_INET6;
		memcpy_s(Addr, ADDR_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
		if (!AddressStringToBinary(Addr, AF_INET6, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, &Result))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv6 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Check address range.
		if (AddressesComparing(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6) > ADDRESS_COMPARE_EQUAL)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv6 address range error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}
//IPv4
	else {
	//Begin address
		AddressRangeTableTemp.Begin.ss_family = AF_INET;
		memcpy_s(Addr, ADDR_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_MINUS));
		if (!AddressStringToBinary(Addr, AF_INET, &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &Result))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//End address
		memset(Addr, 0, ADDR_STRING_MAXSIZE);
		AddressRangeTableTemp.End.ss_family = AF_INET;
		memcpy_s(Addr, ADDR_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
		if (!AddressStringToBinary(Addr, AF_INET, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, &Result))
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv4 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Check address range.
		if (AddressesComparing(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET) > ADDRESS_COMPARE_EQUAL)
		{
			PrintError(LOG_LEVEL_1, LOG_ERROR_IPFILTER, L"IPv4 address range error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Add to global AddressRangeTable.
	for (auto &IPFilterFileSetIter:*IPFilterFileSetModificating)
	{
		if (IPFilterFileSetIter.FileIndex == FileIndex)
		{
			IPFilterFileSetIter.AddressRange.push_back(AddressRangeTableTemp);
			break;
		}
	}

	return true;
}
