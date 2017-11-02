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


#include "Configuration.h"

//Read ipfilter data from files
bool ReadIPFilterData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line, 
	LABEL_IPFILTER_TYPE &LabelType, 
	bool &IsStopLabel)
{
//Convert horizontal tab/HT to space and remove spaces before or after data.
	for (auto &StringIter:Data)
	{
		if (StringIter == ASCII_HT)
			StringIter = ASCII_SPACE;
	}
	while (!Data.empty() && Data.front() == ASCII_SPACE)
		Data.erase(0, 1U);
	while (!Data.empty() && Data.back() == ASCII_SPACE)
		Data.pop_back();
	while (!Data.empty() && Data.find("  ") != std::string::npos)
		Data.erase(Data.find("  "), 1U);
	if (Data.empty())
		return true;

//Delete spaces, horizontal tab/HT, check comments(Number Sign/NS and double slashs) and check minimum length of ipfilter items.
	if (Data.compare(0, strlen("#"), ("#")) == 0 || Data.compare(0, strlen("/"), ("/")) == 0)
		return true;

//Case insensitive
	std::string InsensitiveString(Data);
	CaseConvert(InsensitiveString, true);

//[Local Routing] block(A part)
	if (LabelType == LABEL_IPFILTER_TYPE::NONE && 
		(Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family != 0 || Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family != 0))
	{
		std::wstring WCS_InsensitiveString(FileList_IPFilter.at(FileIndex).FileName);
		CaseConvert(WCS_InsensitiveString, true);
		if (CompareStringReversed(L"CHNROUTING.TXT", WCS_InsensitiveString.c_str()) || CompareStringReversed(L"CHNROUTE.TXT", WCS_InsensitiveString.c_str()))
		{
			LabelType = LABEL_IPFILTER_TYPE::LOCAL_ROUTING;
			IsStopLabel = false;
		}
	}

//[IPFilter] block
	if (InsensitiveString.compare(0, strlen("[IPFILTER]"), ("[IPFILTER]")) == 0)
	{
		LabelType = LABEL_IPFILTER_TYPE::NORMAL;
		IsStopLabel = false;

		return true;
	}

//[Blacklist] block(A part)
	else if (InsensitiveString.compare(0, strlen("[BLACKLIST]"), ("[BLACKLIST]")) == 0)
	{
		LabelType = LABEL_IPFILTER_TYPE::BLACKLIST;
		IsStopLabel = false;

		return true;
	}

//[Local Routing] block(B part)
	else if (InsensitiveString.compare(0, strlen("[LOCAL ROUTING]"), ("[LOCAL ROUTING]")) == 0)
	{
		LabelType = LABEL_IPFILTER_TYPE::LOCAL_ROUTING;
		IsStopLabel = false;

		return true;
	}

//Temporary stop read.
	else if (InsensitiveString.compare(0, strlen("[STOP"), ("[STOP")) == 0)
	{
		if (InsensitiveString.find("END]") != std::string::npos)
		{
			IsStopLabel = false;
			return true;
		}
		else if (InsensitiveString.compare(0, strlen("[STOP]"), ("[STOP]")) == 0)
		{
			IsStopLabel = true;
			return true;
		}
	}
	else if (IsStopLabel)
	{
		return true;
	}

//[Blacklist] block(B part)
	if (LabelType == LABEL_IPFILTER_TYPE::NORMAL && Data.find(ASCII_MINUS) == std::string::npos)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"Data format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete comments(Number Sign/NS and double slashs) and check minimum length.
	else if (Data.rfind(" //") != std::string::npos)
	{
		Data.erase(Data.rfind(" //"), Data.length() - Data.rfind(" //"));
	}
	else if (Data.rfind(" #") != std::string::npos)
	{
		Data.erase(Data.rfind(" #"), Data.length() - Data.rfind(" #"));
	}

//Blacklist items
	if (LabelType == LABEL_IPFILTER_TYPE::BLACKLIST && Parameter.DataCheck_Blacklist)
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
	else if (LabelType == LABEL_IPFILTER_TYPE::LOCAL_ROUTING && Parameter.IsLocalRouting)
	{
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);
		if (Data.length() >= READ_IPFILTER_LOCAL_ROUTING_MINSIZE)
			return ReadLocalRoutingData(Data, FileIndex, Line);
	}
//Main IPFilter items
	else if (LabelType == LABEL_IPFILTER_TYPE::NORMAL && Parameter.OperationMode == LISTEN_MODE::CUSTOM)
	{
		while (Data.find(ASCII_SPACE) != std::string::npos)
			Data.erase(Data.find(ASCII_SPACE), 1U);
		if (Data.length() >= READ_IPFILTER_MINSIZE)
			return ReadMainIPFilterData(Data, FileIndex, Line);
	}

	return true;
}

//Read Blacklist items in IPFilter file from data
bool ReadBlacklistData(
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
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"Data format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//String length check.
	if (Data.length() < READ_IPFILTER_BLACKLIST_MINSIZE || 
		(Data.find(ASCII_MINUS) != std::string::npos && Data.find(ASCII_VERTICAL) != std::string::npos && 
		Data.find(ASCII_MINUS) < Separated && Data.find(ASCII_VERTICAL) < Separated && Data.find(ASCII_MINUS) < Data.find(ASCII_VERTICAL)))
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"Data format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Initialization
	RESULT_BLACKLIST_TABLE ResultBlacklistTableTemp;
	ADDRESS_RANGE_TABLE AddressRangeTableTemp;
	uint8_t AddrBuffer[ADDRESS_STRING_MAXSIZE]{0};
	std::vector<std::string> ListData;
	GetParameterListData(ListData, Data, 0, Separated, ASCII_VERTICAL, false, false);
	ssize_t Result = 0;
	uint16_t BeforeType = 0;

//Mark all data in list.
	for (const auto &StringIter:ListData)
	{
	//AAAA record(IPv6)
		if (StringIter.find(ASCII_COLON) != std::string::npos)
		{
		//Before type check
			if (BeforeType == 0)
			{
				BeforeType = AF_INET6;
			}
			else if (BeforeType != AF_INET6)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"Data format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Range check
				if (StringIter.length() + 1U <= StringIter.find(ASCII_MINUS))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv6 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Convert address(Begin).
				memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
				memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(AF_INET6, AddrBuffer, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.Begin)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv6 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					AddressRangeTableTemp.Begin.ss_family = AF_INET6;
				}

			//Convert address(End).
				memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
				memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(AF_INET6, AddrBuffer, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.End)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv6 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					AddressRangeTableTemp.End.ss_family = AF_INET6;
				}

			//Check address range.
				if (AddressesComparing(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.Begin)->sin6_addr, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.End)->sin6_addr) == ADDRESS_COMPARE_TYPE::GREATER)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv6 address range error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert address.
				memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
				memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str(), StringIter.length());
				if (!AddressStringToBinary(AF_INET6, AddrBuffer, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.Begin)->sin6_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv6 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Check repeat items.
				if (CheckSpecialAddress(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.Begin)->sin6_addr, false, nullptr))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::IPFILTER, L"Repeat item error, this item will disabled", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET6;
				AddressRangeTableTemp.End.ss_family = AF_INET6;
				reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.End)->sin6_addr = reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.Begin)->sin6_addr;
			}

			ResultBlacklistTableTemp.Addresses.push_back(AddressRangeTableTemp);
			memset(&AddressRangeTableTemp, 0, sizeof(AddressRangeTableTemp));
		}
	//A record(IPv4)
		else if (StringIter.find(ASCII_PERIOD) != std::string::npos)
		{
		//Before type check
			if (BeforeType == 0)
			{
				BeforeType = AF_INET;
			}
			else if (BeforeType != AF_INET)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"Data format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Range check
				if (StringIter.length() + 1U <= StringIter.find(ASCII_MINUS))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv4 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Convert address(Begin).
				memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
				memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(AF_INET, AddrBuffer, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.Begin)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv4 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					AddressRangeTableTemp.Begin.ss_family = AF_INET;
				}

			//Convert address(End).
				memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
				memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(AF_INET, AddrBuffer, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.End)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv4 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				else {
					AddressRangeTableTemp.End.ss_family = AF_INET;
				}

			//Check address range.
				if (AddressesComparing(AF_INET, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.Begin)->sin_addr, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.End)->sin_addr) == ADDRESS_COMPARE_TYPE::GREATER)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv4 address range error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert address.
				memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
				memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, StringIter.c_str(), StringIter.length());
				if (!AddressStringToBinary(AF_INET, AddrBuffer, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.Begin)->sin_addr, &Result))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv4 address format error", Result, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

			//Check repeat items.
				if (CheckSpecialAddress(AF_INET, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.Begin)->sin_addr, false, nullptr))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::IPFILTER, L"Repeat item error, this item will disabled", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET;
				AddressRangeTableTemp.End.ss_family = AF_INET;
				reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.End)->sin_addr = reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.Begin)->sin_addr;
			}

			ResultBlacklistTableTemp.Addresses.push_back(AddressRangeTableTemp);
			memset(&AddressRangeTableTemp, 0, sizeof(AddressRangeTableTemp));
		}
		else {
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"Data format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Block these IP addresses from all request.
	ResultBlacklistTableTemp.PatternString.append(Data, Separated, Data.length() - Separated);
	std::string InsensitiveString(ResultBlacklistTableTemp.PatternString);
	CaseConvert(InsensitiveString, true);
	if (InsensitiveString == ("ALL"))
	{
		ResultBlacklistTableTemp.PatternString.clear();
		ResultBlacklistTableTemp.PatternString.shrink_to_fit();
	}
//Other request
	else {
		try {
			std::regex PatternRegexTemp(ResultBlacklistTableTemp.PatternString);
			std::swap(ResultBlacklistTableTemp.PatternRegex, PatternRegexTemp);
		}
		catch (std::regex_error &Error)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"Regular expression pattern error", Error.code(), FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Mark to global list.
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
bool ReadLocalRoutingData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line)
{
//Check data format.
	if (Data.find("/") == std::string::npos || Data.rfind("/") < IPV6_SHORTEST_ADDR_STRING || Data.at(Data.length() - 1U) == ASCII_SLASH)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Address Prefix Block format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
		return false;
	}
	for (const auto &StringIter:Data)
	{
		if (StringIter < ASCII_PERIOD || (StringIter > ASCII_COLON && StringIter < ASCII_UPPERCASE_A) || 
			(StringIter > ASCII_UPPERCASE_F && StringIter < ASCII_LOWERCASE_A) || StringIter > ASCII_LOWERCASE_F)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Address Prefix Block format error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Initialization
	AddressRoutingTable AddressRoutingTableTemp;
	uint8_t AddrBuffer[ADDRESS_STRING_MAXSIZE]{0};
	memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str(), Data.find("/"));
	ssize_t SignedResult = 0;
	size_t UnsignedResult = 0;

//IPv6
	if (Data.find(":") != std::string::npos)
	{
		in6_addr BinaryAddr;
		memset(&BinaryAddr, 0, sizeof(BinaryAddr));
		Data.erase(0, Data.find("/") + 1U);

	//Convert address.
		if (!AddressStringToBinary(AF_INET6, AddrBuffer, &BinaryAddr, &SignedResult))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv6 address format error", SignedResult, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Mark network prefix.
		_set_errno(0);
		UnsignedResult = strtoul(Data.c_str(), nullptr, 0);
		if (UnsignedResult == 0 || UnsignedResult > sizeof(in6_addr) * BYTES_TO_BITS)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv6 prefix error", errno, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			AddressRoutingTableTemp.Prefix = UnsignedResult;
		}

	//IPv6 mark to global list.
		std::unordered_set<uint64_t> AddrBackSet;
		for (auto &IPFilterFileSetIter:*IPFilterFileSetModificating)
		{
			if (IPFilterFileSetIter.FileIndex == FileIndex)
			{
			//Local routing list is empty.
				if (IPFilterFileSetIter.LocalRoutingList.empty())
					goto AddToGlobalList_IPv6;

			//Scan all local routing items to add or insert.
				for (auto &LocalRoutingTableIter:IPFilterFileSetIter.LocalRoutingList)
				{
					if (LocalRoutingTableIter.Prefix == AddressRoutingTableTemp.Prefix)
					{
						const auto AddressRoutingListIter = LocalRoutingTableIter.AddressRoutingList_IPv6.find(hton64(*reinterpret_cast<uint64_t *>(&BinaryAddr)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressRoutingTableTemp.Prefix)));
						if (AddressRoutingListIter != LocalRoutingTableIter.AddressRoutingList_IPv6.end())
						{
							if (AddressRoutingListIter->second.find(hton64(*reinterpret_cast<uint64_t *>(reinterpret_cast<uint8_t *>(&BinaryAddr) + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix))) == AddressRoutingListIter->second.end())
								AddressRoutingListIter->second.insert(hton64(*reinterpret_cast<uint64_t *>(reinterpret_cast<uint8_t *>(&BinaryAddr) + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));
						}
						else {
							AddrBackSet.clear();
							if (AddressRoutingTableTemp.Prefix < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
							{
								AddrBackSet.insert(0);
								LocalRoutingTableIter.AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::unordered_set<uint64_t>>(hton64(*reinterpret_cast<uint64_t *>(&BinaryAddr)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressRoutingTableTemp.Prefix)), AddrBackSet));
							}
							else {
								AddrBackSet.insert(hton64(*reinterpret_cast<uint64_t *>(reinterpret_cast<uint8_t *>(&BinaryAddr) + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));
								LocalRoutingTableIter.AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::unordered_set<uint64_t>>(hton64(*reinterpret_cast<uint64_t *>(&BinaryAddr)), AddrBackSet));
							}
						}

						return true;
					}
				}

			//Jump here to mark to global list.
			AddToGlobalList_IPv6:
				AddrBackSet.clear();
				if (AddressRoutingTableTemp.Prefix < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
				{
					AddrBackSet.insert(0);
					AddressRoutingTableTemp.AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::unordered_set<uint64_t>>(hton64(*reinterpret_cast<uint64_t *>(&BinaryAddr)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressRoutingTableTemp.Prefix)), AddrBackSet));
				}
				else {
					AddrBackSet.insert(hton64(*reinterpret_cast<uint64_t *>(reinterpret_cast<uint8_t *>(&BinaryAddr) + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));
					AddressRoutingTableTemp.AddressRoutingList_IPv6.insert(std::pair<uint64_t, std::unordered_set<uint64_t>>(hton64(*reinterpret_cast<uint64_t *>(&BinaryAddr)), AddrBackSet));
				}
				IPFilterFileSetIter.LocalRoutingList.push_back(AddressRoutingTableTemp);
				break;
			}
		}
	}
//IPv4
	else {
		in_addr BinaryAddr;
		memset(&BinaryAddr, 0, sizeof(BinaryAddr));
		Data.erase(0, Data.find("/") + 1U);

	//Convert address.
		if (!AddressStringToBinary(AF_INET, AddrBuffer, &BinaryAddr, &SignedResult))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv4 address format error", SignedResult, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Mark network prefix.
		_set_errno(0);
		UnsignedResult = strtoul(Data.c_str(), nullptr, 0);
		if (UnsignedResult == 0 || UnsignedResult > sizeof(in_addr) * BYTES_TO_BITS)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv4 prefix error", errno, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			AddressRoutingTableTemp.Prefix = UnsignedResult;
		}

	//IPv4 mark to global list.
		for (auto &IPFilterFileSetIter:*IPFilterFileSetModificating)
		{
			if (IPFilterFileSetIter.FileIndex == FileIndex)
			{
			//Local routing list is empty.
				if (IPFilterFileSetIter.LocalRoutingList.empty())
					goto AddToGlobalList_IPv4;

			//Scan all local routing items to add or insert.
				for (auto &LocalRoutingTableIter:IPFilterFileSetIter.LocalRoutingList)
				{
					if (LocalRoutingTableIter.Prefix == AddressRoutingTableTemp.Prefix)
					{
						if (LocalRoutingTableIter.AddressRoutingList_IPv4.find(htonl(BinaryAddr.s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix))) == LocalRoutingTableIter.AddressRoutingList_IPv4.end())
							LocalRoutingTableIter.AddressRoutingList_IPv4.insert(htonl(BinaryAddr.s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - AddressRoutingTableTemp.Prefix)));

						return true;
					}
				}

			//Jump here to mark to global list.
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
bool ReadAddressPrefixBlock(
	const uint16_t Protocol, 
	std::string OriginalData, 
	const size_t DataOffset, 
	ADDRESS_PREFIX_BLOCK * const AddressPrefix, 
	const std::vector<FILE_DATA> &FileList, 
	const size_t FileIndex, 
	const size_t Line)
{
	std::string Data(OriginalData, DataOffset);

//Check data format.
	if (Data.find("/") == std::string::npos || Data.rfind("/") < IPV6_SHORTEST_ADDR_STRING || Data.at(Data.length() - 1U) == ASCII_SLASH)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Address Prefix Block format error", 0, FileList.at(FileIndex).FileName.c_str(), Line);
		return false;
	}
	for (const auto &StringIter:Data)
	{
		if (StringIter < ASCII_PERIOD || (StringIter > ASCII_COLON && StringIter < ASCII_UPPERCASE_A) || 
			(StringIter > ASCII_UPPERCASE_F && StringIter < ASCII_LOWERCASE_A) || StringIter > ASCII_LOWERCASE_F)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Address Prefix Block format error", 0, FileList.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Initialization
	uint8_t AddrBuffer[ADDRESS_STRING_MAXSIZE]{0};
	memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str(), Data.find("/"));
	Data.erase(0, Data.find("/") + 1U);
	ssize_t SignedResult = 0;
	size_t UnsignedResult = 0;

//IPv6
	if (Protocol == AF_INET6)
	{
	//Convert address.
		if (!AddressStringToBinary(AF_INET6, AddrBuffer, &reinterpret_cast<sockaddr_in6 *>(&AddressPrefix->first)->sin6_addr, &SignedResult))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 address format error", SignedResult, FileList.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Mark network prefix.
		_set_errno(0);
		UnsignedResult = strtoul(Data.c_str(), nullptr, 0);
		if (UnsignedResult == 0 || UnsignedResult > sizeof(in6_addr) * BYTES_TO_BITS)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv6 prefix error", errno, FileList.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			AddressPrefix->second = UnsignedResult;

		//Mark prefix block.
			if (AddressPrefix->second < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
			{
				*reinterpret_cast<uint64_t *>(&reinterpret_cast<sockaddr_in6 *>(&AddressPrefix->first)->sin6_addr) = hton64(ntoh64(*reinterpret_cast<uint64_t *>(&reinterpret_cast<sockaddr_in6 *>(&AddressPrefix->first)->sin6_addr)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - AddressPrefix->second))); //Mark high 64 bits.
				*reinterpret_cast<uint64_t *>(reinterpret_cast<uint8_t *>(&reinterpret_cast<sockaddr_in6 *>(&AddressPrefix->first)->sin6_addr) + sizeof(in6_addr) / 2U) = 0; //Delete low 64 bits.
			}
			else {
				*reinterpret_cast<uint64_t *>(reinterpret_cast<uint8_t *>(&reinterpret_cast<sockaddr_in6 *>(&AddressPrefix->first)->sin6_addr) + sizeof(in6_addr) / 2U) = hton64(ntoh64(*reinterpret_cast<uint64_t *>(reinterpret_cast<uint8_t *>(&reinterpret_cast<sockaddr_in6 *>(&AddressPrefix->first)->sin6_addr) + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - AddressPrefix->second))); //Mark low 64 bits.
			}
		}

		AddressPrefix->first.ss_family = AF_INET6;
	}
//IPv4
	else if (Protocol == AF_INET)
	{
	//Convert address.
		if (!AddressStringToBinary(AF_INET, AddrBuffer, &reinterpret_cast<sockaddr_in *>(&AddressPrefix->first)->sin_addr, &SignedResult))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 address format error", SignedResult, FileList.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Mark network prefix.
		_set_errno(0);
		UnsignedResult = strtoul(Data.c_str(), nullptr, 0);
		if (UnsignedResult == 0 || UnsignedResult > sizeof(in_addr) * BYTES_TO_BITS)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"IPv4 prefix error", errno, FileList.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
		else {
			AddressPrefix->second = UnsignedResult;

		//Mark prefix block.
			reinterpret_cast<sockaddr_in *>(&AddressPrefix->first)->sin_addr.s_addr = htonl(ntohl(reinterpret_cast<sockaddr_in *>(&AddressPrefix->first)->sin_addr.s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - AddressPrefix->second)));
		}

		AddressPrefix->first.ss_family = AF_INET;
	}
	else {
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::PARAMETER, L"Data format error", 0, FileList.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

	return true;
}

//Read Main IPFilter items in IPFilter file from data
bool ReadMainIPFilterData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line)
{
//Initialization
	ADDRESS_RANGE_TABLE AddressRangeTableTemp;
	ssize_t SignedResult = 0;
	size_t Index = 0;

//Check data format.
	if (Data.find(ASCII_COMMA) != std::string::npos && Data.find(ASCII_COMMA) > Data.find(ASCII_MINUS)) //IPFilter.dat
	{
	//IPv4 spacial removed
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
			if (Data.front() == ASCII_PERIOD)
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
		uint8_t Level[ADDRESS_STRING_MAXSIZE]{0};
		memcpy_s(Level, ADDRESS_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_COMMA) + 1U, Data.find(ASCII_COMMA, Data.find(ASCII_COMMA) + 1U) - Data.find(ASCII_COMMA) - 1U);
		_set_errno(0);
		size_t UnsignedResult = strtoul(reinterpret_cast<const char *>(Level), nullptr, 0);
		if ((UnsignedResult == 0 && errno == 0) || (UnsignedResult > 0 && UnsignedResult < ULONG_MAX))
		{
			AddressRangeTableTemp.Level = UnsignedResult;
		}
		else {
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"Level error", errno, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
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
			if (Data.front() == ASCII_PERIOD)
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
				if (Data.front() == ASCII_PERIOD)
					Data.replace(0, 1U, ("0."));
				if (Data.at(Data.length() - 1U) == ASCII_PERIOD)
					Data.append("0");
			}
		}
	}

//Read data.
	uint8_t AddrBuffer[ADDRESS_STRING_MAXSIZE]{0};
	if (Data.find(ASCII_COLON) != std::string::npos) //IPv6
	{
	//Begin address
		AddressRangeTableTemp.Begin.ss_family = AF_INET6;
		memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_MINUS));
		if (!AddressStringToBinary(AF_INET6, AddrBuffer, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.Begin)->sin6_addr, &SignedResult))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv6 address format error", SignedResult, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//End address
		memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
		AddressRangeTableTemp.End.ss_family = AF_INET6;
		memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
		if (!AddressStringToBinary(AF_INET6, AddrBuffer, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.End)->sin6_addr, &SignedResult))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv6 address format error", SignedResult, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Check address range.
		if (AddressesComparing(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.Begin)->sin6_addr, &reinterpret_cast<sockaddr_in6 *>(&AddressRangeTableTemp.End)->sin6_addr) == ADDRESS_COMPARE_TYPE::GREATER)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv6 address range error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}
	else { //IPv4
	//Begin address
		AddressRangeTableTemp.Begin.ss_family = AF_INET;
		memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str(), Data.find(ASCII_MINUS));
		if (!AddressStringToBinary(AF_INET, AddrBuffer, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.Begin)->sin_addr, &SignedResult))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv4 address format error", SignedResult, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//End address
		memset(AddrBuffer, 0, ADDRESS_STRING_MAXSIZE);
		AddressRangeTableTemp.End.ss_family = AF_INET;
		memcpy_s(AddrBuffer, ADDRESS_STRING_MAXSIZE, Data.c_str() + Data.find(ASCII_MINUS) + 1U, Data.length() - Data.find(ASCII_MINUS));
		if (!AddressStringToBinary(AF_INET, AddrBuffer, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.End)->sin_addr, &SignedResult))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv4 address format error", SignedResult, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

	//Check address range.
		if (AddressesComparing(AF_INET, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.Begin)->sin_addr, &reinterpret_cast<sockaddr_in *>(&AddressRangeTableTemp.End)->sin_addr) == ADDRESS_COMPARE_TYPE::GREATER)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::IPFILTER, L"IPv4 address range error", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
			return false;
		}
	}

//Mark to global list.
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
