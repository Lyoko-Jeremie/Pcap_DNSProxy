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


#include "Configuration.h"

//Read hosts data from files
bool __fastcall ReadHostsData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line, 
	size_t &LabelType, 
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

//Multi-line comments check, delete comments(Number Sign/NS and double slashs) and check minimum length of hosts items.
	if (!ReadMultiLineComments(Data, IsLabelComments) || Data.find(ASCII_HASHTAG) == 0 || Data.find(ASCII_SLASH) == 0)
		return true;
	if (Data.rfind(" //") != std::string::npos)
		Data.erase(Data.rfind(" //"), Data.length() - Data.rfind(" //"));
	if (Data.rfind(" #") != std::string::npos)
		Data.erase(Data.rfind(" #"), Data.length() - Data.rfind(" #"));
	if (Data.length() < READ_HOSTS_MINSIZE)
		return true;

//[Base] block
	if (Data.find("[Base]") == 0 || Data.find("[base]") == 0 || 
		Data.find("Version = ") == 0 || Data.find("version = ") == 0 || 
		Data.find("Default TTL = ") == 0 || Data.find("default ttl = ") == 0)
			return true;

//[Local Hosts] block(A part)
	if (LabelType == 0 && (Parameter.DNSTarget.Local_IPv4.Storage.ss_family > 0 || Parameter.DNSTarget.Local_IPv6.Storage.ss_family > 0) && 
	#if defined(PLATFORM_WIN) //Case-insensitive on Windows
		(FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"whitelist.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") + wcslen(L"whitelist.txt") == FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"white_list.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") + wcslen(L"white_list.txt") == FileList_Hosts.at(FileIndex).FileName.length()))
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		(FileList_Hosts.at(FileIndex).FileName.rfind(L"WhiteList.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"WhiteList.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"WhiteList.txt") + wcslen(L"WhiteList.txt") == FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"Whitelist.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"Whitelist.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"Whitelist.txt") + wcslen(L"Whitelist.txt") == FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"whitelist.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"whitelist.txt") + wcslen(L"whitelist.txt")== FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_List.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"White_List.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_List.txt") + wcslen(L"White_List.txt") == FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_list.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"White_list.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"White_list.txt") + wcslen(L"White_list.txt")== FileList_Hosts.at(FileIndex).FileName.length() || 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") != std::wstring::npos && FileList_Hosts.at(FileIndex).FileName.length() > wcslen(L"white_list.txt") && 
		FileList_Hosts.at(FileIndex).FileName.rfind(L"white_list.txt") + wcslen(L"white_list.txt") == FileList_Hosts.at(FileIndex).FileName.length()))
	#endif
			LabelType = LABEL_HOSTS_TYPE_LOCAL;

//[Hosts] block
	if (Data.find("[Hosts]") == 0 || Data.find("[hosts]") == 0)
	{
		LabelType = LABEL_HOSTS;
		return true;
	}

//[Local Hosts] block(B part)
	else if (Data.find("[Local Hosts]") == 0 || Data.find("[Local hosts]") == 0 || Data.find("[local Hosts]") == 0 || Data.find("[local hosts]") == 0)
	{
		LabelType = LABEL_HOSTS_TYPE_LOCAL;
		return true;
	}

//[Address Hosts] block
	else if (Data.find("[Address Hosts]") == 0 || Data.find("[Address hosts]") == 0 || Data.find("[address Hosts]") == 0 || Data.find("[address hosts]") == 0)
	{
		LabelType = LABEL_HOSTS_ADDRESS;
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

//Whitelist items
	if (Data.find("NULL ") == 0 || Data.find("NULL,") == 0 || 
		Data.find("Null ") == 0 || Data.find("Null,") == 0 || 
		Data.find("null ") == 0 || Data.find("null,") == 0)
	{
		return ReadWhitelistAndBannedData(Data, FileIndex, Line, LABEL_HOSTS_TYPE_WHITELIST);
	}

//Banned items
	else if (Data.find("BAN ") == 0 || Data.find("BAN,") == 0 || 
		Data.find("BANNED ") == 0 || Data.find("BANNED,") == 0 || 
		Data.find("Ban ") == 0 || Data.find("Ban,") == 0 || 
		Data.find("Banned ") == 0 || Data.find("Banned,") == 0 || 
		Data.find("ban ") == 0 || Data.find("ban,") == 0 || 
		Data.find("banned ") == 0 || Data.find("banned,") == 0)
	{
		return ReadWhitelistAndBannedData(Data, FileIndex, Line, LABEL_HOSTS_TYPE_BANNED);
	}

//Whitelist Extended items
	else if (Data.find("NULL") == 0 || Data.find("Null") == 0 || Data.find("null") == 0)
	{
		return ReadWhitelistAndBannedData(Data, FileIndex, Line, LABEL_HOSTS_TYPE_WHITELIST_EXTENDED);
	}

//Banned Extended items
	else if (Data.find("BAN") == 0 || Data.find("BANNED") == 0 || Data.find("Ban") == 0 || 
		Data.find("Banned") == 0 || Data.find("ban") == 0 || Data.find("banned") == 0)
	{
		return ReadWhitelistAndBannedData(Data, FileIndex, Line, LABEL_HOSTS_TYPE_BANNED_EXTENDED);
	}

//[Local Hosts] block
	else if (LabelType == LABEL_HOSTS_TYPE_LOCAL)
	{
		if (Parameter.LocalMain)
			return true;
		else if (Parameter.LocalHosts && (Parameter.DNSTarget.Local_IPv4.Storage.ss_family > 0 || Parameter.DNSTarget.Local_IPv6.Storage.ss_family > 0))
			return ReadLocalHostsData(Data, FileIndex, Line);
	}

//[Address Hosts] block
	else if (LabelType == LABEL_HOSTS_ADDRESS)
	{
	//Delete spaces before or after verticals.
		while (Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
		{
			if (Data.find(" |") != std::string::npos)
				Data.erase(Data.find(" |"), strlen(" "));
			if (Data.find("| ") != std::string::npos)
				Data.erase(Data.find("| ") + 1U, strlen("|"));
		}

		return ReadAddressHostsData(Data, FileIndex, Line);
	}

//[Hosts] block
	else {
	//Delete spaces before or after verticals.
		while (Data.find(" |") != std::string::npos || Data.find("| ") != std::string::npos)
		{
			if (Data.find(" |") != std::string::npos)
				Data.erase(Data.find(" |"), strlen(" "));
			if (Data.find("| ") != std::string::npos)
				Data.erase(Data.find("| ") + 1U, strlen("|"));
		}

		return ReadMainHostsData(Data, FileIndex, Line);
	}

	return true;
}

//Read Whitelist and Banned items in Hosts file from data
bool __fastcall ReadWhitelistAndBannedData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line, 
	const size_t LabelType)
{
//Mark separated location and check data format.
	size_t Separated = 0;
	if (Data.find(ASCII_SPACE) != std::string::npos)
	{
		Separated = Data.find(ASCII_SPACE);
	}
	else if (Data.find(ASCII_COMMA) != std::string::npos)
	{
		Separated = Data.find(ASCII_COMMA);
	}
	if (Separated == 0 || ((LabelType == LABEL_HOSTS_TYPE_WHITELIST_EXTENDED || LabelType == LABEL_HOSTS_TYPE_BANNED_EXTENDED) && 
		(Data.find(ASCII_COLON) == std::string::npos || Separated <= Data.find(ASCII_COLON) + 1U)))
	{
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//Mark Whitelist Extended and Banned Extended types.
	HOSTS_TABLE HostsTableTemp;
	if (LabelType == LABEL_HOSTS_TYPE_WHITELIST_EXTENDED || LabelType == LABEL_HOSTS_TYPE_BANNED_EXTENDED)
	{
	//Permit or Deny
		if (LabelType == LABEL_HOSTS_TYPE_WHITELIST_EXTENDED && 
			(Data.find("DENY") != std::string::npos && Data.find("DENY") <= Separated || 
			Data.find("Deny") != std::string::npos && Data.find("Deny") <= Separated || 
			Data.find("deny") != std::string::npos && Data.find("deny") <= Separated) || 
			LabelType == LABEL_HOSTS_TYPE_BANNED_EXTENDED && 
			(Data.find("PERMIT") != std::string::npos && Data.find("PERMIT") <= Separated || 
			Data.find("Permit") != std::string::npos && Data.find("Permit") <= Separated || 
			Data.find("permit") != std::string::npos && Data.find("permit") <= Separated))
				HostsTableTemp.Type_Operation = true;

	//Mark types.
		std::vector<std::string> ListData;
		uint16_t RecordType = 0;
		SSIZE_T Result = 0;

	//Mark all data in list.
		GetParameterListData(ListData, Data, Data.find(ASCII_COLON) + 1U, Separated);
		for (auto StringIter:ListData)
		{
			RecordType = DNSTypeNameToHex(StringIter.c_str());

		//Number types
			if (RecordType <= 0)
			{
				Result = strtoul(StringIter.c_str(), nullptr, 0);
				if (errno != ERANGE && Result > 0 && Result <= UINT16_MAX)
				{
					HostsTableTemp.Type_Record.push_back(htons((uint16_t)Result));
				}
				else {
					PrintError(LOG_ERROR_PARAMETER, L"DNS Records type error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Name types
			else {
				HostsTableTemp.Type_Record.push_back(RecordType);
			}
		}
	}

//Mark patterns.
	HostsTableTemp.PatternString.append(Data, Separated, Data.length() - Separated);
	try {
		std::regex PatternHostsTableTemp(HostsTableTemp.PatternString);
		HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
	}
	catch (std::regex_error& Error)
	{
		PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Mark types.
	if (LabelType == LABEL_HOSTS_TYPE_BANNED || LabelType == LABEL_HOSTS_TYPE_BANNED_EXTENDED)
		HostsTableTemp.Type_Hosts = HOSTS_TYPE_BANNED;
	else 
		HostsTableTemp.Type_Hosts = HOSTS_TYPE_WHITE;

//Add to global HostsList.
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			HostsFileSetIter.HostsList.push_back(HostsTableTemp);
			break;
		}
	}

	return true;
}

//Read Local Hosts items in Hosts file from data
bool __fastcall ReadLocalHostsData(
	std::string Data, 
	const size_t FileIndex, 
	const size_t Line)
{
	HOSTS_TABLE HostsTableTemp;

//Mark patterns.
	HostsTableTemp.PatternString = Data;
	try {
		std::regex PatternHostsTableTemp(HostsTableTemp.PatternString);
		HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
	}
	catch (std::regex_error& Error)
	{
		PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Add to global HostsTable.
	HostsTableTemp.Type_Hosts = HOSTS_TYPE_LOCAL;
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			HostsFileSetIter.HostsList.push_back(HostsTableTemp);
			break;
		}
	}

	return true;
}

//Read Address Hosts items in Hosts file from data
bool __fastcall ReadAddressHostsData(
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
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);

//String length check.
	if (Data.length() < READ_HOSTS_ADDRESS_MINSIZE)
	{
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Initialization
	ADDRESS_HOSTS_TABLE AddressHostsTableTemp;
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

//Get target data.
	std::vector<std::string> TargetListData, SourceListData;
	GetParameterListData(TargetListData, Data, 0, Separated);
	GetParameterListData(SourceListData, Data, Separated, Data.length());
	SSIZE_T Result = 0;

//Mark all data in list.
	for (auto StringIter:TargetListData)
	{
	//AAAA records(IPv6)
		if (StringIter.find(ASCII_COLON) != std::string::npos)
		{
		//Convert to binary address.
			memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
			if (!AddressStringToBinary(StringIter.c_str(), &((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, AF_INET6, Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Add to list.
			SockAddr->ss_family = AF_INET6;
			AddressHostsTableTemp.Address_Target.push_back(*SockAddr);
		}
	//A records(IPv4)
		else {
		//Convert to binary address.
			memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
			if (!AddressStringToBinary(StringIter.c_str(), &((PSOCKADDR_IN)SockAddr.get())->sin_addr, AF_INET, Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Add to list.
			SockAddr->ss_family = AF_INET;
			AddressHostsTableTemp.Address_Target.push_back(*SockAddr);
		}
	}

	SockAddr.reset();

//Get source data.
	ADDRESS_RANGE_TABLE AddressRangeTableTemp;
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

//Mark all data in list.
	for (auto StringIter:SourceListData)
	{
	//AAAA records(IPv6)
		if (StringIter.find(ASCII_COLON) != std::string::npos)
		{
			memset(&AddressRangeTableTemp, 0, sizeof(ADDRESS_RANGE_TABLE));

		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Convert address(Begin).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET6;

			//Convert address(End).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6, Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET6;

			//Check address range.
				if (AddressesComparing(&((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, &((PSOCKADDR_IN6)&AddressRangeTableTemp.End)->sin6_addr, AF_INET6) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address range error", WSAGetLastError(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert to binary address.
				if (!AddressStringToBinary(StringIter.c_str(), &((PSOCKADDR_IN6)&AddressRangeTableTemp.Begin)->sin6_addr, AF_INET6, Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET6;
				AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
			}

		//Add to list.
			AddressHostsTableTemp.Address_Source.push_back(AddressRangeTableTemp);
		}
	//A records(IPv4)
		else {
			memset(&AddressRangeTableTemp, 0, sizeof(ADDRESS_RANGE_TABLE));

		//Address range format
			if (StringIter.find(ASCII_MINUS) != std::string::npos)
			{
			//Convert address(Begin).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.find(ASCII_MINUS));
				if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.Begin.ss_family = AF_INET;

			//Convert address(End).
				memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
				memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, StringIter.c_str() + StringIter.find(ASCII_MINUS) + 1U, StringIter.length() - StringIter.find(ASCII_MINUS) - 1U);
				if (!AddressStringToBinary(Addr.get(), &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET, Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
				AddressRangeTableTemp.End.ss_family = AF_INET;

			//Check address range.
				if (AddressesComparing(&((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, &((PSOCKADDR_IN)&AddressRangeTableTemp.End)->sin_addr, AF_INET) > ADDRESS_COMPARE_EQUAL)
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address range error", WSAGetLastError(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}
			}
		//Normal format
			else {
			//Convert to binary address.
				if (!AddressStringToBinary(StringIter.c_str(), &((PSOCKADDR_IN)&AddressRangeTableTemp.Begin)->sin_addr, AF_INET, Result))
				{
					PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
					return false;
				}

				AddressRangeTableTemp.Begin.ss_family = AF_INET;
				AddressRangeTableTemp.End = AddressRangeTableTemp.Begin;
			}

		//Add to list.
			AddressHostsTableTemp.Address_Source.push_back(AddressRangeTableTemp);
		}
	}

	Addr.reset();

//Add to global AddressHostsTable.
	for (auto &HostsFileSetIter:*HostsFileSetModificating)
	{
		if (HostsFileSetIter.FileIndex == FileIndex)
		{
			HostsFileSetIter.AddressHostsList.push_back(AddressHostsTableTemp);
			break;
		}
	}

	return true;
}

//Read Main Hosts items in Hosts file from data
bool __fastcall ReadMainHostsData(
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
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Delete all spaces and string length check.
	while (Data.find(ASCII_SPACE) != std::string::npos)
		Data.erase(Data.find(ASCII_SPACE), 1U);
	if (Separated < READ_HOSTS_MINSIZE)
		return false;

//Initialization
	HOSTS_TABLE HostsTableTemp;
	std::vector<std::string> ListData;
	GetParameterListData(ListData, Data, 0, Separated);

//Address counts check
	if (ListData.empty())
	{
		PrintError(LOG_ERROR_HOSTS, L"Data format error", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}
	else if (ListData.front().find(ASCII_COLON) != std::string::npos) //AAAA records(IPv6)
	{
		if (ListData.size() > DNS_RR_MAXCOUNT_AAAA)
		{
			PrintError(LOG_ERROR_HOSTS, L"Too many Hosts IPv6 addresses", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

		HostsTableTemp.Type_Record.push_back(htons(DNS_RECORD_AAAA));
	}
	else { //A records(IPv4)
		if (ListData.size() > DNS_RR_MAXCOUNT_A)
		{
			PrintError(LOG_ERROR_HOSTS, L"Too many Hosts IPv4 addresses", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
			return false;
		}

		HostsTableTemp.Type_Record.push_back(htons(DNS_RECORD_A));
	}

//Response initialization
	std::shared_ptr<char> BufferHostsTableTemp(new char[PACKET_MAXSIZE]());
	memset(BufferHostsTableTemp.get(), 0, PACKET_MAXSIZE);
	HostsTableTemp.Response.swap(BufferHostsTableTemp);
	BufferHostsTableTemp.reset();
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	void *DNS_Record = nullptr;
	SSIZE_T Result = 0;

//Mark all data in list.
	for (auto StringIter:ListData)
	{
	//AAAA records(IPv6)
		if (StringIter.find(ASCII_COLON) != std::string::npos)
		{
			DNS_Record = (pdns_record_aaaa)(HostsTableTemp.Response.get() + HostsTableTemp.Length);

		//Convert addresses.
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.length());
			if (!AddressStringToBinary(Addr.get(), &((pdns_record_aaaa)DNS_Record)->Addr, AF_INET6, Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv6 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Make responses.
			((pdns_record_aaaa)DNS_Record)->Name = htons(DNS_POINTER_QUERY);
			((pdns_record_aaaa)DNS_Record)->Classes = htons(DNS_CLASS_IN);
			((pdns_record_aaaa)DNS_Record)->TTL = htonl(Parameter.HostsDefaultTTL);
			((pdns_record_aaaa)DNS_Record)->Type = htons(DNS_RECORD_AAAA);
			((pdns_record_aaaa)DNS_Record)->Length = htons(sizeof(in6_addr));

		//Add to global list.
			HostsTableTemp.Length += sizeof(dns_record_aaaa);
		}
	//A records(IPv4)
		else {
			DNS_Record = (pdns_record_a)(HostsTableTemp.Response.get() + HostsTableTemp.Length);

		//Convert addresses.
			memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
			memcpy_s(Addr.get(), ADDR_STRING_MAXSIZE, StringIter.c_str(), StringIter.length());
			if (!AddressStringToBinary(Addr.get(), &((pdns_record_a)DNS_Record)->Addr, AF_INET, Result))
			{
				PrintError(LOG_ERROR_HOSTS, L"IPv4 address format error", Result, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
				return false;
			}

		//Make responses.
			((pdns_record_a)DNS_Record)->Name = htons(DNS_POINTER_QUERY);
			((pdns_record_a)DNS_Record)->Classes = htons(DNS_CLASS_IN);
			((pdns_record_a)DNS_Record)->TTL = htonl(Parameter.HostsDefaultTTL);
			((pdns_record_a)DNS_Record)->Type = htons(DNS_RECORD_A);
			((pdns_record_a)DNS_Record)->Length = htons(sizeof(in_addr));

		//Add to global list.
			HostsTableTemp.Length += sizeof(dns_record_a);
		}
	}

	Addr.reset();

//Mark patterns.
	HostsTableTemp.PatternString.append(Data, Separated, Data.length() - Separated);
	try {
		std::regex PatternHostsTableTemp(HostsTableTemp.PatternString);
		HostsTableTemp.Pattern.swap(PatternHostsTableTemp);
	}
	catch (std::regex_error& Error)
	{
		PrintError(LOG_ERROR_HOSTS, L"Regular expression pattern error", Error.code(), FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		return false;
	}

//Add to global HostsTable.
	if (HostsTableTemp.Length >= sizeof(dns_qry) + sizeof(in_addr)) //Shortest reply is a A Records with Question part.
	{
		HostsTableTemp.Type_Hosts = HOSTS_TYPE_NORMAL;
		for (auto &HostsFileSetIter:*HostsFileSetModificating)
		{
			if (HostsFileSetIter.FileIndex == FileIndex)
			{
				HostsFileSetIter.HostsList.push_back(HostsTableTemp);
				break;
			}
		}
	}

	return true;
}
