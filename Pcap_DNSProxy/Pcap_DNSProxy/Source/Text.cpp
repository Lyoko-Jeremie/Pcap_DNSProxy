// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on packet capturing
// Copyright (C) 2012-2019 Chengr28
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


#include "../Include/Text.h"

//Convert multiple bytes to wide character string
bool MBS_To_WCS_String(
	const uint8_t * const BufferPointer, 
	const size_t BufferSize, 
	std::wstring &Target)
{
//Check buffer.
	Target.clear();
	if (BufferPointer == nullptr || BufferSize == 0)
		return false;
	const auto DataLength = strnlen_s(reinterpret_cast<const char *>(BufferPointer), BufferSize);
	if (DataLength == 0 || CheckEmptyBuffer(BufferPointer, DataLength))
		return false;

//Initialization
	const auto TargetBuffer = std::make_unique<wchar_t[]>(DataLength + NULL_TERMINATE_LENGTH + MEMORY_RESERVED_BYTES);
	wmemset(TargetBuffer.get(), 0, DataLength + NULL_TERMINATE_LENGTH + MEMORY_RESERVED_BYTES);

//Convert string.
#if defined(PLATFORM_WIN)
	if (MultiByteToWideChar(
			CP_ACP, 
			0, 
			reinterpret_cast<const LPCCH>(BufferPointer), 
			MBSTOWCS_NULL_TERMINATE, 
			TargetBuffer.get(), 
			static_cast<const int>(DataLength + NULL_TERMINATE_LENGTH)) == 0)
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (mbstowcs(TargetBuffer.get(), reinterpret_cast<const char *>(BufferPointer), DataLength + NULL_TERMINATE_LENGTH) == static_cast<const size_t>(RETURN_ERROR))
#endif
	{
		return false;
	}
	else {
		if (wcsnlen_s(TargetBuffer.get(), DataLength + NULL_TERMINATE_LENGTH) == 0)
			return false;
		else 
			Target = TargetBuffer.get();
	}

	return true;
}

//Convert wide character string to multiple bytes
bool WCS_To_MBS_String(
	const wchar_t * const BufferPointer, 
	const size_t BufferSize, 
	std::string &Target)
{
//Check buffer pointer.
	Target.clear();
	if (BufferPointer == nullptr || BufferSize == 0)
		return false;
	const auto DataLength = wcsnlen_s(BufferPointer, BufferSize);
	if (DataLength == 0 || CheckEmptyBuffer(BufferPointer, sizeof(wchar_t) * DataLength))
		return false;

//Initialization
	const auto TargetBuffer = std::make_unique<wchar_t[]>(DataLength + NULL_TERMINATE_LENGTH + MEMORY_RESERVED_BYTES);
	memset(TargetBuffer.get(), 0, DataLength + NULL_TERMINATE_LENGTH + MEMORY_RESERVED_BYTES);

//Convert string.
#if defined(PLATFORM_WIN)
	if (WideCharToMultiByte(
			CP_ACP, 
			0, 
			BufferPointer, 
			WCSTOMBS_NULL_TERMINATE, 
			reinterpret_cast<LPSTR>(TargetBuffer.get()), 
			static_cast<const int>(DataLength + NULL_TERMINATE_LENGTH), 
			nullptr, 
			nullptr) == 0)
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (wcstombs(reinterpret_cast<char *>(TargetBuffer.get()), BufferPointer, DataLength + NULL_TERMINATE_LENGTH) == static_cast<const size_t>(RETURN_ERROR))
#endif
	{
		return false;
	}
	else {
		if (strnlen_s(reinterpret_cast<const char *>(TargetBuffer.get()), DataLength + NULL_TERMINATE_LENGTH) == 0)
			return false;
		else 
			Target = reinterpret_cast<const char *>(TargetBuffer.get());
	}

	return true;
}

//Check character decimal digit(Multiple character version)
bool IsDigit(
	const uint8_t Character)
{
	if (Character >= ASCII_ZERO && Character <= ASCII_NINE)
		return true;

	return false;
}

//Check character decimal digit(Wide character version)
bool IsDigit(
	const wchar_t Character)
{
	if (Character >= ASCII_ZERO && Character <= ASCII_NINE)
		return true;

	return false;
}

/* Temporary Disabled
//Check character alphabetic(Multiple character version)
bool IsAlphabetic(
	const uint8_t Character)
{
	if ((Character >= ASCII_UPPERCASE_A && Character <= ASCII_UPPERCASE_Z) || 
		(Character >= ASCII_LOWERCASE_A && Character <= ASCII_LOWERCASE_Z))
			return true;

	return false;
}

//Check character alphabetic(Wide character version)
bool IsAlphabetic(
	const wchar_t Character)
{
	if ((Character >= ASCII_UPPERCASE_A && Character <= ASCII_UPPERCASE_Z) || 
		(Character >= ASCII_LOWERCASE_A && Character <= ASCII_LOWERCASE_Z))
			return true;

	return false;
}

//Check character upper(Multiple character version)
bool IsUpper(
	const uint8_t Character)
{
	if (Character >= ASCII_UPPERCASE_A && Character <= ASCII_UPPERCASE_Z)
		return true;

	return false;
}

//Check character upper(Wide character version)
bool IsUpper(
	const wchar_t Character)
{
	if (Character >= ASCII_UPPERCASE_A && Character <= ASCII_UPPERCASE_Z)
		return true;

	return false;
}
*/

//Convert lowercase/uppercase words to uppercase/lowercase words(C-Style version)
void CaseConvert(
	uint8_t * const Buffer, 
	const size_t Length, 
	const bool IsLowerToUpper)
{
	if (Buffer != nullptr)
	{
	//Convert words.
		for (size_t Index = 0;Index < Length;++Index)
		{
		//Lowercase to uppercase
			if (IsLowerToUpper)
				Buffer[Index] = static_cast<const uint8_t>(toupper(Buffer[Index]));
		//Uppercase to lowercase
			else 
				Buffer[Index] = static_cast<const uint8_t>(tolower(Buffer[Index]));
		}
	}

	return;
}

//Convert lowercase/uppercase words to uppercase/lowercase words(C++ string version)
void CaseConvert(
	std::string &Buffer, 
	const bool IsLowerToUpper)
{
	for (auto &StringIter:Buffer)
	{
	//Lowercase to uppercase
		if (IsLowerToUpper)
			StringIter = static_cast<const char>(toupper(StringIter));
	//Uppercase to lowercase
		else 
			StringIter = static_cast<const char>(tolower(StringIter));
	}

	return;
}

//Convert lowercase/uppercase words to uppercase/lowercase words(C++ wstring version)
void CaseConvert(
	std::wstring &Buffer, 
	const bool IsLowerToUpper)
{
	for (auto &StringIter:Buffer)
	{
	//Lowercase to uppercase
		if (IsLowerToUpper)
			StringIter = static_cast<const wchar_t>(toupper(StringIter));
	//Uppercase to lowercase
		else 
			StringIter = static_cast<const wchar_t>(tolower(StringIter));
	}

	return;
}

//Get item from string(Multiple character version)
void GetItemFromString(
	std::vector<std::string> &ItemData, 
	const std::string &WholeString, 
	const size_t DataOffset, 
	const size_t Length, 
	const uint8_t SeparatedSign, 
	const bool IsCaseConvert, 
	const bool IsKeepEmptyItem)
{
//Initialization
	std::string NameString;
	ItemData.clear();

//Get all items from string.
	for (auto Index = DataOffset;Index < Length;++Index)
	{
	//The last data
		if (Index + 1U == Length)
		{
			if (WholeString.at(Index) != SeparatedSign)
				NameString.append(WholeString, Index, 1U);
			if (NameString.empty())
			{
				if (IsKeepEmptyItem)
					ItemData.emplace_back(NameString);

				break;
			}
			else {
			//Case insensitive
				if (IsCaseConvert)
					CaseConvert(NameString, false);

			//Add character to the end.
				ItemData.emplace_back(NameString);
				if (IsKeepEmptyItem && WholeString.at(Index) == SeparatedSign)
				{
					NameString.clear();
					ItemData.emplace_back(NameString);
				}

				break;
			}
		}
	//Separated
		else if (WholeString.at(Index) == SeparatedSign)
		{
			if (!NameString.empty())
			{
			//Case insensitive
				if (IsCaseConvert)
					CaseConvert(NameString, false);

			//Add character to the end.
				ItemData.emplace_back(NameString);
				NameString.clear();
			}
			else if (IsKeepEmptyItem)
			{
				ItemData.emplace_back(NameString);
				NameString.clear();
			}
		}
	//Normal data
		else {
			NameString.append(WholeString, Index, 1U);
		}
	}

	return;
}

//Get item from string(Wide character version)
void GetItemFromString(
	std::vector<std::wstring> &ItemData, 
	const std::wstring &WholeString, 
	const size_t DataOffset, 
	const size_t Length, 
	const uint8_t SeparatedSign, 
	const bool IsCaseConvert, 
	const bool IsKeepEmptyItem)
{
//Initialization
	std::wstring NameString;
	ItemData.clear();

//Get all items from string.
	for (auto Index = DataOffset;Index < Length;++Index)
	{
	//The last data
		if (Index + 1U == Length)
		{
			if (WholeString.at(Index) != SeparatedSign)
				NameString.append(WholeString, Index, 1U);
			if (NameString.empty())
			{
				if (IsKeepEmptyItem)
					ItemData.emplace_back(NameString);

				break;
			}
			else {
			//Case insensitive
				if (IsCaseConvert)
					CaseConvert(NameString, false);

			//Add character to the end.
				ItemData.emplace_back(NameString);
				if (IsKeepEmptyItem && WholeString.at(Index) == SeparatedSign)
				{
					NameString.clear();
					ItemData.emplace_back(NameString);
				}

				break;
			}
		}
	//Separated
		else if (WholeString.at(Index) == SeparatedSign)
		{
			if (!NameString.empty())
			{
			//Case insensitive
				if (IsCaseConvert)
					CaseConvert(NameString, false);

			//Add character to the end.
				ItemData.emplace_back(NameString);
				NameString.clear();
			}
			else if (IsKeepEmptyItem)
			{
				ItemData.emplace_back(NameString);
				NameString.clear();
			}
		}
	//Normal data
		else {
			NameString.append(WholeString, Index, 1U);
		}
	}

	return;
}

//Check domain string acceptable(Multiple character version)
bool CheckDomainAcceptable(
	const std::string &DomainString)
{
//Domain length check
	if (DomainString.empty() || DomainString.length() >= DOMAIN_WHOLE_MAXSIZE)
		return false;

//Initialization
	static const uint8_t DomainAcceptableList[] = DNS_DOMAIN_ACCEPTABLE_MBS_CHARACTER;
	size_t Index = 0;

//Domain must use acceptable characters.
	for (const auto &StringIter:DomainString)
	{
		for (Index = 0;Index < strlen(reinterpret_cast<const char *>(DomainAcceptableList));++Index)
		{
			if (DomainAcceptableList[Index] == StringIter)
				break;
			else if (Index + 1U >= strlen(reinterpret_cast<const char *>(DomainAcceptableList)))
				return false;
		}
	}

//Separate labels.
	std::vector<std::string> ItemData;
	GetItemFromString(ItemData, DomainString, 0, DomainString.length(), ASCII_PERIOD, false, true);
	for (const auto &StringItem:ItemData)
	{
	//Label length check
		if (StringItem.empty() || StringItem.length() >= DOMAIN_LABEL_MAXSIZE)
			return false;

	//Hyphen is not permitted to appear at either the beginning or end of a label.
		if (StringItem.front() == ASCII_MINUS || StringItem.back() == ASCII_MINUS)
			return false;
	}

//Essentially requires that top-level domain names not be all-numeric.
	for (Index = 0;Index < ItemData.back().length();++Index)
	{
		if (!IsDigit(reinterpret_cast<const uint8_t &>(ItemData.back().at(Index))))
			break;
		else if (Index + 1U >= ItemData.back().length())
			return false;
	}

	return true;
}

//Check domain string acceptable(Wide character version)
bool CheckDomainAcceptable(
	const std::wstring &DomainString)
{
//Domain length check
	if (DomainString.empty() || DomainString.length() >= DOMAIN_WHOLE_MAXSIZE)
		return false;

//Initialization
	static const wchar_t DomainAcceptableList[] = DNS_DOMAIN_ACCEPTABLE_WCS_CHARACTER;
	size_t Index = 0;

//Domain must use acceptable characters.
	for (const auto &StringIter:DomainString)
	{
		for (Index = 0;Index < wcslen(DomainAcceptableList);++Index)
		{
			if (DomainAcceptableList[Index] == StringIter)
				break;
			else if (Index + 1U >= wcslen(DomainAcceptableList))
				return false;
		}
	}

//Separate labels.
	std::vector<std::wstring> ItemData;
	GetItemFromString(ItemData, DomainString, 0, DomainString.length(), ASCII_PERIOD, false, true);
	for (const auto &StringItem:ItemData)
	{
	//Label length check
		if (StringItem.empty() || StringItem.length() >= DOMAIN_LABEL_MAXSIZE)
			return false;

	//Hyphen is not permitted to appear at either the beginning or end of a label.
		if (StringItem.front() == ASCII_MINUS || StringItem.back() == ASCII_MINUS)
			return false;
	}

//Essentially requires that top-level domain names not be all-numeric.
	for (Index = 0;Index < ItemData.back().length();++Index)
	{
		if (!IsDigit(ItemData.back().at(Index)))
			break;
		else if (Index + 1U >= ItemData.back().length())
			return false;
	}

	return true;
}
