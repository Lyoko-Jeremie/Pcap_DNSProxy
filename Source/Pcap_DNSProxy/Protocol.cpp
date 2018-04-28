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


#include "Protocol.h"

//Convert address strings to binary
bool AddressStringToBinary(
	const uint16_t Protocol, 
	const uint8_t * const AddrBuffer, 
	void * const OriginalAddr, 
	ssize_t * const ErrorCode)
{
//Protocol check
	if (Protocol == AF_INET6)
		memset(OriginalAddr, 0, sizeof(in6_addr));
	else if (Protocol == AF_INET)
		memset(OriginalAddr, 0, sizeof(in_addr));
	else 
		return false;

//Initialization
	std::string AddrString(reinterpret_cast<const char *>(AddrBuffer));
	if (ErrorCode != nullptr)
		*ErrorCode = 0;

//Convert address.
#if defined(PLATFORM_WIN_XP)
	sockaddr_storage SockAddr;
	memset(&SockAddr, 0, sizeof(SockAddr));
	socklen_t SockLength = 0;
#else
	ssize_t Result = 0;
#endif
	if (Protocol == AF_INET6)
	{
	//Check address.
		if (AddrString.find(ASCII_COLON) == std::string::npos || AddrString.find(ASCII_PERIOD) != std::string::npos || 
			AddrString.find("::") != AddrString.rfind("::"))
				return false;
		for (const auto &StringIter:AddrString)
		{
			if (StringIter < ASCII_ZERO || 
				(StringIter > ASCII_COLON && StringIter < ASCII_UPPERCASE_A) || 
				(StringIter > ASCII_UPPERCASE_F && StringIter < ASCII_LOWERCASE_A) || 
				StringIter > ASCII_LOWERCASE_F)
					return false;
		}

	//Check abbreviation format.
		if (AddrString.find(ASCII_COLON) == std::string::npos)
		{
			AddrString = ("::");
			AddrString.append(reinterpret_cast<const char *>(AddrBuffer));
		}
		else if (AddrString.find(ASCII_COLON) == AddrString.rfind(ASCII_COLON))
		{
			AddrString.replace(AddrString.find(ASCII_COLON), 1U, ("::"));
		}

	//Convert to binary.
	#if defined(PLATFORM_WIN_XP)
		SockLength = sizeof(sockaddr_in6);
		if (WSAStringToAddressA(
				const_cast<char *>(AddrString.c_str()), 
				AF_INET6, 
				nullptr, 
				reinterpret_cast<sockaddr *>(&SockAddr), 
				&SockLength) == SOCKET_ERROR)
		{
			if (ErrorCode != nullptr)
				*ErrorCode = WSAGetLastError();

			return false;
		}

		memcpy_s(OriginalAddr, sizeof(reinterpret_cast<sockaddr_in6 *>(&SockAddr)->sin6_addr), &reinterpret_cast<sockaddr_in6 *>(&SockAddr)->sin6_addr, sizeof(reinterpret_cast<sockaddr_in6 *>(&SockAddr)->sin6_addr));
	#else
		Result = inet_pton(AF_INET6, AddrString.c_str(), OriginalAddr);
		if (Result == SOCKET_ERROR || Result == 0)
		{
			if (Result != 0 && ErrorCode != nullptr)
				*ErrorCode = WSAGetLastError();

			return false;
		}
	#endif
	}
	else if (Protocol == AF_INET)
	{
	//Check address.
		if (AddrString.find(ASCII_PERIOD) == std::string::npos || AddrString.find(ASCII_COLON) != std::string::npos)
			return false;
		size_t CommaNum = 0;
		for (const auto &StringIter:AddrString)
		{
			if ((StringIter != ASCII_PERIOD && StringIter < ASCII_ZERO) || StringIter > ASCII_NINE)
				return false;
			else if (StringIter == ASCII_PERIOD)
				++CommaNum;
		}

	//Remove zeros before whole data.
		while (AddrString.length() > 1U && AddrString.front() == ASCII_ZERO && AddrString.at(1U) != ASCII_PERIOD)
			AddrString.erase(0, 1U);

	//Check abbreviation format.
		switch (CommaNum)
		{
			case 0:
			{
				AddrString = ("0.0.0.");
				AddrString.append(reinterpret_cast<const char *>(AddrBuffer));
			}break;
			case 1U:
			{
				AddrString.replace(AddrString.find(ASCII_PERIOD), 1U, (".0.0."));
			}break;
			case 2U:
			{
				AddrString.replace(AddrString.find(ASCII_PERIOD), 1U, (".0."));
			}break;
		}

	//Remove zeros before whole data.
		while (AddrString.find(".00") != std::string::npos)
			AddrString.replace(AddrString.find(".00"), 3U, ("."));
		while (AddrString.find(".0") != std::string::npos)
			AddrString.replace(AddrString.find(".0"), 2U, ("."));
		while (AddrString.find("..") != std::string::npos)
			AddrString.replace(AddrString.find(".."), 2U, (".0."));
		if (AddrString.at(AddrString.length() - 1U) == ASCII_PERIOD)
			AddrString.append("0");

	//Convert to binary.
	#if defined(PLATFORM_WIN_XP)
		SockLength = sizeof(sockaddr_in);
		if (WSAStringToAddressA(
				const_cast<char *>(AddrString.c_str()), 
				AF_INET, 
				nullptr, 
				reinterpret_cast<sockaddr *>(&SockAddr), 
				&SockLength) == SOCKET_ERROR)
		{
			if (ErrorCode != nullptr)
				*ErrorCode = WSAGetLastError();

			return false;
		}

		memcpy_s(OriginalAddr, sizeof(reinterpret_cast<sockaddr_in *>(&SockAddr)->sin_addr), &reinterpret_cast<sockaddr_in *>(&SockAddr)->sin_addr, sizeof(reinterpret_cast<sockaddr_in *>(&SockAddr)->sin_addr));
	#else
		Result = inet_pton(AF_INET, AddrString.c_str(), OriginalAddr);
		if (Result == SOCKET_ERROR || Result == 0)
		{
			if (Result != 0 && ErrorCode != nullptr)
				*ErrorCode = WSAGetLastError();

			return false;
		}
	#endif
	}
	else {
		return false;
	}

	return true;
}

//Convert binary address strings
bool BinaryToAddressString(
	const uint16_t Protocol, 
	const void * const OriginalAddr, 
	void * const AddressString, 
	const size_t StringSize, 
	ssize_t * const ErrorCode)
{
//Initialization
	if (ErrorCode != nullptr)
		*ErrorCode = 0;

//Convert address.
#if defined(PLATFORM_WIN_XP)
	sockaddr_storage SockAddr;
	memset(&SockAddr, 0, sizeof(SockAddr));
	if (Protocol == AF_INET6)
	{
		SockAddr.ss_family = AF_INET6;
		reinterpret_cast<sockaddr_in6 *>(&SockAddr)->sin6_addr = *reinterpret_cast<const in6_addr *>(OriginalAddr);
	}
	else if (Protocol == AF_INET)
	{
		SockAddr.ss_family = AF_INET;
		reinterpret_cast<sockaddr_in *>(&SockAddr)->sin_addr = *reinterpret_cast<const in_addr *>(OriginalAddr);
	}
	else {
		return false;
	}

	DWORD BufferLength = static_cast<DWORD>(StringSize);
	if (WSAAddressToStringA(
		reinterpret_cast<sockaddr *>(&SockAddr), 
		sizeof(sockaddr_in6), 
		nullptr, 
		static_cast<LPSTR>(AddressString), 
		&BufferLength) == SOCKET_ERROR)
#else
	if (inet_ntop(Protocol, const_cast<void *>(OriginalAddr), static_cast<char *>(AddressString), static_cast<socklen_t>(StringSize)) == nullptr)
#endif
	{
		if (ErrorCode != nullptr)
			*ErrorCode = WSAGetLastError();

		return false;
	}

	return true;
}

//Compare two addresses
ADDRESS_COMPARE_TYPE AddressesComparing(
	const uint16_t Protocol, 
	const void * const OriginalAddrBegin, 
	const void * const OriginalAddrEnd)
{
	if (Protocol == AF_INET6)
	{
		for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint8_t);++Index)
		{
			if (static_cast<const in6_addr *>(OriginalAddrBegin)->s6_addr[Index] > static_cast<const in6_addr *>(OriginalAddrEnd)->s6_addr[Index])
			{
				return ADDRESS_COMPARE_TYPE::GREATER;
			}
			else if (static_cast<const in6_addr *>(OriginalAddrBegin)->s6_addr[Index] == static_cast<const in6_addr *>(OriginalAddrEnd)->s6_addr[Index])
			{
				if (Index == sizeof(in6_addr) / sizeof(uint8_t) - 1U)
					return ADDRESS_COMPARE_TYPE::EQUAL;
			}
			else {
				return ADDRESS_COMPARE_TYPE::LESS;
			}
		}
	}
	else if (Protocol == AF_INET)
	{
		if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrBegin)->s_addr)) > *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrEnd)->s_addr)))
		{
			return ADDRESS_COMPARE_TYPE::GREATER;
		}
		else if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrBegin)->s_addr)) == *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrEnd)->s_addr)))
		{
			if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrBegin)->s_addr) + sizeof(uint8_t)) > *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrEnd)->s_addr) + sizeof(uint8_t)))
			{
				return ADDRESS_COMPARE_TYPE::GREATER;
			}
			else if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrBegin)->s_addr) + sizeof(uint8_t)) == *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrEnd)->s_addr) + sizeof(uint8_t)))
			{
				if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrBegin)->s_addr) + sizeof(uint8_t) * 2U) > *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrEnd)->s_addr) + sizeof(uint8_t) * 2U))
				{
					return ADDRESS_COMPARE_TYPE::GREATER;
				}
				else if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrBegin)->s_addr) + sizeof(uint8_t) * 2U) == *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrEnd)->s_addr) + sizeof(uint8_t) * 2U))
				{
					if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrBegin)->s_addr) + sizeof(uint8_t) * 3U) > *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrEnd)->s_addr) + sizeof(uint8_t) * 3U))
						return ADDRESS_COMPARE_TYPE::GREATER;
					else if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrBegin)->s_addr) + sizeof(uint8_t) * 3U) == *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddrEnd)->s_addr) + sizeof(uint8_t) * 3U))
						return ADDRESS_COMPARE_TYPE::EQUAL;
					else 
						return ADDRESS_COMPARE_TYPE::LESS;
				}
				else {
					return ADDRESS_COMPARE_TYPE::LESS;
				}
			}
			else {
				return ADDRESS_COMPARE_TYPE::LESS;
			}
		}
		else {
			return ADDRESS_COMPARE_TYPE::LESS;
		}
	}

	return ADDRESS_COMPARE_TYPE::NONE;
}

//Check IPv4/IPv6 special addresses
bool CheckSpecialAddress(
	const uint16_t Protocol, 
	void * const OriginalAddr, 
	const bool IsPrivateUse, 
	const uint8_t * const DomainBuffer)
{
	if (Protocol == AF_INET6)
	{
	//Private using addresses check
		if (IsPrivateUse && 
			((static_cast<in6_addr *>(OriginalAddr)->s6_addr[0] == 0x20 && static_cast<in6_addr *>(OriginalAddr)->s6_addr[1U] == 0x02) || //6to4 relay/tunnel addresses(2002::/16, Section 2 in RFC 3056)
			(static_cast<in6_addr *>(OriginalAddr)->s6_addr[0] >= 0xFC && static_cast<in6_addr *>(OriginalAddr)->s6_addr[0] <= 0xFD) || //Unique Local Unicast addresses/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
			(static_cast<in6_addr *>(OriginalAddr)->s6_addr[0] == 0xFE && static_cast<in6_addr *>(OriginalAddr)->s6_addr[1U] >= 0x80 && static_cast<in6_addr *>(OriginalAddr)->s6_addr[1U] <= 0xBF) || //Link-Local Unicast Contrast addresses/LUC(FE80::/10, Section 2.5.6 in RFC 4291)
			(static_cast<in6_addr *>(OriginalAddr)->s6_addr[0] == 0xFE && static_cast<in6_addr *>(OriginalAddr)->s6_addr[1U] >= 0xC0) || //Site-Local scoped addresses(FEC0::/10, RFC 3879)
			static_cast<in6_addr *>(OriginalAddr)->s6_addr[0] == 0xFF)) //Multicast addresses(FF00::/8, Section 2.7 in RFC 4291)
				return true;

	//Result Blacklist check
		if (DomainBuffer != nullptr)
		{
		//Domain Case Conversion
			std::string DomainString(reinterpret_cast<const char *>(DomainBuffer));
			CaseConvert(DomainString, false);

		//Main check
			std::lock_guard<std::mutex> IPFilterFileMutex(IPFilterFileLock);
			for (const auto &IPFilterFileSetIter:*IPFilterFileSetUsing)
			{
				for (const auto &ResultBlacklistTableIter:IPFilterFileSetIter.ResultBlacklist)
				{
					if (!ResultBlacklistTableIter.Addresses.empty() && ResultBlacklistTableIter.Addresses.front().Begin.ss_family == AF_INET6 && 
						(ResultBlacklistTableIter.PatternString.empty() || std::regex_match(DomainString, ResultBlacklistTableIter.PatternRegex)))
					{
						for (const auto &AddressRangeTableIter:ResultBlacklistTableIter.Addresses)
						{
							if ((AddressRangeTableIter.End.ss_family == AF_INET6 && 
								AddressesComparing(AF_INET6, OriginalAddr, &reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.Begin)->sin6_addr) >= ADDRESS_COMPARE_TYPE::EQUAL && 
								AddressesComparing(AF_INET6, OriginalAddr, &reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.End)->sin6_addr) <= ADDRESS_COMPARE_TYPE::EQUAL) || 
								memcmp(OriginalAddr, &reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.Begin)->sin6_addr, sizeof(in6_addr)) == 0)
									return true;
						}
					}
				}
			}
		}

	//Address Hosts check
		std::lock_guard<std::mutex> HostsFileMutex(HostsFileLock);
		for (const auto &HostsFileSetIter:*HostsFileSetUsing)
		{
			for (const auto &AddressHostsTableIter:HostsFileSetIter.AddressHostsList)
			{
				if (!AddressHostsTableIter.Address_Target.empty() && AddressHostsTableIter.Address_Target.front().first.ss_family == AF_INET6)
				{
					for (const auto &AddressRangeTableIter:AddressHostsTableIter.Address_Source)
					{
					//Check address.
						if ((AddressRangeTableIter.Begin.ss_family == AF_INET6 && AddressRangeTableIter.End.ss_family == AF_INET6 && 
							AddressesComparing(AF_INET6, OriginalAddr, &reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.Begin)->sin6_addr) >= ADDRESS_COMPARE_TYPE::EQUAL && 
							AddressesComparing(AF_INET6, OriginalAddr, &reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.End)->sin6_addr) <= ADDRESS_COMPARE_TYPE::EQUAL) || 
							memcmp(OriginalAddr, &reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.Begin)->sin6_addr, sizeof(in6_addr)) == 0)
						{
							if (AddressHostsTableIter.Address_Target.size() > 1U)
							{
							//Get a random one.
								std::uniform_int_distribution<size_t> RandomDistribution(0, AddressHostsTableIter.Address_Target.size() - 1U);

							//Rewrite address.
								if (AddressHostsTableIter.Address_Target.front().second > 0)
								{
									if (AddressHostsTableIter.Address_Target.front().second < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
									{
										*(static_cast<uint64_t *>(OriginalAddr)) = hton64(ntoh64(*(static_cast<uint64_t *>(OriginalAddr))) & (UINT64_MAX >> AddressHostsTableIter.Address_Target.front().second));
										*(static_cast<uint64_t *>(OriginalAddr)) = hton64(ntoh64(*(static_cast<const uint64_t *>(OriginalAddr))) | ntoh64(*(reinterpret_cast<const uint64_t *>(&reinterpret_cast<const sockaddr_in6 *>(&AddressHostsTableIter.Address_Target.at(RandomDistribution(*GlobalRunningStatus.RandomEngine)).first)->sin6_addr))));
									}
									else {
										*(static_cast<uint64_t *>(OriginalAddr)) = *(reinterpret_cast<const uint64_t *>(&reinterpret_cast<const sockaddr_in6 *>(&AddressHostsTableIter.Address_Target.at(RandomDistribution(*GlobalRunningStatus.RandomEngine)).first)->sin6_addr));
										*(reinterpret_cast<uint64_t *>(static_cast<uint8_t *>(OriginalAddr) + sizeof(in6_addr) / 2U)) = hton64(ntoh64(*(reinterpret_cast<uint64_t *>(static_cast<uint8_t *>(OriginalAddr) + sizeof(in6_addr) / 2U))) & (UINT64_MAX >> (AddressHostsTableIter.Address_Target.front().second - sizeof(in6_addr) * BYTES_TO_BITS / 2U)));
										*(reinterpret_cast<uint64_t *>(static_cast<uint8_t *>(OriginalAddr) + sizeof(in6_addr) / 2U)) = hton64(ntoh64(*(reinterpret_cast<const uint64_t *>(static_cast<uint8_t *>(OriginalAddr) + sizeof(in6_addr) / 2U))) | ntoh64(*(reinterpret_cast<const uint64_t *>(&reinterpret_cast<const sockaddr_in6 *>(&AddressHostsTableIter.Address_Target.at(RandomDistribution(*GlobalRunningStatus.RandomEngine)).first)->sin6_addr))));
									}
								}
								else {
									*static_cast<in6_addr *>(OriginalAddr) = reinterpret_cast<const sockaddr_in6 *>(&AddressHostsTableIter.Address_Target.at(RandomDistribution(*GlobalRunningStatus.RandomEngine)).first)->sin6_addr;
								}
							}
							else {
							//Rewrite address.
								if (AddressHostsTableIter.Address_Target.front().second > 0)
								{
									if (AddressHostsTableIter.Address_Target.front().second < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
									{
										*(static_cast<uint64_t *>(OriginalAddr)) = hton64(ntoh64(*(static_cast<uint64_t *>(OriginalAddr))) & (UINT64_MAX >> AddressHostsTableIter.Address_Target.front().second));
										*(static_cast<uint64_t *>(OriginalAddr)) = hton64(ntoh64(*(static_cast<const uint64_t *>(OriginalAddr))) | ntoh64(*(reinterpret_cast<const uint64_t *>(&reinterpret_cast<const sockaddr_in6 *>(&AddressHostsTableIter.Address_Target.front().first)->sin6_addr))));
									}
									else {
										*(static_cast<uint64_t *>(OriginalAddr)) = *(reinterpret_cast<const uint64_t *>(&reinterpret_cast<const sockaddr_in6 *>(&AddressHostsTableIter.Address_Target.front().first)->sin6_addr));
										*(reinterpret_cast<uint64_t *>(static_cast<uint8_t *>(OriginalAddr) + sizeof(in6_addr) / 2U)) = hton64(ntoh64(*(reinterpret_cast<uint64_t *>(static_cast<uint8_t *>(OriginalAddr) + sizeof(in6_addr) / 2U))) & (UINT64_MAX >> (AddressHostsTableIter.Address_Target.front().second - sizeof(in6_addr) * BYTES_TO_BITS / 2U)));
										*(reinterpret_cast<uint64_t *>(static_cast<uint8_t *>(OriginalAddr) + sizeof(in6_addr) / 2U)) = hton64(ntoh64(*(reinterpret_cast<const uint64_t *>(static_cast<uint8_t *>(OriginalAddr) + sizeof(in6_addr) / 2U))) | ntoh64(*(reinterpret_cast<const uint64_t *>(&reinterpret_cast<const sockaddr_in6 *>(&AddressHostsTableIter.Address_Target.front().first)->sin6_addr))));
									}
								}
								else {
									*static_cast<in6_addr *>(OriginalAddr) = reinterpret_cast<const sockaddr_in6 *>(&AddressHostsTableIter.Address_Target.front().first)->sin6_addr;
								}
							}

							goto StopLoop;
						}
					}
				}
			}
		}
	}
	else if (Protocol == AF_INET)
	{
	//Private using addresses check
		if (IsPrivateUse && 
			(*reinterpret_cast<uint8_t *>(&static_cast<in_addr *>(OriginalAddr)->s_addr) == 0x0A || //Private class A addresses(10.0.0.0/8, Section 3 in RFC 1918)
			*reinterpret_cast<uint8_t *>(&static_cast<in_addr *>(OriginalAddr)->s_addr) == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
			(*reinterpret_cast<uint8_t *>(&static_cast<in_addr *>(OriginalAddr)->s_addr) == 0xA9 && *(reinterpret_cast<uint8_t *>(&static_cast<in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) >= 0xFE) || //Link-local addresses(169.254.0.0/16, Section 1.5 in RFC 3927)
			(*reinterpret_cast<uint8_t *>(&static_cast<in_addr *>(OriginalAddr)->s_addr) == 0xAC && *(reinterpret_cast<uint8_t *>(&static_cast<in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) >= 0x10 && *(reinterpret_cast<uint8_t *>(&static_cast<in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) <= 0x1F) || //Private class B addresses(172.16.0.0/12, Section 3 in RFC 1918)
			(*reinterpret_cast<uint8_t *>(&static_cast<in_addr *>(OriginalAddr)->s_addr) == 0xC0 && *(reinterpret_cast<uint8_t *>(&static_cast<in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) == 0xA8) || //Private class C addresses(192.168.0.0/16, Section 3 in RFC 1918)
			*reinterpret_cast<uint8_t *>(&static_cast<in_addr *>(OriginalAddr)->s_addr) == 0xE0)) //Multicast addresses(224.0.0.0/4, Section 2 in RFC 3171)
				return true;

	//Result Blacklist check
		if (DomainBuffer != nullptr)
		{
		//Domain Case Conversion
			std::string DomainString(reinterpret_cast<const char *>(DomainBuffer));
			CaseConvert(DomainString, false);

		//Main check
			std::lock_guard<std::mutex> IPFilterFileMutex(IPFilterFileLock);
			for (const auto &IPFilterFileSetIter:*IPFilterFileSetUsing)
			{
				for (const auto &ResultBlacklistTableIter:IPFilterFileSetIter.ResultBlacklist)
				{
					if (!ResultBlacklistTableIter.Addresses.empty() && ResultBlacklistTableIter.Addresses.front().Begin.ss_family == AF_INET && 
						(ResultBlacklistTableIter.PatternString.empty() || std::regex_match(DomainString, ResultBlacklistTableIter.PatternRegex)))
					{
						for (const auto &AddressRangeTableIter:ResultBlacklistTableIter.Addresses)
						{
							if ((AddressRangeTableIter.End.ss_family == AF_INET && 
								AddressesComparing(AF_INET, OriginalAddr, &reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr) >= ADDRESS_COMPARE_TYPE::EQUAL && 
								AddressesComparing(AF_INET, OriginalAddr, &reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr) <= ADDRESS_COMPARE_TYPE::EQUAL) || 
								static_cast<in_addr *>(OriginalAddr)->s_addr == reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr)
									return true;
						}
					}
				}
			}
		}

	//Address Hosts check
		std::lock_guard<std::mutex> HostsFileMutex(HostsFileLock);
		for (const auto &HostsFileSetIter:*HostsFileSetUsing)
		{
			for (const auto &AddressHostsTableIter:HostsFileSetIter.AddressHostsList)
			{
				if (!AddressHostsTableIter.Address_Target.empty() && AddressHostsTableIter.Address_Target.front().first.ss_family == AF_INET)
				{
					for (const auto &AddressRangeTableIter:AddressHostsTableIter.Address_Source)
					{
					//Check address.
						if ((AddressRangeTableIter.Begin.ss_family == AF_INET && AddressRangeTableIter.End.ss_family == AF_INET && 
							AddressesComparing(AF_INET, OriginalAddr, &reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr) >= ADDRESS_COMPARE_TYPE::EQUAL && 
							AddressesComparing(AF_INET, OriginalAddr, &reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr) <= ADDRESS_COMPARE_TYPE::EQUAL) || 
							static_cast<in_addr *>(OriginalAddr)->s_addr == reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr)
						{
							if (AddressHostsTableIter.Address_Target.size() > 1U)
							{
							//Get a random one.
								std::uniform_int_distribution<size_t> RandomDistribution(0, AddressHostsTableIter.Address_Target.size() - 1U);

							//Rewrite address.
								if (AddressHostsTableIter.Address_Target.front().second > 0)
								{
									static_cast<in_addr *>(OriginalAddr)->s_addr = htonl(ntohl(static_cast<in_addr *>(OriginalAddr)->s_addr) & (UINT32_MAX >> AddressHostsTableIter.Address_Target.front().second));
									static_cast<in_addr *>(OriginalAddr)->s_addr = htonl(ntohl(static_cast<in_addr *>(OriginalAddr)->s_addr) | ntohl(reinterpret_cast<const sockaddr_in *>(&AddressHostsTableIter.Address_Target.at(RandomDistribution(*GlobalRunningStatus.RandomEngine)).first)->sin_addr.s_addr));
								}
								else {
									*static_cast<in_addr *>(OriginalAddr) = reinterpret_cast<const sockaddr_in *>(&AddressHostsTableIter.Address_Target.at(RandomDistribution(*GlobalRunningStatus.RandomEngine)).first)->sin_addr;
								}
							}
							else {
							//Rewrite address.
								if (AddressHostsTableIter.Address_Target.front().second > 0)
								{
									static_cast<in_addr *>(OriginalAddr)->s_addr = htonl(ntohl(static_cast<in_addr *>(OriginalAddr)->s_addr) & (UINT32_MAX >> AddressHostsTableIter.Address_Target.front().second));
									static_cast<in_addr *>(OriginalAddr)->s_addr = htonl(ntohl(static_cast<in_addr *>(OriginalAddr)->s_addr) | ntohl(reinterpret_cast<const sockaddr_in *>(&AddressHostsTableIter.Address_Target.front().first)->sin_addr.s_addr));
								}
								else {
									*static_cast<in_addr *>(OriginalAddr) = reinterpret_cast<const sockaddr_in *>(&AddressHostsTableIter.Address_Target.front().first)->sin_addr;
								}
							}

							break;
						}
					}
				}
			}
		}
	}

//Jump here to stop loop.
StopLoop:
	return false;
}

//Check routing of addresses
bool CheckAddressRouting(
	const uint16_t Protocol, 
	const void * const OriginalAddr)
{
	std::lock_guard<std::mutex> IPFilterFileMutex(IPFilterFileLock);

//Check address routing.
	if (Protocol == AF_INET6)
	{
		for (const auto &IPFilterFileSetIter:*IPFilterFileSetUsing)
		{
			for (const auto &LocalRoutingTableIter:IPFilterFileSetIter.LocalRoutingList)
			{
				if (!LocalRoutingTableIter.AddressRoutingList_IPv6.empty())
				{
					if (LocalRoutingTableIter.Prefix < sizeof(in6_addr) * BYTES_TO_BITS / 2U)
					{
						if (LocalRoutingTableIter.AddressRoutingList_IPv6.find(ntoh64(*static_cast<const uint64_t *>(OriginalAddr)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS / 2U - LocalRoutingTableIter.Prefix))) != LocalRoutingTableIter.AddressRoutingList_IPv6.end())
							return true;
					}
					else {
						const auto AddrMapIter = LocalRoutingTableIter.AddressRoutingList_IPv6.find(ntoh64(*static_cast<const uint64_t *>(OriginalAddr)));
						if (AddrMapIter != LocalRoutingTableIter.AddressRoutingList_IPv6.end() && 
							AddrMapIter->second.find(ntoh64(*reinterpret_cast<const uint64_t *>(static_cast<const uint8_t *>(OriginalAddr) + sizeof(in6_addr) / 2U)) & (UINT64_MAX << (sizeof(in6_addr) * BYTES_TO_BITS - LocalRoutingTableIter.Prefix))) != AddrMapIter->second.end())
								return true;
					}
				}
			}
		}
	}
	else if (Protocol == AF_INET)
	{
		for (const auto &IPFilterFileSetIter:*IPFilterFileSetUsing)
		{
			for (const auto &LocalRoutingTableIter:IPFilterFileSetIter.LocalRoutingList)
			{
				if (LocalRoutingTableIter.AddressRoutingList_IPv4.find(ntohl(static_cast<const in_addr *>(OriginalAddr)->s_addr) & (UINT32_MAX << (sizeof(in_addr) * BYTES_TO_BITS - LocalRoutingTableIter.Prefix))) != LocalRoutingTableIter.AddressRoutingList_IPv4.end())
					return true;
			}
		}
	}

	return false;
}

//Operation Mode address filter
bool OperationModeFilter(
	const uint16_t Protocol, 
	const void * const OriginalAddr, 
	const LISTEN_MODE OperationMode)
{
//Empty address check
	if ((Protocol == AF_INET6 && CheckEmptyBuffer(OriginalAddr, sizeof(in6_addr))) || //IPv6
		(Protocol == AF_INET && CheckEmptyBuffer(OriginalAddr, sizeof(in_addr)))) //IPv4
	{
		return false;
	}
//Proxy Mode address filter
	else if (OperationMode == LISTEN_MODE::PROXY)
	{
		if ((Protocol == AF_INET6 && memcmp(OriginalAddr, &in6addr_loopback, sizeof(in6_addr)) == 0) || //Loopback address(::1, Section 2.5.3 in RFC 4291
			(Protocol == AF_INET && static_cast<const in_addr *>(OriginalAddr)->s_addr == htonl(INADDR_LOOPBACK))) //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
				return true;
	}
//Private Mode address filter
	else if (OperationMode == LISTEN_MODE::PRIVATE)
	{
	//IPv6
		if (Protocol == AF_INET6)
		{
			if ((static_cast<const in6_addr *>(OriginalAddr)->s6_addr[0] >= 0xFC && static_cast<const in6_addr *>(OriginalAddr)->s6_addr[0] <= 0xFD) || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
				(static_cast<const in6_addr *>(OriginalAddr)->s6_addr[0] == 0xFE && static_cast<const in6_addr *>(OriginalAddr)->s6_addr[1U] >= 0x80 && static_cast<const in6_addr *>(OriginalAddr)->s6_addr[1U] <= 0xBF) || //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
				(memcmp(OriginalAddr, &in6addr_loopback, sizeof(in6_addr)) == 0)) //Loopback address(::1, Section 2.5.3 in RFC 4291
					return true;
		}
	//IPv4
		else if (Protocol == AF_INET)
		{
			if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) == 0x0A || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
				*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
				(*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) == 0xA9 && *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) >= 0xFE) || //Link-local addresses(169.254.0.0/16, Section 1.5 in RFC 3927)
				(*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) == 0xAC && *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) >= 0x10 && *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) <= 0x1F) || //Private class B address(172.16.0.0/12, Section 3 in RFC 1918)
				(*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) == 0xC0 && *(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) == 0xA8)) //Private class C address(192.168.0.0/16, Section 3 in RFC 1918)
					return true;
		}
	}
//Server Mode address filter
	else if (OperationMode == LISTEN_MODE::SERVER)
	{
		return true;
	}
//Custom Mode address filter
	else if (OperationMode == LISTEN_MODE::CUSTOM)
	{
		std::lock_guard<std::mutex> IPFilterFileMutex(IPFilterFileLock);
		if (Protocol == AF_INET6)
		{
		//Permit mode
			if (Parameter.IsIPFilterTypePermit)
			{
				for (const auto &IPFilterFileSetIter:*IPFilterFileSetUsing)
				{
					for (const auto &AddressRangeTableIter:IPFilterFileSetIter.AddressRange)
					{
					//Check protocol and level.
						if (AddressRangeTableIter.Begin.ss_family != AF_INET6 || Parameter.IPFilterLevel == 0 || AddressRangeTableIter.Level >= Parameter.IPFilterLevel)
							continue;

					//Check address.
						for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint8_t);++Index)
						{
							if (static_cast<const in6_addr *>(OriginalAddr)->s6_addr[Index] > reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.Begin)->sin6_addr.s6_addr[Index] && 
								static_cast<const in6_addr *>(OriginalAddr)->s6_addr[Index] < reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.End)->sin6_addr.s6_addr[Index])
							{
								return true;
							}
							else if (static_cast<const in6_addr *>(OriginalAddr)->s6_addr[Index] == reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.Begin)->sin6_addr.s6_addr[Index] || 
								static_cast<const in6_addr *>(OriginalAddr)->s6_addr[Index] == reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.End)->sin6_addr.s6_addr[Index])
							{
								if (Index == sizeof(in6_addr) / sizeof(uint8_t) - 1U)
									return true;
							}
						}
					}
				}

				return false;
			}
		//Deny mode
			else {
				for (const auto &IPFilterFileSetIter:*IPFilterFileSetUsing)
				{
					for (const auto &AddressRangeTableIter:IPFilterFileSetIter.AddressRange)
					{
					//Check protocol and level.
						if (AddressRangeTableIter.Begin.ss_family != AF_INET6 || Parameter.IPFilterLevel == 0 || AddressRangeTableIter.Level >= Parameter.IPFilterLevel)
							continue;

					//Check address.
						for (size_t Index = 0;Index < sizeof(in6_addr) / sizeof(uint8_t);++Index)
						{
							if (static_cast<const in6_addr *>(OriginalAddr)->s6_addr[Index] > reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.Begin)->sin6_addr.s6_addr[Index] && 
								static_cast<const in6_addr *>(OriginalAddr)->s6_addr[Index] < reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.End)->sin6_addr.s6_addr[Index])
							{
								return false;
							}
							else if (static_cast<const in6_addr *>(OriginalAddr)->s6_addr[Index] == reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.Begin)->sin6_addr.s6_addr[Index] || 
								static_cast<const in6_addr *>(OriginalAddr)->s6_addr[Index] == reinterpret_cast<const sockaddr_in6 *>(&AddressRangeTableIter.End)->sin6_addr.s6_addr[Index])
							{
								if (Index == sizeof(in6_addr) / sizeof(uint8_t) - 1U)
									return false;
							}
						}
					}
				}

				return true;
			}
		}
		else if (Protocol == AF_INET)
		{
		//Permit mode
			if (Parameter.IsIPFilterTypePermit)
			{
				for (const auto &IPFilterFileSetIter:*IPFilterFileSetUsing)
				{
					for (const auto &AddressRangeTableIter:IPFilterFileSetIter.AddressRange)
					{
					//Check protocol and level.
						if (AddressRangeTableIter.Begin.ss_family != AF_INET || Parameter.IPFilterLevel == 0 || AddressRangeTableIter.Level >= Parameter.IPFilterLevel)
							continue;

					//Check address.
						if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) > *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr)) && 
							*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) < *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr)))
						{
							return true;
						}
						else if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr)) || 
							*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr)))
						{
							if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) > *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr) + sizeof(uint8_t)) && 
								*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) < *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr) + sizeof(uint8_t)))
							{
								return true;
							}
							else if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr) + sizeof(uint8_t)) || 
								*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr) + sizeof(uint8_t)))
							{
								if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 2U) > *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr) + sizeof(uint8_t) * 2U) && 
									*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 2U) < *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr) + sizeof(uint8_t) * 2U))
								{
									return true;
								}
								else if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 2U) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr) + sizeof(uint8_t) * 2U) || 
									*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 2U) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr) + sizeof(uint8_t) * 2U))
								{
									if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 3U) >= *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr) + sizeof(uint8_t) * 3U) && 
										*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 3U) <= *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr) + sizeof(uint8_t) * 3U))
											return true;
								}
							}
						}
					}
				}

				return false;
			}
		//Deny mode
			else {
				for (const auto &IPFilterFileSetIter:*IPFilterFileSetUsing)
				{
					for (const auto &AddressRangeTableIter:IPFilterFileSetIter.AddressRange)
					{
					//Check protocol and level.
						if (AddressRangeTableIter.Begin.ss_family != AF_INET || Parameter.IPFilterLevel == 0 || AddressRangeTableIter.Level >= Parameter.IPFilterLevel)
							continue;

					//Check address.
						if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) > *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr)) && 
							*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) < *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr)))
						{
							return false;
						}
						else if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr)) || 
							*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr)) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr)))
						{
							if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) > *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr) + sizeof(uint8_t)) && 
								*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) < *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr) + sizeof(uint8_t)))
							{
								return false;
							}
							else if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr) + sizeof(uint8_t)) || 
								*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t)) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr) + sizeof(uint8_t)))
							{
								if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 2U) > *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr) + sizeof(uint8_t) * 2U) && 
									*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 2U) < *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr) + sizeof(uint8_t) * 2U))
								{
									return false;
								}
								else if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 2U) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr) + sizeof(uint8_t) * 2U) || 
									*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 2U) == *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr) + sizeof(uint8_t) * 2U))
								{
									if (*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 3U) >= *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.Begin)->sin_addr.s_addr) + sizeof(uint8_t) * 3U) && 
										*(reinterpret_cast<const uint8_t *>(&static_cast<const in_addr *>(OriginalAddr)->s_addr) + sizeof(uint8_t) * 3U) <= *(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(&AddressRangeTableIter.End)->sin_addr.s_addr) + sizeof(uint8_t) * 3U))
											return false;
								}
							}
						}
					}
				}

				return true;
			}
		}
		else {
			return false;
		}
	}

	return false;
}

//Count DNS Query Name length
size_t CheckQueryNameLength(
	const uint8_t * const Buffer)
{
	size_t Index = 0;
	for (Index = 0;Index < DOMAIN_MAXSIZE;++Index)
	{
		if (Buffer[Index] == 0)
			break;
		else if (Buffer[Index] >= DNS_POINTER_8_BITS)
			return Index + sizeof(uint16_t) - 1U;
	}

	return Index;
}

//Check DNS query data
bool CheckQueryData(
	DNS_PACKET_DATA * const PacketStructure, 
	uint8_t * const SendBuffer, 
	const size_t SendSize, 
	SOCKET_DATA &LocalSocketData)
{
//Check address(UDP monitor and TCP monitor when accepting connections).
	if (PacketStructure == nullptr || SendBuffer == nullptr || SendSize < DNS_PACKET_MINSIZE || PacketStructure->Protocol == IPPROTO_UDP)
	{
	//IPv6
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6))
		{
			if (!OperationModeFilter(AF_INET6, &reinterpret_cast<const sockaddr_in6 *>(&LocalSocketData.SockAddr)->sin6_addr, Parameter.OperationMode))
				return false;
		}
	//IPv4
		else if (LocalSocketData.AddrLen == sizeof(sockaddr_in))
		{
			if (!OperationModeFilter(AF_INET, &reinterpret_cast<const sockaddr_in *>(&LocalSocketData.SockAddr)->sin_addr, Parameter.OperationMode))
				return false;
		}
		else {
			return false;
		}
	}

//Check address only.
	if (PacketStructure == nullptr || SendBuffer == nullptr || PacketStructure->Protocol == 0 || PacketStructure->Length < DNS_PACKET_MINSIZE)
		return true;

//Check request packet data.
	const auto DNS_Header = reinterpret_cast<dns_hdr *>(PacketStructure->Buffer);
	if (
	//Base DNS header check
//		DNS_Header->ID == 0 || //ID must not be set 0.
//		DNS_Header->Flags == 0 || //Flags must not be set 0.
	//Extended DNS header check
		(Parameter.PacketCheck_DNS && 
	//Must not set Response bit.
		((ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RESPONSE) > 0 || 
	//Must not set Truncated bit.
		(ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_TC) > 0 || 
	//Must not set Reserved bit.
		(ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_Z) > 0 || 
	//Must not set RCode.
		(ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RCODE) > 0 || 
	//Question resource records counts must be set 0 (when DNS Cookies is enabled) or 1.
		(DNS_Header->Question != 0 && ntohs(DNS_Header->Question) != UINT16_NUM_ONE) || 
	//DNS Cookies request must contain EDNS Label.
		(DNS_Header->Question == 0 && 
		(DNS_Header->Answer != 0 || DNS_Header->Authority != 0 || ntohs(DNS_Header->Additional) != UINT16_NUM_ONE)) || 
	//Answer resource records counts must be set 0.
		DNS_Header->Answer > 0 || 
	//Authority resource records counts must be set 0.
		DNS_Header->Authority > 0 || 
	//Additional resource records counts must be set 0 or 1.
		ntohs(DNS_Header->Additional) > UINT16_NUM_ONE)))
	{
	//Set Response bit and RCode Format Error.
		DNS_Header->Flags = htons(DNS_FLAG_SET_R_FE);

	//Send request.
		if (PacketStructure->Length >= DNS_PACKET_MINSIZE)
			SendToRequester(PacketStructure->Protocol, PacketStructure->Buffer, PacketStructure->Length, PacketStructure->BufferSize, LocalSocketData);

		return false;
	}

//Mark normal request Question resource record length.
	if (DNS_Header->Question != 0)
		PacketStructure->Records_QuestionLen = CheckQueryNameLength(PacketStructure->Buffer + sizeof(dns_hdr)) + NULL_TERMINATE_LENGTH + sizeof(dns_qry);

//Scan all resource records.
	size_t PacketIndex = sizeof(dns_hdr) + PacketStructure->Records_QuestionLen, CountIndex = 0;
	auto IsDisableEDNS_Label = false, IsAlreadyEDNS_ClientSubnet = false, IsAlreadyEDNS_Cookies = false;
	for (CountIndex = 0;CountIndex < static_cast<size_t>(ntohs(DNS_Header->Answer) + ntohs(DNS_Header->Authority) + ntohs(DNS_Header->Additional));++CountIndex)
	{
	//Domain pointer check
		if (PacketIndex + sizeof(uint16_t) < PacketStructure->Length && PacketStructure->Buffer[PacketIndex] >= DNS_POINTER_8_BITS)
		{
			const uint16_t DNS_Pointer = ntohs(*reinterpret_cast<uint16_t *>(PacketStructure->Buffer + PacketIndex)) & DNS_POINTER_BIT_GET_LOCATE;
			if (DNS_Pointer >= PacketStructure->Length || DNS_Pointer < sizeof(dns_hdr) || DNS_Pointer == PacketIndex || DNS_Pointer == PacketIndex + 1U)
				return false;
		}

	//Resource records name check
		auto RecordLength = CheckQueryNameLength(PacketStructure->Buffer + PacketIndex) + NULL_TERMINATE_LENGTH;
		if (PacketIndex + RecordLength + sizeof(dns_record_standard) > PacketStructure->Length)
			return false;

	//Standard resource records check
		const auto DNS_Record_Standard = reinterpret_cast<dns_record_standard *>(PacketStructure->Buffer + PacketIndex + RecordLength);
		if (PacketIndex + RecordLength + sizeof(dns_record_standard) + ntohs(DNS_Record_Standard->Length) > PacketStructure->Length)
			return false;

	//Mark exist EDNS Label(OPT Record).
		if (ntohs(DNS_Record_Standard->Type) == DNS_TYPE_OPT)
		{
		//Mark EDNS Label at the first time.
			if (PacketStructure->EDNS_Location == 0 && PacketStructure->EDNS_Length == 0)
			{
				PacketStructure->EDNS_Location = PacketIndex;
				PacketStructure->EDNS_Length = RecordLength + sizeof(dns_record_standard) + ntohs(DNS_Record_Standard->Length);

			//Mark EDNS Label Options.
				for (size_t OptionIndex = PacketStructure->EDNS_Location + sizeof(edns_header);OptionIndex < PacketStructure->EDNS_Location + PacketStructure->EDNS_Length;)
				{
					const auto EDNS_DataOption = reinterpret_cast<edns_data_option *>(PacketStructure->Buffer + OptionIndex);
					if (ntohs(EDNS_DataOption->Code) == EDNS_CODE_CSUBNET)
						IsAlreadyEDNS_ClientSubnet = true;
					else if (ntohs(EDNS_DataOption->Code) == EDNS_CODE_COOKIES)
						IsAlreadyEDNS_Cookies = true;

				//Next loop.
					OptionIndex += sizeof(edns_data_option) + ntohs(EDNS_DataOption->Length);
				}
			}
		//Only one EDNS Label/OPT Record can be stored in a DNS packet.
			else {
			//Set Response bit and RCode Format Error.
				DNS_Header->Flags = htons(DNS_FLAG_SET_R_FE);

			//Send request.
				if (PacketStructure->Length >= DNS_PACKET_MINSIZE)
					SendToRequester(PacketStructure->Protocol, PacketStructure->Buffer, PacketStructure->Length, PacketStructure->BufferSize, LocalSocketData);

				return false;
			}
		}
	//Strict resource record TTL check when enforce strict RFC 2181(https://tools.ietf.org/html/rfc2181) compliance
	//TTL in resource records must less than 2 ^ 31(2147483647).
		else if (Parameter.DataCheck_RRSetTTL && (ntohl(DNS_Record_Standard->TTL) & DNS_RECORD_TTL_GET_BIT_HIGHEST) != 0)
		{
			return false;
		}
	//Some SIG and TSIG require that locate at the end of the packet, temporary disable EDNS Label.
		else if (ntohs(DNS_Record_Standard->Type) == DNS_TYPE_SIG || ntohs(DNS_Record_Standard->Type) == DNS_TYPE_TSIG)
		{
			IsDisableEDNS_Label = true;
		}

	//Mark data structure.
		RecordLength += sizeof(dns_record_standard) + ntohs(DNS_Record_Standard->Length);
		PacketStructure->Records_Location.push_back(PacketIndex);
		PacketStructure->Records_Length.push_back(RecordLength);
		PacketIndex += RecordLength;

	//Mark counts.
		if (CountIndex < static_cast<size_t>(ntohs(DNS_Header->Answer)))
			++PacketStructure->Records_AnswerCount;
		else if (CountIndex < static_cast<size_t>(ntohs(DNS_Header->Answer) + ntohs(DNS_Header->Authority)))
			++PacketStructure->Records_AuthorityCount;
		else if (CountIndex < static_cast<size_t>(ntohs(DNS_Header->Answer) + ntohs(DNS_Header->Authority) + ntohs(DNS_Header->Additional)))
			++PacketStructure->Records_AdditionalCount;
		else 
			return false;
	}

//DNS data structure check and move EDNS Label to the end of packet.
	if ((Parameter.PacketCheck_DNS && 
	//Resource record counts are not match to DNS header.
		(PacketStructure->Records_AnswerCount != static_cast<size_t>(ntohs(DNS_Header->Answer)) || 
		PacketStructure->Records_AuthorityCount != static_cast<size_t>(ntohs(DNS_Header->Authority)) || 
		PacketStructure->Records_AdditionalCount != static_cast<size_t>(ntohs(DNS_Header->Additional)) || 
	//DNS Server Cookies check
		(PacketStructure->Records_QuestionLen == 0 && 
		(PacketStructure->EDNS_Location == 0 || PacketStructure->EDNS_Length == 0 || !IsAlreadyEDNS_Cookies)))) || 
	//Move EDNS Label to the tail.
		(!IsDisableEDNS_Label && !Move_EDNS_LabelToEnd(PacketStructure)))
	{
	//Set Response bit and Recode Format Error.
		DNS_Header->Flags = htons(DNS_FLAG_SET_R_FE);

	//Send request.
		if (PacketStructure->Length >= DNS_PACKET_MINSIZE)
			SendToRequester(PacketStructure->Protocol, PacketStructure->Buffer, PacketStructure->Length, PacketStructure->BufferSize, LocalSocketData);

		return false;
	}

//EDNS Label
	auto IsNeedTruncated = false;
	if (!IsDisableEDNS_Label && DNS_Header->Question != 0 && Parameter.EDNS_Label)
	{
		if ((LocalSocketData.AddrLen == sizeof(sockaddr_in6) && !CheckSpecialAddress(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(const_cast<sockaddr_storage *>(&LocalSocketData.SockAddr))->sin6_addr, true, nullptr)) || //IPv6
			(LocalSocketData.AddrLen == sizeof(sockaddr_in) && !CheckSpecialAddress(AF_INET, &reinterpret_cast<sockaddr_in *>(const_cast<sockaddr_storage *>(&LocalSocketData.SockAddr))->sin_addr, true, nullptr))) //IPv4
				IsNeedTruncated = !Add_EDNS_LabelToPacket(PacketStructure, IsAlreadyEDNS_ClientSubnet, IsAlreadyEDNS_Cookies, const_cast<SOCKET_DATA *>(&LocalSocketData));
		else 
			IsNeedTruncated = !Add_EDNS_LabelToPacket(PacketStructure, IsAlreadyEDNS_ClientSubnet, IsAlreadyEDNS_Cookies, nullptr);
	}

//UDP Truncated check
	if (PacketStructure->Protocol == IPPROTO_UDP && 
		(IsNeedTruncated || 
		(!IsNeedTruncated && PacketStructure->Length + EDNS_RECORD_MAXSIZE > Parameter.EDNS_PayloadSize)))
	{
	//Set Response bit and Truncated bit.
		DNS_Header->Flags = htons(DNS_FLAG_SET_R_TC);

	//Send request.
		if (PacketStructure->Length >= DNS_PACKET_MINSIZE)
			SendToRequester(PacketStructure->Protocol, PacketStructure->Buffer, PacketStructure->Length, PacketStructure->BufferSize, LocalSocketData);

		return false;
	}

//Check Hosts.
	memset(SendBuffer, 0, SendSize);
	const auto DataLength = CheckHostsProcess(PacketStructure, SendBuffer, SendSize, LocalSocketData);
	if (DataLength >= DNS_PACKET_MINSIZE)
	{
		SendToRequester(PacketStructure->Protocol, SendBuffer, DataLength, SendSize, LocalSocketData);
		return false;
	}

	return true;
}

//Connection stream finished check
bool CheckConnectionStreamFin(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint8_t * const Stream, 
	const size_t Length)
{
//HTTP version 1.x CONNECT method
	if (RequestType == REQUEST_PROCESS_TYPE::HTTP_CONNECT_1)
	{
	//Length check
		if (strnlen_s(reinterpret_cast<const char *>(Stream), Length + PADDING_RESERVED_BYTES) > Length)
			return true;

	//HTTP version 1.x response
		std::string DataStream(reinterpret_cast<const char *>(Stream));
		if (DataStream.find("\r\n\r\n") != std::string::npos && 
			(DataStream.compare(0, strlen("HTTP/1.0 200 "), ("HTTP/1.0 200 ")) == 0 || 
			DataStream.compare(0, strlen("HTTP/1.1 200 "), ("HTTP/1.1 200 ")) == 0))
				return true;
	}
//HTTP version 2 CONNECT method
	else if (RequestType == REQUEST_PROCESS_TYPE::HTTP_CONNECT_2)
	{
	//HTTP version 1.x response and HTTP version 2 large length are not supported.
		if (*Stream != 0)
		{
		//Length check
			if (strnlen_s(reinterpret_cast<const char *>(Stream), Length + PADDING_RESERVED_BYTES) > Length)
				return true;

		//HTTP version 1.x response
			std::string DataStream(reinterpret_cast<const char *>(Stream));
			if (DataStream.find("\r\n\r\n") != std::string::npos)
				return true;
		}
	//HTTP version 2 response
		else if (Length >= sizeof(http2_frame_hdr))
		{
			for (size_t Index = 0;Index < Length;)
			{
			//Frame check
				const auto FrameHeader = const_cast<http2_frame_hdr *>(reinterpret_cast<const http2_frame_hdr *>(Stream + Index));
				if (Index + sizeof(http2_frame_hdr) + ntohs(FrameHeader->Length_Low) > Length || 
				//DATA frame must set PADDED and END_STREAM flag.
					(FrameHeader->Type == HTTP_2_FRAME_TYPE_DATA && 
					((FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_PADDED) != 0 || (FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_END_STREAM) != 0)) || 
				//HEADERS frame must set PADDED, END_HEADERS, END_STREAM and PRIORITY flag.
					(FrameHeader->Type == HTTP_2_FRAME_TYPE_HEADERS && 
					((FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_PADDED) != 0 || (FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_END_HEADERS) != 0 || 
					(FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_END_STREAM) != 0 || (FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_PRIORITY) != 0)) || 
				//PRIORITY frame is not supported.
					FrameHeader->Type == HTTP_2_FRAME_TYPE_PRIORITY || 
				//RST_STREAM frame
					FrameHeader->Type == HTTP_2_FRAME_TYPE_RST_STREAM || 
				//SETTINGS frame is ignored.
				//PUSH_PROMISE frame is not supported.
				//PING frame is ignored.
				//GOAWAY frame
					FrameHeader->Type == HTTP_2_FRAME_TYPE_GOAWAY || 
				//WINDOW_UPDATE frame is ignored.
				//CONTINUATION frame must set END_HEADERS flag.
					(FrameHeader->Type == HTTP_2_FRAME_TYPE_CONTINUATION && (FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_END_HEADERS) != 0))
						return true;

			//Length check
				if (Index + sizeof(http2_frame_hdr) + ntohs(FrameHeader->Length_Low) == Length)
					break;
				else 
					Index += sizeof(http2_frame_hdr) + ntohs(FrameHeader->Length_Low);
			}
		}
	}
//HTTP CONNECT shutdown connection.
	else if (RequestType == REQUEST_PROCESS_TYPE::HTTP_CONNECT_SHUTDOWN)
	{
//		if (Length >= sizeof(http2_frame_hdr))
			return true;
	}
//SOCKS client selection
	else if (RequestType == REQUEST_PROCESS_TYPE::SOCKS_CLIENT_SELECTION)
	{
		if (Length >= sizeof(socks_server_selection))
			return true;
	}
//SOCKS username/password authentication
	else if (RequestType == REQUEST_PROCESS_TYPE::SOCKS_USER_AUTH)
	{
		if (Length >= sizeof(socks_server_user_authentication))
			return true;
	}
//SOCKS 5 server command reply
	else if (RequestType == REQUEST_PROCESS_TYPE::SOCKS_5_COMMAND_REPLY)
	{
		if (Length >= sizeof(socks5_server_command_reply))
			return true;
	}
//SOCKS 4/4a server command reply
	else if (RequestType == REQUEST_PROCESS_TYPE::SOCKS_4_COMMAND_REPLY)
	{
		if (Length >= sizeof(socks4_server_command_reply))
			return true;
	}
#if defined(ENABLE_TLS)
//TLS transport
	else if (RequestType == REQUEST_PROCESS_TYPE::TLS_HANDSHAKE || RequestType == REQUEST_PROCESS_TYPE::TLS_TRANSPORT || RequestType == REQUEST_PROCESS_TYPE::TLS_SHUTDOWN)
	{
	//TLS base record scanning
		if (Length >= sizeof(tls_base_record) && 
			reinterpret_cast<const tls_base_record *>(Stream)->ContentType > 0 && 
			ntohs(reinterpret_cast<const tls_base_record *>(Stream)->Version) >= TLS_VERSION_MIN)
		{
		//TLS base record format check
			if (ntohs(reinterpret_cast<const tls_base_record *>(Stream)->Length) + sizeof(tls_base_record) == Length)
			{
				return true;
			}
			else if (ntohs(reinterpret_cast<const tls_base_record *>(Stream)->Length) + sizeof(tls_base_record) < Length)
			{
			//Scan all TLS base records in whole packet.
				size_t InnerLength = ntohs(reinterpret_cast<const tls_base_record *>(Stream)->Length);
				for (size_t Index = 1U;;++Index)
				{
					if (sizeof(tls_base_record) * Index + InnerLength == Length)
					{
						return true;
					}
					else if (sizeof(tls_base_record) * Index + InnerLength < Length)
					{
						if (sizeof(tls_base_record) * (Index + 1U) + InnerLength <= Length)
							InnerLength += ntohs(reinterpret_cast<const tls_base_record *>(Stream + sizeof(tls_base_record) * Index + InnerLength)->Length);
						else 
							break;
					}
					else {
						break;
					}
				}
			}
		}
	}
#endif
//TCP DNS response
	else if ((RequestType == REQUEST_PROCESS_TYPE::SOCKS_MAIN || RequestType == REQUEST_PROCESS_TYPE::TCP_NORMAL || RequestType == REQUEST_PROCESS_TYPE::TCP_WITHOUT_REGISTER) && 
		Length > sizeof(uint16_t) && 
		ntohs(*(reinterpret_cast<const uint16_t *>(Stream))) >= DNS_PACKET_MINSIZE && 
		ntohs(*(reinterpret_cast<const uint16_t *>(Stream))) + sizeof(uint16_t) >= Length)
	{
		return true;
	}

	return false;
}

//Check response CNAME resource records
size_t CheckResponse_CNAME(
	uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize, 
	const size_t CanonicalIndex, 
	const size_t CanonicalLength, 
	size_t &IncreaseCount)
{
//Mark whole DNS query.
	std::string Domain;
	auto DataLength = MarkWholePacketQuery(Buffer, Length, Buffer + CanonicalIndex, CanonicalIndex, Domain);
	if (DataLength <= DOMAIN_MINSIZE || DataLength >= DOMAIN_MAXSIZE || Domain.empty())
		return EXIT_FAILURE;
	else 
		DataLength = 0;
	const auto DNS_Header = reinterpret_cast<dns_hdr *>(Buffer);
	const auto DNS_Query = reinterpret_cast<dns_qry *>(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer));
	IncreaseCount = 0;
	CaseConvert(Domain, false);

//Make domain reversed.
	std::string ReverseDomain(Domain);
	MakeStringReversed(ReverseDomain);
	ReverseDomain.append(".");
	auto IsMatchItem = false;

//CNAME Hosts
	std::lock_guard<std::mutex> HostsFileMutex(HostsFileLock);
	for (const auto &HostsFileSetIter:*HostsFileSetUsing)
	{
		for (const auto &HostsTableIter:HostsFileSetIter.HostsList_CNAME)
		{
			IsMatchItem = false;

		//Dnsmasq normal mode, please visit http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html.
			if (HostsTableIter.IsStringMatching && !HostsTableIter.PatternOrDomainString.empty())
			{
				if (HostsTableIter.PatternOrDomainString == ("#") || //Dnsmasq "#" matches any domain.
					(HostsTableIter.PatternOrDomainString.front() == ReverseDomain.front() && //Quick check to reduce resource using
					CompareStringReversed(HostsTableIter.PatternOrDomainString, ReverseDomain)))
						IsMatchItem = true;
			}
		//Regex mode
			else if (std::regex_match(Domain, HostsTableIter.PatternRegex))
			{
				IsMatchItem = true;
			}

		//Match hosts.
			if (IsMatchItem)
			{
			//Check white and banned hosts list, empty record type list check
				DataLength = CheckWhiteBannedHostsProcess(Length, HostsTableIter, DNS_Header, DNS_Query, nullptr, nullptr);
				if (DataLength >= DNS_PACKET_MINSIZE)
					return DataLength;
				else if (HostsTableIter.RecordTypeList.empty())
					continue;

			//AAAA record(IPv6)
				if (ntohs(DNS_Query->Type) == DNS_TYPE_AAAA && HostsTableIter.RecordTypeList.front() == htons(DNS_TYPE_AAAA))
				{
				//Set header flags and convert DNS query to DNS response packet.
					DNS_Header->Flags = htons(DNS_FLAG_SQR_NE);
					DataLength = CanonicalIndex + CanonicalLength;
					if (DataLength < BufferSize)
						memset(Buffer + DataLength, 0, BufferSize - DataLength);
					else 
						return EXIT_FAILURE;

				//Hosts load balancing
					size_t RandomIndex = 0;
					if (HostsTableIter.AddrOrTargetList.size() > 1U)
					{
						std::uniform_int_distribution<size_t> RandomDistribution(0, HostsTableIter.AddrOrTargetList.size() - 1U);
						RandomIndex = RandomDistribution(*GlobalRunningStatus.RandomEngine);
					}

				//Make response.
					size_t Index = 0;
					for (Index = 0;Index < HostsTableIter.AddrOrTargetList.size();++Index)
					{
					//Make resource records.
						const auto DNS_Record = reinterpret_cast<dns_record_aaaa *>(Buffer + DataLength);
						DataLength += sizeof(dns_record_aaaa);
						DNS_Record->Name = htons(static_cast<uint16_t>(CanonicalIndex) | DNS_POINTER_16_BITS);
						DNS_Record->Classes = htons(DNS_CLASS_INTERNET);
						if (Parameter.HostsDefaultTTL > 0)
							DNS_Record->TTL = htonl(Parameter.HostsDefaultTTL);
						else 
							DNS_Record->TTL = htonl(DEFAULT_HOSTS_TTL);
						DNS_Record->Type = htons(DNS_TYPE_AAAA);
						DNS_Record->Length = htons(sizeof(DNS_Record->Address));
						if (Index == 0)
							DNS_Record->Address = HostsTableIter.AddrOrTargetList.at(RandomIndex).IPv6.sin6_addr;
						else if (Index == RandomIndex)
							DNS_Record->Address = HostsTableIter.AddrOrTargetList.front().IPv6.sin6_addr;
						else 
							DNS_Record->Address = HostsTableIter.AddrOrTargetList.at(Index).IPv6.sin6_addr;

					//Hosts items length check
						if (DataLength + sizeof(dns_record_aaaa) > BufferSize)
						{
							++Index;
							break;
						}
					}

				//Set DNS resource record counts.
					DNS_Header->Authority = 0;
					DNS_Header->Additional = 0;
					IncreaseCount = Index;
					return DataLength;
				}
			//A record(IPv4)
				else if (ntohs(DNS_Query->Type) == DNS_TYPE_A && HostsTableIter.RecordTypeList.front() == htons(DNS_TYPE_A))
				{
				//Set header flags and convert DNS query to DNS response packet.
					DNS_Header->Flags = htons(DNS_FLAG_SQR_NE);
					DataLength = CanonicalIndex + CanonicalLength;
					if (DataLength < BufferSize)
						memset(Buffer + DataLength, 0, BufferSize - DataLength);
					else 
						return EXIT_FAILURE;

				//Hosts load balancing
					size_t RandomIndex = 0;
					if (HostsTableIter.AddrOrTargetList.size() > 1U)
					{
						std::uniform_int_distribution<size_t> RandomDistribution(0, HostsTableIter.AddrOrTargetList.size() - 1U);
						RandomIndex = RandomDistribution(*GlobalRunningStatus.RandomEngine);
					}

				//Make response.
					size_t Index = 0;
					for (Index = 0;Index < HostsTableIter.AddrOrTargetList.size();++Index)
					{
					//Make resource records.
						const auto DNS_Record = reinterpret_cast<dns_record_a *>(Buffer + DataLength);
						DataLength += sizeof(dns_record_a);
						DNS_Record->Name = htons(static_cast<uint16_t>(CanonicalIndex) | DNS_POINTER_16_BITS);
						DNS_Record->Classes = htons(DNS_CLASS_INTERNET);
						if (Parameter.HostsDefaultTTL > 0)
							DNS_Record->TTL = htonl(Parameter.HostsDefaultTTL);
						else 
							DNS_Record->TTL = htonl(DEFAULT_HOSTS_TTL);
						DNS_Record->Type = htons(DNS_TYPE_A);
						DNS_Record->Length = htons(sizeof(DNS_Record->Address));
						if (Index == 0)
							DNS_Record->Address = HostsTableIter.AddrOrTargetList.at(RandomIndex).IPv4.sin_addr;
						else if (Index == RandomIndex)
							DNS_Record->Address = HostsTableIter.AddrOrTargetList.front().IPv4.sin_addr;
						else 
							DNS_Record->Address = HostsTableIter.AddrOrTargetList.at(Index).IPv4.sin_addr;

					//Hosts items length check
						if (DataLength + sizeof(dns_record_a) > BufferSize)
						{
							++Index;
							break;
						}
					}

				//Set DNS resource record counts.
					DNS_Header->Authority = 0;
					DNS_Header->Additional = 0;
					IncreaseCount = Index;
					return DataLength;
				}
			}
		}
	}

	return EXIT_SUCCESS;
}

//Check DNS response results
size_t CheckResponseData(
	const REQUEST_PROCESS_TYPE ResponseType, 
	uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize, 
	size_t * const PacketEDNS_Offset, 
	size_t * const PacketEDNS_Length)
{
//DNS Options part
	const auto DNS_Header = reinterpret_cast<dns_hdr *>(Buffer);
	if (
	//Base DNS header check
//		DNS_Header->ID == 0 || //ID must not be set 0.
		DNS_Header->Flags == 0 || //Flags must not be set 0, first bit in Flags must be set 1 to show it's a response.
	//Extended DNS header check
		(Parameter.PacketCheck_DNS && 
	//Ignore DNSCurve Signature packet.
	#if defined(ENABLE_LIBSODIUM)
		ResponseType != REQUEST_PROCESS_TYPE::DNSCURVE_SIGN && 
	#endif
	//Must be set Response bit.
		((ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RESPONSE) == 0 || 
	//Must not any non-Question resource records when RCode is No Error and not Truncated
		((ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_TC) == 0 && 
		(ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RCODE) == DNS_RCODE_NOERROR && 
		DNS_Header->Answer == 0 && DNS_Header->Authority == 0 && DNS_Header->Additional == 0) || 
	//Response are not authoritative when there are no Authoritative Nameservers Records and Additional resource records.
//		((ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_AA) > 0 && DNS_Header->Authority == 0 && DNS_Header->Additional == 0) || 
	//Do query recursively bit must be set when RCode is No Error and there are Answers resource records.
		((ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RD) == 0 && 
		(ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RCODE) == DNS_RCODE_NOERROR && DNS_Header->Answer == 0) || 
	//Local request failed or Truncated
		((ResponseType == REQUEST_PROCESS_TYPE::LOCAL_NORMAL || ResponseType == REQUEST_PROCESS_TYPE::LOCAL_IN_WHITE) && 
		((ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_RCODE) > DNS_RCODE_NOERROR || 
		((ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_TC) > 0 && 
		DNS_Header->Answer == 0))) || 
	//Must not set Reserved bit.
		(ntohs(DNS_Header->Flags) & DNS_FLAG_GET_BIT_Z) > 0 || 
	//Question resource records counts must be set 0 (when DNS Cookies is enabled) or 1.
		(DNS_Header->Question != 0 && ntohs(DNS_Header->Question) != UINT16_NUM_ONE) || 
	//DNS Cookies request must contain EDNS Label.
		(DNS_Header->Question == 0 && 
		(DNS_Header->Answer != 0 || DNS_Header->Authority != 0 || ntohs(DNS_Header->Additional) != UINT16_NUM_ONE)))))
			return EXIT_FAILURE;

//EDNS Label resource records check
	auto IsNeedCheck_EDNS = false;
	if (Parameter.EDNS_Label && 
		(ResponseType == REQUEST_PROCESS_TYPE::NONE || //Normal
		((ResponseType == REQUEST_PROCESS_TYPE::LOCAL_NORMAL || ResponseType == REQUEST_PROCESS_TYPE::LOCAL_IN_WHITE) && Parameter.EDNS_Switch_Local) || //Local
		(ResponseType == REQUEST_PROCESS_TYPE::SOCKS_MAIN && Parameter.EDNS_Switch_SOCKS) || //SOCKS Proxy
		(ResponseType == REQUEST_PROCESS_TYPE::HTTP_CONNECT_MAIN && Parameter.EDNS_Switch_HTTP_CONNECT) || //HTTP CONNECT Proxy
		(ResponseType == REQUEST_PROCESS_TYPE::DIRECT && Parameter.EDNS_Switch_Direct) || //Direct Request
	#if defined(ENABLE_LIBSODIUM)
		(ResponseType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN && Parameter.EDNS_Switch_DNSCurve) || //DNSCurve
	#endif
		((ResponseType == REQUEST_PROCESS_TYPE::TCP_NORMAL || ResponseType == REQUEST_PROCESS_TYPE::TCP_WITHOUT_REGISTER) && Parameter.EDNS_Switch_TCP) || //TCP
		((ResponseType == REQUEST_PROCESS_TYPE::UDP_NORMAL || ResponseType == REQUEST_PROCESS_TYPE::UDP_WITHOUT_REGISTER) && Parameter.EDNS_Switch_UDP))) //UDP
			IsNeedCheck_EDNS = true;
	if (Parameter.PacketCheck_DNS && 
	//Ignore DNSCurve Signature packet.
	#if defined(ENABLE_LIBSODIUM)
		ResponseType != REQUEST_PROCESS_TYPE::DNSCURVE_SIGN && 
	#endif
		IsNeedCheck_EDNS && DNS_Header->Additional == 0)
			return EXIT_FAILURE;

//Domain pointer check
	if (Parameter.PacketCheck_DNS && 
	//Ignore DNSCurve Signature packet.
	#if defined(ENABLE_LIBSODIUM)
		ResponseType != REQUEST_PROCESS_TYPE::DNSCURVE_SIGN && 
	#endif
		DNS_Header->Question != 0)
	{
	//Find compression pointer in domain.
		for (auto Index = sizeof(dns_hdr);Index < DNS_PACKET_QUERY_LOCATE(Buffer);++Index)
		{
			if (*(Buffer + Index) == static_cast<uint8_t>(DNS_POINTER_8_BIT_STRING))
				return EXIT_FAILURE;
		}

	//Check repeat DNS domain without compression.
		if (ntohs(DNS_Header->Answer) == UINT16_NUM_ONE && DNS_Header->Authority == 0 && DNS_Header->Additional == 0 && 
			CheckQueryNameLength(Buffer + sizeof(dns_hdr)) == CheckQueryNameLength(Buffer + DNS_PACKET_RR_LOCATE(Buffer)))
		{
			if ((ntohs(reinterpret_cast<dns_record_standard *>(Buffer + DNS_PACKET_RR_LOCATE(Buffer) + CheckQueryNameLength(Buffer + sizeof(dns_hdr)) + NULL_TERMINATE_LENGTH)->Type) == DNS_TYPE_A || 
				ntohs(reinterpret_cast<dns_record_standard *>(Buffer + DNS_PACKET_RR_LOCATE(Buffer) + CheckQueryNameLength(Buffer + sizeof(dns_hdr)) + NULL_TERMINATE_LENGTH)->Type) == DNS_TYPE_AAAA) && 
				memcmp(Buffer + sizeof(dns_hdr), Buffer + DNS_PACKET_RR_LOCATE(Buffer), CheckQueryNameLength(Buffer + sizeof(dns_hdr)) + NULL_TERMINATE_LENGTH) == 0)
					return EXIT_FAILURE;
		}
	}

//Mark domain.
	std::string Domain;
	const uint8_t *DomainString = nullptr;
	if (DNS_Header->Question != 0)
	{
	//Convert packet binary to string.
		PacketQueryToString(Buffer + sizeof(dns_hdr), Domain);
		if (!Domain.empty())
			DomainString = reinterpret_cast<const uint8_t *>(Domain.c_str());
	}
//DNS Cookies request check
	else if (ntohs(DNS_Header->Additional) != UINT16_NUM_ONE)
	{
		return EXIT_FAILURE;
	}

//Initialization(Part 2)
	uint16_t DNS_QueryType = 0;
	size_t DataLength = 0, EDNS_Location = 0, EDNS_Length = 0, Index = 0;
	if (DNS_Header->Question != 0) //DNS Cookies request
	{
		DNS_QueryType = reinterpret_cast<dns_qry *>(Buffer + DNS_PACKET_QUERY_LOCATE(Buffer))->Type;
		DataLength = DNS_PACKET_RR_LOCATE(Buffer);
	}
	else {
		DataLength = sizeof(dns_hdr);
	}
	std::vector<std::pair<size_t, size_t>> RecordList_Answer;
	uint16_t PreviousType = 0;
	uint32_t AddressRecord_TTL = 0;
	auto IsFound_EDNS = false, IsFound_DNSSEC = false, IsFound_AddressRecord = false;

//Scan all resource records to check.
	for (Index = 0;Index < static_cast<size_t>(ntohs(DNS_Header->Answer) + ntohs(DNS_Header->Authority) + ntohs(DNS_Header->Additional));++Index)
	{
	//Domain pointer check
		if (DataLength >= Length || DataLength + sizeof(uint16_t) >= Length)
		{
			return EXIT_FAILURE;
		}
		else if (Buffer[DataLength] >= DNS_POINTER_8_BITS)
		{
			const uint16_t DNS_Pointer = ntohs(*reinterpret_cast<uint16_t *>(Buffer + DataLength)) & DNS_POINTER_BIT_GET_LOCATE;
			if (DNS_Pointer >= Length || DNS_Pointer < sizeof(dns_hdr) || DNS_Pointer == DataLength || DNS_Pointer == DataLength + NULL_TERMINATE_LENGTH)
				return EXIT_FAILURE;
		}

	//Mark CNAME Answer records location.
		if (Index < ntohs(DNS_Header->Answer))
			RecordList_Answer.push_back(std::make_pair(DataLength, 0));

	//Mark EDNS Label location(Part 1).
		if (EDNS_Length == 0)
			EDNS_Location = DataLength;

	//Resource records name check
		DataLength += CheckQueryNameLength(Buffer + DataLength) + NULL_TERMINATE_LENGTH;
		if (DataLength + sizeof(dns_record_standard) > Length)
			return EXIT_FAILURE;

	//Standard resource records
		const auto DNS_Record_Standard = reinterpret_cast<dns_record_standard *>(Buffer + DataLength);
		DataLength += sizeof(dns_record_standard);
		if (DataLength > Length || DataLength + ntohs(DNS_Record_Standard->Length) > Length)
			return EXIT_FAILURE;

	//Strict resource record TTL check when enforce strict RFC 2181(https://tools.ietf.org/html/rfc2181) compliance(Part 1)
	//TTL in resource records must less than 2 ^ 31(2147483647).
		if (Parameter.DataCheck_RRSetTTL && (ntohl(DNS_Record_Standard->TTL) & DNS_RECORD_TTL_GET_BIT_HIGHEST) != 0)
			return EXIT_FAILURE;

	//EDNS Label and DNSSEC resource records check
		if (ntohs(DNS_Record_Standard->Type) == DNS_TYPE_OPT)
		{
		//Set EDNS Label record found flag.
		//Only one EDNS Label/OPT Record can be stored in a DNS packet.
			if (!IsFound_EDNS)
				IsFound_EDNS = true;
			else 
				return EXIT_FAILURE;

		//Mark DNSSEC records.
			if (Parameter.DNSSEC_Request && 
				(ntohs(DNS_Record_Standard->Type) == DNS_TYPE_SIG || ntohs(DNS_Record_Standard->Type) == DNS_TYPE_KEY || 
				ntohs(DNS_Record_Standard->Type) == DNS_TYPE_DS || ntohs(DNS_Record_Standard->Type) == DNS_TYPE_RRSIG || 
				ntohs(DNS_Record_Standard->Type) == DNS_TYPE_NSEC || ntohs(DNS_Record_Standard->Type) == DNS_TYPE_DNSKEY || 
				ntohs(DNS_Record_Standard->Type) == DNS_TYPE_NSEC3 || ntohs(DNS_Record_Standard->Type) == DNS_TYPE_NSEC3PARAM || 
				ntohs(DNS_Record_Standard->Type) == DNS_TYPE_CDS || ntohs(DNS_Record_Standard->Type) == DNS_TYPE_CDNSKEY))
			{
			//DNSSEC Validation
				if (Parameter.PacketCheck_DNS && Parameter.EDNS_Label && 
				//Ignore DNSCurve Signature packet.
				#if defined(ENABLE_LIBSODIUM)
					ResponseType != REQUEST_PROCESS_TYPE::DNSCURVE_SIGN && 
				#endif
					!Check_DNSSEC_Record(Buffer + DataLength, ntohs(DNS_Record_Standard->Length), ntohs(DNS_Record_Standard->Type), PreviousType))
						return EXIT_FAILURE;

			//Set DNSSEC record found flag.
				IsFound_DNSSEC = true;
			}

		//Mark EDNS Label location(Part 2).
			EDNS_Length = DataLength + ntohs(DNS_Record_Standard->Length) - EDNS_Location;
		}

	//Read resource records data.
	#if defined(ENABLE_LIBSODIUM)
		if (ResponseType != REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
		{
	#endif
		//AAAA record(IPv6)
			if (ntohs(DNS_Record_Standard->Type) == DNS_TYPE_AAAA && ntohs(DNS_Record_Standard->Length) == sizeof(in6_addr))
			{
			//Check Answer resource records.
				if (Index < ntohs(DNS_Header->Answer))
				{
				//Records Type in responses check
					if (Parameter.PacketCheck_DNS && ntohs(DNS_QueryType) == DNS_TYPE_A)
						return EXIT_FAILURE;

				//Strict resource record TTL check when enforce strict RFC 2181(https://tools.ietf.org/html/rfc2181) compliance(Part 2)
				//This will cause filter to reject DNS answers with incorrect timestamp settings.
				//Multiple RRs of the same type and for the same domain with different TTLs.
					if (Parameter.DataCheck_RRSetTTL)
					{
						if (AddressRecord_TTL == 0)
							AddressRecord_TTL = DNS_Record_Standard->TTL;
						else if (AddressRecord_TTL != DNS_Record_Standard->TTL)
							return EXIT_FAILURE;
					}
				}

			//Check record address.
				if (
				//Check special address.
					(Parameter.DataCheck_Blacklist && CheckSpecialAddress(AF_INET6, Buffer + DataLength, false, DomainString)) || 
				//Check Local Routing.
					(ResponseType == REQUEST_PROCESS_TYPE::LOCAL_NORMAL && Index < ntohs(DNS_Header->Answer) && 
					Parameter.IsLocalRouting && !CheckAddressRouting(AF_INET6, Buffer + DataLength)))
						return EXIT_FAILURE;

			//Set address result found flag.
				IsFound_AddressRecord = true;
			}
		//A record(IPv4)
			else if (ntohs(DNS_Record_Standard->Type) == DNS_TYPE_A && ntohs(DNS_Record_Standard->Length) == sizeof(in_addr))
			{
			//Check Answer resource records.
				if (Index < ntohs(DNS_Header->Answer))
				{
				//Records Type in responses check
					if (Parameter.PacketCheck_DNS && ntohs(DNS_QueryType) == DNS_TYPE_AAAA)
						return EXIT_FAILURE;

				//Strict resource record TTL check when enforce strict RFC 2181(https://tools.ietf.org/html/rfc2181) compliance(Part 2)
				//This will cause filter to reject DNS answers with incorrect timestamp settings.
				//Multiple RRs of the same type and for the same domain with different TTLs.
					if (Parameter.DataCheck_RRSetTTL)
					{
						if (AddressRecord_TTL == 0)
							AddressRecord_TTL = DNS_Record_Standard->TTL;
						else if (AddressRecord_TTL != DNS_Record_Standard->TTL)
							return EXIT_FAILURE;
					}
				}

			//Check record address.
				if (
				//Check special address.
					(Parameter.DataCheck_Blacklist && CheckSpecialAddress(AF_INET, Buffer + DataLength, false, DomainString)) || 
				//Check Local Routing.
					(ResponseType == REQUEST_PROCESS_TYPE::LOCAL_NORMAL && Index < ntohs(DNS_Header->Answer) && 
					Parameter.IsLocalRouting && !CheckAddressRouting(AF_INET, Buffer + DataLength)))
						return EXIT_FAILURE;

			//Set address result found flag.
				IsFound_AddressRecord = true;
			}
	#if defined(ENABLE_LIBSODIUM)
		}
	#endif

	//Mark previous type.
		if (Parameter.PacketCheck_DNS && 
		//Ignore DNSCurve Signature packet.
		#if defined(ENABLE_LIBSODIUM)
			ResponseType != REQUEST_PROCESS_TYPE::DNSCURVE_SIGN && 
		#endif
			Parameter.EDNS_Label && Parameter.DNSSEC_Request)
				PreviousType = DNS_Record_Standard->Type;

	//Mark record length.
		DataLength += ntohs(DNS_Record_Standard->Length);

	//Mark CNAME Answer records length.
		if (Index < ntohs(DNS_Header->Answer) && RecordList_Answer.size() > Index)
		{
			if (ntohs(DNS_Record_Standard->Type) == DNS_TYPE_CNAME)
				RecordList_Answer.at(Index).second = DataLength - RecordList_Answer.at(Index).first;
			else 
				RecordList_Answer.at(Index).first = 0;
		}
	}

//Whole DNS packet resource records check
	if (
	//Ignore DNSCurve Signature packet.
	#if defined(ENABLE_LIBSODIUM)
		ResponseType != REQUEST_PROCESS_TYPE::DNSCURVE_SIGN && 
	#endif
	//EDNS Label and DNSSEC enforce check
		((IsNeedCheck_EDNS && 
		(!IsFound_EDNS || //EDNS Label
		(Parameter.DNSSEC_Request && Parameter.DNSSEC_ForceRecord && !IsFound_DNSSEC))) || //DNSSEC
	//Local request address result check
		((ResponseType == REQUEST_PROCESS_TYPE::LOCAL_NORMAL || ResponseType == REQUEST_PROCESS_TYPE::LOCAL_IN_WHITE) && 
		!Parameter.IsLocalForce && !IsFound_AddressRecord)))
			return EXIT_FAILURE;

//Store EDNS Label temporary.
	std::unique_ptr<uint8_t[]> EDNS_Buffer(nullptr);
	if (EDNS_Length > 0)
	{
	//Mark EDNS Label offset.
		if (PacketEDNS_Offset != nullptr && PacketEDNS_Length != nullptr)
		{
			*PacketEDNS_Offset = EDNS_Location;
			*PacketEDNS_Length = EDNS_Length;
		}

	//Store EDNS Label if any Answer records exist.
		if (!RecordList_Answer.empty())
		{
			auto EDNS_BufferTemp = std::make_unique<uint8_t[]>(EDNS_Length + PADDING_RESERVED_BYTES);
			memset(EDNS_BufferTemp.get(), 0, EDNS_Length + PADDING_RESERVED_BYTES);
			memcpy_s(EDNS_BufferTemp.get(), EDNS_Length, Buffer + EDNS_Location, EDNS_Length);
			EDNS_Buffer.swap(EDNS_BufferTemp);
		}
	}

//Scan all resource records to CNAME Hosts.
	for (Index = 0;Index < RecordList_Answer.size();++Index)
	{
	//CNAME Answer records
		if (RecordList_Answer.at(Index).first > 0)
		{
		//Resource records name length check.
			DataLength = CheckQueryNameLength(Buffer + RecordList_Answer.at(Index).first) + NULL_TERMINATE_LENGTH;
			if (RecordList_Answer.at(Index).second > DataLength + sizeof(dns_record_standard) + DOMAIN_MINSIZE || 
				RecordList_Answer.at(Index).second < DataLength + sizeof(dns_record_standard) + DOMAIN_MAXSIZE)
			{
			//CNAME Hosts check
				size_t IncreaseCount = 0;
				DataLength = CheckResponse_CNAME(Buffer, Length, BufferSize, RecordList_Answer.at(Index).first + DataLength + sizeof(dns_record_standard), RecordList_Answer.at(Index).second - DataLength - sizeof(dns_record_standard), IncreaseCount);
				if (DataLength >= DNS_PACKET_MINSIZE && IncreaseCount > 0)
				{
				//Set DNS resource record counts.
					DNS_Header->Answer = htons(static_cast<uint16_t>(Index + 1U + IncreaseCount));

				//Copy back EDNS Label.
					if (EDNS_Buffer && EDNS_Length > 0 && DataLength + EDNS_Length < BufferSize)
					{
					//Mark EDNS Label offset.
						if (PacketEDNS_Offset != nullptr && PacketEDNS_Length != nullptr)
						{
							*PacketEDNS_Offset = DataLength;
							*PacketEDNS_Length = EDNS_Length;
						}

					//Copy EDNS Label to packet.
						memcpy_s(Buffer + DataLength, BufferSize - DataLength, EDNS_Buffer.get(), EDNS_Length);
						DataLength += EDNS_Length;
						DNS_Header->Additional = htons(UINT16_NUM_ONE);
					}

					return DataLength;
				}
			}
		}
	}

	return Length;
}

//Check DNSSEC Records
bool Check_DNSSEC_Record(
	const uint8_t * const Buffer, 
	const size_t Length, 
	const uint16_t Type, 
	const uint16_t PreviousType)
{
//DS and CDS Records
	if (Type == DNS_TYPE_DS || Type == DNS_TYPE_CDS)
	{
		const auto DNS_Record_DS = reinterpret_cast<const dns_record_ds *>(Buffer);

	//Key Tag, Algorithm and Digest Type check
		if (DNS_Record_DS->KeyTag == 0 || 
			DNS_Record_DS->Algorithm == DNSSEC_AlGORITHM_RESERVED_0 || DNS_Record_DS->Algorithm == DNSSEC_AlGORITHM_RESERVED_4 || 
			DNS_Record_DS->Algorithm == DNSSEC_AlGORITHM_RESERVED_9 || DNS_Record_DS->Algorithm == DNSSEC_AlGORITHM_RESERVED_11 || 
			(DNS_Record_DS->Algorithm >= DNSSEC_AlGORITHM_RESERVED_123 && DNS_Record_DS->Algorithm >= DNSSEC_AlGORITHM_RESERVED_251) || 
			DNS_Record_DS->Algorithm == DNSSEC_AlGORITHM_RESERVED_255 || DNS_Record_DS->Type == DNSSEC_DS_TYPE_RESERVED)
				return false;

	//Algorithm length check
		if ((DNS_Record_DS->Type == DNSSEC_DS_TYPE_SHA1 && Length != sizeof(dns_record_ds) + DNSSEC_LENGTH_SHA1) || 
			(DNS_Record_DS->Type == DNSSEC_DS_TYPE_SHA256 && Length != sizeof(dns_record_ds) + DNSSEC_LENGTH_SHA256) || 
			(DNS_Record_DS->Type == DNSSEC_DS_TYPE_GOST && Length != sizeof(dns_record_ds) + DNSSEC_LENGTH_GOST) || 
			(DNS_Record_DS->Type == DNSSEC_DS_TYPE_SHA384 && Length != sizeof(dns_record_ds) + DNSSEC_LENGTH_SHA384))
				return false;
	}
//SIG and RRSIG Records
	else if (Type == DNS_TYPE_SIG || Type == DNS_TYPE_RRSIG)
	{
		const auto DNS_Record_RRSIG = reinterpret_cast<const dns_record_rrsig *>(Buffer);
		const auto TimeValues = time(nullptr);

	//RRSIG header check
		if (TimeValues <= 0 || 
		//Type Coverded check
			DNS_Record_RRSIG->TypeCovered != PreviousType || 
		//Algorithm check
			DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RESERVED_0 || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RESERVED_4 || 
			DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RESERVED_9 || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RESERVED_11 || 
			(DNS_Record_RRSIG->Algorithm >= DNSSEC_AlGORITHM_RESERVED_123 && DNS_Record_RRSIG->Algorithm >= DNSSEC_AlGORITHM_RESERVED_251) || 
			DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RESERVED_255 || 
		//Labels, Original TTL and Key Tag check
			DNS_Record_RRSIG->Labels == 0 || DNS_Record_RRSIG->TTL == 0 || DNS_Record_RRSIG->KeyTag == 0 || 
		//Signature available time check
			TimeValues < static_cast<time_t>(ntohl(DNS_Record_RRSIG->Inception)) || TimeValues > static_cast<time_t>(ntohl(DNS_Record_RRSIG->Expiration)))
				return false;

	//Algorithm length check
		if (
		//The Signature length must longer than 512 bits/64 bytes in RSA suite.
			((DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RSA_MD5 || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RSA_SHA1 || 
			DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RSA_SHA1_NSEC3_SHA1 || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RSA_SHA256 || 
			DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_RSA_SHA512) && Length <= sizeof(dns_record_rrsig) + DNSSEC_MINSIZE_RSA) || 
		//The Signature length must longer than 768 bits/96 bytes in Diffie-Hellman suite.
			(DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_DH && Length <= sizeof(dns_record_rrsig) + DNSSEC_MINSIZE_DH) || 
		//The Signature length must longer than 1024 bits/128 bytes in DSA suite.
			((DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_DSA || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_DSA_NSEC3_SHA1) && 
			Length <= sizeof(dns_record_rrsig) + DNSSEC_MINSIZE_DSA) || 
		//The Signature length must longer than 192 bits/24 bytes in ECC suite.
			((DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_ECC_GOST || DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_ECDSA_P256_SHA256 || 
			DNS_Record_RRSIG->Algorithm == DNSSEC_AlGORITHM_ECDSA_P386_SHA386) && Length <= sizeof(dns_record_rrsig) + DNSSEC_MINSIZE_ECC))
				return false;
	}
//DNSKEY and CDNSKEY Records
	else if (Type == DNS_TYPE_DNSKEY || Type == DNS_TYPE_CDNSKEY)
	{
		const auto DNS_Record_DNSKEY = reinterpret_cast<const dns_record_dnskey *>(Buffer);

	//Key Revoked bit, Protocol and Algorithm check
		if ((ntohs(DNS_Record_DNSKEY->Flags) & DNSSEC_DNSKEY_FLAGS_RSV) > 0 || DNS_Record_DNSKEY->Protocol != DNSSEC_DNSKEY_PROTOCOL || 
			DNS_Record_DNSKEY->Algorithm == DNSSEC_AlGORITHM_RESERVED_0 || DNS_Record_DNSKEY->Algorithm == DNSSEC_AlGORITHM_RESERVED_4 || 
			DNS_Record_DNSKEY->Algorithm == DNSSEC_AlGORITHM_RESERVED_9 || DNS_Record_DNSKEY->Algorithm == DNSSEC_AlGORITHM_RESERVED_11 || 
			(DNS_Record_DNSKEY->Algorithm >= DNSSEC_AlGORITHM_RESERVED_123 && DNS_Record_DNSKEY->Algorithm >= DNSSEC_AlGORITHM_RESERVED_251) || 
			DNS_Record_DNSKEY->Algorithm == DNSSEC_AlGORITHM_RESERVED_255)
				return false;
	}
//NSEC3 Records
	else if (Type == DNS_TYPE_NSEC3)
	{
		const auto DNS_Record_NSEC3 = reinterpret_cast<const dns_record_nsec3 *>(Buffer);

	//Algorithm check
		if (DNS_Record_NSEC3->Algorithm == DNSSEC_AlGORITHM_RESERVED_0 || DNS_Record_NSEC3->Algorithm == DNSSEC_AlGORITHM_RESERVED_4 || 
			DNS_Record_NSEC3->Algorithm == DNSSEC_AlGORITHM_RESERVED_9 || DNS_Record_NSEC3->Algorithm == DNSSEC_AlGORITHM_RESERVED_11 || 
			(DNS_Record_NSEC3->Algorithm >= DNSSEC_AlGORITHM_RESERVED_123 && DNS_Record_NSEC3->Algorithm >= DNSSEC_AlGORITHM_RESERVED_251) || 
			DNS_Record_NSEC3->Algorithm == DNSSEC_AlGORITHM_RESERVED_255)
				return false;

	//Hash Length check
		if (sizeof(dns_record_nsec3param) + DNS_Record_NSEC3->SaltLength < Length && DNS_Record_NSEC3->Algorithm == DNSSEC_NSEC3_ALGORITHM_SHA1 && 
			*(Buffer + sizeof(dns_record_nsec3param) + DNS_Record_NSEC3->SaltLength) != DNSSEC_LENGTH_SHA1)
				return false;
	}
//NSEC3PARAM Records
	else if (Type == DNS_TYPE_NSEC3PARAM)
	{
		const auto DNS_Record_NSEC3PARAM = reinterpret_cast<const dns_record_nsec3param *>(Buffer);

	//Algorithm check
		if (DNS_Record_NSEC3PARAM->Algorithm == DNSSEC_AlGORITHM_RESERVED_0 || DNS_Record_NSEC3PARAM->Algorithm == DNSSEC_AlGORITHM_RESERVED_4 || 
			DNS_Record_NSEC3PARAM->Algorithm == DNSSEC_AlGORITHM_RESERVED_9 || DNS_Record_NSEC3PARAM->Algorithm == DNSSEC_AlGORITHM_RESERVED_11 || 
			(DNS_Record_NSEC3PARAM->Algorithm >= DNSSEC_AlGORITHM_RESERVED_123 && DNS_Record_NSEC3PARAM->Algorithm >= DNSSEC_AlGORITHM_RESERVED_251) || 
			DNS_Record_NSEC3PARAM->Algorithm == DNSSEC_AlGORITHM_RESERVED_255)
				return false;
	}

	return true;
}
