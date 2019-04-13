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


#include "../Include/Monitor.h"

//Launch general monitor
void GeneralMonitorLauncher(
	void)
{
//Network monitor(Mark Local DNS address to PTR records)
/* Temporary Disabled
	std::thread Thread_NetworkInformationMonitor(std::bind(NetworkInformationMonitor));
	Thread_NetworkInformationMonitor.detach();
*/

	return;
}

//Flush domain cache
void FlushDomainCache_Process(
	const uint8_t * const Domain)
{
/* Temporary Disabled
//Flush domain cache in program.
	std::unique_lock<std::mutex> DNSCacheListMutex((*GlobalRunningStatus.DNSCacheLock));
	if (Domain == nullptr || //Flush all domain cache.
		strnlen_s(reinterpret_cast<const char *>(Domain), DOMAIN_WHOLE_MAXSIZE + MEMORY_RESERVED_BYTES) >= DOMAIN_WHOLE_MAXSIZE)
	{
	//Remove from cache index list.
		if (GlobalRunningStatus.DNSCacheIndexMap != nullptr)
			GlobalRunningStatus.DNSCacheIndexMap->clear();

	//Remove from cache data list.
		if (GlobalRunningStatus.DNSCacheList != nullptr)
			GlobalRunningStatus.DNSCacheList->clear();
	}
//Flush single domain cache.
	else {
	//Make insensitive domain.
		std::string DomainString(reinterpret_cast<const char *>(Domain));
		CaseConvert(DomainString, false);

	//Scan domain cache list.
		if (GlobalRunningStatus.DNSCacheList != nullptr && GlobalRunningStatus.DNSCacheIndexMap != nullptr && 
			GlobalRunningStatus.DNSCacheIndexMap->find(DomainString) != GlobalRunningStatus.DNSCacheIndexMap->end())
		{
		//Remove from cache data list.
			const auto CacheMapRange = GlobalRunningStatus.DNSCacheIndexMap->equal_range(DomainString);
			for (auto CacheMapItem = CacheMapRange.DNS_CACHE_INDEX_MAP_DOMAIN;CacheMapItem != CacheMapRange.DNS_CACHE_INDEX_MAP_POINTER;++CacheMapItem)
				GlobalRunningStatus.DNSCacheList->erase(CacheMapItem->second);

		//Remove from cache index list.
			while (GlobalRunningStatus.DNSCacheIndexMap->find(DomainString) != GlobalRunningStatus.DNSCacheIndexMap->end())
				GlobalRunningStatus.DNSCacheIndexMap->erase(GlobalRunningStatus.DNSCacheIndexMap->find(DomainString));
		}
	}

	DNSCacheListMutex.unlock();
*/

//Flush system domain cache interval time check
	if (NextAllowedFlushTime == 0 || NextAllowedFlushTime <= GetCurrentSystemTime())
		NextAllowedFlushTime = GetCurrentSystemTime() + FLUSH_DOMAIN_CACHE_INTERVAL_TIME * SECOND_TO_MILLISECOND;
	else 
		return;

//Flush domain cache in system.
	std::lock_guard<std::mutex> ScreenMutex((*GlobalRunningStatus.ScreenLock));
#if defined(PLATFORM_WIN)
	system("ipconfig /flushdns 2>nul"); //All Windows version
	fwprintf_s(stderr, L"\n");
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
#if defined(PLATFORM_OPENWRT)
	auto Result = system("/etc/init.d/dnsmasq restart 2>/dev/null"); //Dnsmasq manage domain cache on OpenWrt
#else
	auto Result = system("service nscd restart 2>/dev/null"); //Name Service Cache Daemon service
	Result = system("service dnsmasq restart 2>/dev/null"); //Dnsmasq service
	Result = system("rndc restart 2>/dev/null"); //Name server control utility of BIND(9.1.3 and older version)
	Result = system("rndc flush 2>/dev/null"); //Name server control utility of BIND(9.2.0 and later)
#endif
#elif defined(PLATFORM_MACOS)
//	Result = system("lookupd -flushcache 2>/dev/null"); //Less than Mac OS X Tiger(10.4)
//	Result = system("dscacheutil -flushcache 2>/dev/null"); //Mac OS X Leopard(10.5) and Snow Leopard(10.6)
//	Result = system("killall -HUP mDNSResponder 2>/dev/null"); //Mac OS X Lion(10.7), Mountain Lion(10.8) and Mavericks(10.9)
	auto Result = system("discoveryutil udnsflushcaches 2>/dev/null"); //Mac OS X Yosemite(10.10 - 10.10.3)
	Result = system("discoveryutil mdnsflushcache 2>/dev/null"); //Mac OS X Yosemite(10.10 - 10.10.3)
	Result = system("dscacheutil -flushcache 2>/dev/null"); //Mac OS X Yosemite(10.10.4 - 10.10.5)
	Result = system("killall -HUP mDNSResponder 2>/dev/null"); //Mac OS X El Capitan(10.11) and later
#endif

	return;
}

#if defined(PLATFORM_WIN)
//Mailslot listener of flush domain cache
bool FlushDomainCache_MailslotListener(
	void)
{
//System security initialization
	auto ACL_Buffer = std::make_unique<uint8_t[]>(FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	memset(ACL_Buffer.get(), 0, FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	SECURITY_ATTRIBUTES SecurityAttributes;
	SECURITY_DESCRIPTOR SecurityDescriptor;
	memset(&SecurityAttributes, 0, sizeof(SecurityAttributes));
	memset(&SecurityDescriptor, 0, sizeof(SecurityDescriptor));
	PSID SID_Value = nullptr;
	if (!SystemSecurityInit(reinterpret_cast<const ACL *>(ACL_Buffer.get()), SecurityAttributes, SecurityDescriptor, SID_Value))
	{
		if (SID_Value != nullptr)
		{
			LocalFree(SID_Value);
			SID_Value = nullptr;
		}

		return false;
	}

//Create mailslot.
	const auto MailslotHandle = CreateMailslotW(
		FLUSH_DOMAIN_MAILSLOT_NAME, 
		FILE_BUFFER_SIZE - 1U, 
		MAILSLOT_WAIT_FOREVER, 
		&SecurityAttributes);
	if (MailslotHandle == INVALID_HANDLE_VALUE)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Create mailslot error", GetLastError(), nullptr, 0);
		if (SID_Value != nullptr)
		{
			LocalFree(SID_Value);
			SID_Value = nullptr;
		}

		return false;
	}
//Free pointer.
	else {
		ACL_Buffer.reset();
		if (SID_Value != nullptr)
		{
			LocalFree(SID_Value);
			SID_Value = nullptr;
		}
	}

//Initialization
	const auto MailslotBuffer = std::make_unique<wchar_t[]>(FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	wmemset(MailslotBuffer.get(), 0, FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	std::vector<std::wstring> ItemData;
	std::wstring MessageString;
	std::string DomainString;
	DWORD MessageLength = 0;

//Start mailslot listener.
	while (GlobalRunningStatus.IsNeedExit != nullptr && !GlobalRunningStatus.IsNeedExit->load())
	{
	//Reset parameters.
		wmemset(MailslotBuffer.get(), 0, FILE_BUFFER_SIZE);
		MessageLength = 0;

	//Read message from mailslot.
		if (ReadFile(
				MailslotHandle, 
				MailslotBuffer.get(), 
				FILE_BUFFER_SIZE, 
				&MessageLength, 
				nullptr) == FALSE)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SYSTEM, L"Mailslot read messages error", GetLastError(), nullptr, 0);
			Sleep(GlobalConfiguration.FileRefreshTime);

			continue;
		}

	//Message format check
		if (wcsnlen_s(MailslotBuffer.get(), FILE_BUFFER_SIZE) < wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL) || 
			wcsnlen_s(MailslotBuffer.get(), FILE_BUFFER_SIZE) + wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC) >= FILE_BUFFER_SIZE)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"Domain name parameter error", 0, nullptr, 0);
			continue;
		}
		else {
			MessageString = MailslotBuffer.get();
			MessageString.shrink_to_fit();
		}

	//Flush all domain cache.
		if (MessageString == FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL)
		{
			FlushDomainCache_Process(nullptr);
			continue;
		}

	//Whole string format check
		if (MessageString.compare(0, wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC), FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC) != 0 || 
			MessageString.find(L"||") != std::wstring::npos)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"Domain name parameter error", 0, nullptr, 0);
			continue;
		}

	//List all items from string.
		ItemData.clear();
		ItemData.shrink_to_fit();
		GetItemFromString(ItemData, MessageString, wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC), MessageString.length(), ASCII_VERTICAL, false, false);
		for (const auto &StringItem:ItemData)
		{
		//Check all items domain acceptable.
			if (!CheckDomainAcceptable(StringItem))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"Domain name parameter error", 0, nullptr, 0);
				break;
			}

		//Convert to multiple character.
			DomainString.clear();
			DomainString.shrink_to_fit();
			if (!WCS_To_MBS_String(StringItem.c_str(), StringItem.length(), DomainString))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Convert multiple or wide character string error", 0, nullptr, 0);
				break;
			}

		//Flush specific domain cache.
			if (!DomainString.empty())
				FlushDomainCache_Process(reinterpret_cast<const uint8_t *>(DomainString.c_str()));
		}
	}

//Listener terminated
	CloseHandle(
		MailslotHandle);
	if (GlobalRunningStatus.IsNeedExit != nullptr && !GlobalRunningStatus.IsNeedExit->load())
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Mailslot module listener terminated", 0, nullptr, 0);
	return false;
}

//Mailslot sender of flush domain cache
bool WINAPI FlushDomainCache_MailslotSender(
	const wchar_t * const Domain)
{
//Mailslot initialization
	std::wstring Message(L"[System Error] Create mailslot error");
	const auto FileHandle = CreateFileW(
		FLUSH_DOMAIN_MAILSLOT_NAME, 
		GENERIC_WRITE, 
		FILE_SHARE_READ, 
		nullptr, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		nullptr);
	if (FileHandle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == 0)
		{
			Message.append(L".\n");
			PrintToScreen(true, false, Message.c_str());
		}
		else {
			ErrorCodeToMessage(LOG_ERROR_TYPE::SYSTEM, GetLastError(), Message);
			Message.append(L".\n");
			PrintToScreen(true, false, Message.c_str(), GetLastError());
		}

		return false;
	}

//Message initialization
	if (Domain == nullptr)
	{
		Message = FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL;
	}
	else {
		Message = FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC;
		Message.append(Domain);
		if (Message.length() + NULL_TERMINATE_LENGTH >= FILE_BUFFER_SIZE)
		{
			PrintToScreen(true, false, L"[System Error] Mailslot write messages error.\n");
			return false;
		}
	}

//Write to mailslot.
	DWORD WrittenBytes = 0;
	if (WriteFile(
			FileHandle, 
			Message.c_str(), 
			static_cast<DWORD>(sizeof(wchar_t) * Message.length() + NULL_TERMINATE_LENGTH), 
			&WrittenBytes, 
			nullptr) == 0)
	{
		CloseHandle(
			FileHandle);
		Message = L"[System Error] Mailslot write messages error";
		if (GetLastError() == 0)
		{
			Message.append(L".\n");
			PrintToScreen(true, false, Message.c_str());
		}
		else {
			ErrorCodeToMessage(LOG_ERROR_TYPE::SYSTEM, GetLastError(), Message);
			Message.append(L".\n");
			PrintToScreen(true, false, Message.c_str(), GetLastError());
		}

		return false;
	}
	else {
		CloseHandle(
			FileHandle);
		PrintToScreen(true, false, L"[Notice] Flush domain cache message was sent successfully.\n");
	}

	return true;
}
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//FIFO pipe listener of flush domain cache
bool FlushDomainCache_PipeListener(
	void)
{
//Initialization
	const auto PipeBuffer = std::make_unique<uint8_t[]>(FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	memset(PipeBuffer.get(), 0, FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	std::vector<std::string> ItemData;
	std::string MessageString;
	int PipeHandle = 0;
	ssize_t MessageLength = 0;

//Start FIFO pipe Listener.
	while (GlobalRunningStatus.IsNeedExit != nullptr && !GlobalRunningStatus.IsNeedExit->load())
	{
	//Create FIFO pipe and create its notify listener.
		unlink(FLUSH_DOMAIN_PIPE_PATH_NAME);
		errno = 0;
		if (mkfifo(FLUSH_DOMAIN_PIPE_PATH_NAME, O_CREAT) == RETURN_ERROR || 
			chmod(FLUSH_DOMAIN_PIPE_PATH_NAME, S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH) == RETURN_ERROR)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Create FIFO pipe error", errno, nullptr, 0);
			Sleep(GlobalConfiguration.FileRefreshTime);

			continue;
		}

	//Open FIFO pipe.
		errno = 0;
		PipeHandle = open(FLUSH_DOMAIN_PIPE_PATH_NAME, O_RDONLY, 0);
		if (PipeHandle == RETURN_ERROR)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"FIFO pipe read messages error", errno, nullptr, 0);
			Sleep(GlobalConfiguration.FileRefreshTime);

			continue;
		}

	//Read file data.
		errno = 0;
		memset(PipeBuffer.get(), 0, FILE_BUFFER_SIZE);
		MessageLength = read(PipeHandle, PipeBuffer.get(), FILE_BUFFER_SIZE);
		if (MessageLength == RETURN_ERROR)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SYSTEM, L"FIFO pipe read messages error", errno, nullptr, 0);
			close(PipeHandle);
			PipeHandle = 0;

			continue;
		}

	//Message format check
		if (strnlen_s(reinterpret_cast<const char *>(PipeBuffer.get()), FILE_BUFFER_SIZE) < strlen(FLUSH_DOMAIN_PIPE_MESSAGE_ALL) || 
			strnlen_s(reinterpret_cast<const char *>(PipeBuffer.get()), FILE_BUFFER_SIZE) + strlen(FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC) >= FILE_BUFFER_SIZE)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"Domain name parameter error", 0, nullptr, 0);
			close(PipeHandle);
			PipeHandle = 0;

			continue;
		}
		else {
			MessageString = reinterpret_cast<const char *>(PipeBuffer.get());
			MessageString.shrink_to_fit();
		}

	//Flush all domain cache.
		if (MessageString == FLUSH_DOMAIN_PIPE_MESSAGE_ALL)
		{
			FlushDomainCache_Process(nullptr);
			close(PipeHandle);
			PipeHandle = 0;

			continue;
		}

	//Whole string format check
		if (MessageString.compare(0, strlen(FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC), FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC) != 0 || 
			MessageString.find("||") != std::string::npos)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"Domain name parameter error", 0, nullptr, 0);
			close(PipeHandle);
			PipeHandle = 0;

			continue;
		}

	//List all items from string.
		ItemData.clear();
		ItemData.shrink_to_fit();
		GetItemFromString(ItemData, MessageString, strlen(FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC), MessageString.length(), ASCII_VERTICAL, false, false);
		for (const auto &StringItem:ItemData)
		{
		//Check all items domain acceptable.
			if (!CheckDomainAcceptable(StringItem))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"Domain name parameter error", 0, nullptr, 0);
				break;
			}

		//Flush specific domain cache.
			FlushDomainCache_Process(reinterpret_cast<const uint8_t *>(StringItem.c_str()));
		}

	//Close FIFO pipe.
		close(PipeHandle);
		PipeHandle = 0;
	}

//Listener terminated
	close(PipeHandle);
	unlink(FLUSH_DOMAIN_PIPE_PATH_NAME);
	if (GlobalRunningStatus.IsNeedExit != nullptr && !GlobalRunningStatus.IsNeedExit->load())
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"FIFO pipe module listener terminated", 0, nullptr, 0);
	return true;
}

//Flush domain cache FIFO pipe sender
bool FlushDomainCache_PipeSender(
	const uint8_t * const Domain)
{
//Message initialization
	std::string Message;
	if (Domain == nullptr)
	{
		Message = FLUSH_DOMAIN_PIPE_MESSAGE_ALL;
	}
	else {
		Message = FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC;
		Message.append(reinterpret_cast<const char *>(Domain));
		if (Message.length() + NULL_TERMINATE_LENGTH >= FILE_BUFFER_SIZE)
		{
			PrintToScreen(true, false, L"[System Error] FIFO pipe write messages error.\n");
			return false;
		}
	}

//Write to FIFO pipe.
	errno = 0;
	const int PipeHandle = open(FLUSH_DOMAIN_PIPE_PATH_NAME, O_WRONLY | O_TRUNC | O_NONBLOCK, 0);
	if (PipeHandle > 0)
	{
		if (write(PipeHandle, Message.c_str(), Message.length() + NULL_TERMINATE_LENGTH) > 0)
		{
			close(PipeHandle);
			PrintToScreen(true, false, L"[Notice] Flush domain cache message was sent successfully.\n");

			return true;
		}
		else {
			close(PipeHandle);
		}
	}

//Print error log.
	std::wstring ErrorString(L"[System Error] FIFO pipe write messages error");
	if (errno == 0)
	{
		ErrorString.append(L".\n");
		PrintToScreen(true, false, ErrorString.c_str());
	}
	else {
		ErrorCodeToMessage(LOG_ERROR_TYPE::SYSTEM, errno, ErrorString);
		ErrorString.append(L".\n");
		PrintToScreen(true, false, ErrorString.c_str(), errno);
	}

	return false;
}
#endif
