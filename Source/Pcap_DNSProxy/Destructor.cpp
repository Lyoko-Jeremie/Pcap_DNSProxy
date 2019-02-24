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


#include "Destructor.h"

//Release all temporary resources
void ReleaseTemporaryResource(
	GLOBAL_STATUS * const Reference)
{
//Set need exit signal.
	if (Reference->IsNeedExit != nullptr)
		Reference->IsNeedExit->store(true);

//Close all sockets.
//Temporary Disabled

#if defined(PLATFORM_WIN)
//Mutex handle cleanup
	if (Reference->MutexHandle != nullptr)
	{
		ReleaseMutex(
			Reference->MutexHandle);
		CloseHandle(
			Reference->MutexHandle);
		Reference->MutexHandle = nullptr;
	}

//WinSock cleanup
	if (Reference->IsLoad_WinSock)
	{
		WSACleanup();
		Reference->IsLoad_WinSock = false;
	}

//Close all file handles.
//	_fcloseall();
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//Mutex handle cleanup
	if (Reference->MutexHandle != 0 && Reference->MutexHandle != RETURN_ERROR)
	{
		flock(Reference->MutexHandle, LOCK_UN);
		close(Reference->MutexHandle);
		Reference->MutexHandle = 0;
	}

//Free all OpenSSL libraries.
//Temporary Disabled

//Close all file handles.
#if (defined(PLATFORM_FREEBSD) || (defined(PLATFORM_LINUX) && !defined(PLATFORM_OPENWRT)))
//	fcloseall();
#endif
#endif

//Wait for a moment.
	if (Reference->StartupTime > 0)
		Sleep(STANDARD_THREAD_TIMEOUT);

	return;
}

//GlobalStatus class destructor
GlobalStatus::~GlobalStatus(
	void)
{
	ReleaseTemporaryResource(this);

//Delete and reset pointers.
	delete IsNeedExit;
	delete RandomEngine;
/* Temporary Disabled
	delete FileList_Config;
	delete FileList_IPFilter;
	delete FileList_Hosts;
	delete DNSCacheList;
	delete DNSCacheIndexMap;
*/
	delete ScreenLock;
/* Temporary Disabled
	delete DNSCacheLock;
*/
	delete Path_Global_WCS;
	delete Path_ErrorLog_WCS;
	delete FileList_Hosts_WCS;
	delete FileList_IPFilter_WCS;
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	delete Path_Global_MBS;
	delete Path_ErrorLog_MBS;
	delete FileList_Hosts_MBS;
	delete FileList_IPFilter_MBS;
#endif
	IsNeedExit = nullptr;
	RandomEngine = nullptr;
/* Temporary Disabled
	FileList_Config = nullptr;
	FileList_IPFilter = nullptr;
	FileList_Hosts = nullptr;
	DNSCacheList = nullptr;
	DNSCacheIndexMap = nullptr;
*/
	ScreenLock = nullptr;
/* Temporary Disabled
	DNSCacheLock = nullptr;
*/
	Path_Global_WCS = nullptr;
	Path_ErrorLog_WCS = nullptr;
	FileList_Hosts_WCS = nullptr;
	FileList_IPFilter_WCS = nullptr;
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	Path_Global_MBS = nullptr;
	Path_ErrorLog_MBS = nullptr;
	FileList_Hosts_MBS = nullptr;
	FileList_IPFilter_MBS = nullptr;
#endif

//Exit process.
	return;
}

//ConfigurationTable class destructor
ConfigurationTable::~ConfigurationTable(
	void)
{
//Temporary Disabled

	return;
}

//SocketValueTable class destructor
SocketValueTable::~SocketValueTable(
	void)
{
//Close all sockets and clear list.
	if (!ValueSet.empty())
	{
		for (auto &SocketItem:ValueSet)
			SetSocketAttribute(SocketItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		ValueSet.clear();
//		ValueSet.shrink_to_fit();
	}

	return;
}
