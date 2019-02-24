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


#include "Pcap_DNSProxy.h"

//The main function
#if defined(PLATFORM_WIN)
int wmain(
	int argc, 
	wchar_t * argv[])
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
int main(
	int argc, 
	char * argv[])
#endif
{
//Command count check
	if (argc < COMMAND_COUNT_MIN)
		return EXIT_FAILURE;
//Library version check
	else if (!CheckLibraryVersion())
		return EXIT_FAILURE;
//Load prepare process.
	else if (!LoadPrepareProcess(argc, argv))
		return EXIT_FAILURE;
//Load main process.
/* Temporary Disabled
	else if (!LoadMainProcess())
		return EXIT_FAILURE;
*/

//Return code
	return EXIT_SUCCESS;
}

//Load prepare process
#if defined(PLATFORM_WIN)
bool LoadPrepareProcess(
	int argc, 
	wchar_t * argv[])
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool LoadPrepareProcess(
	int argc, 
	char * argv[])
#endif
{
//Load path and file name.
	if (!LoadPathFileName())
		return false;
//Set screen to no any buffers.
	else if (!SetScreenBuffer())
		return false;
//Set console status and mark program startup time.
	else if (!SetConsoleStartupTime())
		return false;
#if defined(PLATFORM_WIN)
//Load Winsock module.
	else if (!LoadWinsock())
		return false;
#endif
//Read commands.
	else if (!ReadCommand(argc, argv))
		return false;
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
//Set program to daemon mode.
	else if (GlobalRunningStatus.IsDaemon && !SetProgramDaemon())
		return false;
#endif
//Read configuration file.
/* Temporary Disabled
	else if (!ReadConfiguration(true))
		return false;
*/
//Process unique check
	else if (GlobalConfiguration.IsProcessUnique && !CheckProcessUnique())
		return false;
//Set system signal handler
	else if (!SetSignalHandler())
		return false;

//Set up alternate configuration table, launch all monitors, and wait for multiple threads to work.
	AlternateConfiguration.SetToAlternate();
	GeneralMonitorLauncher();
	Sleep(STANDARD_THREAD_TIMEOUT);

#if defined(PLATFORM_WIN)
//Load service.
	if (!LoadService())
		return false;
#endif

	return true;
}
