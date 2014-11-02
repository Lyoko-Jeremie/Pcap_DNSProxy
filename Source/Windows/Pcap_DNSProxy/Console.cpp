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


#include "Pcap_DNSProxy.h"

extern Configuration Parameter;

//Catch Control-C exception from keyboard.
BOOL WINAPI CtrlHandler(const DWORD fdwCtrlType)
{
	switch(fdwCtrlType)
	{
	//Handle the CTRL-C signal.
		case CTRL_C_EVENT:
		{
			if (Parameter.Console)
				wprintf_s(L"Get Control-C.\n");
			return FALSE;
		}
	//Handle the CTRL-Break signal.
		case CTRL_BREAK_EVENT:
		{
			if (Parameter.Console)
				wprintf_s(L"Get Control-Break.\n");
			return FALSE;
		}
	//Handle the Closing program signal.
		case CTRL_CLOSE_EVENT:
		{
			return FALSE;
		}
	//Handle the Closing program signal.
		case CTRL_LOGOFF_EVENT:
		{
			return FALSE;
		}
	//Handle the shutdown signal.
		case CTRL_SHUTDOWN_EVENT:
		{
			return FALSE;
		}
		default: {
			return FALSE;
		}
	}
}
