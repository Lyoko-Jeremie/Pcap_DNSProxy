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


#ifndef PCAP_DNSPROXY_CONSTRUCTOR_H
#define PCAP_DNSPROXY_CONSTRUCTOR_H

#include "Include.h"

//Entity global variable
GLOBAL_STATUS GlobalRunningStatus;
CONFIGURATION_TABLE GlobalConfiguration, AlternateConfiguration;

//Localization function
void SetDefault_GlobalStatus(
	GLOBAL_STATUS * const GlobalRunningStatusParameter);
void SetDefault_ConfigurationTable(
	CONFIGURATION_TABLE * const ConfigurationParameter);
#endif
