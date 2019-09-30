Pcap_DNSProxy
=====
Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap

### Wiki & Release Backup

the Wiki : https://github.com/Lyoko-Jeremie/Pcap_DNSProxy_wiki
the Binary Release : https://github.com/Lyoko-Jeremie/Pcap_DNSProxy_release

### Releases
[![GitHub release](https://img.shields.io/github/release/chengr28/Pcap_DNSProxy.svg)](https://github.com/chengr28/Pcap_DNSProxy/releases/latest)
[![GitHub (pre-)release](https://img.shields.io/github/release/chengr28/Pcap_DNSProxy/all.svg?label=pre-release)](https://github.com/chengr28/Pcap_DNSProxy/releases)

### Usage
**Please visit [Documents folder](https://github.com/chengr28/Pcap_DNSProxy/tree/master/Documents) to read detail introduction.**
* [简体中文介绍](README.zh-Hans.md)
* [繁體中文介紹](README.zh-Hant.md)

### Summary
Pcap_DNSProxy is a tool based on WinPcap/LibPcap which can filter DNS poisoning. It provides a convenient and powerful way to change Hosts via regular expressions, DNSCurve/DNSCrypt protocol support, as well as parallel request and TCP request support. Multiple servers parallel request can improve the reliability of domain name resolution in a bad network:
* IPv4/IPv6 dual stack support, custom the multiple listening addresses, port and protocols.
* Provides DNS service for other devices with custom limiting requests.
* CNAME Hosts and Local DNS servers resolution support, which can improve DNS service quality.
* Main/Alternate servers support and servers parallel requests with multiple times support, which can improve DNS service reliability.
* Built-in DNS cache, also EDNS tag, DNSSEC and DNSCurve/DNSCrypt protocol support.
* SOCKS version 4/4a/5 and HTTP CONNECT tunnel protocol including TLS/SSL handshake support.
* Lots of options and powerful error reporting.
* ASCII, UTF-8(/BOM), UTF-16(LE/BE) and UTF-32(LE/BE) encoding including Unicode standard requirements support.

### Platform
* Windows
  * **64-bit/x64: Windows Vista/2008 and later.**
  * **32-bit/x86: Windows XP SP3/2003 SP2 and later.**
* FreeBSD/Linux
  * FreeBSD/Linux which support all [dependency packages](https://github.com/chengr28/Pcap_DNSProxy/tree/master/Documents).
* macOS
  * **64-bit Mac OS X 10.8(Mountain Lion) and later.**
* OpenWrt/LEDE
  * **Please visit [openwrt-Pcap_DNSProxy project](https://github.com/wongsyrone/openwrt-Pcap_DNSProxy).**
* Supported types of network devices in capture module
  * Ethernet and Apple IEEE 1394/FireWire in data link layer.
  * IPv4/PPPoE and IPv6/PPPoEv6 in network layer.

### License
GNU General Public License/GNU GPL v2
