Pcap_DNSProxy
=====
Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap

### Releases
[! [GitHub release] (https://img.shields.io/github/release/chengr28/Pcap_DNSProxy.svg)] (https://github.com/chengr28/Pcap_DNSProxy/releases/latest)
[! [GitHub (pre) release] (https://img.shields.io/github/release/chengr28/Pcap_DNSProxy/all.svg?label=pre-release)] (https://github.com/chengr28 / Pcap_DNSProxy / releases)

### Usage
** Documentation See the contents of the project [Documents folder] (https://github.com/chengr28/Pcap_DNSProxy/tree/master/Documents) **

### Summary
Pcap_DNSProxy is a tool based on WinPcap / LibPcap for filtering DNS poisoning, providing a convenient and powerful way to modify Hosts with regular expressions, as well as support for DNSCurve / DNSCrypt protocol, parallel and TCP protocol requests. Multi-server parallel request function, but also improve the reliability of domain name resolution in harsh network environments:
* IPv4 / IPv6 protocol dual stack support, and can customize multi-port multi-address monitoring and remote request protocol
* Server mode provides parsing services for other devices, limiting the scope of requests
* Support for CNAME records and analysis of the results of Hosts and also support Local Hosts DNS server resolution, can improve the speed of the domain name resolution and server access speed
* Main / standby dual server mode, external server support parallel requests multiple times, improve DNS resolution reliability
* Independent DNS cache, EDNS tag, DNSSEC request function and full DNSCurve / DNSCrypt protocol support
* Native SOCKS version 4 / 4a / 5 and HTTP CONNECT tunneling protocols include support for TLS / SSL encrypted connections
* Rich configuration parameters and options and error reporting
* Supports ASCII and UTF-8 (/ BOM) and UTF-16 (LE / BE) and UTF-32 (LE / BE) encoding as well as Unicode standard requirements to achieve all the space /

### Platform
* Windows
  * ** 64-bit / x64 version: Windows Vista / 2008 and newer version **
  * ** 32-bit / x86 version: Windows XP SP3 / 2003 SP2 and newer version **
* Linux
  * Linux distributions that support the [dependency package required for compilation] (https://github.com/chengr28/Pcap_DNSProxy/tree/master/Documents)
* MacOS
  * ** support for 64-bit Mac OS X 10.8 (Mountain Lion) and updated macOS version **
  * The official version can be installed via Homebrew
* OpenWrt / LEDE
  * ** See [openwrt-pcap_DNSProxy project] (https://github.com/wongsyrone/openwrt-Pcap_DNSProxy) **
* This tool ** captures the module type of the supported module
  * Network devices with Ethernet and Apple IEEE 1394 / FireWire networks
  * Native IPv4 / PPPoE and IPv6 / PPPoEv6 networks