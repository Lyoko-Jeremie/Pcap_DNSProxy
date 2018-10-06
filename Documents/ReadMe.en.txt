Pcap_DNSProxy project in GitHub:
https://github.com/chengr28/Pcap_DNSProxy

Pcap_DNSProxy project in Sourceforge:
https://sourceforge.net/projects/pcap-dnsproxy


-------------------------------------------------------------------------------


How to install:
Please read specific platform ReadMe_xx text files!


Special attention:
  * If you need to let the flow of the program through the system routing level of the agent (such as VPN, etc.) for functional variable name resolution, select one of the options, restart the configuration after the completion of the service:
    * Direct Request = IPv4
    * Direct Request = IPv6
    * Direct Request = IPv4 + IPv6
    * More is the system routing level of the agent will be through the virtual network interface card to connect, then the DNS by the agent to control their own, then do not need to do any operation
  * Configuration file Hosts file IPFilter file and the directory where the error report is located in the above installation method section in step 4 registered service information prevail
    * Do not fill more than 4096 bytes/4KB
    * File read only supports the entire text of a single encoding and line feed format combination, do not mix the text in the support of the encoding or newline format!
  * Please check whether the address and port of the service are occupied by other programs or other instances of the program before starting the service. Otherwise, the monitoring conflicts may not work properly
  * Anti-virus software/third-party firewall may prevent the operation of the program, please act all allowed or the program to join the white list
  * If the service does not promptly respond to the start or control request, please note that there is an error report generated, detailed error information see FAQ document Error.log detailed error report section
  * The names of directories and programs can be changed at will, but be sure to complete the installation method before step 4. If the path to the tool directory is to be moved after the service is registered, see the precautions in step 2 above.
  * Windows XP If there is a 10022 error, you need to enable the system's IPv6 support (run administrator as an administrator to enter ipv6 install and enter, one-time operation), and then reboot service
  * Technical support only for the latest version, please make sure to upgrade to the latest version.


Special use skills:
Here are some of the proposed project group introduction and use of skills for your reference and use. For details on adjusting the configuration, see the section below

* Configure the different combinations will have different effects, introduce several more commonly used combination:
  * Default configuration: UDP request + capture mode
  * Outgoing Protocol = .. TCP: UDP request after the first request and UDP packet capture mode, the occupation of the network resources is relatively high
    * Because the TCP request most of the time will not be poisoned, this combination of filtering effect is more reliable
  * EDNS Label = 1: Enable EDNS request tag function
    * This function will improve the filtering capacity of the forged data package, the combination of the filter effect is more reliable
  * Change the target server's request port to a non-standard DNS port: for example, OpenDNS supports 53 standard ports and 5353 nonstandard port requests
    * Non-standard DNS port at this stage has not yet been disturbed, this combination of filtering effect is more reliable
  * Multiple Request Times = xx: Apply to all requests except the request server, a request multiple send function
    * This feature is used to combat network packet loss is more serious, the system and network resources are relatively high, but in the case of poor network environment can improve the reliability of the results obtained
  * DNSCurve = 1 simultaneous Encryption = 1: use DNSCurve (DNSCrypt) encryption mode request function variable name resolution
    * This combination of encrypted transmission of all functional variable name request, function variable name resolution reliability of the highest
* Optimize the large number of requests under the program performance:
  * Do not set any TCP protocol to outgoing process, TCP protocol will take up computer resources more than UDP protocol.
  * Pcap Reading Timeout This parameter allows the packet capture module to crawl the packet at a higher frequency
  * Cache Parameter + Default TTL as much as possible to increase the parameters of the cache can increase the retention time or queue length, increase the cache hit rate
  * Thread Pool Maximum Number This parameter can be increased by increasing the maximum number of buffers that can be requested
  * Queue Limits Reset Time Do not turn on parameters that limit the number of requests
  * Multiple Request Times is extremely harsh, caution, consumes a lot of system resources and will increase the delay


-------------------------------------------------------------------------------


Function and technology:

* The role of batch processing:
  * The end of the operation will have the results of the operation, the specific need to pay attention to the screen prompts
  * 1: Install service - register the program as a system service and start the program for Windows Firewall test
  * 2: Uninstall service - to stop and uninstall the service of the tool
  * 3: Start service - start the service of the tool
  * 4: Stop service - stop the service of the tool
  * 5: Restart service - restart the service of the tool
  * 6: Flush DNS cache in Pcap_DNSProxy - Refresh the program's internal and system DNS cache
  * 7: Flush DNS cache in system only - Refreshes the system's DNS cache
  * 8: Exit - exit
* The file name supported by the profile (only the higher priority will be read and the lower priority will be ignored):
  * Windows: Config.ini> Config.conf> Config.cfg> Config
  * Linux/macOS: Config.conf> Config.ini> Config.cfg> Config
* Request function variable name resolution precedence
  * Use the system API function to perform the function variable name resolution (mostly): Hosts> Pcap_DNSProxy Hosts entries (Whitelist/whitelist entries> Hosts list)> DNS cache> Local hosts/DNS resolution function variable name list> Remote DNS server
  * Read the DNS server address directly from the web interface card settings Function Variable Name Resolution (small): Pcap_DNSProxy Hosts configuration file (Whitelist/whitelist entry> Hosts list)> DNS cache> Local Hosts/DNS resolution in the country Variable list of names> Remote DNS server
  * Requests the priority of the remote DNS server: Direct Request mode> DNSCurve Encryption/Unencrypted mode of TCP mode (if any)> DNSCurve Encrypted/Unencrypted mode in UDP mode (if any)> TCP mode Normal request (if any )> UDP mode normal request
* The tool's DNSCurve (DNSCrypt) protocol is built-in implementation, do not need to install DNSCrypt official tool!
  * Automatically get the connection information must ensure that the system time is correct, otherwise the certificate will lead to failure to get the connection information failed!
  * DNSCrypt official tool will take up the local DNS port caused Pcap_DNSProxy deployment failed!


-------------------------------------------------------------------------------


Program Operation Parameter Description:
Because some features can not be specified by using the configuration file, so use the program plug-in parameters to support
All plug-in parameters can also be queried with the -h and --help parameters

* --config-path Path
   Starts the job directory where the profile is located
* --help
   Output the program description information to the screen
* --version
   Export the program version number to the screen
* --flush-dns
   Immediately empty all programs and DNS buffers within the system
* --flush-dns Domain
   Immediately clear the function variable name for the Domain and all systems within the DNS cache
* --keypair-generator
   Generate the key group required for the DNSCurve (DNSCrypt) protocol to KeyPair.txt
* --lib-version
   Outputs the version number of the library used for the program to the screen
* --log-file Path+Name
  Set location of log file, output to stderr or stdout if Path+Name set to them.
* --disable-daemon
   Turn off daemon mode (Linux)
* --first-setup
   Perform a local firewall test (Windows)


-------------------------------------------------------------------------------


Profile Details Description:

Valid parameter format is "option name = value/data" (without quotation marks, note the position of the equal sign)
Note: The configuration file will only be restarted at the beginning of the tool service, after modifying the parameters of the file (see the restart service in the Note section above)

Base - the basic parameter area
  * Version - the version of the profile used to correctly identify the profile: this parameter is not related to the program version number, do not modify
  * File Refresh Time - File Refresh Interval: in seconds and a minimum of 5
    * This parameter also determines the sublimation of the time of the monitor's sleep time, which means that it will start for a long period of time and check if there is a need to re-run a specific monitoring project without waiting for a long time to complete the dormant To be able to re-monitor this, the appropriate configuration of this function on the program's network adaptability will be improved
  * Large Buffer Size - Fixed length of the large data buffer: in bytes, with a minimum of 2048
  * Additional Path - additional data file to read the path, attached to the directory path under the Hosts file and IPFilter file will be read in order: Please fill in the directory of the absolute path
    * This parameter supports multiple paths at the same time. Please use|separate between paths
  * Hosts File Name - Hosts file name, attached to the Hosts file name will be read in turn
    * This parameter supports multiple file names at the same time. Please use|separate between paths
  * IPFilter File Name - IPFilter file name, the IPFilter file name attached here will be read in sequence
    * This parameter supports multiple file names at the same time. Please use|separate between paths

* Log - Log parameter area
  * Print Log Level - Specify the log output level: leave blank to 3
    * 0 to disable the log output function
    * 1 for outputting a major error
    * 2 for output general error
    * 3 for outputting all errors
  * Maximum size of log file: Maximum capacity of log file: The unit can be added to the unit, the unit is KB/MB/GB, the acceptable range is 4 KB - 256 MB, if it is blank, 8 MB
    * Note: log file reaches the maximum capacity will be deleted directly, and then re-generate a new log file, the original log will not be able to recover!

* Listen - Listen to parameter areas
  * Process Unique - Process instance uniqueness check switch: 1 to enable/0 to disable.
    * Only one program instance can only be run at the same time
    * When the program is closed, the number of instances will not be checked, the program can run multiple and listen to different combinations of addresses and ports, but the functions that depend on the system's global features will not be available:
      * The address and port combination between different instances can not be repeated, otherwise it will not work because the listening conflict does not work
      * Plug-in parameters --flush-dns (Domain) will not be used, then if you need to clear the program's internal DNS cache, you can edit the profile to change the file modification time
  * Pcap Capture - capturing the function of the main switch, open the packet capture module can be used normally: 1 to enable/0 to disable.
    * Note: If the packet capture module is closed, it will automatically open the Direct Request function, enable Direct Request on the DNS poisoning pollution defensive ability is relatively weak
  * Pcap Devices Blacklist - Specifies that the network interface card containing this string will be ignored by capturing the network interface card containing this name, name or description
    * This parameter supports the designation of multiple names, case insensitive, formatted as "the name of the web interface card (name of the web interface card)" (without quotation marks, optional items in brackets)
    * The name or profile obtained from the system by the packet capture module is not necessarily the same as that shown by other network setup programs
  * Pcap Reading Timeout - Packet capture time, packets will only be read after waiting for a timeout, and the remaining time packets are in hibernation: in milliseconds, with a minimum of 10
    * Read the timeout time need to balance the demand and resource consumption, the time set too long will lead to the domain name resolution request response slow response request timeout, too fast will take up too much system to deal with resources
  * Listen Protocol - the protocol supported by the local listening request: can be filled with IPv4 and IPv6 and TCP and UDP
    * Fill in the agreement can be arbitrarily combined, only fill IPv4 or IPv6 with UDP or TCP, only listen to the specified agreement of the local port
  * Listen Port - the port of the listening port, the local listening request: the format "port A (|port B)" (without quotation marks, brackets are optional items)
    * Port can be filled in the service name, service name list see below
    * Port number must between 1 and 65535, default number is 53.
    * When multiple ports are filled in, the program will listen for requests at the same time
    * When the corresponding agreement Listen Address takes effect, this parameter of the corresponding agreement will be automatically ignored
  * Operation Mode - Program monitoring mode: Server/Server mode, Private/private network mode and Proxy/proxy mode
    * Server/server mode: Open the DNS port, for all other devices to provide proxy function variable name resolution request service
    * Private/private network mode: open the DNS port, can only be limited to the private network address of the device to provide proxy function variable name resolution request service
    * Proxy/proxy mode: only open the loopback address of the DNS port, only for the machine to provide proxy function variable name resolution request service
    * Custom/custom mode: open the DNS port, the available address determined by the IPFilter parameters
    * When the corresponding agreement Listen Address takes effect, this parameter of the corresponding agreement will be automatically ignored
  * IPFilter Type - IPFilter parameter type: divided into Deny prohibited and Permit allowed, corresponding to the application of IPFilter parameters for the blacklist or white list
  * IPFilter Level - IPFilter parameter filtering level, the higher the level of the more stringent filtering, and IPFilter entries corresponding to: 0 is not enabled for filtering, if left to 0
  * Accept Type - Disables or allows only requests for DNS types listed in the format "Deny: DNS record name or ID (name or ID of DNS record)" or "Permit: DNS record name or ID (|DNS record Name or ID) "(without quotation marks, optional items in parentheses), list of all available DNS types:
    * A/1
    * NS/2
    * MD/3
    * MF/4
    * CNAME/5
    * SOA/6
    * MB/7
    * MG/8
    * MR/9
    * NULL/10
    * WKS/11
    * PTR/12
    * HINFO/13
    * MINFO/14
    * MX/15
    * TXT/16
    * RP/17
    * AFSDB/18
    * X25/19
    * ISDN/20
    * RT/21
    * NSAP/22
    * NSAP_PTR/23
    * SIG/24
    * KEY/25
    * PX/26
    * GPOS/27
    * AAAA/28
    * LOC/29
    * NXT/30
    * EID/31
    * NIMLOC/32
    * SRV/33
    * ATMA/34
    * NAPTR/35
    * KX/36
    * CERT/37
    * A6/38
    * DNAME/39
    * SINK/40
    * OPT/41
    * APL/42
    * DS/43
    * SSHFP/44
    * IPSECKEY/45
    * RRSIG/46
    * NSEC/47
    * DNSKEY/48
    * DHCID/49
    * NSEC3/50
    * NSEC3PARAM/51
    * TLSA/52
    * HIP/55
    * NINFO/56
    * RKEY/57
    * TALINK/58
    * CDS/59
    * CDNSKEY/60
    * OPENPGPKEY/61
    * SPF/99
    * UINFO/100
    * UID/101
    * GID/102
    * UNSPEC/103
    * NID/104
    * L32/105
    * L64/106
    * LP/107
    * EUI48/108
    * EUI64/109
    * ADDRS/248
    * TKEY/249
    * TSIG/250
    * IXFR/251
    * AXFR/252
    * MAILB/253
    * MAILA/254
    * ANY/255
    * URI/256
    * CAA/257
    * TA/32768
    * DLV/32769
    * RESERVED/65535

* DNS - function variable name resolution parameter area
  * Outgoing Protocol - The protocol of sending request to remote DNS server: Format is "Network Layer + Transport Layer( + Type)" (without quotation marks, items in brackets are optional).
    * Network Layer can be filled in "IPv4" or "IPv6" or "IPv4 + IPv6". Auto select protocol if fill in "IPv4 + IPv6" or nothing.
    * Transport Layer can be filled in "TCP" or "UDP" or "TCP + UDP". Program will retry using UDP if TCP is failed, fill in "Force TCP" to stop this operation.
    * Filling in "Type" will enable selecting protocol based on DNS type.
  * Direct Request - Direct connection mode, enable the system will use the system directly request the remote server: can fill in IPv4 and IPv6 and 0, turn off to 0
    * It is recommended when the system uses the global proxy function, the program will be in addition to all the requests outside the domestic server directly to the system without any filtering and other processing, the system will automatically send the request to the remote server for analysis
    * When you fill in IPv4 or IPv6, you will enable the Direct Request function of the corresponding protocol. Filling in IPv4 + IPv6 will enable all protocol functions
  * Cache Type - the type of DNS cache: sub-Timer/Chrono, Queue/Queue type and their mixed type, fill in 0 to turn off this feature
    * Timer/Timing: DNS buffers that exceed the specified time will be discarded
    * Queue/Queue: When the queue length is exceeded, the oldest DNS cache is deleted
    * Blending type: When the specified time is exceeded and the queue length is exceeded, the oldest DNS cache is deleted
  * Cache Type - the type of DNS cache: sub-Timer/Chrono, Queue/Queue type and their mixed type, fill in 0 to turn off this feature
    * Timer/Timing: DNS buffers that exceed the specified time will be discarded
    * Queue/Queue: When the queue length is exceeded, the oldest DNS cache is deleted
    * Mixed type: When the specified time is exceeded, the oldest DNS cache is deleted when the queue length is exceeded and the TTL of the function variable itself is exceeded
  * Cache Parameter - DNS cache parameters: sub-Timer/Chrono, Queue/Queue type and their mixed type, fill in 0 to turn off this feature
    * Timer/Timing type
      * Cache time in seconds
      * If the average TTL value of the resolution result is greater than this value, use [TTL + this value] for the final cache time
      * If the average TTL value of the resolution result is less than or equal to this value, use [this value] as the final cache time
      * If fill 0, the final cache time is TTL
    Queue/Queue: Queue Length
    * Mixed type
      * Queue length
      * The final cache time in this mode is determined by the Default TTL parameter
  * Cache Single IPv4 Address Prefix - IPv4 protocol Separate DNS cache queue address used by the length: the unit is the bit, the maximum is 32 to fill in 0 to turn off this feature
    * All requests at private addresses are not controlled by this parameter and have a default cache queue
  * Cache Single IPv6 Address Prefix - IPv6 protocol Separate DNS cache queue address used by the length: the unit is bit, up to 128 fill in 0 to turn off this feature
    * All requests at private addresses are not controlled by this parameter and have a default cache queue
  * Default TTL - cached DNS record default retention time: in seconds, left for 900 seconds/15 minutes
    * When the DNS cache type is mixed, this parameter will determine the final cache time
      * If the average TTL value of the resolution result is greater than this value, use [TTL + this value] for the final cache time
      * If the average TTL value of the resolution result is less than or equal to this value, use [this value] as the final cache time
      * If fill 0, the final cache time is TTL
  
* Local DNS - Domestic function variable name resolution parameter area
  * Local Protocol - The protocol of sending request to local(ISP's) DNS server: Format is "Network Layer + Transport Layer( + Type)" (without quotation marks, items in brackets are optional).
    * Network Layer can be filled in "IPv4" or "IPv6" or "IPv4 + IPv6". Auto select protocol if fill in "IPv4 + IPv6" or nothing.
    * Transport Layer can be filled in "TCP" or "UDP" or "TCP + UDP". Program will retry using UDP if TCP is failed, fill in "Force TCP" to stop this operation.
    * Filling in "Type" will enable selecting protocol based on DNS type.
  * Local Hosts - Whitelist Domestic Server Request Features: On 1/Off 0
    * This function will only try to read the data in the Local Hosts whitelist and will not read any white list data when it is off
  * Local Routing - Local routing table identification: open to 1/off to 0
    * After this function is enabled, all requests will be sent to the domestic server for domain name resolution, and then the next step according to the analysis results
  * Local Force Request - Forced to use the domestic server to resolve: open to 1/off to 0
  * NOTE: A description of the combination of Local Hosts, Local Routing, and Local Force Request
    * By default, the server fails to resolve in the country will be the next step
    * All parameters are off, directly skip the process of using the domestic server for domain name resolution
    * Local Hosts can be turned on separately: Will be (black) whitelisted (no) hit the rules of the domain name, (not) use the domestic server to resolve
    * Local Routing can be opened independently: All requests will be sent to the domestic server for domain name resolution first, and then match according to the routing table. The result of parsing the hit routing table will be directly returned to the requester
    * Local Force Request can not be enabled separately: need to be used with Local Hosts
    * Local Hosts + Local Routing can not be enabled at the same time: Function conflict
    * Local Hosts + Local Force Request can be enabled at the same time: Forcing the domain name that has hit the rule can only be resolved by using the domestic server. If the result of the parsing is incorrect, it will be directly discarded and the entire parsing process will be terminated
    * Local Routing + Local Force Request can not be enabled at the same time: Function conflict
    * Local Hosts + Local Routing + Local Force Request can be enabled at the same time: All requests (except those specified in the blacklist) will be sent to the local server for domain name resolution first. According to the nature of the request:
      * If the domain name of the request hits Local Hosts, the domain name that has been hit must be forcibly resolved using the domestic server. If the result of the parsing is incorrect, the domain name will be directly discarded and the entire parsing process will be terminated
      * If the requested domain name does not hit Local Hosts match according to the routing table, the result of the hit routing table will be returned directly to the requester
      * All requests that did not hit and did not successfully match the routing table will proceed to the next step

* Addresses - normal mode address area
  * IPv4 Listen Address - IPv4 local listening address: need to enter a port format with the address, leave it blank
    * Supports multiple addresses
    * The Operation Mode and Listen Port parameters of the IPv4 protocol will be automatically ignored when this value is entered
  * IPv4 EDNS Client Subnet Address - IPv4 user subnet address, after the input will be added to all requests for this address EDNS subnet information: need to enter a prefix with the length of the local public network address, leave blank Enabled
    * This feature requires the EDNS Label parameter to be enabled
    * EDNS Client Subnet Relay parameter priority is higher than this parameter. After enabling, the EDNS subnet address of EDNS Client Subnet Relay will be added preferentially.
    * The RFC standard recommends that the IPv4 address has a first code length of 24 bits and an IPv6 address of 56 bits
  * IPv4 Main DNS Address - IPv4 primary DNS server address: need to enter a port format with the address, leave it blank
    * Support multiple addresses, pay attention to fill will be forced to enable the Alternate Multiple Request parameters
    * Support the use of service name instead of port number
  * IPv4 Alternate DNS Address - IPv4 secondary DNS server address: need to enter a port format with the address, leave it blank
    * Support multiple addresses, pay attention to fill will be forced to enable the Alternate Multiple Request parameters
    * Support the use of service name instead of port number
  * IPv4 Local Main DNS Address - IPv4 main domestic DNS server address for domestic function variable name resolution: need to enter a port format with the address, leave it blank
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
  * IPv4 Local Alternate DNS Address - IPv4 backup DNS server address for internal function variable name resolution: need to enter a port format with the address, leave the space is not enabled
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
  * IPv6 Listen Address - IPv6 local listening address: need to enter a port format with the address, leave it blank
    * Supports multiple addresses
    * After entering this value, the Operation and Listen Port parameters of the IPv6 protocol will be automatically ignored
  * IPv6 EDNS Client Subnet Address - IPv6 user terminal network address, after the input will be added to all requests for this address EDNS subnet information: need to enter a prefix with the length of the local public network address, leave blank Enabled
    * This feature requires the EDNS Label parameter to be enabled
    * EDNS Client Subnet Relay parameter priority is higher than this parameter. After enabling, the EDNS subnet address of EDNS Client Subnet Relay will be added preferentially.
    * The RFC standard recommends that the IPv4 address has a first code length of 24 bits and an IPv6 address of 56 bits
  * IPv6 Main DNS Address - IPv6 Primary DNS Server Address: You need to enter a port with a port format, leave it blank
    * Support multiple addresses, pay attention to fill will be forced to enable the Alternate Multiple Request parameters
    * Support the use of service name instead of port number
  * IPv6 Alternate DNS Address - IPv6 secondary DNS server address: need to enter a port format with the address, leave it blank
    * Support multiple addresses, pay attention to fill will be forced to enable the Alternate Multiple Request parameters
    * Support the use of service name instead of port number
  * IPv6 Local DNS Address - IPv6 Main Domestic DNS Server Address for Domestic Function Variable Name Resolution: Requires input of a port with a port format, leaving blank
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
* IPv6 Local Alternate DNS Address - IPv6 Alternate Domestic DNS Server Address for Domestic Function Variable Name Resolution: Requires input of a port with a port format, leaving blank
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
  * Note:
    * Port address format:
      * A single IPv4 is "IPv4 address: port" (without quotation marks)
      * A single IPv6 is "[IPv6 address]: port" (without quotation marks)
      * Multiple IPv4 is "Address A: Port|Address B: Port|Address C: Port" (without quotation marks)
      * Multiple IPv6 is "[Address A]: Port|[Address B]: Port|[Address C]: Port" (without quotation marks)
      * Enable simultaneous request for multiple servers Simultaneous request to the server in the list to resolve the variable name and use the results of the fastest response server, and requests the alternate server to automatically enable the Alternate Multiple Request parameter (see below)
      * The number of servers that can be filled in is: Enter the number of primary/standby servers
      * Multiple Request Times = Total requested value, this value can not exceed 32
    * Format with preamble length address:
       * IPv4 is "IPv4 address/mask length" (without quotation marks)
       * IPv6 is "IPv6 address/prefix length" (without quotation marks)
    * When you specify a port, you can use the service name instead:
      * TCPMUX/1
      * ECHO/7
      * DISCARD/9
      * SYSTAT/11
      * DAYTIME/13
      * NETSTAT/15
      * QOTD/17
      * MSP/18
      * CHARGEN/19
      * FTP_DATA/20
      * FTP_DATA/21
      * SSH/22
      * TELNET/23
      * SMTP/25
      * TIMESERVER/37
      * RAP/38
      * RLP/39
      * NAMESERVER/42
      * WHOIS/43
      * TACACS/49
      * DNS/53
      * XNSAUTH/56
      * MTP/57
      * BOOTPS/67
      * BOOTPC/68
      * TFTP/69
      * RJE/77
      * FINGER/79
      * TTYLINK/87
      * SUPDUP/95
      * SUNRPC/111
      * SQL/118
      * NTP/123
      * EPMAP/135
      * NETBIOS_NS/137
      * NETBIOS_DGM/138
      * NETBIOS_SSN/139
      * IMAP/143
      * BFTP/152
      * SGMP/153
      * SQLSRV/156
      * DMSP/158
      * SNMP/161
      * SNMP_TRAP/162
      * ATRTMP/201
      * ATHBP/202
      * QMTP/209
      * IPX/213
      * IMAP3/220
      * BGMP/246
      * TSP/318
      * IMMP/323
      * ODMR/366
      * RPC2PORTMAP/369
      * CLEARCASE/371
      * HPALARMMGR/383
      * ARNS/384
      * AURP/387
      * LDAP/389
      * UPS/401
      * SLP/427
      * HTTPS/443
      * SNPP/444
      * MICROSOFTDS/445
      * KPASSWD/464
      * TCPNETHASPSRV/475
      * RETROSPECT/497
      * ISAKMP/500
      * BIFFUDP/512
      * WHOSERVER/513
      * SYSLOG/514
      * ROUTERSERVER/520
      * NCP/524
      * COURIER/530
      * COMMERCE/542
      * RTSP/554
      * NNTP/563
      * HTTPRPCEPMAP/593
      * IPP/631
      * LDAPS/636
      * MSDP/639
      * AODV/654
      * FTPSDATA/989
      * FTPS/990
      * NAS/991
      * TELNETS/992

* Values ​​- Extended parameter value area
  * Thread Pool Base Number - Runtime Basis Minimum Hold Thread: Min 8 Set to 0 Turn off the function of the thread
  * Thread Pool Maximum Number - Maximum threads in pool or buffer queue length: Minimum is 8, set to 8 if empty or 0.
    * When the Queue Limits Reset Time parameter is enabled, this parameter is the maximum number of requests per unit of time
    * The number of buffers used to receive data when the Queue Limits Reset Time parameter is not enabled
  * Thread Pool Reset Time - Time between rescan thread number to match policy: In seconds, Min 5 Set to 0 Turn this feature off
  * Queue Limits Reset Time - Data Buffer Queue Quantity Limit Reset Time: In seconds, Min 5 Set to 0 Turn this feature off
  * EDNS Payload Size - EDNS label with the maximum load length used: minimum for the DNS protocol to achieve the requirements of 512 (bytes), leave the EDNS label is required to use the shortest 1220 (bytes)
  * IPv4 Packet TTL - issue IPv4 packet header TTL value: 0 is automatically determined by the operating system, the value of 1 - 255 between
    * This parameter supports the specified range of values. The value actually used at the time of sending each packet is randomly specified within this range. The specified range is a closed range
  * IPv4 Main DNS TTL - IPv4 The primary DNS server accepts the requested remote DNS server packet TTL value: 0 is automatically fetched, the value is between 1 - 255
    * Supports multiple TTL values, corresponding to IPv4 DNS Address
  * IPv4 Alternate DNS TTL - The IPv4 secondary DNS server accepts the TTL value of the remote DNS server package that is requested: 0 is automatically fetched, with a value between 1 - 255
    * Supports multiple TTL values, corresponding to IPv4 Alternate DNS Address
  * IPv6 Packet Hop Limits - issue IPv6 header header HopLimits value: 0 is automatically determined by the operating system, the value of 1 - 255 between
    * This parameter supports the specified range of values. The value actually used at the time of sending each packet is randomly specified within this range. The specified range is a closed range
  * IPv6 Main DNS Hop Limits - IPv6 primary DNS server accepts the requested remote DNS server bundle Hop Limits value: 0 for automatic acquisition, the value is between 1 - 255
    * Supports multiple Hop Limits values, corresponding to IPv6 DNS Address
  * IPv6 Alternate DNS Hop Limits - IPv6 standby DNS server accepts the requested remote DNS server bundle Hop Limits value: 0 for automatic acquisition, the value is between 1 - 255
    * Supports multiple Hop Limits values, corresponding to IPv6 Alternate DNS Address
  * Hop Limits Fluctuation - IPv4 TTL/IPv6 Hop Limits Acceptable range, that is, IPv4 TTL/IPv6 Hop Limits value range of ± data packets can be accepted, to avoid the short-term changes in the network environment caused by the failure of the problem : The value is between 1 - 255
  * Reliable Once Socket Timeout - one-time reliable protocol port timeout: in milliseconds, a minimum of 500 can be left blank, leave the time for the 3000
    * One-time refers to the request in a RTT round-trip network transmission can be completed, such as standard DNS and DNSCurve (DNSCrypt) agreement
    * Reliable port refers to TCP protocol
  * Reliable Serial Socket Timeout - tandem reliable protocol port timeout: in milliseconds, a minimum of 500 can be left blank, leaving 1500
    * Tandem means that this operation requires multiple interactive network transmission to complete, such as SOCKS and HTTP CONNECT agreement
    * Reliable port refers to TCP protocol
  * Unreliable Once Socket Timeout - One-time unreliable protocol port timeout: in milliseconds, minimum 500 can be left blank, leave the time for 2000
    * One-time refers to the request in a RTT round-trip network transmission can be completed, such as standard DNS and DNSCurve (DNSCrypt) agreement
    * Unreliable port refers to UDP/ICMP/ICMPv6 agreement
  * Unreliable Serial Socket Timeout - Serial Unreliable Protocol Port Timeout: in milliseconds, a minimum of 500 can be left blank, leave the time for 1000
    * Tandem means that this operation requires multiple interactive network transmission to complete, such as SOCKS and HTTP CONNECT agreement
    * Unreliable port refers to UDP/ICMP/ICMPv6 agreement
 * TCP Fast Open - TCP Fast Open feature:
    * Support for this feature:
      * Windows platform
        * 1 to enable/0 to disable.
        * Server-side support, the client due to different types of I/O problems temporarily unable to support
        * Requires Windows 10 Version 1607 and later support
      * Linux platform:
        * This parameter can be specified to support TCP Fast Open queue length, directly fill in the value of more than 0 is the queue length, turn off to 0
        * Full support for server and client
        * IPv4 agreement requires Linux Kernel 3.7 and the latest version of the support, IPv6 agreement requires Linux Kernel 3.16 and the latest version of the kernel support
      * MacOS platform:
        * 1 to enable/0 to disable.
        * Full support for server and client
        * Requires macOS 10.11 Sierra and later versions support
    * Warning: Do not open this feature on an unsupported version, or it may prevent the program from sending or receiving packets normally!
  * Receive Waiting - the packet reception wait time, after the program will try to wait for a period of time to try to receive all the packets and return to the final arrival of the package: the unit is milliseconds, leave it blank or set to 0 to turn off this feature
    * This parameter is closely related to Pcap Reading Timeout, since the packet capture module will return to the program once every other time. When the packet reception wait time is less than the read timeout time, this parameter will not become Meaning, in some cases even slow down the response speed of the function variable name resolution
    * Although this parameter is enabled, it only determines the waiting time of the packet capture module, but it also affects the request of the non-packet capture module. The non-packet capture module automatically switches to the last reply received after waiting for a timeout, defaulting to the correct response to the first arrival, and their time-out by Reliable Once Socket Timeout/Unreliable Once Socket Timeout Parameter decision
    * In general, the reliability of the data package is likely to be higher
  * ICMP Test - ICMP/Ping test interval: in seconds, a minimum of 5 is set to 0 to turn off this function
  * Domain Test - DNS Server Resolution Function Variable Name Test Interval: In seconds, a minimum of 5 is set to 0 to turn off this feature
  * Alternate Times - Standby server failure thresholds, if a threshold exceeds a threshold triggers a server switch: In times, set to 5 if empty or 0.
  * Alternate Time Range - Standby Server Failed Thresholds Calculation Period: In seconds, minimum is 5, set to 10 if empty or 0.
  * Alternate Reset Time - Standby Server Resets the toggle time. After this switchover, this event will switch back to the primary server: In seconds, minimum is 5, set to 300 if empty or 0.
  * Multiple Request Times - Send parallel function to the same remote server at a time Variable name name Resolution request: 0 and 1 request 1 request when a request is received, 2 requests when a request is received 2, 3 Receive a request request 3 times .. and so on
    * This value will be applied to all remote servers except Local Hosts, so it may be stressful on the system and the remote server. Please consider the risk of opening!
    * The maximum number that can be filled in is: Enter the number of primary/standby servers
  * Multiple Request Times = Total requested value, this value cannot exceed 32.
    * Generally, unless the packet is very serious interference with the normal use of this is not recommended to open, open does not recommend the value set too much. The actual use of each +1 can be restarted after the service test results, find the most appropriate value
  * Note:
    * The TTL protocol is TTL (A)|TTL (B)|TTL (C) "(without quotation marks), or can be directly preset (that is, only one 0 does not use this format) TTL will be automatically obtained by the program
    Hop Limits (B)|Hop Limits (C) "(without quotation marks), can also be directly preset (that is, only fill a 0 does not use this format) All Hop Limits will be automatically retrieved by the program
    * The order in which multiple TTL/Hop Limits values ​​are used is the same as the order of addresses in the corresponding address parameters

* Switches - controls the switch area
  * Domain Case Conversion - random conversion function variable name request case: 1 to enable/0 to disable.
  * Compression Pointer Mutation - Randomly add compression index: 1 (+ 2 + 3), close to 0
    * There are three different types of random compression indicators, corresponding to 1 and 2 and 3
    * Can be used alone one, that is, only fill a number, or fill in multiple, the middle of the use of +
    * When you fill in multiple, you will randomly use one of them when you need to randomly add a compression metric, and each request may not be the same
  * EDNS Label - EDNS tag support, will be added after the request to add EDNS label: all 1 to enable/0 to disable.
    * This parameter can be specified only part of the request process using EDNS tags, divided into the specified mode and exclusion mode:
    * Specify the list mode, the process is listed to enable this feature: EDNS Label = Local + SOCKS Proxy + HTTP CONNECT Proxy + Direct Request + DNSCurve + TCP + UDP
    * Exclude list mode, the process listed does not enable this feature: EDNS Label = All - Local - SOCKS Proxy - HTTP CONNECT Proxy - Direct Request - DNSCurve - TCP - UDP
  * EDNS Client Subnet Relay - EDNS user terminal network forwarding function, after opening will be from non-private network address for all requests to add their request to use the address of the EDNS subnet address: 1 to enable/0 to disable.
    * This feature requires the EDNS Label parameter to be enabled
    * The priority of this parameter is higher than that of the IPv4/IPv6 EDNS Client Subnet Address. Therefore, when the EDNS subnet address needs to be added, the address of this parameter will be added first
  * DNSSEC Request - DNSSEC request, after opening will try to add DNSSEC request for all requests: 1 to enable/0 to disable.
    * This feature requires the EDNS Label parameter to be enabled
    * This feature does not have any ability to verify DNSSEC records, a separate open theory can not avoid the problem of DNS poisoning
  * DNSSEC Force Record - Force DNSSEC record function, will discard all functions without any DNSSEC records: 1 to enable/0 to disable.
    * This feature requires EDNS Label and DNSSEC Request parameters
    * This function does not have the full DNSSEC record test capability, a separate open theory can not avoid the problem of DNS poisoning
    * Warning: Due to the small number of functional variable names currently deployed DNSSEC, there is no DNSSEC function variable name resolution without DNSSEC records, which will cause all undeployed DNSSEC function variable name resolution failure!
  * Alternate Multiple Request - The standby server requests parameters at the same time, and requests the server that responds to the primary and standby servers at the same time with the fastest response: On 1/Off is 0
    * This request is enforced when multiple requests are enabled by the multi-server, and all servers that are present in the manifest are requested at the same time and the results of the fastest response server are used
  * IPv4 Do Not Fragment - IPv4 packet header Do Not Fragment flag: 1 to enable/0 to disable.
    * This feature does not support the macOS platform, this platform will directly ignore this parameter
  * TCP Data Filter - TCP packet header detection: 1 to enable/0 to disable.
  * DNS Data Filter - DNS header detection: 1 to enable/0 to disable.
  * Blacklist Filter - Resolve the results of the blacklist filter: 1 to enable/0 to disable.
  * Resource Record Set TTL Filter - RFC 2181 clarifications to the DNS specification, restrict TTL values of RRSet: 1 to enable/0 to disable.

* Data - data area
  * ICMP ID - ICMP/Ping packet header ID: Hexadecimal character in 0x****, randomly generated if empty.
  * ICMP Sequence - ICMP/Ping Package Header Sequence/Serial Number: Hexadecimal character in the format 0x ****, if left blank, increments from 0x0001 to each request loopback increment
  * ICMP Padding Data - ICMP Additional information, Ping program to send the request to make up the data to reach the Ethernet type network to send the minimum length of the data: length of 18 bytes - 2048 bytes between the ASCII data , Leave the ICMP extension using the Ping program
  * Domain Test Protocol - Protocol used when sending a request using Domain Test: Fill in TCP and UDP
  * Domain Test ID - DNS packet header ID: Hexadecimal character in 0x****, randomly generated if empty.
  * Domain Test Data - DNS Server Resolution Function Variable Name Test: Please enter a correct domain which less than 253 bytes of ASCII, randomly generated if empty.
  * Local Machine Server Name - Local DNS Server Name: Enter the correct function variable name and do not exceed 253 bytes of ASCII data, leaving pcap-dnsproxy.server as the local server name

* Proxy - proxy area
  * SOCKS Proxy - SOCKS protocol master switch, control all options related to the SOCKS protocol: 1 to enable/0 to disable.
  * SOCKS Version - Version used by the SOCKS Agreement: Fill in 4 or 4A or 5
    * SOCKS version 4 does not support IPv6 address and function variable name of the target server, and does not support UDP forwarding function
    * SOCKS version 4a does not support IPv6 address of the target server, and does not support UDP forwarding function
  * SOCKS Protocol - The protocol of sending request to SOCKS server: Format is "Network Layer + Transport Layer( + Type)" (without quotation marks, items in brackets are optional).
    * Network Layer can be filled in "IPv4" or "IPv6" or "IPv4 + IPv6". Auto select protocol if fill in "IPv4 + IPv6" or nothing.
    * Transport Layer can be filled in "TCP" or "UDP" or "TCP + UDP". Program will retry using TCP if UDP is failed, fill in "Force UDP" to stop this operation.
    * Filling in "Type" will enable selecting protocol based on DNS type.
  * SOCKS UDP No Handshake - SOCKS UDP does not shake hands mode, will not open after the TCP handshake directly send UDP forwarding request: 1 to enable/0 to disable.
    * The standard flow of the SOCKS protocol must use the TCP connection to exchange handshaking information before using the UDP forwarding function. Otherwise, the SOCKS server will discard the forwarding request
    * Part of the SOCKS local proxy can be directly UDP forwarding without the use of TCP connection exchange handshake information, please be sure to confirm the SOCKS server support before
  * SOCKS Proxy Only - Only use the SOCKS protocol proxy mode, all requests will only be made via the SOCKS protocol: 1 to enable/0 to disable.
  * SOCKS IPv4 Address - SOCKS protocol IPv4 primary SOCKS server address: need to enter a port format with the address
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
  * SOCKS IPv6 Address - SOCKS Agreement IPv6 Primary SOCKS Server Address: Requires input of a port with a port format
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
  * SOCKS Target Server - SOCKS The final destination server: you need to enter a port format IPv4/IPv6 address or function variable name
    * Does not support multiple address or function variable names, can only fill in a single address or function variable name
    * Support the use of service name instead of port number
  * SOCKS Username - User name used when connecting to SOCKS server: maximum length of 255 characters, blank
  * SOCKS Password - the password used to connect to the SOCKS server: up to 255 characters, leave it blank
  * HTTP CONNECT Proxy - HTTP CONNECT protocol master switch, control all options related to the HTTP CONNECT protocol: 1 to enable/0 to disable.
  * HTTP CONNECT Protocol - The protocol of sending request to HTTP CONNECT proxy server: Format is "Network Layer( + Type)" (without quotation marks, items in brackets are optional).
    * Network Layer can be filled in "IPv4" or "IPv6" or "IPv4 + IPv6". Auto select protocol if fill in "IPv4 + IPv6" or nothing.
    * Filling in "Type" will enable selecting protocol based on DNS type.
  * HTTP CONNECT Proxy Only - Only use the HTTP CONNECT protocol proxy mode, all requests will be made only via the HTTP CONNECT protocol: 1 to enable/0 to disable.
  * HTTP CONNECT IPv4 Address - HTTP CONNECT protocol IPv4 Primary HTTP CONNECT server address: need to enter a port format with the address
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
  * HTTP CONNECT IPv6 Address - HTTP CONNECT Agreement IPv6 Primary HTTP CONNECT Server Address: Requires input of a port with a port format
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
  * HTTP CONNECT Target Server - HTTP CONNECT The final destination server: you need to enter a port format IPv4/IPv6 address or function variable name
    * Does not support multiple address or function variable names, can only fill in a single address or function variable name
    * Support the use of service name instead of port number
  * HTTP CONNECT TLS Handshake - HTTP CONNECT Agreement TLS Handshake and Encrypted Transfer Master Switch: 1 to enable/0 to disable.
  * HTTP CONNECT TLS Version - HTTP CONNECT protocol Enable TLS Handshake and Encrypted Transmission Specified version used: Set to 0 to automatically select
    * At this stage can be filled with 1.0 or 1.1 or 1.2
    * Windows XP/2003 and Windows Vista do not support versions higher than 1.0
    * OpenSSL 1.0.0 and previous versions do not support versions higher than 1.0
  * HTTP CONNECT TLS Validation - HTTP CONNECT protocol When TLS handshaking is enabled Server certificate chain check: 1 to enable/0 to disable.
    * Warning: Turn off this feature will likely cause the encrypted connection to be attacked by the middleman, strongly recommended to open!
    * Warning: OpenSSL 1.0.2 previous version does not support check the server certificate function variable name match, please pay attention!
  * HTTP CONNECT TLS Server Name Indication - HTTP CONNECT The function used to specify the TLS handshake. Variable Name Server: Please enter the correct function variable name and do not exceed 253 bytes ASCII data, leave it blank Features
  * HTTP CONNECT TLS ALPN - HTTP CONNECT Agreement Whether to enable Application-Layer Protocol Negotiation/ALPN extension when TLS handshaking: 1 to enable/0 to disable.
    * This feature is not supported on Windows 8 and earlier
    * OpenSSL 1.0.1 and previous versions do not support this feature
    * Warning: Do not open this feature on an unsupported version, or it may prevent the program from sending or receiving packets normally!
  * HTTP CONNECT Version - Version used by the HTTP CONNECT protocol: set to 0 to automatically select
    * At this stage can be filled 1.1 or 2
    * Note: According to the standard requirements, use HTTP/2 to open HTTP CONNECT TLS Handshake at the same time must be filled with HTTP CONNECT TLS Server Name Indication and enable HTTP CONNECT TLS ALPN parameters
    * Note: According to the standard requirements, use HTTP/2 to open HTTP CONNECT TLS Handshake at the same time must specify greater than or equal to 1.2 HTTP CONNECT TLS Version
    * Warning: This feature does not support the transition from 1.1 to 2 transition program, the use of HTTP/2 if the server does not support the request will directly lead to failure!
  * HTTP CONNECT Header Field - Include information on HTTP CONNECT Header: The information entered will be added directly to the HTTP CONNECT Header
    * This parameter can be repeated many times, and all the information about the HTTP CONNECT header of the content will be recorded and added to the HTTP CONNECT header in sequence
    * Note: According to the standard requirements, the region can not fill in any of the following fields:
      * Connection
      * Content-Length
      * Proxy-Connection
      * Transfer-Encoding
      * Upgrade
  * HTTP CONNECT Proxy Authorization - Authentication information used when connecting an HTTP CONNECT proxy server: You need to enter the "username: password" (without the quotation marks), leave it blank
    * Only Base mode authentication is supported

* DNSCurve - DNSCurve Agreement Basic Parameter Area
  * DNSCurve - DNSCurve protocol master switch that controls all options related to the DNSCurve protocol: 1 to enable/0 to disable.
  * DNSCurve Protocol - The protocol of sending request to DNSCurve server: Format is "Network Layer + Transport Layer( + Type)" (without quotation marks, items in brackets are optional).
    * Network Layer can be filled in "IPv4" or "IPv6" or "IPv4 + IPv6". Auto select protocol if fill in "IPv4 + IPv6" or nothing.
    * Transport Layer can be filled in "TCP" or "UDP" or "TCP + UDP". Program will retry using TCP if UDP is failed, fill in "Force UDP" to stop this operation.
    * Filling in "Type" will enable selecting protocol based on DNS type.
  * DNSCurve Payload Size - The maximum payload length that is included with the DNSCurve tag, as well as the total length of the request sent and the requested fill length: in bytes
    * Minimum for the DNS protocol to achieve the requirements of 512, leaving 512
    * Maximum of Ethernet MTU minus the DNSCurve header length, it is recommended not to exceed 1220
    * The DNSCurve protocol requires this value to be a multiple of 64
  * DNSCurve Reliable Socket Timeout - Reliable DNSCurve Protocol Port Timeout, Reliable Port TCP Protocol: in milliseconds, minimum to 500, can be left blank, leave space for 3000
  * DNSCurve Unreliable Socket Timeout - unreliable DNSCurve protocol port timeout time, unreliable port refers to the UDP protocol: in milliseconds, the minimum is 500, can be left blank, leave the time for the 2000
  * DNSCurve Encryption - Enable encryption, DNSCurve protocol supports both encrypted and unencrypted modes: 1 to enable/0 to disable.
  * DNSCurve Encryption Only - only use encryption mode, all requests will only be through DNCurve encryption mode: 1 to enable/0 to disable.
    * Note: Use "Only use encryption mode" must provide the server's magic number and fingerprints for request and reception
  * DNSCurve Client Ephemeral Key - One-off client key group mode, each request resolution using a randomly generated one-time client key group, providing forward security: 1 to enable/0 to disable.
  * DNSCurve Key Recheck Time - DNSCurve Agreement DNS Server Connection Information Check Interval: In seconds, minimum is 10, set to 1800 if empty or 0.

* DNSCurve Database - DNSCurve Agreement Database area
  * DNSCurve Database Name - The file name of the DNSCurve agreement database
    * Multiple file names are not supported
  * DNSCurve Database IPv4 Main DNS - DNSCurve Agreement IPv4 Primary DNS Server Address: The Name field of the corresponding server in the DNSCurve protocol database needs to be populated
  * DNSCurve Database IPv4 Alternate DNS - DNSCurve Agreement IPv4 Secondary DNS Server Address: You need to fill in the Name field of the corresponding server in the DNSCurve protocol repository
  * DNSCurve Database IPv6 Main DNS - DNSCurve Agreement IPv6 Primary DNS Server Address: You need to fill in the Name field of the corresponding server in the DNSCurve protocol database
  * DNSCurve Database IPv6 Alternate DNS - DNSCurve Agreement IPv6 Alternate DNS Server Address: You need to fill in the Name field of the corresponding server in the DNSCurve protocol repository
  * Note:
    * Enabling this feature will override the configuration of the DNSCurve server set in the profile!
    * When there are multiple DNSCurve agreement databases in multiple additional paths, the first name field is present, whichever is first read

* DNSCurve Addresses - DNSCurve protocol address area
  * DNSCurve IPv4 Main DNS Address - DNSCurve Agreement IPv4 Primary DNS Server Address: Requires input of a port formatted address
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
  * DNSCurve IPv4 Alternate DNS Address - DNSCurve protocol IPv4 secondary DNS server address: need to enter a port format with the address
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
  * DNSCurve IPv6 Main DNS Address - DNSCurve Agreement IPv6 Primary DNS Server Address: Requires input of a port formatted address
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
  * DNSCurve IPv6 Alternate DNS Address - DNSCurve Agreement IPv6 Alternate DNS Server Address: Requires input of a port formatted address
    * Does not support multiple addresses, can only fill a single address
    * Support the use of service name instead of port number
  * DNSCurve IPv4 Main Provider Name - DNSCurve Agreement IPv4 Primary DNS Server Provider, enter the correct function variable name and do not exceed 253 bytes of ASCII data
  * DNSCurve IPv4 Alternate Provider Name - DNSCurve Agreement IPv4 Backup DNS Server Provider, enter the correct function variable name and do not exceed 253 bytes of ASCII data
  * DNSCurve IPv6 Main Provider Name - DNSCurve Agreement IPv6 Primary DNS Server Provider, enter the correct function variable name and do not exceed 253 bytes of ASCII data
  * DNSCurve IPv6 Alternate Provider Name - DNSCurve Agreement IPv6 Alternate DNS Server Provider, enter the correct function variable name and do not exceed 253 bytes of ASCII data
  * Note:
    * Automatically get DNSCurve server connection information must be entered when the provider function variable name, can not be left blank
    * More support for DNSCurve (DNSCrypt) servers please move https://github.com/dyne/dnscrypt-proxy/blob/master/dnscrypt-resolvers.csv

* DNSCurve Keys - DNSCurve agreement key area
  * DNSCurve Client Public Key - Custom Client Public Key: Can be generated using KeyPairGenerator, leaving it blank automatically every time it starts
  * DNSCurve Client Secret Key - custom client private key: can be generated using KeyPairGenerator, leave it automatically every time you start
  * DNSCurve IPv4 Main DNS Public Key - DNSCurve Agreement IPv4 Primary DNS Server Authentication Public Key
  * DNSCurve IPv4 Alternate DNS Public Key - DNSCurve Agreement IPv4 Backup DNS Server Authentication Public Key
  * DNSCurve IPv6 Main DNS Public Key - DNSCurve Agreement IPv6 Primary DNS Server Authentication Public Key
  * DNSCurve IPv6 Alternate DNS Public Key - DNSCurve Agreement IPv6 Alternate DNS Server Authentication Public Key
  * DNSCurve IPv4 Main DNS Fingerprint - DNSCurve Agreement IPv4 main DNS server transmission with fingerprints, leaving blank automatically through the server provider and public key to obtain
  * DNSCurve IPv4 Alternate DNS Fingerprint - DNSCurve agreement IPv4 backup DNS server transmission with fingerprints, leave the space automatically through the server provider and the public key to obtain
  * DNSCurve IPv6 Main DNS Fingerprint - DNSCurve Agreement IPv6 Alternate DNS Server Transfer Fingerprint, Leave blank automatically via server provider and public key
  * DNSCurve IPv6 Alternate DNS Fingerprint - DNSCurve Agreement IPv6 Alternate DNS Server transmission with fingerprints, leaving blank is automatically obtained through the server provider and public key
  * Note:
    * The "public key" on the public website is generally a public key for verification, which is used to verify the fingerprints used for communication with the server. Both are of a different nature.

* DNSCurve Magic Number - DNSCurve Agreement Magic Number Area
  DNSCurve Agreement IPv4 Primary DNS Server Receiving Magic Number: The length must be 8 bytes (ASCII) or 18 bytes (hexadecimal), leaving the program using built-in receive magic number
  * DNSCurve IPv4 Alternate Receive Magic Number - DNSCurve Agreement IPv4 Alternate DNS Server Received Magic Number: The length must be 8 bytes (ASCII) or 18 bytes (hexadecimal), leaving the program using built-in receive magic number
  * DNSCurve IPv6 Main Receive Magic Number - DNSCurve Agreement IPv6 Primary DNS Server Receiving Magic Number: The length must be 8-byte (ASCII) or 18-byte (hexadecimal), leaving the program with built-in receive magic
  * DNSCurve IPv6 Alternate Receive Magic Number - DNSCurve Agreement IPv6 Alternate DNS Server Receiving Magic Number: The length must be 8-byte (ASCII) or 18-byte (hexadecimal), leaving the program with built-in receive magic
  * DNSCurve IPv4 Main DNS Magic Number - DNSCurve Agreement IPv4 Primary DNS Server Send Magic: The length must be 8-byte (ASCII) or 18-byte (hexadecimal), leaving it blank automatically
  * DNSCurve IPv4 Alternate DNS Magic Number - DNSCurve Agreement IPv4 Alternate DNS Server Sent Magic Number: The length must be 8 bytes (ASCII) or 18 bytes (hexadecimal), leaving it blank automatically
  * DNSCurve IPv6 Main DNS Magic Number - Agreement IPv6 Primary DNS Server Send Magic: The length must be 8-byte (ASCII) or 18-byte (hexadecimal), leaving it blank automatically
  * DNSCurve IPv6 Alternate DNS Magic Number - DNSCurve Agreement IPv6 Alternate DNS Server Sent Magic Number: The length must be 8 bytes (ASCII) or 18 bytes (hexadecimal), leaving it blank automatically
  * Note: The Magic Number parameter is also supported with ASCII characters or hexadecimal strings
    * Can be filled directly to print ASCII string can be
    * Hexadecimal string need to precede the string with 0x (case sensitive)


-------------------------------------------------------------------------------


Hosts File Format Description:

The Hosts profile is divided into multiple areas that provide different functions
* The area is identified by the label, and it is not deleted when it is modified
* The total length of an entry must not exceed 4096 bytes/4KB
* Need to be added Please add #/pound sign at the beginning of the entry
* The priority order is reduced from top to bottom, the higher the priority of the entry
* Parallel Hosts entry support quantity is determined by the requested function variable name and EDNS Payload length, no more than 75 A records or 43 AAAA records


* Whitelist - whitelist entry
  * This type of entry lists the required functional variable names that will directly bypass Hosts without using the Hosts feature
  * Valid parameter format is "NULL regular expression" (without quotation marks)
  * Attention to priority issues, such as an area with a whitelist entry:

    NULL.*\.Test\.test
    127.0.0.2|127.0.0.2. 127.0.0.3.*\.Test

  * Although.*\.Test contains.*\.Test\.test but because of the priority order from top to bottom decrement, so first hit.*\.Test\.test and return to the use of remote server resolution
  * Thus bypassing the following entry, do not use the function of Hosts


* Whitelist Extended - white list entry extension function
  * This type of entry also supports specific types of functions that conform to the rules. Variable name requests that directly bypass Hosts will not use the Hosts feature
  * Valid parameter format is "NULL: DNS type(|DNS type) Regular expression" (without quotation marks, brackets are optional items)
  * Only allow specific types of function variable name request, valid parameter format is "NULL(Permit): DNS type(|DNS type) Regular expression" (without quotation marks)

    NULL: A|AAAA.*\.Test\.test
    NULL(Deny): NS|SOA.*\.Test

  * The first is to skip the A record of the matching rule and the function variable name request of the AAAA record. Other types of requests are matched rules
  * And the second only matches the NS record of the rule and the function variable name request for the SOA record, and the other type of request is skipped directly

* Banned - blacklist entry
  * This type of entry lists the required function variable name will directly return to the function variable name does not exist function, to avoid redirection caused by the problem
  * Valid parameter format is "BANNED regular expression" (without quotation marks)
  * Note the priority of the problem, for example, there is a blacklist entry area:

    Banned.*\.Test\.test
    127.0.0.2|127.0.0.2. 127.0.0.3.*\.Test

  *.*\.Test contains.*\.Test\.test but because of the priority from top to bottom decrement, so the first hit. *. Test.test and directly return function variable name does not exist
  * Thus bypassing the following entry to achieve the purpose of the mask function variable name


* Banned Extended - blacklist entry extension function
  * This type of entry also supports the ability to mask or release a specific type of function name request that conforms to the rule
  * Valid parameter format is "BANNED: DNS type(|DNS type) Regular expression" (without quotation marks, brackets are optional items)
  * Only the specific type of function variable name request is allowed. The valid parameter format is "BANNED (Permit): DNS type(|DNS type) Regular expression" (without quotation marks, optional items in parentheses)

    BANNED: A|AAAA.*\.Test\.test
    BANNED (Permit): NS|SOA.*\.Test

  * The first is the mask record of the matching rule and the AAAA record of the domain name request, other types of requests are released
  * And the second is only the release of the rules of the NS records and SOA records of the domain name request, other types of requests are blocked


* Hosts/CNAME Hosts - Main Hosts List/CNAME Hosts List
  * The main difference between the main Hosts list and the CNAME Hosts list is that the scope of the role is different. The scope of the former is the received function variable name resolution request, which is the received function variable name resolution result
    * Valid parameter format is "Address (|address A|address B) Function variable name of the regular formula" (without quotation marks, brackets are optional items, pay attention to the location of the interval)
  * According to the source address Hosts list, according to the received function variable name resolution request source address to determine whether the need for Hosts
    * The valid parameter format is "Source Address/Front Length (|Source Address A/Front Length A|Source Address B/Front Length B) -> Address (Address A|Address B) Function Variable name of the regular formula "(without quotation marks, brackets are optional items, pay attention to the location of the interval)
  * The interval between the address and the regular expression can be a space/half space or HT/level positioning symbol, the interval length is not limited, but do not enter the full space
  * An entry can only accept a URL type(IPv4/IPv6), if the same function variable name needs to be IPv4/IPv6 Hosts, please divided into two entry input
  * The principle of parallel address for a return to multiple records, and the specific use of which records by the requestor, usually for the first
  * For example, there is a valid data area under [Hosts]:

    127.0.0.2|127.0.0.2|127.0.0.3.*\.Test\.test
    127.0.0.4|127.0.0.5|127.0.0.6.*\.Test
    ::1|::2|::3.*\.Test\.test
    ::4|::5|::6.*\.Test

  *.*\.Test contains.*\.Test\.test but because of the priority order from top to bottom down, so the first hit. *. Test \.Test and direct return, no other checks
    * Request to parse xxx.test A record (IPv4) will return 127.0.0.4, 127.0.0.5 and 127.0.0.6
    * Request to parse xxx.test AAAA records (IPv6) will return::4,::5 and::6
    * Request to parse xxx.test.test A record (IPv4) will return 127.0.0.1, 127.0.0.2 and 127.0.0.3
    * Request to parse xxx.test.test for AAAA records (IPv6) will return::1,::2 and::3

* Local Hosts - Active DNS resolution function variable name list
This area is used to improve the access speed by using the DNS server resolution for the function variable name. Please make sure that the DNS server address is not empty during use (see the section above for details of the configuration file)
Valid parameter format is "regular expression" (without quotation marks)
  * To use this feature, you must open the Local Hosts option in the profile!
  * This function does not filter any DNS server response in the country. Please make sure that the information entered in this area will not be disturbed by DNS poisoning
  * For example, there is a [Local Hosts] valid data area:

    .*\.Test\.test
    .*\.Test

  * All functional variable name requests that conform to the above regular expressions will be resolved using the domestic DNS server


* Address Hosts - parse the results address of the other list
  * The region data is used to replace the addresses in the resolution results, providing more accurate Hosts customization capabilities
  * Target address area support Use the network header format to replace the header data of the address in the resolution based on the specified prefix length
    * When using the network header format, the first destination address entry must specify the prefix length, and the other destination address can be omitted or written.
    * After the network header format is specified, it will be applied to all target addresses. Note that the entire entry can only specify the same prefix length
  * For example, there is a valid data area under [Address Hosts]:

    127.0.0.1|127.0.0.2 127.0.0.0-127.255.255.255
    255.255.255.255/24 255.254.253.252
    ::1::-::FFFF
    FFFF:EEEE::/ 64|FFFF:EEEE::FFFF::EEEE|​​FFFF::EEEF-FFFF::FFFF

  * Resolution of the address range of 127.0.0.0 to 127.255.255.255 will be replaced by 127.0.0.1 or 127.0.0.2
  * The resolution of the result is 255.254.253.252 when the address is replaced by 255.255.255.252
  * The resolution of the address range is: to::FFFF will be replaced by::1
  * FFFF::EEEE or FFFF::EEEF:EFFF::EEEF to FFFF:::EEEE or FFFF:EEEE::xxxx:xxxx:xxxx:xxxx

* Stop - temporarily stop reading the label
  * Add "[Stop End]" (without quotation marks) before adding "[Stop]" and data to stop reading the data.
  * Temporary stop reading after the entry into force need to temporarily stop reading the end of the label or other labels will not start reading again
  * For example, there is a piece of information area:

    [Hosts]
    [Stop]
    127.0.0.2|127.0.0.2|127.0.0.3.*\.Test\.test
    127.0.0.4|127.0.0.5|127.0.0.6.*\.Test
    [Stop End]
    ::1|::2|::3.*\.Test\.test
    ::4|::5|::6.*\.Test

    [Local Hosts]
    .*\.Test\.test
    .*\.Test

  * From the [Stop] line, the following to the [Stop End] between the data will not be read
  * The actual valid data area is:

    [Hosts]
    ::1|::2|::3.*\.Test\.test
    ::4|::5|::6.*\.Test

    [Local Hosts]
    .*\.Test\.test
    .*\.Test


* Dnsmasq Address - Dnsmasq compatible address format
  * Address Compatible format for Hosts/CNAME Hosts - Main Hosts List/CNAME Hosts List
  * Valid parameter format:
    * First code support --ADDRESS=/ or --Address=/ or --address=/ or ADDRESS=/ or Address=/ or address=/
    * Normal function Variable name String match mode is "Address=/ function variable name suffix/(address)" (without quotation marks, brackets are optional items), function variable name suffix If only fill in "#" It means matching all function variable names
    * Regular expression mode is "Address=/:Regular expression:/(address)" (without quotation marks, brackets are optional items)
    * If the address part is left blank, it is equivalent to Banned - blacklist entry
  * For example, the following [Hosts] entry is exactly equivalent:

    Address=/:.*\Btest:/127.0.0.1
    Address=/test/ 127.0.0.1

  * Match all functional variable names to resolve the results to::1

    Address=/#/::1

  * On the rules of the function of the variable name return function variable name does not exist information

    Address=/test/


* Dnsmasq Server - Dnsmasq compatible server format
  * To use this feature, you must open the Local Hosts option in the profile!
  * Server compatibility format for Local Hosts - List of DNS resolution variables in the territory
  * Valid parameter format:
    * First code support - SERVER=/ or --Server=/ or --server=/ or SERVER=/ or Server=/ or server=/
    * Common function variable name string match mode is "Server=/ (function variable name suffix)/(specify the DNS address to resolve (# port))" (without quotation marks, brackets are optional items)
    * Regular operation mode is "Server=/(:regular expression:)/(specify the DNS address to resolve (# port))" (without quotation marks, brackets are optional items)
    * Function variable name suffix or: regular expression: part of the blank is not filled, the equivalent of matching does not meet the standard function variable name, for example, nothing.
    * Specifies that the DNS address part of the parsing is empty if it is left, which is equivalent to using the default DNS server specified by the program profile
    * Specifies that the DNS address part of the resolution is only filled with "#" equivalent to Whitelist - whitelist entry
  * For example, the following [Local Hosts] entry is exactly equivalent:

    Server=/:.*\ Btest:/::1 # 53
    Server=/ test/::1

  * The function variable name that conforms to the rule is parsed using the default DNS server specified by the program profile

    Server=/ test /

  * Does not meet the standard function variable name all sent to 127.0.0.1 for analysis

    Server=// 127.0.0.1


-------------------------------------------------------------------------------


IPFilter File Format Description:

IPFilter profiles are divided into blacklist/blacklist area and IPFilter/address filtering area and Local Routing/internal routing table area
* The area is identified by the label, and it is not deleted when it is modified
* The total length of an entry must not exceed 4096 bytes/4KB
* Need to be added Please add #/pound sign at the beginning of the entry


* Blacklist - Blacklist area
When the Blacklist Filter is on, it will check the list of this function variable name and resolution results, if the resolution contains a function variable name corresponding to the blacklist address, it will directly discard the resolution
Valid parameter format is "address (|address A|address B) regular expression" (without quotation marks, brackets are optional items, pay attention to the location of the interval)
  * The interval between the address and the regular expression can be a space/half space or HT/level positioning symbol, the interval length is not limited, but do not enter the full space
  * An entry can only accept a URL type(IPv4/IPv6), if the same function variable name need to simultaneously IPv4/IPv6 address filtering, divided into two entry input


* IPFilter - address filtering area
Address Filtering Blacklist or whitelist is determined by the IPFilter Type value of the profile, Deny forbidden/blacklist and Permit allowed/whitelist
The valid parameter format is "Start Address - End Address, Filter Level, Entry Profile Comment" (without quotation marks)
  * Supports both IPv4 and IPv6 addresses, but separate two entries when filling out


* Local Routing - the internal routing table area
When Local Routing is on, it will check whether the routing table of this list is hit. Check whether it is related to whether the function name request is using the local server. If the routing table is hit, the result will be returned directly. The hit will discard the resolution result and The server initiates the request again
Valid parameter format is "Address block/network prefix length" (without quotation marks)
  * This routing table supports IPv4 and IPv6 protocols
  * IPv4 network prefix must between 1 and 32.
  * IPv6 network prefix must between 1 and 128.


* Stop - temporarily stop reading the label
  * For more information, see the introduction to this function


-------------------------------------------------------------------------------


Auto-refresh support profile list:

* The parameters in the following list are automatically refreshed after writing to the configuration file without having to reboot the program. The refresh of the other parameters must be restarted
* If it is not necessary to recommend not to rely on the program automatically refresh function, it is strongly recommended to modify the configuration file after the re-boot program!

* Version
* File Refresh Time
* Print Log Level
* Log Maximum Size
* IPFilter Type
* IPFilter Level
* Accept Type
* Direct Request
* Default TTL
* Local Protocol
* Thread Pool Reset Time
* IPv4 Packet TTL
* IPv4 Main DNS TTL
* IPv4 Alternate DNS TTL
* IPv6 Packet Hop Limits
* IPv6 Main DNS Hop Limits
* IPv6 Alternate DNS Hop Limits
* Hop Limits Fluctuation
* Reliable Once Socket Timeout
* Reliable Serial Socket Timeout
* Unreliable Once Socket Timeout
* Unreliable Serial Socket Timeout
* Receive Waiting
* ICMP Test
* Domain Test
* Multiple Request Times
* Domain Case Conversion
* IPv4 Do Not Fragment
* TCP Data Filter
* DNS Data Filter
* Resource Record Set TTL Filter
* Domain Test Protocol
* SOCKS Target Server
* SOCKS Username
* SOCKS Password
* HTTP CONNECT Target Server
* HTTP CONNECT TLS Version
* HTTP CONNECT TLS Validation
* HTTP CONNECT Header Field
* HTTP CONNECT Proxy Authorization
* DNSCurve Reliable Socket Timeout
* DNSCurve Unreliable Socket Timeout
* DNSCurve Key Recheck Time
* DNSCurve Client Public Key
* DNSCurve Client Secret Key
* DNSCurve IPv4 Main DNS Public Key
* DNSCurve IPv4 Alternate DNS Public Key
* DNSCurve IPv6 Main DNS Public Key
* DNSCurve IPv6 Alternate DNS Public Key
* DNSCurve IPv4 Main DNS Fingerprint
* DNSCurve IPv4 Alternate DNS Fingerprint
* DNSCurve IPv6 Main DNS Fingerprint
* DNSCurve IPv6 Alternate DNS Fingerprint
* DNSCurve IPv4 Main Receive Magic Number
* DNSCurve IPv4 Alternate Receive Magic Number
* DNSCurve IPv6 Main Receive Magic Number
* DNSCurve IPv6 Alternate Receive Magic Number
* DNSCurve IPv4 Main DNS Magic Number
* DNSCurve IPv4 Alternate DNS Magic Number
* DNSCurve IPv6 Main DNS Magic Number
* DNSCurve IPv6 Alternate DNS Magic Number
