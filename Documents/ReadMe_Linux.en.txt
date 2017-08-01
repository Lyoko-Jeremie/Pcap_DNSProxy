Pcap_DNSProxy Project GitHub page:
Https://github.com/chengr28/Pcap_DNSProxy

Pcap_DNSProxy Project Sourceforge page:
Https://sourceforge.net/projects/pcap-dnsproxy


* For more details on the program and configuration, see ReadMe (..). Txt


-------------------------------------------------- -----------------------------


installation method:
The installation process is relatively long and more complex operation, please give some patience to follow the instructions!

1. Prepare the program to compile the environment: before the need to use the package management tool to install, or need to compile and install the dependent library
  * Dependent Tools / Library List:
    * GCC / g ++ is available at https://gcc.gnu.org
      * GCC minimum version requirement 4.9 from this version GCC full support C ++ 11 standard, 4.9 before the version of the C + + 11 standard implementation problems
      * GCC current version can be used gcc --version view, use the old version of GCC forced compiler may be unpredictable!
    * CMake can be accessed at https://cmake.org
    * LibPcap can be accessed at http://www.tcpdump.org/#latest-release
      * When decompressing LibPcap dependencies, you can skip compiling and installing dependencies and tools in the following table. For details, see below.
      * Get root permission after use. / Configure -> make -> make install can be
      * Part of the Linux distributions may also require support for the libpcap-dev tool, as well as running ldconfig to refresh the system library cache
    * Libsodium can be accessed at https://github.com/jedisct1/libsodium
      * If you are depriving Libsodium dependencies, you can skip compiling and installing dependencies and tools in the following table. For details, see below.
      * After getting the root permission, go to the directory and run ./autogen.sh -> ./configure -> make -> make install
      * Part of the Linux distributions may also require support for the libsodium-dev tool, as well as running ldconfig to refresh the system library cache
    * OpenSSL is available at https://www.openssl.org
      * If you peel off the OpenSSL dependency, you can skip the compilation and installation of the following dependencies and tools, as described in the following, not recommended
      * Get root permission after use. / Configure [compilation platform] -> make -> make install can be
      * Part of the Linux distributions may also require support for the libssl-dev / openssl-dev tool, as well as running ldconfig to refresh the system library cache

2. Compile the Pcap_DNSProxy program and configure the program properties
  * Do not change the script's newline format (UNIX / LF)
  * Use the terminal to enter the Source / Auxiliary / Scripts directory, use chmod 755 CMake_Build.sh to get the script to execute the license
  * Execute the compiler using ./CMake_Build.sh
    * What the script does:
      * CMake will compile and generate the Pcap_DNSProxy program in the Release directory
      * Copy the required scripts and default profiles from the ExampleConfig directory and the Scripts directory to the Release directory and set the basic read and write executable permissions
    * Add the parameter --enable-static that is ./CMake_Build.sh --enable-static to enable static compilation
  * Use the ./CMake_Build.sh script to provide the parameters:
    * Executed using ./CMake_Build.sh --disable-libpcap Depends on LibPcap dependencies, deprecated
      * Will not require LibPcap library support after peeling
      * After stripping the program will be completely lost support LibPcap function, and the operation will not produce any error, caution!
    * Execution use ./CMake_Build.sh --disable-libsodium Depends on Libsodium dependencies, deprecated
      * Will not require the support of the Libs sink library after compilation
      * After the spin-off program will be completely lost support DNSCurve (DNSCrypt) protocol function, and the operation will not produce any error, caution!
    * Execution is used ./CMake_Build.sh --disable-tls can be stripped of dependencies on OpenSSL, deprecated
      * Sketch will not require the OpenSSL library after skimming
      * After the spin-off program will completely lose support TLS / SSL agreement function, and the operation will not produce any error, caution!

3. Configure the system daemon service
  * Due to the different Linux distributions, the system services and daemons are handled differently. This step is for reference only.
    * The included Linux_Install.Systemd.sh script applies to systems that use Systemd Init by default
      * Linux Debian 8.x official release and updated version of the system content, the test can be used directly
    * The included Linux_Install.SysV.sh script applies to systems that are preset to use System V Init
      * Linux Debian 6.x - 7.x official release version of the system content, the test can be used directly
    * For more details, see the description of the other Linux distributions below, and the official instructions for the Linux distributions used
  * When using Systemd Init:
    * Into the Release directory and edit the Pcap_DNSProxy.service file, save after editing:
      * WorkingDirectory = item is the absolute path to the directory where the program resides
      * ExecStart = item is the absolute path of the directory where the program is located and the name of the program is added at the end
    * Under the root permission ./Linux_Install.Systemd.sh Execute the service installation script, the script's actions:
      * Set the service control script to basically read and write executable permissions
      * Install the service control script into the / etc / systemd / system directory
      * Try to start the Pcap_DNSProxy service and display the status of the service after the operation is performed
      * Each time the system starts will automatically start the service
    * For more information on Systemd service control, see the documentation for each Linux release
  * When using System V Init:
    * Into the Release directory and edit the PcapDNSProxyService file, save after editing:
      The NAME entry is the name of the program
      * The PATH entry is the absolute path of the program
    * Under the root permission ./Linux_Install.SysV.sh Execute the service installation script, the script's actions:
      * Set the service control script to basically read and write executable permissions
      * Install the service control script into the /etc/init.d directory
      * Try to start the PcapDNSProxyService service and display the status of the service after the operation is performed
      * Each time the system starts each time it will automatically run the script to start the service
    * Can be directly input sh PcapDNSProxyService without parameters query usage
      * Start - start the service
      * Stop - stop service
      * Force-reload / restart - restart service
      * Status - service status, if the PID is empty, the service is not started

3. Configure the system daemon service
  * Due to the different Linux distributions, the system services and daemons are handled differently. This step is for reference only.
    * The included Linux_Install.Systemd.sh script applies to systems that use Systemd Init by default
      * Linux Debian 8.x official release and the updated version of the system environment, the test can be used directly
    * The included Linux_Install.SysV.sh script applies to systems that use System V Init by default
      * Linux Debian 6.x - 7.x official release system environment, the test can be used directly
    * For more details, see the description of other Linux distributions below, and the official instructions for the Linux distributions
  * When using Systemd Init:
    * Into the Release directory and edit the Pcap_DNSProxy.service file, save after editing:
      * WorkingDirectory = item is the absolute path to the directory where the program is located
      * ExecStart = item is the absolute path of the directory where the program is located and the name of the program is added at the end
    * Under the root privileges ./Linux_Install.Systemd.sh Execute the service installation script, the operation of the script:
      * Change the owner of the Pcap_DNSProxy.service service control script to root
      * Install the service control script into the / etc / systemd / system directory
      * Try to start the Pcap_DNSProxy service and display the status of the service after the operation is performed
      * Each time the system starts will automatically start the service
    * For more information on Systemd service control, see the documentation for the official Linux documentation
  * When using System V Init:
    * Into the Release directory and edit the PcapDNSProxyService file, save after editing:
      The NAME entry is the name of the program
      * The PATH entry is the absolute path to the program
    * Under the root privileges. /Linux_Install.SysV.sh Execute the service installation script, the script's actions:
      * Change the owner of the PcapDNSProxyService service control script to root
      * Install the service control script into the /etc/init.d directory
      * Try to start the PcapDNSProxyService service and display the status of the service after the operation is performed
      * Each time the system starts each time it will automatically run the script to start the service
    * Can be directly input sh PcapDNSProxyService without parameters query usage
      * Start - start the service
      * Stop - stop service
      * Force-reload / restart - restart service
      * Status - service status, if the PID is empty, the service is not started

4. Please follow the normal work below to see a section of the method, the first program is in the normal work test and then modify the network settings!

5. Configure the system DNS server settings
  * See https://developers.google.com/speed/public-dns/docs/using Changing your DNS servers settings in the Linux section
  * GUI interface to GNOME 3 example:
    * Open all program lists and -> Settings - Hardware Category - Network
    * If you want to edit the current network settings -> press the gear button
    * Select IPv4
      * In the DNS section, it will automatically set to close
      * Fill in the server with 127.0.0.1 and apply it
    * Select IPv6
      * In the DNS section, it will automatically set to close
      * Fill in the server with :: 1 and apply
    * Make sure to only fill in these two addresses, fill in other addresses may cause the system to select other DNS servers to bypass the program's proxy
    * Reboot the network connection
  * Modify the system file directly Modify the DNS server settings:
    * When the address is automatically acquired (DHCP):
      * Enter the / etc / dhcp or / etc / dhcp3 directory as root (depending on the dhclient.conf file location)
      * Directly modify the dhclient.conf file, modify or add prepend domain-name-servers one can
      * If prepend domain-name-servers is annotated, you need to remove the comments for the configuration to take effect, without adding new entries
      * Dhclient.conf file may exist multiple prepend domain-name-servers items, is the settings of the various network interface, directly modify the total settings can be
    * Use service network (/ networking) restart or ifdown / ifup or ifconfig stop / start to restart network service / network port
      * When the address is not automatically acquired (DHCP):
      * Enter the / etc directory with the root permission
      * Directly modify the resolv.conf file nameserver can be
      * If the configuration is overridden after rebooting, you need to modify or create the new /etc/resolvconf/resolv.conf.d file with the same content as resolv.conf
      * Use service network (/ networking) restart or ifdown / ifup or ifconfig stop / start to restart network service / network port


-------------------------------------------------- -----------------------------


Reboot service method:
* Systemd section:
  1. Open the terminal and use su to get the root permission
  2. Use systemctl restart Pcap_DNSProxy to restart the service directly
  3. Can also be the first systemctl stop Pcap_DNSProxy stop service, wait a while and then systemctl start Pcap_DNSProxy start service
* SysV section:
  1. Open the terminal and use su to get the root permission
  2. Use service PcapDNSProxyService restart to restart the service directly
  3. You can also service PcapDNSProxyService stop stop service, wait for some time and then service PcapDNSProxyService start start service


Update the program method (do not overwrite it directly, otherwise it may cause unpredictable errors):
* Systemd section:
  1. Open the terminal, use su to get the root permission and enter the Release directory
  2. Execute the service uninstall script using ./Linux_Uninstall.Systemd.sh
  3. Back up all profiles and delete all Pcap_DNSProxy dependencies
  4. Redeploy Pcap_DNSProxy by installation method
    * Restore the backup configuration file to the Release directory before proceeding to step 4
    * Config.conf file is recommended to be reset once in accordance with the backup profile, such as direct coverage may lead to no new features
* SysV section:
  1. Open the terminal, use su to get the root permission and enter the Release directory
  2. Execute the service uninstall script using ./Linux_Uninstall.SysV.sh
  3. Back up all profiles and delete all Pcap_DNSProxy dependencies
  4. Redeploy Pcap_DNSProxy by installation method
    * Restore the backup configuration file to the Release directory before proceeding to step 4
    * Config.conf file is recommended to be reset once in accordance with the backup profile, such as direct coverage may lead to no new features


Uninstall method:
* This is for reference only if different Linux distributions are handled differently for system services and daemons
1. Restore the system network settings
2. Go to the Release directory as root and execute ./Linux_Uninstall.Systemd.sh or ./Linux_Uninstall.SysV.sh
3. Delete all Pcap_DNSProxy related files


-------------------------------------------------- -----------------------------


Normal work View method:

1. Open the terminal
2. Enter dig @ 127.0.0.1 www.google.com or dig @ :: 1 www.google.com and press Enter
3. The results should be similar:

   > Dig www.google.com
   ; (1 server found)
   ;; global options: + cmd
   ;; Got answer:
   ;; - >> HEADER << - opcode: QUERY, status: NOERROR, id: ..
   ;; flags: ..; QUERY: .., ANSWER: .., AUTHORITY: .., ADDITIONAL: ..

   QUESTTION SECTION:
   ; Www.google.com. IN A

   ;; ANSWER SECTION:
   ..

   ;; Query time: .. msec
   ; SERVER: :: 1 # 53 (:: 1) (depending on the network environment, 127.0.0.1 when the local listening protocol is IPv4)
   WHEN: ..
   ;; MSG SIZE rcvd: ..

4. If you do not have the above results, please move the Linux version of the FAQ document running the results analysis section

-------------------------------------------------------------------------------


Description of other Linux distributions:

* Linux Debian series:
  * Official release version 8.x and later versions require the use of Systemd to manage system services
  * The official release version 6.x - 7.x version requires the use of the insserv management system service
  * Official release version 6.x The following version requires the use of update-rc.d to manage system services, see https://wiki.debian.org/Daemon
* Linux Red Hat and openSUSE series:
  * Use chkconfig to manage system services
  * See https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Deployment_Guide/s2-services-chkconfig.html
* If you need to write your own service startup script, please note that the Pcap_DNSProxyService service needs to be used after the following modules are initialized. It is recommended to reduce the priority order as much as possible. Otherwise, the error report will be built and exit directly:
  * Need to mount all file systems
  * Need to initialize the system log
  * After starting the network service and the network device is initialized
  * After the system time is set
  * After the native name is set
* You can also add the program directly to the startup item, note that you must start with the root permission or can not open the local monitor port
  * Program built-in set the daemon code, will not block the system after the operation
