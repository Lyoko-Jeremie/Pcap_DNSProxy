Pcap_DNSProxy Project GitHub page:
https://github.com/chengr28/Pcap_DNSProxy

Pcap_DNSProxy Project Sourceforge page:
https://sourceforge.net/projects/pcap-dnsproxy


* For more details on the program and configuration, please read ReadMe(..).txt.


-------------------------------------------------------------------------------


Installation Method
The installation process is relatively long and more complex operation, please give some patience to follow the instructions!

1. Prepare the program to compile the environment: before the need to use the package management tool to install, or need to compile and install the dependent library
  * Dependency:
    * Compiler must support C++ 14, please select one of them:
      * GCC/g++, requires 5.0 and later.
      * Clang/LLVM, requires 3.4 and later.
    * CMake
    * LibEvent
    * LibPcap
      * When decompressing LibPcap dependencies, you can skip compiling and installing dependencies and tools in the following table. For details, see below.
    * Libsodium
      * If you are depriving Libsodium dependencies, you can skip compiling and installing dependencies and tools in the following table. For details, see below.
    * OpenSSL
      * If you peel off the OpenSSL dependency, you can skip the compilation and installation of the following dependencies and tools, as described in the following, not recommended

2. Compile the Pcap_DNSProxy program and configure the program properties
  * Use the terminal to enter the Source/Auxiliary/Scripts directory, use chmod 755 CMake_Build.sh to get the script to execute the license
  * Execute the compiler using ./CMake_Build.sh
    * What the script does:
      * CMake will compile and generate the Pcap_DNSProxy program in the Release directory
      * Copy the required scripts and default profiles from the ExampleConfig directory and the Scripts directory to the Release directory and set the basic read and write executable permissions
    * Add the parameter --enable-static that is ./CMake_Build.sh --enable-static to enable static compilation
  * Use the ./CMake_Build.sh script to provide the parameters:
    * Using ./CMake_Build.sh --disable-libpcap --disable-libsodium --disable-tls will remove dependencies correspondingly, no recommended
    * Please notice that disable commands will lose the support correspondingly.

3. Configure the system daemon service
  * Due to the different Linux distributions, the system services and daemons are handled differently. This step is for reference only.
    * The included Linux_Install.Systemd.sh script applies to systems that use Systemd Init by default
      * Linux Debian 8.x official release and updated version of the system content, the test can be used directly
    * The included Linux_Install.SysV.sh script applies to systems that are preset to use System V Init
      * Linux Debian 6.x - 7.x official release version of the system content, the test can be used directly
    * For more details, see the description of the other Linux distributions below, and the official instructions for the Linux distributions used
  * When using Systemd Init:
    * Into the Release directory and edit the Pcap_DNSProxy.service file, save after editing:
      * WorkingDirectory= item is the absolute path to the directory where the program resides
      * ExecStart= item is the absolute path of the directory where the program is located and the name of the program is added at the end
    * Under the root permission ./Linux_Install.Systemd.sh Execute the service installation script, the script's actions:
      * Set the service control script to basically read and write executable permissions
      * Install the service control script into the/etc/systemd/system directory
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
      * Force-reload/restart - restart service
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
      * WorkingDirectory= item is the absolute path to the directory where the program is located
      * ExecStart= item is the absolute path of the directory where the program is located and the name of the program is added at the end
    * Under the root privileges ./Linux_Install.Systemd.sh Execute the service installation script, the operation of the script:
      * Change the owner of the Pcap_DNSProxy.service service control script to root
      * Install the service control script into the/etc/systemd/system directory
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
      * Force-reload/restart - restart service
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
      * Fill in the server with ::1 and apply
    * Make sure to only fill in these two addresses, fill in other addresses may cause the system to select other DNS servers to bypass the program's proxy
    * Reboot the network connection
  * Modify the system file directly Modify the DNS server settings:
    * When the address is automatically acquired (DHCP):
      * Enter the/etc/dhcp or/etc/dhcp3 directory as root (depending on the dhclient.conf file location)
      * Directly modify the dhclient.conf file, modify or add prepend domain-name-servers one can
      * If prepend domain-name-servers is annotated, you need to remove the comments for the configuration to take effect, without adding new entries
      * Dhclient.conf file may exist multiple prepend domain-name-servers items, is the settings of the various network interface, directly modify the total settings can be
    * Use service network (/ networking) restart or ifdown/ifup or ifconfig stop/start to restart network service/network port
      * When the address is not automatically acquired (DHCP):
      * Enter the/etc directory with the root permission
      * Directly modify the resolv.conf file nameserver can be
      * If the configuration is overridden after rebooting, you need to modify or create the new /etc/resolvconf/resolv.conf.d file with the same content as resolv.conf
      * Use service network (/ networking) restart or ifdown/ifup or ifconfig stop/start to restart network service/network port


-------------------------------------------------------------------------------


Restart service method:
* Systemd:
  1. Open the terminal and use "su" to get root permission.
  2. Use "systemctl restart Pcap_DNSProxy" to restart the service.
  3. Another way: Use "systemctl stop Pcap_DNSProxy" to stop service, wait a moment and then use "systemctl start Pcap_DNSProxy" to start service.
* SysV:
  1. Open the terminal and use "su" to get root permission.
  2. Use "service PcapDNSProxyService restart" to restart the service.
  3. Another way: Use "service PcapDNSProxyService stop" to stop service, wait a moment and then use "service PcapDNSProxyService start" to start service.


How to update if configuration version not changed:
* Systemd:
  1. Open the terminal and use "su" to get root permission and enter the Release directory.
  2. Use "systemctl stop Pcap_DNSProxy" to stop service.
  3. Remove all executable files in the folder.
  4. Decompress all executable files of latest Pcap_DNSProxy to the same folder.
  5. Use "systemctl start Pcap_DNSProxy" to start service.
* SysV:
  1. Open the terminal and use "su" to get root permission and enter the Release directory.
  2. Use "service PcapDNSProxyService stop" to stop service.
  3. Remove all executable files in the folder.
  4. Decompress all executable files of latest Pcap_DNSProxy to the same folder.
  5. Use "service PcapDNSProxyService start" to start service.


How to update if configuration version changed:
* Systemd:
  1. Open the terminal and use "su" to get root permission and enter the Release directory.
  2. Run "./Linux_Uninstall.Systemd.sh".
  3. Do BACKUP to profiles and delete all Pcap_DNSProxy files.
  4. Redeploy Pcap_DNSProxy via installation method.
    * Restore backup file to Release directory before proceeding to step 4.
    * Config.conf file is recommended to be reset once in accordance with the backup profile.
* SysV:
  1. Open the terminal and use "su" to get root permission and enter the Release directory.
  2. Run "./Linux_Uninstall.SysV.sh".
  3. Do BACKUP to profiles and delete all Pcap_DNSProxy files.
  4. Redeploy Pcap_DNSProxy via installation method.
    * Restore backup file to Release directory before proceeding to step 4.
    * Config.conf file is recommended to be reset once in accordance with the backup profile.


Uninstall method:
* Different Linux distributions are handled differently for system services and daemons, please read their documents.
1. Restore system network settings.
2. Go to Release directory as root and run "./Linux_Uninstall.Systemd.sh" or "./Linux_Uninstall.SysV.sh".
3. Delete all Pcap_DNSProxy files.


-------------------------------------------------------------------------------


Normal work View method:

1. Open the terminal
2. Enter "dig @ 127.0.0.1 www.google.com" or "dig @::1 www.google.com" and press Enter
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
   ; SERVER: ::1#53(::1) (depending on the network environment, 127.0.0.1 when the local listening protocol is IPv4)
   WHEN: ..
   ;; MSG SIZE rcvd: ..

4. If you do not have the above results, please move the Linux version of the FAQ document running the results analysis section


-------------------------------------------------------------------------------


Description of other Linux distributions:

* Linux Debian series:
  * Official release version 8.x and later versions require the use of Systemd to manage system services
  * The official release version 6.x - 7.x version requires the use of the insserv management system service
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
