Pcap_DNSProxy Project GitHub page:
https://github.com/chengr28/Pcap_DNSProxy

Pcap_DNSProxy Project Sourceforge page:
https://sourceforge.net/projects/pcap-dnsproxy


* For more details on the program and configuration, please read ReadMe(..).txt.

  
-------------------------------------------------------------------------------


Installation method (required as administrator):

1. Visit https://www.winpcap.org to download and install WinPcap with administrator privileges
  * WinPcap only need to be installed once, before the latest version of the installation or later update the tool, please start from the second step
  * If the WinPcap prompt has been installed in the old version can not continue, see the FAQ in the run results analysis section
  * The self-starting option during installation has no effect on the operation of the tool. The tool directly calls the WinPcap API without going through the server program

2. Visit https://github.com/chengr28/Pcap_DNSProxy/releases to download the binary executable file to the local
  * Windows version of Pcap_DNSProxy in the binary executable file in the Windows directory, the entire directory can be a separate out of the run

3. Open the downloaded binary executable file, extract the Windows directory to any location on the disk
  * Directory location and program file name can be arbitrarily changed, it is recommended that the project placed in a separate directory
  * The profile needs to use a fixed file name (see the Features and Techniques section below for more details)

4. After determining the name and path of the tool directory, go to the directory and right-click on the administrator (Vista and later) or run the ServiceControl.bat (XP/2003) by pressing the administrator login twice (XP/2003)
  * Enter 1 and press Enter, select "1: Install service" to install the service
  * Batch processing will program the system services, and firewall test, each boot service will automatically start
  * At this point, the Windows system asks if you want to agree to programmatically access the network. Please tick "private network" and "public network" and confirm

5. Please follow the following section of the normal work to see the method, the first test whether the normal work and then modify the network settings!

6. Open the Network and Sharing Center - Change Adapter Settings Select either Local or Wireless or Broadband
  * Right-click "Properties" - "Internet Protocol (TCP/IP)" (XP/2003) or "Internet Protocol Version 4 (IPv4)" (Vista and later) - "Properties" - check "Use the following DNS server Device address "
  * In the "preferred DNS server" fill in "127.0.0.1" (without quotation marks) to determine the save and exit
  * If you need to use the IPv6 protocol for the local server
    * Right click on "Properties" - "Internet Protocol Version 6 (IPv6)" - "Properties" - check "Use the following DNS server address"
    * Enter "::1" (without the quotation marks) in the "Preferred DNS Server" to confirm the save and exit
  * Make sure to only fill in these two addresses, fill in other addresses may cause the system to select other DNS servers to bypass the program's proxy
  * Note: It is recommended to "local connection" and "wireless connection" and "broadband connection" all modified!


-------------------------------------------------------------------------------


Restart the service method (required as an administrator):
1. Right-click on the administrator (Vista and later) or run the ServiceControl.bat (XP/2003) by pressing the administrator login twice (XP/2003)
2. Enter 5 and press Enter, select "5: Restart service" to restart the service immediately


How to update if configuration version not changed:
1.Download latest Pcap_DNSProxy, please notice that DNS service will temporary stop until finished.
2.Run ServiceControl.bat as administrator right.
3.Enter 4 also known as "4: Stop service".
4.Remove all executable files in the folder.
5.Decompress all executable files of latest Pcap_DNSProxy to the same folder.
6.Run ServiceControl.bat as administrator right.
7.Enter 3 also known as "3: Start service".


How to update if configuration version changed:
1.Download latest Pcap_DNSProxy, please notice that DNS service will temporary stop until finished.
2.Please BACKUP all custom configurations before update!
3.Run ServiceControl.bat as administrator right.
4.Enter 2 also known as "2: Uninstall service".
5.Remove all files in the folder.
6.Decompress all files of latest Pcap_DNSProxy to the same folder.
7.Restore all custom configurations.
8.Redeploy Pcap_DNSProxy in step 4 of the installation method.


How to use it in safe mode (requires an administrator):
* Program has the ability to run in safe mode, in safe mode, right-click as an administrator to run the program directly
* Direct operation mode has a console window, close the program directly close the console window can be


Unload method (required as administrator):
1. Restore the DNS function variable name server address configuration according to step 6 of the installation method
2. Right-click on the administrator (Vista and later) or run the ServiceControl.bat (XP/2003) by pressing the administrator login (XP/2003)
  * Enter 2 and press Enter, select "2: Uninstall service" to uninstall the service
  * Note: Windows Firewall may have permission to access the network information, it may need to use the registry cleanup after the clean-up
  * Transfer the tool directory path does not need to uninstall the service, first stop the service transfer, transfer is completed after the restart service


-------------------------------------------------------------------------------


Normal work View method:

1. Open a command prompt
   * At the beginning of the menu or direct Win + R call up, enter cmd and press Enter
   * Start Menu - Program/All Programs - Accessories - Command Prompt
2. Enter "nslookup www.google.com 127.0.0.1" or "nslookup www.google.com ::1" and press Enter
3. The results should be similar:

    > Nslookup www.google.com
     Server: pcap-dnsproxy.server (depending on the value of the profile settings, see the section below for details on the configuration file)
     Address: 127.0.0.1 (depending on the network environment, when the local listening protocol is IPv6: 1)

     Non-authoritative response:
     Name: www.google.com
     Addresses: ... (IP address or address list)


4. If you do not have the above results, please move the section in the FAQ document to run the results analysis section
