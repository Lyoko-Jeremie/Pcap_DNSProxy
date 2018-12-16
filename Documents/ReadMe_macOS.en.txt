Pcap_DNSProxy Project GitHub page:
https://github.com/chengr28/Pcap_DNSProxy

Pcap_DNSProxy Project Sourceforge page:
https://sourceforge.net/projects/pcap-dnsproxy


* For more details on the program and configuration, please read ReadMe(..).txt.

  
-------------------------------------------------------------------------------


Installation method (using compiled binary executable):

1. Open the downloaded binary executable file, extract the macOS directory to any location on the disk
2. Edit the pcap_dnsproxy.service.plist file
  * Change <string>/usr/local/etc/pcap_dnsproxy</string> to <string>Program location/Program Name</string>.
  * Change <string>/usr/local/etc/pcap_dnsproxy</string> to <string>Program location</string>.
3. Open the terminal, use sudo -i to obtain root permissions and enter the macOS directory:
  * Use cd to switch back to the directory where the program is located
  * Use chmod 755 macOS_Install.sh to make the service installation script obtain executable permissions
  * Execute the service installation script using ./macOS_Install.sh
  * What the script does:
    * Set the program, script, and basic read and write execute permissions for the plist configuration file
    * Load and start daemon services
    * After each boot in the login before the daemon service will automatically start
4. Please follow the following section of the normal work to see the method, the first test whether the normal work and then modify the network settings!
5. Open the System Preferences window
  * Go to the "Web" section
  * Select the network interface card you are using and click the "Advanced" button
  * Switch to the "DNS" tab and click on the "+" under "DNS Server"
  * Enter 127.0.0.1(IPv4)/::1(IPv6)
    * Make sure to only fill in these two addresses, fill in other addresses may cause the system to select other DNS servers to bypass the program's proxy
  * Press "OK" and then press "Apply"


-------------------------------------------------------------------------------


Installation method (compile binary executable file):

1. Prepare the program compilation environment
  * Dependency:
    * CMake
    * LibEvent
    * LibPcap
      * Can be diabled by link parameters.
    * Libsodium
      * Can be diabled by link parameters.
    * OpenSSL
      * Can be diabled by link parameters.

2. Compile the Pcap_DNSProxy program and configure the program properties
  * Use the terminal to enter the Source/Auxiliary/Scripts directory, use chmod 755 CMake_Build.sh to get the script to execute the license
  * Execute the compiler using ./CMake_Build.sh
    * What the script does:
      * CMake will compile and generate the Pcap_DNSProxy program in the Release directory
      * Copy the required scripts and default profiles from the ExampleConfig directory and the Scripts directory to the Release directory and set the basic read and write executable permissions
  * Use the ./CMake_Build.sh script to provide the parameters:
    * Using ./CMake_Build.sh --disable-libpcap --disable-libsodium --disable-tls will remove dependencies correspondingly, no recommended
    * Please notice that disable commands will lose the support correspondingly.

3. Follow the instructions in step 3 of the installation method (using the compiled binary executable).


-------------------------------------------------------------------------------


Special notes about the OpenSSL library:
By default, the OpenSSL library does not contain any trusted root certificate library, the first time you need to use the user to add:

* Open the utility - keychain access - system root certificate, select all the certificates in the list to cert.pem the PEM format to export to any location
* Open the terminal, use sudo-i to get the root permission and enter the directory just exported location
* Use the mv cert.pem certificate target directory /cert.pem to move the system root certificate to the archive to OpenSSL's certificate directory
* The certificate destination directory here is located near the OpenSSL library deployment directory found by CMake as described above for the Found OpenSSL directive. There should be a subdirectory named certs in the directory
* For example mv cert.pem /usr/local/ssl


-------------------------------------------------------------------------------


Restart service method:
1. Open the terminal, use "sudo -i" to get the root permission and go to /Library/LaunchDaemons directory.
2. Use "launchctl unload pcap_dnsproxy.service.plist" to stop the service, and wait a moment.
3. Use "launchctl load pcap_dnsproxy.service.plist" to start the service.


How to update if configuration version not changed:
1. Open the terminal, use "sudo -i" to get the root permission and go to /Library/LaunchDaemons directory.
2. Remove all executable files in the macOS folder.
3. Decompress all executable files of latest Pcap_DNSProxy to the same folder.
4. Use "launchctl load pcap_dnsproxy.service.plist" to start the service.


How to update if configuration version changed:
1. Open the terminal, use "sudo -i" to get root permission and enter macOS directory.
2. Run "./macOS_Uninstall.sh"
3. Do BACKUP all profiles and delete all Pcap_DNSProxy files.
  * Restore the backup configuration files to the macOS directory before proceeding to step 4.
4. Redeploy Pcap_DNSProxy via installation method.
  * Config.conf file is recommended to be reset according to the backup profiles.


Uninstall method:
1. Restore the system network settings.
2. Open the terminal, use "sudo -i" to get root permissions and enter macOS directory.
3. Run "./macOS_Uninstall.sh"
  * This script: Stop, uninstall daemon service, and remove plist profile.
4. Remove all Pcap_DNSProxy files.


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

4. If the above results, please move the macOS version of the FAQ document running results analysis section
