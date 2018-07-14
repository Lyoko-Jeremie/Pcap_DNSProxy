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

* After installing the new version of the OpenSSL library for the system, undef: OPENSSL .. error when compiling TLS/SSL functionality:
  * The reason is that macOS comes with the OpenSSL series version is very old (0.9.8) does not support the new version of the feature, the link in the link using the system comes with the library error
  * At this point, look at the records of the compilation process, write down the OpenSSL library directory found by CMake, which Found OpenSSL indicates, and confirm that the version
  * You can edit the CMakeLists.txt file in the Pcap_DNSProxy directory:
    * Please be sure to pay attention to the issue of quotation marks, you must use the ASCII standard quotation marks
    * Find the find_package (OpenSSL REQUIRED) statement and open another line
    * Fill in the new line in the set (CMAKE_EXE_LINKER_FLAGS "$ {CMAKE_EXE_LINK_ERAG_US) - L just recorded directory") priority to specify the link found by the library
    * For example set (CMAKE_EXE_LINKER_FLAGS "$ {CMAKE_EXE_LINKER_FLAGS} -L/usr/local/lib")
    * Save the file and re-run ./CMake_Build.sh can
* By default, the OpenSSL library does not contain any trusted root certificate library, the first time you need to use the user to add:
  * Open the utility - keychain access - system root certificate, select all the certificates in the list to cert.pem the PEM format to export to any location
  * Open the terminal, use sudo-i to get the root permission and enter the directory just exported location
  * Use the mv cert.pem certificate target directory /cert.pem to move the system root certificate to the archive to OpenSSL's certificate directory
  * The certificate destination directory here is located near the OpenSSL library deployment directory found by CMake as described above for the Found OpenSSL directive. There should be a subdirectory named certs in the directory
  * For example mv cert.pem /usr/local/ssl


-------------------------------------------------------------------------------


Reboot service method:
1. Open the terminal, use sudo -i to get the root permission and go to the/Library/LaunchDaemons directory
2. Use the launchctl unload pcap_dnsproxy.service.plist to stop the service, wait a while
3. Use launchctl load pcap_dnsproxy.service.plist to start the service


Update the program method (do not overwrite it directly, otherwise it may cause unpredictable errors):
1. Open the terminal, use sudo -i to obtain root permissions and enter the macOS directory
2. Execute the service uninstall script using ./macOS_Uninstall.sh
3. Back up all profiles and delete all Pcap_DNSProxy dependencies
  * Restore the backup configuration files to the macOS directory before proceeding to step 4
4. Redeploy Pcap_DNSProxy by installation method
  * Config.conf file is recommended to be reset according to the backup profile, such as direct coverage may lead to no new features


Uninstall method:
1. Restore the system network settings
2. Open the terminal, use sudo -i to obtain root permissions and enter the macOS directory
3. Execute the service uninstall script using ./macOS_Uninstall.sh
  * What the script does: stop and uninstall the daemon service, remove the plist profile
4. Remove all Pcap_DNSProxy dependencies


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
