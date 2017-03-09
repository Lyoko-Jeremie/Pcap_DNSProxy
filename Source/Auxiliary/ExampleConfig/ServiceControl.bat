:: Pcap_DNSProxy service control batch
:: Pcap DNSProxy, a local DNS server based on WinPcap and LibPcap
:: Author: Hugo Chan, wongsyrone, Chengr28


@echo off

:: Administrative permission check
net session >NUL 2>NUL
if ERRORLEVEL 1 (
	color 4F
	echo Please run as Administrator.
	echo.
	pause & break
	echo.
	cls
)


:: Processor architecture and system version check
set Arch=
if %PROCESSOR_ARCHITECTURE%%PROCESSOR_ARCHITEW6432% == x86 (
	set Arch=_x86
)
ver | findstr /L /I " 5." >NUL
if not ERRORLEVEL 1 (
	set Arch=_XP
)
set Prog=Pcap_DNSProxy%Arch%.exe


:: Choice
:CHOICE
echo Pcap_DNSProxy service control batch
echo.
echo 1: Install service
echo 2: Uninstall service
echo 3: Start service
echo 4: Stop service
echo 5: Restart service
echo 6: Flush DNS cache in Pcap_DNSProxy
echo 7: Flush DNS cache in system only
echo 8: Exit
echo.
set /P UserChoice="Choose: "
set UserChoice=CASE_%UserChoice%
cd /D "%~dp0"
cls
goto %UserChoice%


:: Service install
:CASE_1
	sc stop PcapDNSProxyService
	sc delete PcapDNSProxyService
	ping 127.0.0.1 -n 3 >NUL
	taskkill /F /IM Pcap_DNSProxy.exe >NUL

	sc create PcapDNSProxyService binPath= "%~dp0%Prog%" DisplayName= "PcapDNSProxy Service" start= auto
	reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v Application /d "%~dp0%Prog%" /f
	reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v AppDirectory /d "%~dp0" /f
	%Prog% --first-setup

	sc description PcapDNSProxyService "Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap"
	sc failure PcapDNSProxyService reset= 0 actions= restart/5000/restart/10000//
	sc start PcapDNSProxyService
	ipconfig /flushdns
	call :CHECK_PROG
	pause
	cls
	goto :CHOICE


:: Service uninstall
:CASE_2
	sc stop PcapDNSProxyService
	sc delete PcapDNSProxyService
	ping 127.0.0.1 -n 3 >NUL
	taskkill /F /IM Pcap_DNSProxy.exe >NUL
	ipconfig /flushdns
	echo.
	pause
	cls
	goto :CHOICE


:: Service start
:CASE_3
	sc start PcapDNSProxyService
	ping 127.0.0.1 -n 3 >NUL
	ipconfig /flushdns
	ping 127.0.0.1 -n 3 >NUL
	call :CHECK_PROG
	pause
	cls
	goto :CHOICE


:: Service stop
:CASE_4
	sc stop PcapDNSProxyService
	ping 127.0.0.1 -n 3 >NUL
	ipconfig /flushdns
	echo.
	pause
	cls
	goto :CHOICE


:: Service restart
:CASE_5
	sc stop PcapDNSProxyService
	ping 127.0.0.1 -n 3 >NUL
	taskkill /F /IM Pcap_DNSProxy.exe >NUL
	sc start PcapDNSProxyService
	ping 127.0.0.1 -n 3 >NUL
	ipconfig /flushdns
	call :CHECK_PROG
	pause
	cls
	goto :CHOICE


:: Flush DNS cache(Pcap_DNSProxy)
:CASE_6
	call :CHECK_PROG
	%Prog% --flush-dns
	echo.
	pause
	cls
	goto :CHOICE


:: Flush DNS cache(System)
:CASE_7
	ipconfig /flushdns
	echo.
	pause
	cls
	goto :CHOICE


:: Exit
:CASE_8
	exit


:: Process check
:CHECK_PROG
	tasklist | findstr /L /I "%Prog%" >NUL
	if ERRORLEVEL 1 (
		color 4F
		echo.
		echo The program is not running, please check the configurations and error log.
		echo.
		pause
		color 07
		cls
		goto :CHOICE
	)
	echo.
