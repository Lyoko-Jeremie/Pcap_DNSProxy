:: Pcap_DNSProxy service control batch
:: Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
:: 
:: Author: Hugo Chan, Syrone Wong, Chengr28
:: 


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
set ServiceName=PcapDNSProxyService


:: Command
set Command=%~1
if not "%Command%" == "" (
	goto CASE_%Command%
)


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
	call :DEL_SERVICE
	ping 127.0.0.1 -n 3 >NUL
	call :KILL_PROG
	ping 127.0.0.1 -n 3 >NUL
	sc create %ServiceName% binPath= "%~dp0%Prog%" DisplayName= "PcapDNSProxy Service" start= auto
	%Prog% --first-setup
	sc description %ServiceName% "Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap"
	sc failure %ServiceName% reset= 0 actions= restart/5000/restart/10000//
	sc start %ServiceName%
	ipconfig /flushdns
	call :CHECK_PROG
	if "%Command%" == "" (
		pause
		cls
		goto :CHOICE
	) else (
		exit
	)


:: Service uninstall
:CASE_2
	call :DEL_SERVICE
	ping 127.0.0.1 -n 3 >NUL
	call :KILL_PROG
	ipconfig /flushdns
	if "%Command%" == "" (
		echo.
		pause
		cls
		goto :CHOICE
	) else (
		exit
	)


:: Service start
:CASE_3
	sc start %ServiceName%
	ping 127.0.0.1 -n 3 >NUL
	ipconfig /flushdns
	ping 127.0.0.1 -n 3 >NUL
	call :CHECK_PROG
	if "%Command%" == "" (
		pause
		cls
		goto :CHOICE
	) else (
		exit
	)


:: Service stop
:CASE_4
	sc stop %ServiceName%
	ping 127.0.0.1 -n 3 >NUL
	ipconfig /flushdns
	if "%Command%" == "" (
		echo.
		pause
		cls
		goto :CHOICE
	) else (
		exit
	)


:: Service restart
:CASE_5
	sc stop %ServiceName%
	ping 127.0.0.1 -n 3 >NUL
	call :KILL_PROG
	ping 127.0.0.1 -n 3 >NUL
	sc start %ServiceName%
	ping 127.0.0.1 -n 3 >NUL
	ipconfig /flushdns
	call :CHECK_PROG
	if "%Command%" == "" (
		pause
		cls
		goto :CHOICE
	) else (
		exit
	)


:: Flush DNS cache(Pcap_DNSProxy)
:CASE_6
	call :CHECK_PROG
	%Prog% --flush-dns
	if "%Command%" == "" (
		echo.
		pause
		cls
		goto :CHOICE
	) else (
		exit
	)


:: Flush DNS cache(System)
:CASE_7
	ipconfig /flushdns
	if "%Command%" == "" (
		echo.
		pause
		cls
		goto :CHOICE
	) else (
		exit
	)


:: Exit
:CASE_8
	color
	exit


:: Process check
:CHECK_PROG
	tasklist | findstr /L /I "%Prog%" >NUL
	if %ERRORLEVEL% EQU 1 (
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
	goto :EOF

:: Process kill
:KILL_PROG
	tasklist | findstr /L /I "%Prog%" >NUL
	if %ERRORLEVEL% EQU 0 (
		taskkill /F /IM %Prog% >NUL
		goto :EOF
	)
	goto :EOF


:: Service delete
:DEL_SERVICE
	sc query %ServiceName% >NUL
	if %ERRORLEVEL% EQU 0 (
		sc stop %ServiceName%
		sc delete %ServiceName%
		goto :EOF
	)
	goto :EOF