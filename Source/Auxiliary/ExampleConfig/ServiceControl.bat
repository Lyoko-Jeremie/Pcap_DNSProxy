:: Pcap_DNSProxy service control batch
:: Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
:: 
:: Contributions: Hugo Chan, Syrone Wong, Stzx, Chengr28
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
set Architecture=
if %PROCESSOR_ARCHITECTURE%%PROCESSOR_ARCHITEW6432% == x86 (
	set Architecture=_x86
)
ver | findstr /L /I " 5." >NUL
if not ERRORLEVEL 1 (
	set Architecture=_XP
)
set Executable=Pcap_DNSProxy%Architecture%.exe
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
echo 6: Flush domain cache in Pcap_DNSProxy
echo 7: Flush domain cache in system only
echo 8: Exit
echo.
set /P UserChoice="Choose: "
set UserChoice=CASE_%UserChoice%
cd /D "%~dp0"
cls
goto %UserChoice%


:: Service install
:CASE_1
	call :DELETE_SERVICE
	ping 127.0.0.1 -n 3 >NUL
	call :KILL_PROCESS
	ping 127.0.0.1 -n 3 >NUL
	sc create %ServiceName% binPath= "%~dp0%Executable%" DisplayName= "PcapDNSProxy Service" start= auto
	%Executable% --firewall-test
	sc description %ServiceName% "Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap"
	sc failure %ServiceName% reset= 0 actions= restart/5000/restart/10000//
	sc start %ServiceName%
	ipconfig /flushdns
	call :CHECK_PROCESS
	if "%Command%" == "" (
		pause
		cls
		goto :CHOICE
	) else (
		exit
	)


:: Service uninstall
:CASE_2
	call :DELETE_SERVICE
	ping 127.0.0.1 -n 3 >NUL
	call :KILL_PROCESS
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
	call :CHECK_PROCESS
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
	call :KILL_PROCESS
	ping 127.0.0.1 -n 3 >NUL
	sc start %ServiceName%
	ping 127.0.0.1 -n 3 >NUL
	ipconfig /flushdns
	call :CHECK_PROCESS
	if "%Command%" == "" (
		pause
		cls
		goto :CHOICE
	) else (
		exit
	)


:: Flush domain cache(Pcap_DNSProxy)
:CASE_6
	call :CHECK_PROCESS
	%Executable% --flush-dns
	if "%Command%" == "" (
		echo.
		pause
		cls
		goto :CHOICE
	) else (
		exit
	)


:: Flush domain cache(System)
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
:CHECK_PROCESS
	tasklist | findstr /L /I "%Executable%" >NUL
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
:KILL_PROCESS
	tasklist | findstr /L /I "%Executable%" >NUL
	if %ERRORLEVEL% EQU 0 (
		taskkill /F /IM %Executable% >NUL
		goto :EOF
	)
	goto :EOF


:: Service delete
:DELETE_SERVICE
	sc query %ServiceName% >NUL
	if %ERRORLEVEL% EQU 0 (
		sc stop %ServiceName%
		sc delete %ServiceName%
		goto :EOF
	)
	goto :EOF
