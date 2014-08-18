:: Pcap_DNSProxy query service batch
:: A local DNS server base on WinPcap and LibPcap.
:: 
:: Author: PyDNSProxy project(https://code.google.com/p/pydnsproxy)
:: In Windows XP/2003, 'sc query' will always exit with status code '0',
:: No matter the query faild or not.
:: 

@echo off

@echo.
sc query PcapDNSProxyService | find "SERVICE_NAME: PcapDNSProxyService"
@echo.
@pause
