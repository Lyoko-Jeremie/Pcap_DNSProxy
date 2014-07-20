@echo off
sc stop PcapDNSProxyService
sc delete PcapDNSProxyService
@echo.
@echo Done. Please confirm the PcapDNSProxyService service had been deleted.
@echo.
@pause
