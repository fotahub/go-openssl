@echo off
setlocal
set SCRIPT_DIR=%~dp0
set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%

rem Set cert file and server names
set ROOT_CA_CERT_BASE_NAME=rootCA
set INTERMEDIATE_CA_CERT_BASE_NAME=intermediateCA
set SERVER_CERT_BASE_NAME=server
set SERVER_NAME=localhost

rem Generate "localhost, Fotahub, Inc. (US) --- trustpoint, Fotahub, Inc. (US) --- trustcenter, Fotahub, Inc. (US)" cert chain
call %SCRIPT_DIR%\helpers\gen-certs.bat ^
  %ROOT_CA_CERT_BASE_NAME% ^
  %INTERMEDIATE_CA_CERT_BASE_NAME% ^
  %SERVER_CERT_BASE_NAME% ^
  %SERVER_NAME% ^
  %SCRIPT_DIR%\..\certs

endlocal