@echo off
rem See https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309 
rem and https://community.axway.com/s/question/0D52X000065Ykx2SAC/example-scripts-to-create-certificate-chain-with-openssl for details

set ROOT_CA_NAME=trustcenter
set "ROOT_CA_ORGANIZATION=Fotahub, Inc."
set ROOT_CA_COUNTRY=US
set ROOT_CA_CERT_BASE_NAME=%1

set INTERMEDIATE_CA_NAME=trustpoint
set "INTERMEDIATE_CA_ORGANIZATION=Fotahub, Inc."
set INTERMEDIATE_CA_COUNTRY=US
set INTERMEDIATE_CA_CERT_BASE_NAME=%2

set SERVER_NAME=%4
set "SERVER_ORGANIZATION=Fotahub, Inc."
set SERVER_COUNTRY=US
set SERVER_CERT_BASE_NAME=%3

set DESTDIR=%5
if not defined DESTDIR set DESTDIR=%~dp0
if %DESTDIR:~-1% == \ set DESTDIR=%DESTDIR:~0,-1%

set ROOT_CA_CERT_BASE_PATH=%DESTDIR%\%ROOT_CA_CERT_BASE_NAME%
set INTERMEDIATE_CA_CERT_BASE_PATH=%DESTDIR%\%INTERMEDIATE_CA_CERT_BASE_NAME%
set SERVER_CERT_BASE_PATH=%DESTDIR%\%SERVER_CERT_BASE_NAME%

if not exist %DESTDIR% mkdir %DESTDIR%

echo:
echo ######## Creating Root CA ########
echo:

echo:
echo -------- Generating root CA key --------
echo:

openssl genrsa -out %ROOT_CA_CERT_BASE_PATH%.key 4096

echo:
echo -------- Creating and self-signing root CA certificate --------
echo:

openssl req -new -x509 -sha256 -days 3650 -nodes ^
  -subj "/C=%ROOT_CA_COUNTRY%/O=%ROOT_CA_ORGANIZATION%/CN=%ROOT_CA_NAME%" ^
  -key %ROOT_CA_CERT_BASE_PATH%.key ^
  -out %ROOT_CA_CERT_BASE_PATH%.crt

openssl x509 -noout -text -in %ROOT_CA_CERT_BASE_PATH%.crt

echo:
echo ######## Creating intermediate CA ########
echo:

echo:
echo -------- Generating intermediate CA key --------
echo:

openssl genrsa -out %INTERMEDIATE_CA_CERT_BASE_PATH%.key 4096

echo:
echo -------- Creating certificate signing request (CSR) for intermediate CA --------
echo:

openssl req -new -sha256 ^
  -subj "/C=%INTERMEDIATE_CA_COUNTRY%/O=%INTERMEDIATE_CA_ORGANIZATION%/CN=%INTERMEDIATE_CA_NAME%" ^
  -key %INTERMEDIATE_CA_CERT_BASE_PATH%.key  ^
  -out %INTERMEDIATE_CA_CERT_BASE_PATH%.csr

echo:
echo -------- Generating and signing intermediate CA certificate using intermediate CA CSR along with the root CA key --------
echo:

(
echo subjectKeyIdentifier=hash
echo authorityKeyIdentifier=keyid:always,issuer:always
echo basicConstraints = CA:true
) > %INTERMEDIATE_CA_CERT_BASE_PATH%.conf

openssl x509 -req -sha256 -days 2650 ^
  -in %INTERMEDIATE_CA_CERT_BASE_PATH%.csr ^
  -CA %ROOT_CA_CERT_BASE_PATH%.crt ^
  -CAkey %ROOT_CA_CERT_BASE_PATH%.key ^
  -CAcreateserial ^
  -extfile %INTERMEDIATE_CA_CERT_BASE_PATH%.conf ^
  -out %INTERMEDIATE_CA_CERT_BASE_PATH%.crt

openssl x509 -noout -text -in %INTERMEDIATE_CA_CERT_BASE_PATH%.crt
openssl verify -CAfile %ROOT_CA_CERT_BASE_PATH%.crt %INTERMEDIATE_CA_CERT_BASE_PATH%.crt

echo:
echo ######## Issuing server certificate for '%SERVER_NAME%' ########
echo:

echo:
echo -------- Generating server certificate key --------
echo:

openssl genrsa -out %SERVER_CERT_BASE_PATH%.key 4096

echo:
echo -------- Creating certificate signing request (CSR) for '%SERVER_NAME%' --------
echo:

openssl req -new -sha256 ^
  -subj "/C=%SERVER_COUNTRY%/O=%SERVER_ORGANIZATION%/CN=%SERVER_NAME%" ^
  -key %SERVER_CERT_BASE_PATH%.key  ^
  -out %SERVER_CERT_BASE_PATH%.csr

echo:
echo -------- Generating and signing server certificate using '%SERVER_NAME%' CSR and key along with the intermediate CA key --------
echo:

openssl x509 -req -sha256 -days 365 ^
  -in %SERVER_CERT_BASE_PATH%.csr ^
  -CA %INTERMEDIATE_CA_CERT_BASE_PATH%.crt ^
  -CAkey %INTERMEDIATE_CA_CERT_BASE_PATH%.key ^
  -CAcreateserial ^
  -out %SERVER_CERT_BASE_PATH%.crt

echo:
echo -------- Augmenting server certificate to full certificate chain (signed server certificate plus intermediate CA certificate) --------
echo:

type %INTERMEDIATE_CA_CERT_BASE_PATH%.crt >> %SERVER_CERT_BASE_PATH%.crt

openssl x509 -noout -text -in %SERVER_CERT_BASE_PATH%.crt
openssl verify -verbose -CAfile %ROOT_CA_CERT_BASE_PATH%.crt -untrusted %INTERMEDIATE_CA_CERT_BASE_PATH%.crt %SERVER_CERT_BASE_PATH%.crt