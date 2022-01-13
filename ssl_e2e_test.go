// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"bytes"
	"bufio"
	"io"
	"sync"
	"testing"
	"fmt"
	"strings"
	"errors"

)

var (
	serverFullChainBytes = []byte(`-----BEGIN CERTIFICATE-----
MIIE+jCCAuICFCu6xcsmB9x0xLM2Wvb9ZL+1JaGNMA0GCSqGSIb3DQEBCwUAMDox
CzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1Gb3RhaHViLCBJbmMuMRMwEQYDVQQDDAp0
cnVzdHBvaW50MB4XDTIyMDExMzE5MzMwMVoXDTIzMDExMzE5MzMwMVowOTELMAkG
A1UEBhMCVVMxFjAUBgNVBAoMDUZvdGFodWIsIEluYy4xEjAQBgNVBAMMCWxvY2Fs
aG9zdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALqV4pGooQVhSnWN
dfWwHX3IHCckzeWz9ZETqhYwxqWoxoM4W2nx5gx1mgJzhfHAlcyQ7CvQOPxdnRtY
H1PtjFCEKpnWnIcr2ZCbffE3qN7OPvo7wlj5ADwOP8GxsaEf/feE7bbT6PmLznbZ
Tnd2egNzpUyBwiBWeNePeXDIz4cHPCjdzx9xGx1tGslKTPvj3ZUCTiBIbLVUQv+L
u7pqZDJUdMjWqvm+3ScM3lpdtE0cPdMmmk1AU5bzfKxb1NSwOKE4NOCFa752GlT9
tE3x9GmUIkIB5q7Ch509Gy446p2XBtKNQJnY7/Fm1BzXZ2qhQ+L6c238XY49DfrL
oms1fUu+06QhhTMK8MpkPojIZrfhA7GwjjSGrpNazmrvlw/hcn62I6xsit5zvI3k
aN9/ig0P4ZdbWRcVGxR0vU6lHnmF4KpTt7IwxGjkt+aK5r0dxeBamaQ86T3mg6HB
DbY+OFvJ6tT+WC/PYrWtxZya0WZOtc+gzlc0cFRAFXnxX+RRp6SsCHY9T1ejrzcO
+3ZYdzNGBxluCxoFdBxAcdJHJqHOefz2J9zRmOY7tofk/RnBkrvi8G5zQsg5luwA
NO1aqXefJ83rZ6gVFOrR3I/0cGFfMCKk6Pr+66gPx+2D3nxdVKUrzhf85nt/UY7Z
Egds4q6RsDccjIIK3KysXt6P+yBlAgMBAAEwDQYJKoZIhvcNAQELBQADggIBAEIq
NtzdGtGjAVZMA1NKnITkc7xAzT3w0/NsFyTz2E2FWKMIUwX4wIr2ppk2vvPVDaSn
x5yuMmhyl5XsadAkMpo5JOSToKfvks1f4tuvcP/0pOYM+DW9Cy4E04x54Ilhq5V6
k5ueLMRJp3kJmC4G7MnkMuZbqRNWZozWNIHrDWk25efrO1s6w2QKAR+Qf6hszkN3
YPljU4A79c6z/qV6AE1R4nFhLqDiuMpkaOmJxeahedB4XJvAyWThIofBJsyTFDDc
Xk7AEWWy5GsUFlACJLbHE9T5RRkTclI4P0Lmyv7GhDDFX3004yt9mneNn5RtPzZ9
G0HbZBdvCimzJqxC8pxZIwUvr2S8x3UxYr2tujeavFDLmDR/NHDWR+yZCo3+QIgy
Tj50k6NTFa8V8sIWY9sN5ij+17WcK7r1U+zPDtyd4/NNYuNmLZuexWYfRufX+cI7
o5pK24ZMoGwvt4/GZFq4qgxiuUQopVGyllYDCF4TH3ICDAWBxxvqMC3vcqTG7Sb3
k3xreiXF23FO5xGQedOfStd9JcsHfmtQsbPhEgt02agXWkQwU81fwE3oVu/Fq+yv
M7KMtrOODjZh390bwu4/NOjm+wMbV14PljNUAiC44BGskKWVCXx5OOADncE/FXqM
pVJW8OD6YPsWJ4I5pWGwPxbZOfEYjXjqywcsI5r3
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFrDCCA5SgAwIBAgIUcmOOFByhRDRwe2uQIuFtAr0GeNkwDQYJKoZIhvcNAQEL
BQAwOzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZvdGFodWIsIEluYy4xFDASBgNV
BAMMC3RydXN0Y2VudGVyMB4XDTIyMDExMzE5MzMwMVoXDTI5MDQxNjE5MzMwMVow
OjELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZvdGFodWIsIEluYy4xEzARBgNVBAMM
CnRydXN0cG9pbnQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCjzFHj
7oC1SH8lrKqp13pVthnTOdDrU6JujVuxGmGGBCPhRi9fxe3oXxWgYrZiF2ro1hcW
yJmVTb3s3BxgQJe8ZgZW8qcXCdYgunUHUHIH9+q4NjlVDdgEbhoRlL8hxsp6g9Zo
aJG3WANwikWDm5/byHMEiVwz/byrOujJBIjfykuLNA6s62JFLCkSwzfFQI8bDriB
T3xMbD3ycubK+USYJSiTq4J+wfNDRXbcaDP/hKQOiG2lo/awIVVeQMFqSyUkB0gQ
WMAoLdIJPK8c15wZFmPW4vY2QmJm/dCszxUXj3OuY6f/wh6BzrvXeCUndFqeW8XU
RdK00IsA0tsAWjdbHIBmrmEMhtJZpTdcmsNt9KXhZ7sAJrovL1sYrTIzUEj18DHB
v8qbDchtDz11aQ2LF4vk5IUb9qJ0d0KR0rEOexXQjn3XoCHzRjUdfqmY0zF9n4rT
hN979WDxLZmXKxuOtd070ncKIakBu3vuDSU9L8KFcXxKdem/BHspfuB7TAYHalQY
KqGApuR9Sx1EPejeMVbriQ00FQqdrB1wurx4yCg1IMB1NkWgj8+BmfqsWCydK61Y
vBGieHapi+c3IHa1IbwxrfT0aJFNWjm/HioHWDpflJ8+9Nx83mi8tlLlQEtFGgKj
ozBRg4nsCixum+pzMWwLPGHyB67vvPcMGIL13QIDAQABo4GoMIGlMB0GA1UdDgQW
BBRXmnxgUlhkR9ayipoQKpadmu895DB2BgNVHSMEbzBtgBTHw22VmvXZrCUmGEe7
R/7k+U963qE/pD0wOzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZvdGFodWIsIElu
Yy4xFDASBgNVBAMMC3RydXN0Y2VudGVyghQed4MP1qvc5zmCRssC42wQeSp7CzAM
BgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQCdhHxVCeqQbzl/R4r2aL4n
Sqj9mkfBCB0aK842Y6vs4s1zQqxBvpIAETiZq7srhzznJfRE7q0mSKw9TUUMk0hd
oUHqxTUa+Aq0f663qo0Swfy/0C8HMF00lEGXV2gWQXOOnH/2FW8gCpXtAo7JOGwQ
xlzu9ivxqv8b1kMTF1lKICSQ0R3hkBNIrH9S4dc+iKVcAgAUrj8rhXhV2c0d67Wf
swR0EpNj3hZzYY4FNm67VbAyUWPQo6XGQq+Ek8bt/4IsRYmJgTKpB25xUxbEnq3d
oast/OCTnBpmphWDa/vvCUuneLAKr8YB5LdsMDmTaOH2JYkDqtvPJPbhAXTwmV0Y
cXHSZT2JpZ7qppc8Iq0oWo/R8GZ6yJW33BDncvWt/DG/plNdct7LKLXJHyH0m1xX
qJVyn2MDp0C2AnU9B5ui7uM7I41U7mg76uLOu2SiHPpO27vefaazcH+eRv5+6k9N
p+DlX9hKrRbE8/fE8fkv3N1YS/xLLpJnAlH6W6P8QXSP1Qf5PXw1nq8R0ZVkD5sj
R4qF6jz4TLlVsyq5rdlasLAs0Vzm8Ms0rOeXO8yMUlaekPktHP1c4UihdQpO/zRQ
X7lazkjE+2ICTBq9gi303nRx3F1XTOA6eWsMBrEiTsI9D6E0BXHdp6EcWiOaR1wZ
7fq7o+KXA0uLWssx584dgw==
-----END CERTIFICATE-----	
`)

	serverKeyBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`)

	rootCABytes = []byte(`-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgIUHneDD9ar3Oc5gkbLAuNsEHkqewswDQYJKoZIhvcNAQEL
BQAwOzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZvdGFodWIsIEluYy4xFDASBgNV
BAMMC3RydXN0Y2VudGVyMB4XDTIyMDExMzE5MzMwMFoXDTMyMDExMTE5MzMwMFow
OzELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUZvdGFodWIsIEluYy4xFDASBgNVBAMM
C3RydXN0Y2VudGVyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqzLb
zUHGrUpToM9g9BykwbuNYZDW2zXHfo8LAson+rbIvZV4hVJ92mi68gtImP/jVBtd
ksdktqkfLlqEsVEPC76GubwhhEE1wYDeMEW6mNY7s0sFjQlwlHPzRYMNN2b6PFlu
/IwkNEZbjFvTqrlUW3+GsriVjnAlseKaZaHeXx+uRkvkIS3sfkvIuTTb6r99VUEi
F8oNLz1yDDu0YzdT+q9aXL7d2tn7alXijOPxo7awebYk86fiKSrVjLcyBfmeHC98
eq1/n8CG/ZJ5s9cP+4K9xml+RfbkadoXe+pIuaOadFPgZ7jgwP5muPHs1rvqVLKh
fSmQ7VhXxCjT+FiKsGzQQwOD5fc07UqyiP9qyjRiZqwfVSWh43BJgtmspkIt4XZS
3ZY7eGxLY/j2MqUD4w/swvRCAh5WlonfUQkQpl8clhrAs+U4bwkDLbv+I8gPteey
y1AyILMavMKPsS3jKyVI3S7Kn1nA77ScQSJiMFWDbeiaqUUaRn3wPiW122GnnvQM
YCk8No59/DqCNLyzyCHbf8TwW4C1JCAh6avPO7vagLgjofIILbpz31GXrLU8Dw9M
uswSgKU00x1Og4qycQozmKAaeG0xNXVteiXnw9CrjioYNZzxqXz9facx+ibammRu
T0fClePgZr4pD2Dh+nGhHTNfjGlqCMYYBHHayX8CAwEAAaNTMFEwHQYDVR0OBBYE
FMfDbZWa9dmsJSYYR7tH/uT5T3reMB8GA1UdIwQYMBaAFMfDbZWa9dmsJSYYR7tH
/uT5T3reMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAC1ve56b
0AnVtTtlSoCdHG8SL0OEE+zF8K7uBwZenuMw87HFZoxsq//1ur8quZi9sttK+1oc
zTM6UBc4lew9gRc3YyGbekON9+ZTN/aQs3tobddT2AKkdAguey7yZOhPS5DKz3wK
uz0Twsga4ZDjHXoSHyU8Vw5Umgoz0yXCDXdxvIdq4yHCMw+ihcl4g6OKHF0ypOkL
aFa2qy5fYgI5HUwwByecuBsenHWUQ5g/tm5eV+LFbYZMki6QX7hUKJgY9rLSPLOx
7BZAwLiQy9CikrGq8TEbx58mstubJLs64E0cIgYvj1AZTcFX1qloOrF5opvyVuTk
4r2/mDHD72NZuZYeiXnoX1sNHJugeBMnF/Hj/65BsHNAcsj31g1bSZ7SXJUyIShO
vaGpAsS7IN2OFFDlIZk7ltZqrumbtKpiDM4Nir2H3VnAl2dLlsEG6BoT7b1hQozR
lLV4J7ttUili0OCNCpFJp1336+icXaLunxSeRdb0m2Wk/Qu30BlBlGX6t6r4NMlV
zsQqSkFncIKds4IbOzzVneMG63/dC6kxk+wI2s4mTysIA7JkfQ1INcKX3jdmK/so
L9hfEtfTTMeN2HqmWdm1kYBX1+Baxx6OheCa8tSiJgK/Vel6uH1LRwTQHbH5cvMN
y7U9bEnkS5tv+1Wm9t8sbrIBZVZg6IQNvSNZ
-----END CERTIFICATE-----
`)
)

func TestOpenSSLClientServer(t *testing.T) {
	clientMsg := "client test message\n"
	serverMsg := "server test message\n"
	ctrlChrReplacer := strings.NewReplacer("\r", "\\r", "\n", "\\n")
	
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()

		ctx, err := NewCtx()
		if err != nil {
			t.Fatal(err)
		}
		err = ctx.GetCertificateStore().LoadCertificatesFromPEM(rootCABytes)
		if err != nil {
			t.Fatal(err)
		}
		ctx.SetVerifyMode(VerifyPeer)

		fmt.Println("    [Client] Connecting to server")
		clientConn, err := Dial("tcp", "localhost:8080", ctx, 0)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("    [Client] Sending message: %s\n", ctrlChrReplacer.Replace(clientMsg))
		 _, err = io.Copy(clientConn, bytes.NewReader([]byte(clientMsg)))
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println("    [Client] Waiting for message from server")
		msg, err := bufio.NewReader(clientConn).ReadString('\n')
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		fmt.Printf("    [Client] Received message: %s\n", ctrlChrReplacer.Replace(msg))
		if msg != serverMsg {
			t.Fatal("mismatched server message")
		}

		fmt.Println("    [Client] Disconnecting from server")
		err = clientConn.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()
	go func() {
		defer wg.Done()

		ctx, err := NewCtx()
		if err != nil {
			t.Fatal(err)
		}
		key, err := LoadPrivateKeyFromPEM(serverKeyBytes)
		if err != nil {
			t.Fatal(err)
		}
		err = ctx.UsePrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certs := SplitPEM(serverFullChainBytes)
		if len(certs) == 0 {
			t.Fatal(errors.New("No PEM certificate(s) found"))
		}
		fmt.Printf("    [Server] Server full chain length: %d\n", len(certs))
		first, certs := certs[0], certs[1:]
		cert, err := LoadCertificateFromPEM(first)
		if err != nil {
			t.Fatal(err)
		}
		err = ctx.UseCertificate(cert)
		if err != nil {
			t.Fatal(err)
		}
		for _, pem := range certs {
			cert, err := LoadCertificateFromPEM(pem)
			if err != nil {
				t.Fatal(err)
			}
			err = ctx.AddChainCertificate(cert)
			if err != nil {
				t.Fatal(err)
			}
		}
	
		fmt.Println("    [Server] Starting server")
		l, err := Listen("tcp", "localhost:8080", ctx)
		defer l.Close()
		
		fmt.Println("    [Server] Waiting for client to connect")
		serverConn, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("    [Server] Client connected")
	
		fmt.Println("    [Server] Waiting for message from client")
		msg, err := bufio.NewReader(serverConn).ReadString('\n')
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		fmt.Printf("    [Server] Received message: %s\n", ctrlChrReplacer.Replace(msg))
		if msg != clientMsg {
			t.Fatal("mismatched message")
		}

		fmt.Printf("    [Server] Sending message: %s\n", ctrlChrReplacer.Replace(serverMsg))
		 _, err = io.Copy(serverConn, bytes.NewReader([]byte(serverMsg)))
		if err != nil {
			t.Fatal(err)
		}
	
		fmt.Println("    [Server] Stopping server")
		err = serverConn.Close()
		if err != nil {
			t.Fatal(err)
		}	
	}()
	wg.Wait()
}
