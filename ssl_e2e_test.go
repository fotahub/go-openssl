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
MIIE+jCCAuICFDr2EVg9xTZdDomfGiGr2nQ8jle6MA0GCSqGSIb3DQEBCwUAMDox
CzAJBgNVBAYTAkZSMRYwFAYDVQQKDA1pdGVtaXMgRnJhbmNlMRMwEQYDVQQDDAp0
cnVzdHBvaW50MB4XDTIwMTAwOTE1MDgyOFoXDTIxMDEwNzE1MDgyOFowOTELMAkG
A1UEBhMCRlIxFjAUBgNVBAoMDWl0ZW1pcyBGcmFuY2UxEjAQBgNVBAMMCWxvY2Fs
aG9zdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALaSTkkjGEh1riYV
bYiWR7yGffy8BPRpTbnNWyNzgqgW4wlQrmt2vjEwLq4xV2PZfl3isYBKlRdUQjVt
1jA2LgS5dW7wlcN6O1fElOQ5CyW3XGTfvIoxZ9YcQFdTeU5sV2phQ56/NJHc0gaI
nhGLk+Zh3NgIHbM/1pU7gYvrUexhfThZTcrjAyw/nHRmvXuvPPWIixocagshuQrt
pGWwnEiKbWQm7VOMzuMqA5XR8PQtcleFozBmJRV3+2jZn9Ub4WtjnW02vc4oXtGx
J6MHHOMS4dmkXW6FGBvLLoetpQMrwbVWyuk09LyZMsYgwO1+JrSMgcWn8xGT5U8N
0HBDpEBkigjPgBaqBw2mN48NOndXtGGH8AcsGMducjz+ZLpYWUhOj/9yCEOaiCWB
Tsad+LN6772BYjaZQ67zJC//R541OQXrVoAdhRA58VTiv+zYChp/mxPfQNYqoWRM
CEt76BGAd4j1dhCUN7BnETGiU0y0ZUp9BHnVvLjwYEr1EELuuR+NJiYCZnVE7ilt
rn0BkXqn24NwUyfmnODiiz6zBE7b7GXgXJ8GzhJ+CF4Qmp9pv0iSpZ5CttspipVY
nsCGvGvNoRLuFbzUY66r4ZefysomTocayUSYVHzlxh5AWMEQJhieqELa6QYPd/mA
Lb2QAgNOKvHfrwlMYSySu8GqIo2xAgMBAAEwDQYJKoZIhvcNAQELBQADggIBAKs4
PefGjP4ZHtF/ITbW6cOqBz4Xum6RLzhszIGZ3fm7ncqeZhXO3gE60gAciNNQ9lqj
4Yi3BjBIbcLytvzfdXf3o1bf2v1uwPkKRU1cUDc6CU39viSBzzSS/dqANPSwos/S
u8tpnQX5UuRmcf0J12FzyEXktitdb3HbAqsR09/O4iLZegTs0/ba4pM0ndka/bhW
uq0XZYo9IJzfE+1YjDa0yVtAzx30i+Ua9LjTKs2G1syISyVZjhLEP7hY84cYrxBb
JK8yLqE6R8qh8Dhi4kdS9wGbdG9vbITdH88IKGXzOsSdi9qXv3pGnjdxgdtkAZf5
1mlIGT+bdvMSNxQzvXnQWhJueHAaZzUEZsYFyVSGw3AKlKuiHPEyTLtyxtTPY0cm
qhP6teuKYsL9WCX+9mpRKr1X8taARNU4tN6ElqwtkkwOFLj8gn8kLAhKm+vLuX8n
40C9VdLY7VLTLL6KIiAvjeZKkAY+P0h8MKBBn1QTVhOZcc2zbVTiH4zazcVgokps
a3qkfpJafed6acFtmT92lMLTQIfSjDW39JqXyWWxpxqKwabXNIli7cBZyFoZ4GwB
Ox/sfh4QCuSBBdMoTt3wJYy7tnqfBdICQVRUxeDx3k5NkV2xbo/y1Gw7KFxbOigP
6wnDWbA/9EolpGqtfXaOwAUcmJU/sQvoEne6y/LU
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFrDCCA5SgAwIBAgIUJOkJRaDWFtsvamZ9jCBZ74Y37m8wDQYJKoZIhvcNAQEL
BQAwOzELMAkGA1UEBhMCRlIxFjAUBgNVBAoMDWl0ZW1pcyBGcmFuY2UxFDASBgNV
BAMMC3RydXN0Y2VudGVyMB4XDTIwMTAwOTE1MDgyN1oXDTI4MDExMTE1MDgyN1ow
OjELMAkGA1UEBhMCRlIxFjAUBgNVBAoMDWl0ZW1pcyBGcmFuY2UxEzARBgNVBAMM
CnRydXN0cG9pbnQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDPjqSq
fh02nYTF84TtF+2YWbXEBLID79LNCW0XYeTRCY64C3jDnRYeg9z3uKjwX+x3/1yW
+LDlVYuKufTS/weYT/tNFq/sNsbu/dGBhZeX7BKK4Fs5iZGGL4BbliO3e/JRYqvE
uoKhxXH78stJQ3/dPFAALr2kKpbKZ08IkPAkpAXjAHntyQLqGzXpZLsG0/6pliyE
kWsd3p1doesQGFDwtdOz89Rirzx+QZSX/UHm/x5JPUCDa5E+uxqiZhANg/+I0keE
yQgpm6hxbHwwwzlpJcGUD87H5i7hnKbPRXrIKEESZwgEmGQ8W+Cv3kq4Sg/b2d6C
04b6qgk76+hqCfwS2dl+Kc9WFI9aP58+PWKyB125svcrxZiCW81mZYZE5Slm4kaD
WlbNCIMdop8NkM955hgUizL9H+tSWCWJcobRgTy68vXQz0ys09XQcHp9w8FMzco+
lfsMTo0EzajojvoGBiHYG3Sk8IDdP2O07dxASEYAeS/reQC8gffdLY9MK7CUgMLK
JFMb0RroQO5REPXJb+PFrhkgncVgFENx73PE++WE6ngi68zdBHLGXJQvpf/W4sOh
IQ1K+ZtHREg1yNOwXXO52vA4s7YawRZu0MF7rxitUFpGF9i3anAmid5NjcrR6Xrb
nGwbOfAh+8SiAnwsKTvexr15EyoGHQQ7Qhj/awIDAQABo4GoMIGlMB0GA1UdDgQW
BBQBLAUgSfZlhnO2xOYwy8ZgOGaD4DB2BgNVHSMEbzBtgBSOEJ+DV4p7rF4tpjg0
9Ubg1y3WgaE/pD0wOzELMAkGA1UEBhMCRlIxFjAUBgNVBAoMDWl0ZW1pcyBGcmFu
Y2UxFDASBgNVBAMMC3RydXN0Y2VudGVyghRWCBczUIXEGhw1zMs1p/s1Vj5fqjAM
BgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQB6m5jD4A33N3PQ9fpuny7p
gvAiCBrulS0WMSyd6Yd9X8c2dpW3LUOOI4zAeMnJia9q4VPu8SGBgkTBSsyzqePU
rMxCE9C15838qjxmv99vrJZIpfmZsUn3MfGhWExKHEg0leZVFHysX0jV7xzXAC2H
R3NUNm4wjFcse4SaB9HZdqpXlqEZ/T1/gYO8C7lm0uFSYGpQlVnSJ5eerye67RkI
Xyp+GV9Q4XwR33c5mItcvArQXLAwlWOYwh0mWg9br03sqJGWD91+p7k55/lKKIcu
VfLjT1cfTzQqR1/GbvxnTW7Ym715TSsIzkNrlVwRQlT+W5lXqLwTWSvdfjUvbD1Z
mFm2uVn8uN1L/deaPl11RsF0w6DcLxzLit1eS+3vOZUrhtaFvti4MjLuehp8T/+N
ncKif1yXnhbxLxb43L34RyIzls6zgbH2WDZW+T9OQCUhgyqmpUw3YwQ4jVfLXGYq
kT6oPTR5rLrBJXN8YPHJja5In3ru86LcUGtb/qumRm0sL2lhHTzQfi3WUUeQGl5M
GCmo7J31eFShdWvYq8IFZf3UyYkExhn7IbmzmSQnfW0frH+zQOJZtTxzykifWvjR
lHfJFicW/2Jn+1QLo/jEZoAHoo8ELe1xFAU7+ED7F/jS1awqL6zRHcyoy7oppqHk
Spv5Hd+5J7ZM2c/ZrZVgIQ==
-----END CERTIFICATE-----	
`)

	serverKeyBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----	
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
-----END RSA PRIVATE KEY-----
`)

	rootCABytes = []byte(`-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgIUVggXM1CFxBocNczLNaf7NVY+X6owDQYJKoZIhvcNAQEL
BQAwOzELMAkGA1UEBhMCRlIxFjAUBgNVBAoMDWl0ZW1pcyBGcmFuY2UxFDASBgNV
BAMMC3RydXN0Y2VudGVyMB4XDTIwMTAwOTE1MDgyNloXDTMwMTAwNzE1MDgyNlow
OzELMAkGA1UEBhMCRlIxFjAUBgNVBAoMDWl0ZW1pcyBGcmFuY2UxFDASBgNVBAMM
C3RydXN0Y2VudGVyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7tRJ
EUGx05G+29ON6P4wNzsoq9jVruqR8xbb0v3lya9ZadVvqPtlPB5QTnZbR3TEAazO
h4GLa8/fkZd2xTA7m7y3SWd1ntO5t06i4r8MIYhl7o/A4Leng47JIRRrCCRQTy5z
T5Y+pKiZkcttt5z9IXUZsN6olBxzqX7DTSsfKreeHLdIZg3MPbzdDWkSA1vc1TID
qa6JSCiJnZFDzpdXlLL/Y1rNUwt0VhYuUgwHz4r493sfN9q2srMRBdHZeSKaN/en
z6RgWojKWy7yXekIsromgy63NuXNtgPwX1IFTfWFJNIxapyFGiHS/Seo7hqaaoS5
BG9ot66+WiGyAFHIlxDFAoPq+eCUFeprsyUDyNaimKl8H3CDYyntEfd/U8Kq562A
RwEe6apeLvNrwZLV8Le020MaQoRyorU1q6qtE2+nNgbInT3psn8/YBZ/p59WW9XC
lUtYVjWtNppeb7YyEBtpa07kVpskVV3hHGobkRBAr5b4dom6PA6N422KSho8byJ6
W45MYk/nhA52DMSlPwuROdmOyezL7UUGvcK/0ihpApoeQ8N+Qqp4d2ox/fYazhOW
NLKZdII3YKfF1QVt4B9LsB1BBi/Q+q7uaFIXx1rPvf4lq5Sm6gm7rfKEu0mZR/yJ
9deKzge+s2WdfVTSWXF5sqRCQiyHKxx14XS7F6kCAwEAAaNTMFEwHQYDVR0OBBYE
FI4Qn4NXinusXi2mODT1RuDXLdaBMB8GA1UdIwQYMBaAFI4Qn4NXinusXi2mODT1
RuDXLdaBMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBALPIBtL7
h02mHT5txJwFnQDWX0nGdGI16vKEIeigqGMWTlGwKxWDvx6szunqQDdQUplb79dm
eLIoCT9qsxiHrSbQEhIDZlRh9aP+n8Ohdtdh6Yjm+YEOOzPdN3N0W/hzanZJIuQN
TqWicXiFPbdCGMafGntErPOV5PLPstn9yM2a1CvBsK6zppaddl5NHdAt6eIr7sia
356SyW+UGyJSTjLFWll8z4aLAGQirmxIebTtzO0nXRv/Dd3NoroIr7Y6Rxf79foZ
BhMv3cNq1/D9zTeNfSjYGCJNBslLy3EfxFFB+fJmg2DOpHwQOydVUEb4jFqN71fF
UFX7MBosv4J/K+bQP8nMvkk8TS6Cep8OXU+GbJB76bCxNt4UVgUGrItJC97q8ntQ
ZpCyoUHzcECluhWQX1vPFm5NSXs94FqTOlsoRMb/yJ/V5oRWwDFoK2eMOq7fBaws
sd8ylRVsGPJJe3Z7OQdBwlN7D985TwglXAzsLUw+FDH2cNxZtqlwziddNxAoJ3oY
WgnawydlC3ExHKbWiW9os5TDIxpkWgy5xNDgIJlP2ArSi/ZlKLWngnws66cQY20C
68dcGa0RPdM91Rm/PKRgtRAemRxV6q8xOCzlTYWjlWl3dbQW/xeB5+XkHMDXIhTR
lB6cAHjBZSVmI3KBHszT7ZDHDjrdxD3MFZFp
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
