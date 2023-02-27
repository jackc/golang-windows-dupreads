package nbconn_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"dupreads/nbconn"
)

// Test keys generated with:
//
// $ openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -nodes -days 20000 -subj '/CN=localhost'

var testTLSPublicKey = []byte(`-----BEGIN CERTIFICATE-----
MIICpjCCAY4CCQCjQKYdUDQzKDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwIBcNMjIwNjA0MTY1MzE2WhgPMjA3NzAzMDcxNjUzMTZaMBQxEjAQ
BgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALHbOu80cfSPufKTZsKf3E5rCXHeIHjaIbgHEXA2SW/n77U8oZX518s+27FO0sK5
yA0WnEIwY34PU359sNR5KelARGnaeh3HdaGm1nuyyxBtwwAqIuM0UxGAMF/mQ4lT
caZPxG+7WlYDqnE3eVXUtG4c+T7t5qKAB3MtfbzKFSjczkWkroi6cTypmHArGghT
0VWWVu0s9oNp5q8iWchY2o9f0aIjmKv6FgtilO+geev+4U+QvtvrziR5BO3/3EgW
c5TUVcf+lwkvp8ziXvargmjjnNTyeF37y4KpFcex0v7z7hSrUK4zU0+xRn7Bp17v
7gzj0xN+HCsUW1cjPFNezX0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAbEBzewzg
Z5F+BqMSxP3HkMCkLLH0N9q0/DkZaVyZ38vrjcjaDYuabq28kA2d5dc5jxsQpvTw
HTGqSv1ZxJP3pBFv6jLSh8xaM6tUkk482Q6DnZGh97CD4yup/yJzkn5nv9OHtZ9g
TnaQeeXgOz0o5Zq9IpzHJb19ysya3UCIK8oKXbSO4Qd168seCq75V2BFHDpmejjk
D92eT6WODlzzvZbhzA1F3/cUilZdhbQtJMqdecKvD+yrBpzGVqzhWQsXwsRAU1fB
hShx+D14zUGM2l4wlVzOAuGh4ZL7x3AjJsc86TsCavTspS0Xl51j+mRbiULq7G7Y
E7ZYmaKTMOhvkg==
-----END CERTIFICATE-----`)

// The strings.ReplaceAll is used to placate any secret scanners that would squawk if they saw a private key embedded in
// source code.
var testTLSPrivateKey = []byte(strings.ReplaceAll(`-----BEGIN TESTING KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCx2zrvNHH0j7ny
k2bCn9xOawlx3iB42iG4BxFwNklv5++1PKGV+dfLPtuxTtLCucgNFpxCMGN+D1N+
fbDUeSnpQERp2nodx3WhptZ7sssQbcMAKiLjNFMRgDBf5kOJU3GmT8Rvu1pWA6px
N3lV1LRuHPk+7eaigAdzLX28yhUo3M5FpK6IunE8qZhwKxoIU9FVllbtLPaDaeav
IlnIWNqPX9GiI5ir+hYLYpTvoHnr/uFPkL7b684keQTt/9xIFnOU1FXH/pcJL6fM
4l72q4Jo45zU8nhd+8uCqRXHsdL+8+4Uq1CuM1NPsUZ+wade7+4M49MTfhwrFFtX
IzxTXs19AgMBAAECggEBAJcHt5ARVQN8WUbobMawwX/F3QtYuPJnKWMAfYpwTwQ8
TI32orCcrObmxeBXMxowcPTMUnzSYmpV0W0EhvimuzRbYr0Qzcoj6nwPFOuN9GpL
CuBE58NQV4nw9SM6gfdHaKb17bWDvz5zdnUVym9cZKts5yrNEqDDX5Aq/S8n27gJ
/qheXwSxwETVO6kMEW1ndNIWDP8DPQ0E4O//RuMZwxpnZdnjGKkdVNy8I1BpgDgn
lwgkE3H3IciASki1GYXoyvrIiRwMQVzvYD2zcgwK9OZSjZe0TGwAGa+eQdbs3A9I
Ir1kYn6ZMGMRFJA2XHJW3hMZdWB/t2xMBGy75Uv9sAECgYEA1o+oRUYwwQ1MwBo9
YA6c00KjhFgrjdzyKPQrN14Q0dw5ErqRkhp2cs7BRdCDTDrjAegPc3Otg7uMa1vp
RgU/C72jwzFLYATvn+RLGRYRyqIE+bQ22/lLnXTrp4DCfdMrqWuQbIYouGHqfQrq
MfdtSUpQ6VZCi9zHehXOYwBMvQECgYEA1DTQFpe+tndIFmguxxaBwDltoPh5omzd
3vA7iFct2+UYk5W9shfAekAaZk2WufKmmC3OfBWYyIaJ7QwQpuGDS3zwjy6WFMTE
Otp2CypFCVahwHcvn2jYHmDMT0k0Pt6X2S3GAyWTyEPv7mAfKR1OWUYi7ZgdXpt0
TtL3Z3JyhH0CgYEAwveHUGuXodUUCPvPCZo9pzrGm1wDN8WtxskY/Bbd8dTLh9lA
riKdv3Vg6q+un3ZjETht0dsrsKib0HKUZqwdve11AcmpVHcnx4MLOqBzSk4vdzfr
IbhGna3A9VRrZyqcYjb75aGDHwjaqwVgCkdrZ03AeEeJ8M2N9cIa6Js9IAECgYBu
nlU24cVdspJWc9qml3ntrUITnlMxs1R5KXuvF9rk/OixzmYDV1RTpeTdHWcL6Yyk
WYSAtHVfWpq9ggOQKpBZonh3+w3rJ6MvFsBgE5nHQ2ywOrENhQbb1xPJ5NwiRcCc
Srsk2srNo3SIK30y3n8AFIqSljABKEIZ8Olc+JDvtQKBgQCiKz43zI6a0HscgZ77
DCBduWP4nk8BM7QTFxs9VypjrylMDGGtTKHc5BLA5fNZw97Hb7pcicN7/IbUnQUD
pz01y53wMSTJs0ocAxkYvUc5laF+vMsLpG2vp8f35w8uKuO7+vm5LAjUsPd099jG
2qWm8jTPeDC3sq+67s2oojHf+Q==
-----END TESTING KEY-----`, "TESTING KEY", "PRIVATE KEY"))

type recordedReadConn struct {
	net.Conn

	readLock sync.Mutex
	readLog  *bytes.Buffer

	recordedWriteConn *recordedWriteConn
}

func (c *recordedReadConn) Read(b []byte) (int, error) {
	c.readLock.Lock()
	defer c.readLock.Unlock()

	n, err := c.Conn.Read(b)
	c.readLog.Write(b[:n])

	c.recordedWriteConn.writeLock.Lock()
	defer c.recordedWriteConn.writeLock.Unlock()

	readLog := c.readLog
	writeLog := c.recordedWriteConn.writeLog

	fmt.Printf("readLog.Len(): %d, writeLog.Len(): %d\n", readLog.Len(), writeLog.Len())
	for i := 0; i < readLog.Len(); i++ {
		if readLog.Bytes()[i] != writeLog.Bytes()[i] {
			fmt.Println("mismatch at", i)
			fmt.Println(readLog.Bytes()[i-20 : i+20])
			fmt.Println(writeLog.Bytes()[i-20 : i+20])
			fmt.Println(
				bytes.Contains(writeLog.Bytes(), readLog.Bytes()[i:i+10]),
				bytes.Index(writeLog.Bytes(), readLog.Bytes()[i:i+10]),
				i-bytes.Index(writeLog.Bytes(), readLog.Bytes()[i:i+10]),
			)
			os.Exit(1)
		}
	}

	return n, err
}

type recordedWriteConn struct {
	net.Conn

	writeLock sync.Mutex
	writeLog  *bytes.Buffer
}

func (c *recordedWriteConn) Write(b []byte) (n int, err error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	n, err = c.Conn.Write(b)
	c.writeLog.Write(b[:n])
	return n, err
}

// makeTCPConns returns a connected pair of net.Conns running over TCP on localhost.
func makeTCPConns() (clientConn, serverConn net.Conn, err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()

	type acceptResultT struct {
		conn net.Conn
		err  error
	}
	acceptChan := make(chan acceptResultT)

	go func() {
		conn, err := ln.Accept()
		acceptChan <- acceptResultT{conn: conn, err: err}
	}()

	clientConn, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	acceptResult := <-acceptChan
	if err != nil {
		return nil, nil, err
	}

	serverConn = acceptResult.conn

	return clientConn, serverConn, nil
}

func makeRecordedConns(w, r net.Conn) (*recordedWriteConn, *recordedReadConn) {
	recordedWriteConn := &recordedWriteConn{Conn: w, writeLog: &bytes.Buffer{}}
	recordedReadConn := &recordedReadConn{Conn: r, readLog: &bytes.Buffer{}, recordedWriteConn: recordedWriteConn}
	return recordedWriteConn, recordedReadConn
}

func makeTSLConnection(clientConn, serverConn net.Conn) (clientTLSConn, serverTLSConn net.Conn, err error) {
	netConn := nbconn.NewNetConn(clientConn)

	cert, err := tls.X509KeyPair(testTLSPublicKey, testTLSPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	tlsServer := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	serverTLSHandshakeChan := make(chan error)
	go func() {
		err := tlsServer.Handshake()
		serverTLSHandshakeChan <- err
	}()

	nbconnTLSConn, err := nbconn.TLSClient(netConn, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, nil, err
	}

	err = <-serverTLSHandshakeChan
	if err != nil {
		return nil, nil, err
	}

	return nbconnTLSConn, tlsServer, nil
}

// This test exercises the non-blocking write path. Because writes are buffered it is difficult trigger this with
// certainty and visibility. So this test tries to trigger what would otherwise be a deadlock by both sides writing
// large values.
func TestInternalNonBlockingWrite(t *testing.T) {
	// Make a connected pair of TCP connections.
	tcpClientConn, tcpServerConn, err := makeTCPConns()
	if err != nil {
		t.Errorf("makeTCPConns failed: %v", err)
	}

	// Wrap the connections in recording connections.
	recordedClientConn, recordedServerConn := makeRecordedConns(tcpClientConn, tcpServerConn)

	// Establish a TLS connection from the client to the server.
	clientConn, serverConn, err := makeTSLConnection(recordedClientConn, recordedServerConn)
	if err != nil {
		t.Errorf("makeTLSConnection failed: %v", err)
	}
	defer clientConn.Close()
	defer serverConn.Close()

	const deadlockSize = 4 * 1024 * 1024
	writeBuf := make([]byte, deadlockSize)
	for i := range writeBuf {
		writeBuf[i] = 1
	}
	n, err := clientConn.Write(writeBuf)
	if err != nil {
		t.Errorf("clientConn.Write failed: %v", err)
	}
	if deadlockSize != n {
		t.Errorf("clientConn.Write wrote wrong number of bytes: %d instead of %d", n, deadlockSize)
	}

	errChan := make(chan error, 1)
	go func() {
		remoteWriteBuf := make([]byte, deadlockSize)
		_, err := serverConn.Write(remoteWriteBuf)
		if err != nil {
			errChan <- err
			return
		}

		fmt.Println("after remote write")

		readBuf := make([]byte, deadlockSize)
		_, err = io.ReadFull(serverConn, readBuf)
		errChan <- err
	}()

	readBuf := make([]byte, deadlockSize)
	_, err = io.ReadFull(clientConn, readBuf)
	if err != nil {
		t.Errorf("io.ReadFull(clientConn, readBuf) failed: %v", err)
	}

	err = <-errChan
	if err != nil {
		t.Errorf("serverConn goroutine encountered an error: %v", err)
	}
}
