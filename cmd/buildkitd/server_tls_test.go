package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/moby/buildkit/cmd/buildkitd/config"
	"github.com/stretchr/testify/require"
)

type testTLSCertificate struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	pem    []byte
	keyPEM []byte
	pair   tls.Certificate
}

func newTestTLSCertificate(t *testing.T, parent *testTLSCertificate, server bool) *testTLSCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	cert := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	issuer, signer := cert, key
	if parent == nil {
		cert.IsCA = true
		cert.KeyUsage |= x509.KeyUsageCertSign
	} else {
		issuer, signer = parent.cert, parent.key
		if server {
			cert.DNSNames = []string{"buildkit.test"}
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, issuer, key.Public(), signer)
	require.NoError(t, err)
	cert, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	result := &testTLSCertificate{cert: cert, key: key,
		pem:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
	result.pair, err = tls.X509KeyPair(result.pem, result.keyPEM)
	require.NoError(t, err)
	return result
}

// Emissary publishes complete versioned directories with atomic symlink swaps.
func publishTestTLSFiles(t *testing.T, base, link string, files map[string][]byte) {
	t.Helper()
	dir, err := os.MkdirTemp(base, link+"-")
	require.NoError(t, err)
	for name, data := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0600))
	}
	tmp := filepath.Join(base, link+".new")
	require.NoError(t, os.Symlink(dir, tmp))
	require.NoError(t, os.Rename(tmp, filepath.Join(base, link)))
}

func publishTestServer(t *testing.T, dir string, cert *testTLSCertificate) {
	t.Helper()
	publishTestTLSFiles(t, dir, "server", map[string][]byte{"cert.pem": cert.pem, "key.pem": cert.keyPEM})
}

func publishTestClientCA(t *testing.T, dir string, roots ...*testTLSCertificate) {
	t.Helper()
	var data []byte
	for _, root := range roots {
		data = append(data, root.pem...)
	}
	publishTestTLSFiles(t, dir, "client", map[string][]byte{"ca.pem": data})
}

func testServerTLSConfig(dir string) config.TLSConfig {
	return config.TLSConfig{Reload: true, Cert: filepath.Join(dir, "server/cert.pem"), Key: filepath.Join(dir, "server/key.pem"), CA: filepath.Join(dir, "client/ca.pem")}
}

func startTestTLSServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done; wg.Wait() })
	return ln.Addr().String()
}

func testClientTLSConfig(version uint16, leaf *testTLSCertificate, roots ...*testTLSCertificate) *tls.Config {
	pool := x509.NewCertPool()
	for _, root := range roots {
		pool.AddCert(root.cert)
	}
	cfg := &tls.Config{ServerName: "buildkit.test", RootCAs: pool, MinVersion: version, MaxVersion: version, ClientSessionCache: tls.NewLRUClientSessionCache(8)}
	if leaf != nil {
		cfg.Certificates = []tls.Certificate{leaf.pair}
	}
	return cfg
}

func echoTestTLS(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		return err
	}
	var response [1]byte
	_, err := io.ReadFull(conn, response[:])
	return err
}

func connectTestTLS(t *testing.T, address string, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, cfg)
	if err != nil {
		return nil, err
	}
	if err := echoTestTLS(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, nil
}

func TestServerCredentialsReload(t *testing.T) {
	for name, version := range map[string]uint16{"TLS12": tls.VersionTLS12, "TLS13": tls.VersionTLS13} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			serverCA1, serverCA2 := newTestTLSCertificate(t, nil, false), newTestTLSCertificate(t, nil, false)
			clientCA1, clientCA2 := newTestTLSCertificate(t, nil, false), newTestTLSCertificate(t, nil, false)
			server1, server2 := newTestTLSCertificate(t, serverCA1, true), newTestTLSCertificate(t, serverCA2, true)
			client1, client2 := newTestTLSCertificate(t, clientCA1, false), newTestTLSCertificate(t, clientCA2, false)
			publishTestServer(t, dir, server1)
			publishTestClientCA(t, dir, clientCA1)
			cfg, err := serverCredentials(testServerTLSConfig(dir))
			require.NoError(t, err)
			addr := startTestTLSServer(t, cfg)
			oldClient := testClientTLSConfig(version, client1, serverCA1, serverCA2)
			active, err := connectTestTLS(t, addr, oldClient)
			require.NoError(t, err)
			resumed, err := connectTestTLS(t, addr, oldClient)
			require.NoError(t, err)
			require.True(t, resumed.ConnectionState().DidResume, "exercise actual session resumption")
			require.NoError(t, resumed.Close())
			// Invalid server material must not publish a partially updated CA pool.
			publishTestTLSFiles(t, dir, "server", map[string][]byte{"cert.pem": server2.pem, "key.pem": server1.keyPEM})
			publishTestClientCA(t, dir, clientCA2)
			stillOld, err := connectTestTLS(t, addr, testClientTLSConfig(version, client1, serverCA1))
			require.NoError(t, err)
			require.Equal(t, server1.cert.SerialNumber, stillOld.ConnectionState().PeerCertificates[0].SerialNumber)
			_, err = connectTestTLS(t, addr, testClientTLSConfig(version, client2, serverCA1, serverCA2))
			require.Error(t, err)
			publishTestTLSFiles(t, dir, "client", map[string][]byte{"ca.pem": []byte("invalid CA")})
			publishTestServer(t, dir, server2)
			_, err = connectTestTLS(t, addr, testClientTLSConfig(version, client1, serverCA1))
			require.NoError(t, err)
			// Overlap both client roots before moving callers onto the new issuer.
			publishTestClientCA(t, dir, clientCA1, clientCA2)
			newConn, err := connectTestTLS(t, addr, testClientTLSConfig(version, client2, serverCA2))
			require.NoError(t, err)
			require.Equal(t, server2.cert.SerialNumber, newConn.ConnectionState().PeerCertificates[0].SerialNumber)
			_, err = connectTestTLS(t, addr, oldClient)
			require.NoError(t, err)
			// Retiring a root also rejects tickets authenticated using that root.
			publishTestClientCA(t, dir, clientCA2)
			_, err = connectTestTLS(t, addr, oldClient)
			require.Error(t, err)
			_, err = connectTestTLS(t, addr, testClientTLSConfig(version, client1, serverCA1, serverCA2))
			require.Error(t, err)
			_, err = connectTestTLS(t, addr, testClientTLSConfig(version, client2, serverCA2))
			require.NoError(t, err)
			require.NoError(t, echoTestTLS(active), "existing stream survives all rotations and root retirement")
		})
	}
}

func TestServerCredentialsReloadStartup(t *testing.T) {
	_, err := serverCredentials(config.TLSConfig{Reload: true})
	require.Error(t, err)
	dir := t.TempDir()
	root := newTestTLSCertificate(t, nil, false)
	server := newTestTLSCertificate(t, root, true)
	publishTestServer(t, dir, server)
	publishTestClientCA(t, dir, root)
	cfg := testServerTLSConfig(dir)
	require.NoError(t, os.Remove(cfg.CA))
	_, err = serverCredentials(cfg)
	require.Error(t, err)
	publishTestTLSFiles(t, dir, "client", map[string][]byte{"ca.pem": []byte("invalid")})
	_, err = serverCredentials(cfg)
	require.Error(t, err)
}

func TestServerCredentialsStatic(t *testing.T) {
	dir := t.TempDir()
	root := newTestTLSCertificate(t, nil, false)
	old, newCert := newTestTLSCertificate(t, root, true), newTestTLSCertificate(t, root, true)
	publishTestServer(t, dir, old)
	publishTestClientCA(t, dir, root)
	input := testServerTLSConfig(dir)
	input.Reload = false
	cfg, err := serverCredentials(input)
	require.NoError(t, err)
	require.Nil(t, cfg.GetConfigForClient)
	publishTestServer(t, dir, newCert)
	addr := startTestTLSServer(t, cfg)
	conn, err := connectTestTLS(t, addr, testClientTLSConfig(tls.VersionTLS13, newTestTLSCertificate(t, root, false), root))
	require.NoError(t, err)
	require.Equal(t, old.cert.SerialNumber, conn.ConnectionState().PeerCertificates[0].SerialNumber)
}
