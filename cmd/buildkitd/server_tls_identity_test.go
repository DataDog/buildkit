package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/moby/buildkit/cmd/buildkitd/config"
	"github.com/stretchr/testify/require"
)

const testAllowedSPIFFE = "spiffe://example.org/kubernetes/gitlab-runner/project"

func testClientIdentity(t *testing.T, root *testTLSCertificate, identities ...string) *testTLSCertificate {
	t.Helper()
	cert := newTestTLSCertificate(t, root, false)
	cert.cert.Subject.CommonName = testAllowedSPIFFE
	for _, identity := range identities {
		uri, err := url.Parse(identity)
		require.NoError(t, err)
		cert.cert.URIs = append(cert.cert.URIs, uri)
	}
	der, err := x509.CreateCertificate(rand.Reader, cert.cert, root.cert, cert.key.Public(), root.key)
	require.NoError(t, err)
	cert.cert, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	cert.pem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert.pair, err = tls.X509KeyPair(cert.pem, cert.keyPEM)
	require.NoError(t, err)
	return cert
}

func TestServerCredentialsSPIFFE(t *testing.T) {
	for name, version := range map[string]uint16{"TLS12": tls.VersionTLS12, "TLS13": tls.VersionTLS13} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			root := newTestTLSCertificate(t, nil, false)
			publishTestServer(t, dir, newTestTLSCertificate(t, root, true))
			publishTestClientCA(t, dir, root)
			input := testServerTLSConfig(dir)
			input.AllowedClientSPIFFEIDs = []string{testAllowedSPIFFE}
			cfg, err := serverCredentials(input)
			require.NoError(t, err)
			addr := startTestTLSServer(t, cfg)
			client := testClientTLSConfig(version, testClientIdentity(t, root, testAllowedSPIFFE), root)
			_, err = connectTestTLS(t, addr, client)
			require.NoError(t, err)
			resumed, err := connectTestTLS(t, addr, client)
			require.NoError(t, err)
			require.True(t, resumed.ConnectionState().DidResume)
			for name, ids := range map[string][]string{
				"wrong namespace":             {"spiffe://example.org/kubernetes/unrelated/project"},
				"wrong service account":       {"spiffe://example.org/kubernetes/gitlab-runner/unrelated"},
				"wrong trust domain":          {"spiffe://other.org/kubernetes/gitlab-runner/project"},
				"URI suffix":                  {testAllowedSPIFFE + "-other"},
				"URI prefix":                  {testAllowedSPIFFE + "/child"},
				"path case":                   {"spiffe://example.org/kubernetes/gitlab-runner/Project"},
				"missing URI with allowed CN": {},
				"multiple URI SANs":           {testAllowedSPIFFE, "spiffe://example.org/other"},
				"non SPIFFE scheme":           {"https://example.org/kubernetes/gitlab-runner/project"},
				"encoded path":                {"spiffe://example.org/kubernetes/gitlab-runner/%70roject"},
			} {
				t.Run(name, func(t *testing.T) {
					_, err := connectTestTLS(t, addr, testClientTLSConfig(version, testClientIdentity(t, root, ids...), root))
					require.Error(t, err)
				})
			}
			_, err = connectTestTLS(t, addr, testClientTLSConfig(version, nil, root))
			require.Error(t, err)
			untrusted := newTestTLSCertificate(t, nil, false)
			_, err = connectTestTLS(t, addr, testClientTLSConfig(version, testClientIdentity(t, untrusted, testAllowedSPIFFE), root))
			require.Error(t, err, "an allowed URI must not bypass chain verification")
		})
	}
}

func TestServerCredentialsSPIFFEResumedDenial(t *testing.T) {
	for name, version := range map[string]uint16{"TLS12": tls.VersionTLS12, "TLS13": tls.VersionTLS13} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			root := newTestTLSCertificate(t, nil, false)
			publishTestServer(t, dir, newTestTLSCertificate(t, root, true))
			publishTestClientCA(t, dir, root)
			input := testServerTLSConfig(dir)
			permissive, err := serverCredentials(input)
			require.NoError(t, err)
			input.AllowedClientSPIFFEIDs = []string{testAllowedSPIFFE}
			strict, err := serverCredentials(input)
			require.NoError(t, err)
			var resumedCheck atomic.Bool
			verify := strict.VerifyConnection
			strict.VerifyConnection = func(cs tls.ConnectionState) error { resumedCheck.Store(cs.DidResume); return verify(cs) }
			// Keep one listener/ticket-key scope while applying a stricter policy.
			var selected atomic.Pointer[tls.Config]
			selected.Store(permissive)
			outer := &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return selected.Load(), nil }}
			addr := startTestTLSServer(t, outer)
			wrong := testClientTLSConfig(version, testClientIdentity(t, root, "spiffe://example.org/kubernetes/unrelated/project"), root)
			first, err := connectTestTLS(t, addr, wrong)
			require.NoError(t, err)
			require.NoError(t, first.Close())
			selected.Store(strict)
			_, err = connectTestTLS(t, addr, wrong)
			require.Error(t, err)
			require.True(t, resumedCheck.Load(), "identity authorization must reject a real resumed session")
		})
	}
}

func TestServerCredentialsSPIFFEConfig(t *testing.T) {
	for _, id := range []string{"", "spiffe://example.org", "spiffe://example.org/", "spiffe://Example.org/workload", "https://example.org/workload", "spiffe://example.org:443/workload", "spiffe://user@example.org/workload", "spiffe://example.org/workload?x=1", "spiffe://example.org/workload#x", "spiffe://example.org/a/../b", "spiffe://example.org/a//b", "spiffe://example.org/a/", "spiffe://example.org/%77orkload", "spiffe://example.org/workload*"} {
		t.Run(id, func(t *testing.T) { _, err := parseAllowedClientSPIFFEIDs([]string{id}); require.Error(t, err) })
	}
	_, err := serverCredentials(config.TLSConfig{AllowedClientSPIFFEIDs: []string{testAllowedSPIFFE}})
	require.ErrorContains(t, err, "requires a client CA")
}
