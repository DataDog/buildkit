package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/moby/buildkit/cmd/buildkitd/config"
	"github.com/moby/buildkit/util/bklog"
	"github.com/pkg/errors"
)

type tlsFileDigests [3][sha256.Size]byte

type serverTLSCredentials struct {
	mu                     sync.Mutex
	config                 config.TLSConfig
	current                *tls.Config
	digests                tlsFileDigests
	lastError              string
	allowedClientSPIFFEIDs map[string]struct{}
}

func serverCredentials(cfg config.TLSConfig) (*tls.Config, error) {
	allowed, err := parseAllowedClientSPIFFEIDs(cfg.AllowedClientSPIFFEIDs)
	if err != nil {
		return nil, err
	}
	if len(allowed) != 0 && cfg.CA == "" {
		return nil, errors.New("allowedClientSPIFFEIDs requires a client CA and mutual TLS")
	}
	if cfg.Cert == "" && cfg.Key == "" && !cfg.Reload && len(allowed) == 0 {
		return nil, nil
	}
	if cfg.Cert == "" || cfg.Key == "" {
		return nil, errors.New("you must specify key and cert file if one is specified")
	}
	state := &serverTLSCredentials{config: cfg, allowedClientSPIFFEIDs: allowed}
	if err := state.load(); err != nil {
		return nil, err
	}
	if !cfg.Reload {
		return state.current, nil
	}
	// Keep the listener config stable, including its session ticket keys. Only
	// subsequent handshakes use a replacement; established streams are untouched.
	outer := state.current.Clone()
	outer.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if err := state.load(); err != nil {
			if message := err.Error(); message != state.lastError {
				bklog.L.WithError(err).Warn("could not reload server TLS credentials; retaining last valid configuration")
				state.lastError = message
			}
		} else {
			state.lastError = ""
		}
		return state.current, nil
	}
	return outer, nil
}

func (s *serverTLSCredentials) load() error {
	files, digests, err := readTLSFiles(s.config)
	if err != nil {
		return err
	}
	if s.current != nil && digests == s.digests {
		return nil
	}
	certificate, err := tls.X509KeyPair(files[0], files[1])
	if err != nil {
		return errors.Wrap(err, "could not load server key pair")
	}
	if s.config.Reload {
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return errors.Wrap(err, "could not parse server certificate")
		}
		if now := time.Now(); now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			return errors.New("server certificate is outside its validity period")
		}
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"}}
	if s.config.CA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(files[2]) {
			return errors.New("failed to append ca cert")
		}
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConf.ClientCAs = pool
	}
	if len(s.allowedClientSPIFFEIDs) != 0 {
		// Unlike VerifyPeerCertificate, this also runs for resumed connections.
		tlsConf.VerifyConnection = func(cs tls.ConnectionState) error {
			return authorizeClientSPIFFE(cs.PeerCertificates, s.allowedClientSPIFFEIDs)
		}
	}
	// Publish all material together, only after every configured file parsed.
	s.current, s.digests = tlsConf, digests
	return nil
}

func readTLSFiles(cfg config.TLSConfig) ([3][]byte, tlsFileDigests, error) {
	paths := [3]string{cfg.Cert, cfg.Key, cfg.CA}
	var resolved [3]string
	var files [3][]byte
	var digests tlsFileDigests
	for i, path := range paths {
		if path == "" {
			continue
		}
		var err error
		resolved[i], err = filepath.EvalSymlinks(path)
		if err != nil {
			return files, digests, errors.Wrapf(err, "could not resolve TLS file %s", path)
		}
		files[i], err = os.ReadFile(resolved[i])
		if err != nil {
			return files, digests, errors.Wrapf(err, "could not read TLS file %s", path)
		}
		digests[i] = sha256.Sum256(files[i])
	}
	for i, path := range paths {
		if path == "" {
			continue
		}
		current, err := filepath.EvalSymlinks(path)
		if err != nil || current != resolved[i] {
			return files, digests, errors.Errorf("TLS file changed while loading: %s", path)
		}
	}
	return files, digests, nil
}
