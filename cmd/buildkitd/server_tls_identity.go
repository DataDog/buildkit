package main

import (
	"crypto/x509"
	"net/url"
	"path"
	"strings"

	"github.com/pkg/errors"
)

func parseAllowedClientSPIFFEIDs(ids []string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !validClientSPIFFEID(id) {
			return nil, errors.Errorf("allowedClientSPIFFEIDs contains an invalid or noncanonical SPIFFE workload ID: %q", id)
		}
		allowed[id] = struct{}{}
	}
	return allowed, nil
}

func validClientSPIFFEID(id string) bool {
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" || len(u.Host) > 255 || u.Host != strings.ToLower(u.Host) ||
		u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawPath != "" || strings.Contains(id, "%") || u.String() != id {
		return false
	}
	for _, c := range u.Host {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
			return false
		}
	}
	if u.Path == "" || u.Path == "/" || path.Clean(u.Path) != u.Path {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, c := range segment {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
				return false
			}
		}
	}
	return true
}

func authorizeClientSPIFFE(certs []*x509.Certificate, allowed map[string]struct{}) error {
	// SPIFFE X509-SVIDs have exactly one URI SAN. Do not accept a CN, DNS SAN,
	// another certificate in the chain, a URI prefix, or an ambiguous identity.
	if len(certs) == 0 || len(certs[0].URIs) != 1 {
		return errors.New("client certificate must have exactly one SPIFFE URI SAN")
	}
	id := certs[0].URIs[0].String()
	if !validClientSPIFFEID(id) {
		return errors.New("client certificate has an invalid SPIFFE URI SAN")
	}
	if _, ok := allowed[id]; !ok {
		return errors.New("client SPIFFE identity is not allowed")
	}
	return nil
}
