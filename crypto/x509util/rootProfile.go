package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"

	"github.com/pkg/errors"
)

// DefaultRootCertValidity is the default validity of a root certificate in the step PKI.
var DefaultRootCertValidity = time.Hour * 24 * 365 * 10

// Root implements the Profile for a root certificate.
type Root struct {
	base
}

// DefaultDuration returns the default Root Certificate duration.
func (r *Root) DefaultDuration() time.Duration {
	return DefaultRootCertValidity
}

// NewRootProfile returns a new root x509 Certificate profile.
func NewRootProfile(name string, withOps ...WithOption) (Profile, error) {
	crt := defaultRootTemplate(name)
	return NewRootProfileWithTemplate(crt, withOps...)
}

// NewRootProfileWithTemplate returns a new root x509 Certificate profile.
func NewRootProfileWithTemplate(crt *x509.Certificate, withOps ...WithOption) (Profile, error) {
	p, err := newProfile(&Root{}, crt, crt, nil, withOps...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// self-signed certificate
	p.SetIssuerPrivateKey(p.SubjectPrivateKey())
	return p, nil
}

func defaultRootTemplate(cn string) *x509.Certificate {
	notBefore := time.Now()
	return &x509.Certificate{
		IsCA:                  true,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(DefaultRootCertValidity),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageTimeStamping,
		},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			[]int{1, 3, 6, 1, 4, 1, 311, 20, 2, 2},    // Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
			[]int{1, 3, 6, 1, 4, 1, 311, 10, 3, 12},   // Document Signing (1.3.6.1.4.1.311.10.3.12)
			[]int{1, 3, 6, 1, 4, 1, 311, 80, 1},       // Document Encryption (1.3.6.1.4.1.311.80.1)
		},
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		Issuer:                pkix.Name{CommonName: cn},
		Subject:               pkix.Name{CommonName: cn},
	}
}
