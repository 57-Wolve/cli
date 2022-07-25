package x509util

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
)

// DefaultIntermediateCertValidity is the default validity of a intermediate certificate in the step PKI.
var DefaultIntermediateCertValidity = time.Hour * 24 * 365 * 10

// Intermediate implements the Profile for a intermediate certificate.
type Intermediate struct {
	base
}

// DefaultDuration returns the default Intermediate Certificate duration.
func (i *Intermediate) DefaultDuration() time.Duration {
	return DefaultIntermediateCertValidity
}

// NewIntermediateProfile returns a new intermediate x509 Certificate profile.
func NewIntermediateProfile(name string, iss *x509.Certificate, issPriv crypto.PrivateKey, withOps ...WithOption) (Profile, error) {
	sub := defaultIntermediateTemplate(name)
	return newProfile(&Intermediate{}, sub, iss, issPriv, withOps...)
}

func defaultIntermediateTemplate(name string) *x509.Certificate {
	notBefore := time.Now()
	return &x509.Certificate{
		IsCA:                  true,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(DefaultIntermediateCertValidity),
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
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		Issuer:                pkix.Name{CommonName: name},
		Subject:               pkix.Name{CommonName: name},
	}
}
