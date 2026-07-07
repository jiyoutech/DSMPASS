package main

import (
	"crypto/tls"
	"sync"
)

type dynamicCertificateLoader struct {
	mu       sync.RWMutex
	certFile string
	keyFile  string
	cached   *tls.Certificate
}

func dynamicTLSConfig(certFile, keyFile string) *tls.Config {
	loader := &dynamicCertificateLoader{certFile: certFile, keyFile: keyFile}
	return &tls.Config{GetCertificate: loader.GetCertificate}
}

func (l *dynamicCertificateLoader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
	if err != nil {
		l.mu.RLock()
		cached := l.cached
		l.mu.RUnlock()
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}
	l.mu.Lock()
	l.cached = &cert
	l.mu.Unlock()
	return &cert, nil
}
