package main

import (
	"crypto/tls"
	"os"
	"sync"
)

type certificateFileState struct {
	certModUnixNano int64
	certSize        int64
	keyModUnixNano  int64
	keySize         int64
}

type dynamicCertificateLoader struct {
	mu          sync.RWMutex
	certFile    string
	keyFile     string
	cached      *tls.Certificate
	cachedState certificateFileState
}

func dynamicTLSConfig(certFile, keyFile string) *tls.Config {
	loader := &dynamicCertificateLoader{certFile: certFile, keyFile: keyFile}
	return &tls.Config{GetCertificate: loader.GetCertificate}
}

func (l *dynamicCertificateLoader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	state, err := currentCertificateFileState(l.certFile, l.keyFile)
	if err != nil {
		return l.cachedOrError(err)
	}
	l.mu.RLock()
	if l.cached != nil && state == l.cachedState {
		cached := l.cached
		l.mu.RUnlock()
		return cached, nil
	}
	l.mu.RUnlock()

	cert, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
	if err != nil {
		return l.cachedOrError(err)
	}
	l.mu.Lock()
	l.cached = &cert
	l.cachedState = state
	l.mu.Unlock()
	return &cert, nil
}

func (l *dynamicCertificateLoader) cachedOrError(err error) (*tls.Certificate, error) {
	l.mu.RLock()
	cached := l.cached
	l.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}
	return nil, err
}

func currentCertificateFileState(certFile, keyFile string) (certificateFileState, error) {
	certInfo, err := os.Stat(certFile)
	if err != nil {
		return certificateFileState{}, err
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		return certificateFileState{}, err
	}
	return certificateFileState{
		certModUnixNano: certInfo.ModTime().UnixNano(),
		certSize:        certInfo.Size(),
		keyModUnixNano:  keyInfo.ModTime().UnixNano(),
		keySize:         keyInfo.Size(),
	}, nil
}
