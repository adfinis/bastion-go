// Copyright (c) Adfinis
// SPDX-License-Identifier: MPL-2.0

package bastion

import (
	"errors"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SSHAuthMethod defines a function that returns an SSH authentication method.
type SSHAuthMethod func() (ssh.AuthMethod, error)

// WithSSHAgentAuth returns an SSH agent authentication method.
func WithSSHAgentAuth() SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return getSSHAgentAuth()
	}
}

func getSSHAgentAuth() (ssh.AuthMethod, error) {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers), nil
}

// WithPrivateKeyAuth returns a private key authentication method.
func WithPrivateKeyAuth(privateKey string) SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return getPrivateKeyAuth(privateKey)
	}
}

func getPrivateKeyAuth(privateKey string) (ssh.AuthMethod, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(signer), nil
}

// WithPrivateKeyAuthWithPassphrase returns a private key authentication method with passphrase support.
func WithPrivateKeyAuthWithPassphrase(privateKey string, passphrase string) SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return getPrivateKeyAuthWithPassphrase(privateKey, passphrase)
	}
}

func getPrivateKeyAuthWithPassphrase(privateKey string, passphrase string) (ssh.AuthMethod, error) {
	var signer ssh.Signer
	var err error

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(privateKey))
	}

	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(signer), nil
}

// WithPrivateKeyFileAuth returns a private key file authentication method.
func WithPrivateKeyFileAuth(keyPath string) SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return getPrivateKeyFileAuth(keyPath)
	}
}

func getPrivateKeyFileAuth(keyPath string) (ssh.AuthMethod, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return getPrivateKeyAuth(string(key))
}

// WithPrivateKeyFileAuthWithPassphrase returns a private key file authentication method with passphrase support.
func WithPrivateKeyFileAuthWithPassphrase(keyPath string, passphrase string) SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return getPrivateKeyFileAuthWithPassphrase(keyPath, passphrase)
	}
}

func getPrivateKeyFileAuthWithPassphrase(keyPath string, passphrase string) (ssh.AuthMethod, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return getPrivateKeyAuthWithPassphrase(string(key), passphrase)
}

// WithPrivateKeyAuthWithSignedCert returns a private key authentication method with a signed certificate.
func WithPrivateKeyAuthWithSignedCert(privateKey string, cert string) SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return getPrivateKeyAuthWithSignedCert(privateKey, cert)
	}
}

func getPrivateKeyAuthWithSignedCert(privateKey string, cert string) (ssh.AuthMethod, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}
	return getSignedCertAuth(signer, cert)
}

// WithPrivateKeyAuthWithSignedCertFile returns a private key authentication method with a signed certificate read from a file.
func WithPrivateKeyAuthWithSignedCertFile(privateKey string, certPath string) SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return getPrivateKeyAuthWithSignedCertFile(privateKey, certPath)
	}
}

func getPrivateKeyAuthWithSignedCertFile(privateKey string, certPath string) (ssh.AuthMethod, error) {
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	return getPrivateKeyAuthWithSignedCert(privateKey, string(cert))
}

// WithPrivateKeyAuthWithPassphraseWithSignedCert returns a private key authentication method with passphrase support and a signed certificate.
func WithPrivateKeyAuthWithPassphraseWithSignedCert(privateKey string, passphrase string, cert string) SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return getPrivateKeyAuthWithPassphraseWithSignedCert(privateKey, passphrase, cert)
	}
}

func getPrivateKeyAuthWithPassphraseWithSignedCert(privateKey string, passphrase string, cert string) (ssh.AuthMethod, error) {
	var signer ssh.Signer
	var err error

	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(privateKey))
	}
	if err != nil {
		return nil, err
	}
	return getSignedCertAuth(signer, cert)
}

// WithPrivateKeyAuthWithPassphraseWithSignedCertFile returns a private key authentication method with passphrase support and a signed certificate read from a file.
func WithPrivateKeyAuthWithPassphraseWithSignedCertFile(privateKey string, passphrase string, certPath string) SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return getPrivateKeyAuthWithPassphraseWithSignedCertFile(privateKey, passphrase, certPath)
	}
}

func getPrivateKeyAuthWithPassphraseWithSignedCertFile(privateKey string, passphrase string, certPath string) (ssh.AuthMethod, error) {
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	return getPrivateKeyAuthWithPassphraseWithSignedCert(privateKey, passphrase, string(cert))
}

// WithPrivateKeyFileAuthWithPassphraseWithSignedCert returns a private key file authentication method with passphrase support and a signed certificate.
func WithPrivateKeyFileAuthWithPassphraseWithSignedCert(keyPath string, passphrase string, cert string) SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return getPrivateKeyFileAuthWithPassphraseWithSignedCert(keyPath, passphrase, cert)
	}
}

func getPrivateKeyFileAuthWithPassphraseWithSignedCert(keyPath string, passphrase string, cert string) (ssh.AuthMethod, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return getPrivateKeyAuthWithPassphraseWithSignedCert(string(key), passphrase, cert)
}

// WithPrivateKeyFileAuthWithPassphraseWithSignedCertFile returns a private key file authentication method with passphrase support and a signed certificate read from a file.
func WithPrivateKeyFileAuthWithPassphraseWithSignedCertFile(keyPath string, passphrase string, certPath string) SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return getPrivateKeyFileAuthWithPassphraseWithSignedCertFile(keyPath, passphrase, certPath)
	}
}

func getPrivateKeyFileAuthWithPassphraseWithSignedCertFile(keyPath string, passphrase string, certPath string) (ssh.AuthMethod, error) {
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	return getPrivateKeyFileAuthWithPassphraseWithSignedCert(keyPath, passphrase, string(cert))
}

func getSignedCertAuth(signer ssh.Signer, cert string) (ssh.AuthMethod, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert))
	if err != nil {
		return nil, err
	}
	certificate, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not a valid SSH certificate")
	}
	certSigner, err := ssh.NewCertSigner(certificate, signer)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(certSigner), nil
}

// KeyboardInteractiveChallenge is a callback for answering SSH keyboard-interactive challenges.
// It receives the challenge name, instruction, questions, and echo flags, and returns answers.
type KeyboardInteractiveChallenge func(name, instruction string, questions []string, echos []bool) ([]string, error)

// WithKeyboardInteractiveAuth returns a keyboard-interactive authentication method using the provided challenge callback.
func WithKeyboardInteractiveAuth(challenge KeyboardInteractiveChallenge) SSHAuthMethod {
	return func() (ssh.AuthMethod, error) {
		return ssh.KeyboardInteractive(ssh.KeyboardInteractiveChallenge(challenge)), nil
	}
}
