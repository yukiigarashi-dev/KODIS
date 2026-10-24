//go:build unix

package approve

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pub, priv := keypair(t, 7)
	privPath := filepath.Join(dir, "approver.key")
	pubPath := filepath.Join(dir, "approver.pub")
	if err := WritePrivateKey(privPath, priv); err != nil {
		t.Fatal(err)
	}
	if err := WritePublicKey(pubPath, pub); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("private key written with %04o", perm)
	}
	gotPriv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPriv, priv) || !bytes.Equal(gotPub, pub) {
		t.Fatal("round trip mismatch")
	}
}

func TestWriteNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approver.key")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, priv := keypair(t, 8)
	if err := WritePrivateKey(path, priv); err == nil {
		t.Fatal("overwrote existing key")
	}
	if b, _ := os.ReadFile(path); string(b) != "existing" {
		t.Fatal("existing file modified")
	}
}

func TestLoadPrivateKeyRejects(t *testing.T) {
	dir := t.TempDir()
	pub, priv := keypair(t, 9)
	good := filepath.Join(dir, "good.key")
	if err := WritePrivateKey(good, priv); err != nil {
		t.Fatal(err)
	}
	goodPEM, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "pub.pem")
	if err := WritePublicKey(pubPath, pub); err != nil {
		t.Fatal(err)
	}
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}

	write := func(name string, data []byte, perm os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, perm); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, perm); err != nil { // WriteFile is subject to umask
			t.Fatal(err)
		}
		return p
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"group readable": write("g.key", goodPEM, 0o640),
		"world readable": write("w.key", goodPEM, 0o604),
		"symlink":        link,
		"directory":      dir,
		"missing":        filepath.Join(dir, "missing.key"),
		"not PEM":        write("n.key", []byte("hello"), 0o600),
		"public key PEM": write("p.key", pubPEM, 0o600),
		"trailing data":  write("t.key", append(append([]byte{}, goodPEM...), "junk"...), 0o600),
		"two PEM blocks": write("2.key", append(append([]byte{}, goodPEM...), goodPEM...), 0o600),
		"PEM headers":    write("h.key", []byte(strings.Replace(string(goodPEM), "-----\n", "-----\nProc-Type: 4,ENCRYPTED\n\n", 1)), 0o600),
		"oversized":      write("big.key", bytes.Repeat([]byte("A"), maxKeyFileSize+1), 0o600),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPrivateKey(path); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	if _, err := LoadPrivateKey(good); err != nil {
		t.Fatalf("good key rejected: %v", err)
	}
}

func TestLoadPrivateKeyRejectsFIFOWithoutBlocking(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo.key")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := LoadPrivateKey(p)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LoadPrivateKey blocked on a FIFO")
	}
}

func TestLoadPublicKeyRejectsPrivate(t *testing.T) {
	dir := t.TempDir()
	_, priv := keypair(t, 10)
	p := filepath.Join(dir, "k")
	if err := WritePrivateKey(p, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicKey(p); err == nil {
		t.Fatal("private key accepted as public key")
	}
}
