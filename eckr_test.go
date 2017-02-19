package eckr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
	"testing"
)

func TestEckrRandom(t *testing.T) {
	hash := make([]byte, 32)
	for i := 0; i < 1000; i++ {
		n, err := io.ReadFull(rand.Reader, hash)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if n != 32 {
			t.Fatal("error reading random data")
		}
		c := elliptic.P256()
		priv, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		pub := priv.PublicKey
		r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		///////////////////////////////////////

		keys, err := RecoverPublicKeys(c, hash[:], r, s)
		if err != nil {
			t.Fatalf("error: %v", err)
		}

		if keys[0].X.Cmp(pub.X) == 0 && keys[0].Y.Cmp(pub.Y) == 0 {
			continue
		}

		if keys[1].X.Cmp(pub.X) == 0 && keys[1].Y.Cmp(pub.Y) == 0 {
			continue
		}

		t.Fatalf("Could not derive keys: iteration:%d", i)
	}
}

func TestEckr(t *testing.T) {
	c := elliptic.P256()
	msg := "hello world"
	// public key
	x, _ := new(big.Int).SetString("b05e0deeee51b52956eff8034ffbc09a5331143114c1fb1c82705504f978370a", 16)
	y, _ := new(big.Int).SetString("2ee7efa2467fec9d0b8f7a860503919decb0bad76bc797bf482e95254e226fcc", 16)
	pubkey := &ecdsa.PublicKey{Curve: c, X: x, Y: y}
	// signature
	r, _ := new(big.Int).SetString("350b1572ff1b72831383c1d7c15c5aba106d62af007551d22bd313f25b1dfba8", 16)
	s, _ := new(big.Int).SetString("bf58baa28d760df87db5e069bd2dde2080d4dbd03cd76421bdcd1cc58c82ae69", 16)

	// validate signature
	sum := sha256.Sum256([]byte(msg))
	if !ecdsa.Verify(pubkey, sum[:], r, s) {
		t.Fatal("Bad test data: Could not validate ecdsa signature")
	}

	keys, err := RecoverPublicKeys(c, sum[:], r, s)

	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// With data above keys[0] matches
	if keys[0].X.Cmp(x) != 0 {
		t.Fatalf("Did not derive public key X %x != %x", keys[0].X, x)
	}
	if keys[0].Y.Cmp(y) != 0 {
		t.Fatalf("Did not derive public key Y %x != %x", keys[0].Y, y)
	}
}
