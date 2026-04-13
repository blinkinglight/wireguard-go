package device

import "github.com/cloudflare/circl/dh/x25519"

func x25519PublicKey(sk *NoisePrivateKey) (pk NoisePublicKey) {
	skKey := (*x25519.Key)(sk)
	pkKey := (*x25519.Key)(&pk)
	x25519.KeyGen(pkKey, skKey)
	return pk
}

func x25519SharedSecretInto(ss *[NoisePublicKeySize]byte, sk *NoisePrivateKey, pk NoisePublicKey) bool {
	skKey := (*x25519.Key)(sk)
	pkKey := (*x25519.Key)(&pk)
	ssKey := (*x25519.Key)(ss)
	return x25519.Shared(ssKey, skKey, pkKey)
}
