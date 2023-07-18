package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
)

func CreateKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

func CreateNonce() string {
	return strconv.Itoa(int(time.Now().Unix()))
}

func Hash(payload []byte, nonce, channel, chaincode, method, deadline string, pubkey []byte) [32]byte {
	bb := append(removeSpacesBetweenCommaAndQuotes(payload), nonce...) // resolve the unclear json serialization behavior in protojson package
	fmt.Printf("\npaylod - %s\n", bb)
	bb = append(bb, channel...)
	bb = append(bb, chaincode...)
	bb = append(bb, method...)
	bb = append(bb, deadline...)
	b58Pubkey := base58.Encode(pubkey)
	fmt.Printf("\nb58Pubkey - %s\n", b58Pubkey)
	bb = append(bb, b58Pubkey...)
	fmt.Printf("\nbb - %s\n", bb)
	return sha256.Sum256(bb)
}

func CreateSig(payload []byte, nonce, channel, chaincode, method, deadline string, privateKey []byte) ([]byte, []byte) {
	pubKey := ed25519.PrivateKey(privateKey).Public()
	hashed := Hash(payload, nonce, channel, chaincode, method, deadline, []byte(pubKey.(ed25519.PublicKey)))
	sig := ed25519.Sign(ed25519.PrivateKey(privateKey), hashed[:])
	return []byte(pubKey.(ed25519.PublicKey)), sig
}

func CheckSig(payload []byte, nonce, channel, chaincode, method, deadline string, pubKey []byte, sig []byte) error {
	hashed := Hash(payload, nonce, channel, chaincode, method, deadline, pubKey)
	fmt.Printf("\nhash_to_sign - %s\n", base58.Encode(hashed[:]))
	if !ed25519.Verify(ed25519.PublicKey(pubKey), hashed[:], sig) {
		return ErrCheckSignatureFailed
	}
	return nil
}

func removeSpacesBetweenCommaAndQuotes(s []byte) []byte {
	removed := strings.ReplaceAll(string(s), `", "`, `","`)
	removed = strings.ReplaceAll(removed, `"}, {"`, `"},{"`)
	return []byte(strings.ReplaceAll(removed, `], "`, `],"`))
}
