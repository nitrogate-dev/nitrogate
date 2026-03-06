package attest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type DSSEEnvelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type SignedAttestation struct {
	Envelope  DSSEEnvelope `json:"envelope"`
	PublicKey string       `json:"publicKey"`
	Timestamp string       `json:"timestamp"`
}

func Sign(statement *InTotoStatement, privateKeySeedB64 string) (*SignedAttestation, error) {
	seed, err := base64.StdEncoding.DecodeString(privateKeySeedB64)
	if err != nil {
		return nil, errors.New("invalid base64 signing key")
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("ed25519 seed must be 32 bytes")
	}

	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	payload, err := statement.ToJSON()
	if err != nil {
		return nil, err
	}

	payloadB64 := base64.StdEncoding.EncodeToString(payload)

	pae := paeEncode("application/vnd.in-toto+json", payload)
	sig := ed25519.Sign(privKey, pae)

	envelope := DSSEEnvelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     payloadB64,
		Signatures: []Signature{
			{
				KeyID: "",
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}

	return &SignedAttestation{
		Envelope:  envelope,
		PublicKey: base64.StdEncoding.EncodeToString(pubKey),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func Verify(signed *SignedAttestation) (bool, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(signed.PublicKey)
	if err != nil {
		return false, errors.New("invalid public key encoding")
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, errors.New("invalid public key size")
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	payload, err := base64.StdEncoding.DecodeString(signed.Envelope.Payload)
	if err != nil {
		return false, errors.New("invalid payload encoding")
	}

	if len(signed.Envelope.Signatures) == 0 {
		return false, errors.New("no signatures in envelope")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signed.Envelope.Signatures[0].Sig)
	if err != nil {
		return false, errors.New("invalid signature encoding")
	}

	pae := paeEncode(signed.Envelope.PayloadType, payload)
	return ed25519.Verify(pubKey, pae, sigBytes), nil
}

func ExtractStatement(signed *SignedAttestation) (*InTotoStatement, error) {
	payload, err := base64.StdEncoding.DecodeString(signed.Envelope.Payload)
	if err != nil {
		return nil, err
	}

	var stmt InTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, err
	}
	return &stmt, nil
}

// PAE (Pre-Authentication Encoding) per DSSE spec
func paeEncode(payloadType string, payload []byte) []byte {
	// DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>
	result := []byte("DSSEv1 ")
	result = append(result, intToBytes(len(payloadType))...)
	result = append(result, ' ')
	result = append(result, []byte(payloadType)...)
	result = append(result, ' ')
	result = append(result, intToBytes(len(payload))...)
	result = append(result, ' ')
	result = append(result, payload...)
	return result
}

func intToBytes(n int) []byte {
	s := []byte{}
	for n > 0 {
		s = append([]byte{byte('0' + n%10)}, s...)
		n /= 10
	}
	if len(s) == 0 {
		return []byte("0")
	}
	return s
}
