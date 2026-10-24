package webpush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// recordSize is the RFC 8188 record size written in the header. The
	// whole message is a single record.
	recordSize = 4096
	saltSize   = 16
	authSize   = 16
	keySize    = 65 // uncompressed P-256 point
	headerSize = saltSize + 4 + 1 + keySize
	tagSize    = 16
	// MaxPayloadSize is the largest plaintext Encrypt accepts: the header,
	// padding delimiter and GCM tag must fit, with the payload, in 4096
	// octets, the body size every push service is required to accept.
	MaxPayloadSize = recordSize - headerSize - 1 - tagSize // 3993
)

// ErrPayloadTooLarge is returned for a plaintext over MaxPayloadSize, and
// (wrapped in a *StatusError) when a push service answers 413.
var ErrPayloadTooLarge = errors.New("webpush: payload too large")

// Encrypt encrypts plaintext for a subscription with the RFC 8291
// "aes128gcm" scheme. p256dh is the subscription's uncompressed P-256
// public key and auth its 16-byte authentication secret. A fresh ephemeral
// key and salt are generated for every call. The result is the complete
// request body: the RFC 8188 header followed by one record.
func Encrypt(p256dh, auth, plaintext []byte) ([]byte, error) {
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("webpush: generate ephemeral key: %w", err)
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("webpush: generate salt: %w", err)
	}
	return encryptWith(p256dh, auth, plaintext, as, salt)
}

// encryptWith is Encrypt with the ephemeral application-server key and the
// salt supplied, so the RFC 8291 Section 5 vector can be reproduced.
func encryptWith(p256dh, auth, plaintext []byte, as *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(plaintext) > MaxPayloadSize {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrPayloadTooLarge, len(plaintext), MaxPayloadSize)
	}
	if len(auth) != authSize {
		return nil, fmt.Errorf("webpush: auth secret is %d bytes, want %d", len(auth), authSize)
	}
	if len(salt) != saltSize {
		return nil, fmt.Errorf("webpush: salt is %d bytes, want %d", len(salt), saltSize)
	}
	ua, err := ecdh.P256().NewPublicKey(p256dh)
	if err != nil {
		return nil, fmt.Errorf("webpush: invalid p256dh key: %w", err)
	}
	secret, err := as.ECDH(ua)
	if err != nil {
		return nil, fmt.Errorf("webpush: ecdh: %w", err)
	}
	uaPub := ua.Bytes()
	asPub := as.PublicKey().Bytes()

	// RFC 8291 Section 3.4: IKM = HKDF(auth, ecdh_secret, key_info, 32).
	keyInfo := make([]byte, 0, len("WebPush: info\x00")+2*keySize)
	keyInfo = append(keyInfo, "WebPush: info\x00"...)
	keyInfo = append(keyInfo, uaPub...)
	keyInfo = append(keyInfo, asPub...)
	ikm, err := hkdf.Key(sha256.New, secret, auth, string(keyInfo), 32)
	if err != nil {
		return nil, fmt.Errorf("webpush: derive ikm: %w", err)
	}
	// RFC 8188 Section 2.2/2.3.
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, fmt.Errorf("webpush: derive prk: %w", err)
	}
	cek, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, fmt.Errorf("webpush: derive cek: %w", err)
	}
	nonce, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, fmt.Errorf("webpush: derive nonce: %w", err)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("webpush: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("webpush: gcm: %w", err)
	}

	out := make([]byte, headerSize, headerSize+len(plaintext)+1+tagSize)
	copy(out, salt)
	binary.BigEndian.PutUint32(out[saltSize:], recordSize)
	out[saltSize+4] = keySize
	copy(out[saltSize+5:], asPub)

	record := make([]byte, 0, len(plaintext)+1)
	record = append(record, plaintext...)
	record = append(record, 0x02) // last-record padding delimiter, no padding
	// The sequence number of the only record is 0, so the nonce is used
	// unchanged (RFC 8188 Section 2.3).
	return gcm.Seal(out, nonce, record, nil), nil
}
