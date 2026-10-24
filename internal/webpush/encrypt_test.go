package webpush

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// RFC 8291 Section 5 / Appendix A example values
// (https://www.rfc-editor.org/rfc/rfc8291#section-5).
const (
	rfcPlaintext  = "When I grow up, I want to be a watermelon"
	rfcAuthSecret = "BTBZMqHH6r4Tts7J_aSIgg"
	rfcUAPrivate  = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
	rfcUAPublic   = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx" +
		"aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	rfcASPrivate = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	rfcASPublic  = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg" +
		"Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	rfcSalt = "DGv6ra1nlYgDCS1FRnbzlw"
	rfcBody = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml" +
		"mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT" +
		"pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
)

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func TestEncryptRFC8291Vector(t *testing.T) {
	as, err := ecdh.P256().NewPrivateKey(b64(t, rfcASPrivate))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(as.PublicKey().Bytes(), b64(t, rfcASPublic)) {
		t.Fatal("AS public key does not match the RFC")
	}
	got, err := encryptWith(b64(t, rfcUAPublic), b64(t, rfcAuthSecret), []byte(rfcPlaintext), as, b64(t, rfcSalt))
	if err != nil {
		t.Fatalf("encryptWith: %v", err)
	}
	if want := b64(t, rfcBody); !bytes.Equal(got, want) {
		t.Fatalf("body mismatch\n got %s\nwant %s", base64.RawURLEncoding.EncodeToString(got), rfcBody)
	}
}

func TestDecryptHelperAcceptsRFCVector(t *testing.T) {
	ua, err := ecdh.P256().NewPrivateKey(b64(t, rfcUAPrivate))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := decryptForTest(ua, b64(t, rfcAuthSecret), b64(t, rfcBody))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != rfcPlaintext {
		t.Fatalf("plaintext = %q", pt)
	}
}

func newUAKeys(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	ua, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	if _, err := rand.Read(auth); err != nil {
		t.Fatal(err)
	}
	return ua, auth
}

func TestEncryptRoundTrip(t *testing.T) {
	ua, auth := newUAKeys(t)
	for _, n := range []int{0, 1, 41, 1000, MaxPayloadSize} {
		pt := make([]byte, n)
		if _, err := rand.Read(pt); err != nil {
			t.Fatal(err)
		}
		body, err := Encrypt(ua.PublicKey().Bytes(), auth, pt)
		if err != nil {
			t.Fatalf("n=%d: Encrypt: %v", n, err)
		}
		if len(body) > recordSize {
			t.Fatalf("n=%d: body is %d bytes, more than %d", n, len(body), recordSize)
		}
		got, err := decryptForTest(ua, auth, body)
		if err != nil {
			t.Fatalf("n=%d: decrypt: %v", n, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}
}

func TestEncryptFreshKeyAndSaltEachCall(t *testing.T) {
	ua, auth := newUAKeys(t)
	a, err := Encrypt(ua.PublicKey().Bytes(), auth, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(ua.PublicKey().Bytes(), auth, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[:16], b[:16]) || bytes.Equal(a[21:86], b[21:86]) {
		t.Fatal("salt or ephemeral key reused across calls")
	}
}

func TestEncryptPayloadTooLarge(t *testing.T) {
	ua, auth := newUAKeys(t)
	_, err := Encrypt(ua.PublicKey().Bytes(), auth, make([]byte, MaxPayloadSize+1))
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
	}
}

func TestEncryptRejectsBadKeys(t *testing.T) {
	ua, auth := newUAKeys(t)
	if _, err := Encrypt([]byte{4, 1, 2}, auth, []byte("x")); err == nil {
		t.Error("bad p256dh accepted")
	}
	if _, err := Encrypt(ua.PublicKey().Bytes(), auth[:15], []byte("x")); err == nil {
		t.Error("15-byte auth accepted")
	}
}

// decryptForTest decrypts an aes128gcm body the way a user agent does
// (RFC 8291 Section 3.4, RFC 8188 Section 2).
func decryptForTest(ua *ecdh.PrivateKey, auth, body []byte) ([]byte, error) {
	if len(body) < 21 {
		return nil, errors.New("short header")
	}
	salt := body[:16]
	rs := binary.BigEndian.Uint32(body[16:20])
	idlen := int(body[20])
	if len(body) < 21+idlen {
		return nil, errors.New("short keyid")
	}
	asPub := body[21 : 21+idlen]
	ct := body[21+idlen:]
	if uint32(len(ct)) > rs {
		return nil, errors.New("multiple records not supported")
	}
	as, err := ecdh.P256().NewPublicKey(asPub)
	if err != nil {
		return nil, err
	}
	secret, err := ua.ECDH(as)
	if err != nil {
		return nil, err
	}
	info := append([]byte("WebPush: info\x00"), ua.PublicKey().Bytes()...)
	info = append(info, asPub...)
	ikm, err := hkdf.Key(sha256.New, secret, auth, string(info), 32)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimRight(string(pt), "\x00")
	if !strings.HasSuffix(trimmed, "\x02") {
		return nil, errors.New("missing last-record delimiter")
	}
	return []byte(trimmed[:len(trimmed)-1]), nil
}
