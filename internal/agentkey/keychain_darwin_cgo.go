//go:build darwin && cgo

// macOS Secure Enclave cgo bridge for ECDSA P-256 agent keys.
//
// This file implements the KeychainBackend interface against Apple's
// Security.framework. Keys are generated inside the SE and their raw
// private bytes never leave the hardware — the only operation exposed
// is signing.
//
// Attribute set (matches the design doc):
//   kSecAttrKeyType             kSecAttrKeyTypeECSECPrimeRandom (P-256)
//   kSecAttrKeySizeInBits       256
//   kSecAttrTokenID             kSecAttrTokenIDSecureEnclave
//   kSecAttrIsPermanent         true
//   kSecAttrApplicationTag      "dop.agent." + lookupID
//   kSecAttrAccessControl       privateKeyUsage (no biometric — Mode 1)
//   kSecAttrAccessible          WhenUnlockedThisDeviceOnly
//
// Signing uses kSecKeyAlgorithmECDSASignatureMessageX962SHA256, which
// returns X9.62/DER-encoded signature bytes (variable length ~70-72).
//
// LIMITATIONS (v1.11 initial):
//   - Available() returns true only if the SE is actually reachable
//     (no daemon session check yet — that comes when the daemon takes
//     ownership of signing operations)
//   - No List() in the Backend interface yet — collectAgentKeys()
//     walks the file backend directory only; SE-only entries won't
//     show up in `dop agent list` until we add a SE list op
//   - Error strings from CoreFoundation OSStatus codes are terse

package agentkey

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

// Small helpers so the Go side doesn't have to fight CoreFoundation
// object references directly.

// dop_se_generate creates an SE-backed P-256 key labeled with the
// given application tag. Returns the DER-encoded public key on
// success; the private key stays inside the SE forever.
//
// Signature bytes are returned via *out_pub / *out_pub_len (caller
// must free out_pub with free()).
//
// Returns 0 on success, non-zero OSStatus on failure.
OSStatus dop_se_generate(
    const char *tag_utf8,
    size_t tag_len,
    unsigned char **out_pub,
    size_t *out_pub_len
) {
    CFDataRef tagData = CFDataCreate(NULL, (const UInt8 *)tag_utf8, (CFIndex)tag_len);
    if (!tagData) return errSecAllocate;

    CFErrorRef acError = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
        &acError
    );
    if (!access) {
        CFRelease(tagData);
        if (acError) CFRelease(acError);
        return errSecAuthFailed;
    }

    CFMutableDictionaryRef privKeyAttrs = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFDictionarySetValue(privKeyAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(privKeyAttrs, kSecAttrApplicationTag, tagData);
    CFDictionarySetValue(privKeyAttrs, kSecAttrAccessControl, access);

    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    int bits = 256;
    CFNumberRef bitsRef = CFNumberCreate(NULL, kCFNumberIntType, &bits);
    CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, bitsRef);
    CFDictionarySetValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, privKeyAttrs);

    CFErrorRef genError = NULL;
    SecKeyRef privKey = SecKeyCreateRandomKey(attrs, &genError);
    OSStatus status = errSecSuccess;
    if (!privKey) {
        status = genError ? (OSStatus)CFErrorGetCode(genError) : errSecKeyIsSensitive;
        if (genError) CFRelease(genError);
        goto cleanup;
    }

    SecKeyRef pubKey = SecKeyCopyPublicKey(privKey);
    if (!pubKey) {
        status = errSecParam;
        CFRelease(privKey);
        goto cleanup;
    }

    CFErrorRef expErr = NULL;
    CFDataRef pubData = SecKeyCopyExternalRepresentation(pubKey, &expErr);
    CFRelease(pubKey);
    CFRelease(privKey);
    if (!pubData) {
        status = expErr ? (OSStatus)CFErrorGetCode(expErr) : errSecParam;
        if (expErr) CFRelease(expErr);
        goto cleanup;
    }
    CFIndex plen = CFDataGetLength(pubData);
    unsigned char *buf = (unsigned char *)malloc((size_t)plen);
    if (buf) {
        memcpy(buf, CFDataGetBytePtr(pubData), (size_t)plen);
        *out_pub = buf;
        *out_pub_len = (size_t)plen;
    } else {
        status = errSecAllocate;
    }
    CFRelease(pubData);

cleanup:
    CFRelease(bitsRef);
    CFRelease(attrs);
    CFRelease(privKeyAttrs);
    CFRelease(access);
    CFRelease(tagData);
    return status;
}

// dop_se_public loads the public key for the tag. Returns 0 + fills
// out_pub/out_pub_len on success. errSecItemNotFound if the tag
// doesn't exist.
OSStatus dop_se_public(
    const char *tag_utf8,
    size_t tag_len,
    unsigned char **out_pub,
    size_t *out_pub_len
) {
    CFDataRef tagData = CFDataCreate(NULL, (const UInt8 *)tag_utf8, (CFIndex)tag_len);
    if (!tagData) return errSecAllocate;

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrApplicationTag, tagData);
    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

    SecKeyRef privKey = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&privKey);
    CFRelease(query);
    CFRelease(tagData);
    if (status != errSecSuccess || !privKey) {
        return status;
    }

    SecKeyRef pubKey = SecKeyCopyPublicKey(privKey);
    CFRelease(privKey);
    if (!pubKey) return errSecParam;

    CFErrorRef expErr = NULL;
    CFDataRef pubData = SecKeyCopyExternalRepresentation(pubKey, &expErr);
    CFRelease(pubKey);
    if (!pubData) {
        if (expErr) CFRelease(expErr);
        return errSecParam;
    }
    CFIndex plen = CFDataGetLength(pubData);
    unsigned char *buf = (unsigned char *)malloc((size_t)plen);
    if (!buf) {
        CFRelease(pubData);
        return errSecAllocate;
    }
    memcpy(buf, CFDataGetBytePtr(pubData), (size_t)plen);
    CFRelease(pubData);
    *out_pub = buf;
    *out_pub_len = (size_t)plen;
    return errSecSuccess;
}

// dop_se_sign signs message_len bytes at message with the SE key
// identified by tag. Uses ECDSA-P256/SHA-256 with X9.62/DER encoding.
// Returns 0 on success + fills out_sig/out_sig_len.
OSStatus dop_se_sign(
    const char *tag_utf8,
    size_t tag_len,
    const unsigned char *message,
    size_t message_len,
    unsigned char **out_sig,
    size_t *out_sig_len
) {
    CFDataRef tagData = CFDataCreate(NULL, (const UInt8 *)tag_utf8, (CFIndex)tag_len);
    if (!tagData) return errSecAllocate;

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrApplicationTag, tagData);
    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

    SecKeyRef privKey = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&privKey);
    CFRelease(query);
    CFRelease(tagData);
    if (status != errSecSuccess || !privKey) return status;

    CFDataRef msgData = CFDataCreate(NULL, (const UInt8 *)message, (CFIndex)message_len);
    if (!msgData) {
        CFRelease(privKey);
        return errSecAllocate;
    }

    CFErrorRef sigErr = NULL;
    CFDataRef sigData = SecKeyCreateSignature(
        privKey,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        msgData,
        &sigErr
    );
    CFRelease(msgData);
    CFRelease(privKey);
    if (!sigData) {
        status = sigErr ? (OSStatus)CFErrorGetCode(sigErr) : errSecParam;
        if (sigErr) CFRelease(sigErr);
        return status;
    }
    CFIndex slen = CFDataGetLength(sigData);
    unsigned char *buf = (unsigned char *)malloc((size_t)slen);
    if (!buf) {
        CFRelease(sigData);
        return errSecAllocate;
    }
    memcpy(buf, CFDataGetBytePtr(sigData), (size_t)slen);
    CFRelease(sigData);
    *out_sig = buf;
    *out_sig_len = (size_t)slen;
    return errSecSuccess;
}

// dop_se_ecdh computes ECDH between the SE-stored private key
// identified by tag and the peer public key (uncompressed X9.62
// P-256, 65 bytes starting with 0x04). Returns the raw shared X
// coordinate (32 bytes) via *out_secret / *out_secret_len — caller
// must free with free(). Returns 0 on success, non-zero OSStatus on
// failure.
//
// Algorithm used: kSecKeyAlgorithmECDHKeyExchangeStandard — gives us
// the raw shared secret without any KDF applied. We run HKDF over it
// on the Go side (envseal.OpenWithShared) so both sides use the same
// key derivation regardless of whether the shared secret came from
// SE or from crypto/ecdh.
OSStatus dop_se_ecdh(
    const char *tag_utf8, size_t tag_len,
    const unsigned char *peer_pub, size_t peer_pub_len,
    unsigned char **out_secret, size_t *out_secret_len
) {
    CFDataRef tagData = CFDataCreate(NULL, (const UInt8 *)tag_utf8, (CFIndex)tag_len);
    if (!tagData) return errSecAllocate;

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrApplicationTag, tagData);
    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

    SecKeyRef privKey = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&privKey);
    CFRelease(query);
    CFRelease(tagData);
    if (status != errSecSuccess || !privKey) return status;

    // Rebuild the peer public key from raw X9.62 bytes.
    CFDataRef peerPubData = CFDataCreate(NULL, (const UInt8 *)peer_pub, (CFIndex)peer_pub_len);
    if (!peerPubData) { CFRelease(privKey); return errSecAllocate; }

    CFMutableDictionaryRef pubAttrs = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFDictionarySetValue(pubAttrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(pubAttrs, kSecAttrKeyClass, kSecAttrKeyClassPublic);
    int keySize = 256;
    CFNumberRef bits = CFNumberCreate(NULL, kCFNumberIntType, &keySize);
    CFDictionarySetValue(pubAttrs, kSecAttrKeySizeInBits, bits);
    CFRelease(bits);

    CFErrorRef pubErr = NULL;
    SecKeyRef peerPubKey = SecKeyCreateWithData(peerPubData, pubAttrs, &pubErr);
    CFRelease(pubAttrs);
    CFRelease(peerPubData);
    if (!peerPubKey) {
        status = pubErr ? (OSStatus)CFErrorGetCode(pubErr) : errSecParam;
        if (pubErr) CFRelease(pubErr);
        CFRelease(privKey);
        return status;
    }

    // The ECDH exchange itself. Empty params dict — we want the raw
    // shared X coordinate, no wrap around anything.
    CFDictionaryRef params = CFDictionaryCreate(
        NULL, NULL, NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFErrorRef ecdhErr = NULL;
    CFDataRef sharedData = SecKeyCopyKeyExchangeResult(
        privKey,
        kSecKeyAlgorithmECDHKeyExchangeStandard,
        peerPubKey,
        params,
        &ecdhErr
    );
    CFRelease(params);
    CFRelease(peerPubKey);
    CFRelease(privKey);
    if (!sharedData) {
        status = ecdhErr ? (OSStatus)CFErrorGetCode(ecdhErr) : errSecParam;
        if (ecdhErr) CFRelease(ecdhErr);
        return status;
    }

    CFIndex slen = CFDataGetLength(sharedData);
    unsigned char *buf = (unsigned char *)malloc((size_t)slen);
    if (!buf) { CFRelease(sharedData); return errSecAllocate; }
    memcpy(buf, CFDataGetBytePtr(sharedData), (size_t)slen);
    CFRelease(sharedData);
    *out_secret = buf;
    *out_secret_len = (size_t)slen;
    return errSecSuccess;
}

// dop_se_delete removes the SE key with the given tag. Returns 0 on
// success or if the key was already absent.
OSStatus dop_se_delete(const char *tag_utf8, size_t tag_len) {
    CFDataRef tagData = CFDataCreate(NULL, (const UInt8 *)tag_utf8, (CFIndex)tag_len);
    if (!tagData) return errSecAllocate;

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrApplicationTag, tagData);
    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);

    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    CFRelease(tagData);
    if (status == errSecItemNotFound) return errSecSuccess;
    return status;
}
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/fray/dop/internal/vault"
)

// seStore is the real Secure-Enclave-backed store. The private key
// material lives in the SE — this struct only holds the application
// tag (identifier) and a cached public key.
type seStore struct {
	lookupID string
	tag      string
	pubkey   []byte
}

func (s *seStore) LookupID() string     { return s.lookupID }
func (s *seStore) KeyType() string      { return vault.KeyTypeP256 }
func (s *seStore) PublicKey() []byte    { return append([]byte(nil), s.pubkey...) }
func (s *seStore) Extractable() bool    { return false }
func (s *seStore) StorageDescription() string {
	return "macOS Secure Enclave (p256, tag=" + s.tag + ", non-extractable)"
}

// SharedSecret runs ECDH between the SE-backed key and peerPub via
// SecKeyCopyKeyExchangeResult (v1.12). Returns the raw 32-byte X
// coordinate; caller (envseal) applies HKDF to derive the AEAD key.
func (s *seStore) SharedSecret(peerPub []byte) ([]byte, error) {
	if len(peerPub) != 65 || peerPub[0] != 0x04 {
		return nil, fmt.Errorf("SE ecdh: peer pubkey must be uncompressed X9.62 (65B starting with 0x04), got %dB", len(peerPub))
	}
	var outBuf *C.uchar
	var outLen C.size_t
	tagC := C.CString(s.tag)
	defer C.free(unsafe.Pointer(tagC))
	pubPtr := (*C.uchar)(unsafe.Pointer(&peerPub[0]))
	status := C.dop_se_ecdh(
		tagC, C.size_t(len(s.tag)),
		pubPtr, C.size_t(len(peerPub)),
		&outBuf, &outLen,
	)
	if status != 0 {
		return nil, fmt.Errorf("SE ecdh failed: OSStatus %d", int(status))
	}
	defer C.free(unsafe.Pointer(outBuf))
	return C.GoBytes(unsafe.Pointer(outBuf), C.int(outLen)), nil
}

func (s *seStore) Sign(challenge []byte) ([]byte, error) {
	var outSig *C.uchar
	var outLen C.size_t
	tagC := C.CString(s.tag)
	defer C.free(unsafe.Pointer(tagC))
	var msgPtr *C.uchar
	if len(challenge) > 0 {
		msgPtr = (*C.uchar)(unsafe.Pointer(&challenge[0]))
	}
	status := C.dop_se_sign(
		tagC, C.size_t(len(s.tag)),
		msgPtr, C.size_t(len(challenge)),
		&outSig, &outLen,
	)
	if status != 0 {
		return nil, fmt.Errorf("SE sign failed: OSStatus %d", int(status))
	}
	defer C.free(unsafe.Pointer(outSig))
	sig := C.GoBytes(unsafe.Pointer(outSig), C.int(outLen))
	return sig, nil
}

// keychainAvailable is set by init() below when the SE bridge probes
// its dependencies. Used by Available().
var keychainAvailable = true

// realKeychainLoad is the cgo-backed replacement for the stub Load in
// keychain_backend_darwin.go. Wired via the seOverride package var
// (see below).
func realKeychainLoad(b *KeychainBackend, lookupID string) (Store, error) {
	tag := b.AppTagPrefix + lookupID
	tagC := C.CString(tag)
	defer C.free(unsafe.Pointer(tagC))

	var outPub *C.uchar
	var outLen C.size_t
	status := C.dop_se_public(tagC, C.size_t(len(tag)), &outPub, &outLen)
	if status == C.errSecItemNotFound {
		return nil, ErrNotFound
	}
	if status != 0 {
		return nil, fmt.Errorf("SE load failed: OSStatus %d", int(status))
	}
	defer C.free(unsafe.Pointer(outPub))
	pub := C.GoBytes(unsafe.Pointer(outPub), C.int(outLen))
	return &seStore{lookupID: lookupID, tag: tag, pubkey: pub}, nil
}

// realKeychainGenerate creates a new SE-backed P-256 key.
func realKeychainGenerate(b *KeychainBackend, lookupID, keyType string) (Store, error) {
	if keyType != "" && keyType != vault.KeyTypeP256 {
		return nil, fmt.Errorf("keychain-darwin: only p256 supported, got %q", keyType)
	}
	tag := b.AppTagPrefix + lookupID
	tagC := C.CString(tag)
	defer C.free(unsafe.Pointer(tagC))

	var outPub *C.uchar
	var outLen C.size_t
	status := C.dop_se_generate(tagC, C.size_t(len(tag)), &outPub, &outLen)
	if status != 0 {
		return nil, fmt.Errorf("SE generate failed: OSStatus %d", int(status))
	}
	defer C.free(unsafe.Pointer(outPub))
	pub := C.GoBytes(unsafe.Pointer(outPub), C.int(outLen))
	return &seStore{lookupID: lookupID, tag: tag, pubkey: pub}, nil
}

func realKeychainDelete(b *KeychainBackend, lookupID string) error {
	tag := b.AppTagPrefix + lookupID
	tagC := C.CString(tag)
	defer C.free(unsafe.Pointer(tagC))
	status := C.dop_se_delete(tagC, C.size_t(len(tag)))
	if status != 0 {
		return fmt.Errorf("SE delete failed: OSStatus %d", int(status))
	}
	return nil
}

// init wires the cgo implementations into the KeychainBackend hooks
// declared in keychain_backend_darwin.go. That file defines the stub
// versions; this file overrides them when cgo is on.
func init() {
	seLoad = realKeychainLoad
	seGenerate = realKeychainGenerate
	seDelete = realKeychainDelete
	seAvailable = func() bool { return true }
}
