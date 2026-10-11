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
#include <string.h>

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

// dop_se_rename_tag changes the kSecAttrApplicationTag of an existing
// SE-backed key. Used by v1.12 bearer rotation to re-tag the agent's
// SE key from the old bearer's lookup id to the new bearer's lookup
// id without regenerating the underlying hardware key.
//
// Returns errSecItemNotFound if there's no key at old_tag, or a
// non-zero OSStatus on any other Security.framework failure.
OSStatus dop_se_rename_tag(
    const char *old_tag_utf8, size_t old_tag_len,
    const char *new_tag_utf8, size_t new_tag_len
) {
    CFDataRef oldTag = CFDataCreate(NULL, (const UInt8 *)old_tag_utf8, (CFIndex)old_tag_len);
    if (!oldTag) return errSecAllocate;
    CFDataRef newTag = CFDataCreate(NULL, (const UInt8 *)new_tag_utf8, (CFIndex)new_tag_len);
    if (!newTag) { CFRelease(oldTag); return errSecAllocate; }

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrApplicationTag, oldTag);
    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);

    CFMutableDictionaryRef changes = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFDictionarySetValue(changes, kSecAttrApplicationTag, newTag);

    OSStatus status = SecItemUpdate(query, changes);
    CFRelease(query);
    CFRelease(changes);
    CFRelease(oldTag);
    CFRelease(newTag);
    return status;
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

// ---------------------------------------------------------------------------
// Handle-based Secure Enclave keys (dop-ofn). A permanent SE keychain item
// needs keychain entitlements (provisioning profile) — no dop build has
// them, so key creation failed with -34018 everywhere. A NON-permanent SE
// key needs no entitlement: the private key is still generated and kept
// inside the Secure Enclave; we persist only its token object handle
// ("toid" attribute) — an SE-wrapped blob that only this Mac's SE can use —
// and rebuild the key from it with SecKeyCreateWithData. Same model as
// CryptoKit's SecureEnclave.P256 dataRepresentation.

static SecKeyRef dop_seh_load(const unsigned char *h, size_t hlen, OSStatus *st) {
    CFDataRef toid = CFDataCreate(NULL, h, (CFIndex)hlen);
    if (!toid) { *st = errSecAllocate; return NULL; }
    CFMutableDictionaryRef a = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(a, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(a, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(a, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(a, CFSTR("toid"), toid);
    CFErrorRef err = NULL;
    SecKeyRef k = SecKeyCreateWithData(toid, a, &err);
    CFRelease(a);
    CFRelease(toid);
    if (!k) {
        *st = err ? (OSStatus)CFErrorGetCode(err) : errSecParam;
        if (err) CFRelease(err);
        return NULL;
    }
    *st = errSecSuccess;
    return k;
}

static OSStatus dop_copy_out(CFDataRef d, unsigned char **out, size_t *out_len) {
    CFIndex n = CFDataGetLength(d);
    unsigned char *buf = (unsigned char *)malloc((size_t)n);
    if (!buf) return errSecAllocate;
    memcpy(buf, CFDataGetBytePtr(d), (size_t)n);
    *out = buf;
    *out_len = (size_t)n;
    return errSecSuccess;
}

// dop_seh_generate creates a non-permanent SE P-256 key. Returns its
// handle and its uncompressed public key (both malloc'd).
OSStatus dop_seh_generate(unsigned char **out_handle, size_t *out_handle_len,
                          unsigned char **out_pub, size_t *out_pub_len) {
    CFErrorRef err = NULL;
    SecAccessControlRef ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &err);
    if (!ac) { if (err) CFRelease(err); return errSecAuthFailed; }
    CFMutableDictionaryRef priv = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(priv, kSecAttrIsPermanent, kCFBooleanFalse);
    CFDictionarySetValue(priv, kSecAttrAccessControl, ac);
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int bits = 256;
    CFNumberRef bitsRef = CFNumberCreate(NULL, kCFNumberIntType, &bits);
    CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, bitsRef);
    CFDictionarySetValue(attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, priv);
    SecKeyRef key = SecKeyCreateRandomKey(attrs, &err);
    CFRelease(bitsRef); CFRelease(attrs); CFRelease(priv); CFRelease(ac);
    if (!key) {
        OSStatus st = err ? (OSStatus)CFErrorGetCode(err) : errSecKeyIsSensitive;
        if (err) CFRelease(err);
        return st;
    }
    OSStatus st = errSecSuccess;
    CFDictionaryRef ka = SecKeyCopyAttributes(key);
    CFDataRef toid = ka ? (CFDataRef)CFDictionaryGetValue(ka, CFSTR("toid")) : NULL;
    SecKeyRef pub = SecKeyCopyPublicKey(key);
    CFDataRef pubData = pub ? SecKeyCopyExternalRepresentation(pub, NULL) : NULL;
    if (!toid || !pubData) {
        st = errSecParam;
    } else if ((st = dop_copy_out(toid, out_handle, out_handle_len)) == errSecSuccess) {
        st = dop_copy_out(pubData, out_pub, out_pub_len);
        if (st != errSecSuccess) { free(*out_handle); *out_handle = NULL; }
    }
    if (pubData) CFRelease(pubData);
    if (pub) CFRelease(pub);
    if (ka) CFRelease(ka);
    CFRelease(key);
    return st;
}

// dop_seh_public rebuilds the key from its handle and returns its
// uncompressed public key — errors mean the handle isn't usable here
// (another Mac, another user, SE reset).
OSStatus dop_seh_public(const unsigned char *h, size_t hlen, unsigned char **out_pub, size_t *out_pub_len) {
    OSStatus st;
    SecKeyRef k = dop_seh_load(h, hlen, &st);
    if (!k) return st;
    SecKeyRef pub = SecKeyCopyPublicKey(k);
    CFDataRef d = pub ? SecKeyCopyExternalRepresentation(pub, NULL) : NULL;
    st = d ? dop_copy_out(d, out_pub, out_pub_len) : errSecParam;
    if (d) CFRelease(d);
    if (pub) CFRelease(pub);
    CFRelease(k);
    return st;
}

OSStatus dop_seh_sign(const unsigned char *h, size_t hlen, const unsigned char *msg, size_t msg_len,
                      unsigned char **out_sig, size_t *out_sig_len) {
    OSStatus st;
    SecKeyRef k = dop_seh_load(h, hlen, &st);
    if (!k) return st;
    CFDataRef m = CFDataCreate(NULL, msg, (CFIndex)msg_len);
    CFErrorRef err = NULL;
    CFDataRef sig = SecKeyCreateSignature(k, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, m, &err);
    if (sig) { st = dop_copy_out(sig, out_sig, out_sig_len); CFRelease(sig); }
    else { st = err ? (OSStatus)CFErrorGetCode(err) : errSecParam; if (err) CFRelease(err); }
    CFRelease(m);
    CFRelease(k);
    return st;
}

OSStatus dop_seh_ecdh(const unsigned char *h, size_t hlen, const unsigned char *peer, size_t peer_len,
                      unsigned char **out_secret, size_t *out_secret_len) {
    OSStatus st;
    SecKeyRef k = dop_seh_load(h, hlen, &st);
    if (!k) return st;
    CFDataRef pd = CFDataCreate(NULL, peer, (CFIndex)peer_len);
    CFMutableDictionaryRef pa = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(pa, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(pa, kSecAttrKeyClass, kSecAttrKeyClassPublic);
    CFErrorRef err = NULL;
    SecKeyRef peerKey = SecKeyCreateWithData(pd, pa, &err);
    CFRelease(pa); CFRelease(pd);
    if (!peerKey) {
        st = err ? (OSStatus)CFErrorGetCode(err) : errSecParam;
        if (err) CFRelease(err);
        CFRelease(k);
        return st;
    }
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDataRef shared = SecKeyCopyKeyExchangeResult(k, kSecKeyAlgorithmECDHKeyExchangeStandard, peerKey, params, &err);
    if (shared) { st = dop_copy_out(shared, out_secret, out_secret_len); CFRelease(shared); }
    else { st = err ? (OSStatus)CFErrorGetCode(err) : errSecParam; if (err) CFRelease(err); }
    CFRelease(params); CFRelease(peerKey); CFRelease(k);
    return st;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// MigrateLookupID re-tags the SE key from the old lookup id to
// newLookupID via SecItemUpdate. The underlying hardware key is
// untouched — same private material, new applicationTag. Used by
// v1.12 bearer rotation.
func (s *seStore) MigrateLookupID(newLookupID string) error {
	oldTag := s.tag
	newTag := "dop.agent." + newLookupID
	oldC := C.CString(oldTag)
	defer C.free(unsafe.Pointer(oldC))
	newC := C.CString(newTag)
	defer C.free(unsafe.Pointer(newC))
	status := C.dop_se_rename_tag(
		oldC, C.size_t(len(oldTag)),
		newC, C.size_t(len(newTag)),
	)
	if status != 0 {
		return fmt.Errorf("SE tag rename %s→%s failed: OSStatus %d", oldTag, newTag, int(status))
	}
	s.tag = newTag
	s.lookupID = newLookupID
	return nil
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

// seHandleMagic prefixes a .se handle file (format version 1).
const seHandleMagic = "dop-se-v1\n"

// seHandleStore is a Secure Enclave key persisted as its SE-wrapped
// handle in <Root>/agent-keys/<lookup>.se (0600). The private key never
// leaves the SE; the handle only works with this Mac's SE, so copying
// the file elsewhere yields nothing usable. Anyone running as the same
// user here can still ask the SE to sign with it — same-machine trust
// is unchanged (threat model).
type seHandleStore struct {
	lookupID string
	path     string
	handle   []byte
	pubkey   []byte
}

func (s *seHandleStore) LookupID() string  { return s.lookupID }
func (s *seHandleStore) KeyType() string   { return vault.KeyTypeP256 }
func (s *seHandleStore) PublicKey() []byte { return append([]byte(nil), s.pubkey...) }
func (s *seHandleStore) Extractable() bool { return false }
func (s *seHandleStore) StorageDescription() string {
	return "macOS Secure Enclave (p256, handle " + s.path + ", non-extractable)"
}

func (s *seHandleStore) Sign(challenge []byte) ([]byte, error) {
	var out *C.uchar
	var n C.size_t
	var msg *C.uchar
	if len(challenge) > 0 {
		msg = (*C.uchar)(unsafe.Pointer(&challenge[0]))
	}
	st := C.dop_seh_sign((*C.uchar)(unsafe.Pointer(&s.handle[0])), C.size_t(len(s.handle)), msg, C.size_t(len(challenge)), &out, &n)
	if st != 0 {
		return nil, fmt.Errorf("SE sign failed: OSStatus %d", int(st))
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(n)), nil
}

func (s *seHandleStore) SharedSecret(peerPub []byte) ([]byte, error) {
	if len(peerPub) != 65 || peerPub[0] != 0x04 {
		return nil, fmt.Errorf("SE ecdh: peer pubkey must be uncompressed X9.62 (65B starting with 0x04), got %dB", len(peerPub))
	}
	var out *C.uchar
	var n C.size_t
	st := C.dop_seh_ecdh((*C.uchar)(unsafe.Pointer(&s.handle[0])), C.size_t(len(s.handle)),
		(*C.uchar)(unsafe.Pointer(&peerPub[0])), C.size_t(len(peerPub)), &out, &n)
	if st != 0 {
		return nil, fmt.Errorf("SE ecdh failed: OSStatus %d", int(st))
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(n)), nil
}

// MigrateLookupID renames the handle file (bearer rotation). The SE key
// itself is untouched.
func (s *seHandleStore) MigrateLookupID(newLookupID string) error {
	newPath := filepath.Join(filepath.Dir(s.path), newLookupID+".se")
	if err := os.Rename(s.path, newPath); err != nil {
		return fmt.Errorf("SE handle rename: %w", err)
	}
	s.path, s.lookupID = newPath, newLookupID
	return nil
}

func seHandlePath(root, lookupID string) string {
	return filepath.Join(root, "agent-keys", lookupID+".se")
}

// loadSEHandle reads <lookup>.se and checks the SE can still use it.
func loadSEHandle(root, lookupID string) (Store, error) {
	path := seHandlePath(root, lookupID)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(raw), seHandleMagic) || len(raw) == len(seHandleMagic) {
		return nil, fmt.Errorf("SE handle %s: unknown format", path)
	}
	h := raw[len(seHandleMagic):]
	var out *C.uchar
	var n C.size_t
	if st := C.dop_seh_public((*C.uchar)(unsafe.Pointer(&h[0])), C.size_t(len(h)), &out, &n); st != 0 {
		return nil, fmt.Errorf("SE handle %s not usable on this Mac (OSStatus %d) — was it copied from another machine?", path, int(st))
	}
	defer C.free(unsafe.Pointer(out))
	return &seHandleStore{lookupID: lookupID, path: path, handle: h, pubkey: C.GoBytes(unsafe.Pointer(out), C.int(n))}, nil
}

// generateSEHandle creates a non-permanent SE key and writes its handle.
func generateSEHandle(root, lookupID string) (Store, error) {
	var h, pub *C.uchar
	var hn, pn C.size_t
	if st := C.dop_seh_generate(&h, &hn, &pub, &pn); st != 0 {
		return nil, fmt.Errorf("SE generate failed: OSStatus %d", int(st))
	}
	defer C.free(unsafe.Pointer(h))
	defer C.free(unsafe.Pointer(pub))
	handle := C.GoBytes(unsafe.Pointer(h), C.int(hn))
	path := seHandlePath(root, lookupID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, append([]byte(seHandleMagic), handle...), 0o600); err != nil {
		return nil, err
	}
	return &seHandleStore{lookupID: lookupID, path: path, handle: handle, pubkey: C.GoBytes(unsafe.Pointer(pub), C.int(pn))}, nil
}

// ProbeSecureEnclave creates a throwaway SE key (never stored — it
// vanishes with the process) to check the chip really answers. Used by
// `dop doctor` instead of guessing from the code signature (dop-4td).
func ProbeSecureEnclave() error {
	var h, pub *C.uchar
	var hn, pn C.size_t
	if st := C.dop_seh_generate(&h, &hn, &pub, &pn); st != 0 {
		return fmt.Errorf("OSStatus %d", int(st))
	}
	C.free(unsafe.Pointer(h))
	C.free(unsafe.Pointer(pub))
	return nil
}

// keychainAvailable is set by init() below when the SE bridge probes
// its dependencies. Used by Available().
var keychainAvailable = true

// realKeychainLoad is the cgo-backed replacement for the stub Load in
// keychain_backend_darwin.go. Wired via the seOverride package var
// (see below).
func realKeychainLoad(b *KeychainBackend, lookupID string) (Store, error) {
	// Handle file first (every key created since dop-ofn); then the
	// pre-dop-ofn permanent keychain item, if one exists.
	if b.Root != "" {
		if s, err := loadSEHandle(b.Root, lookupID); err != ErrNotFound {
			return s, err
		}
	}
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
	if b.Root != "" {
		return generateSEHandle(b.Root, lookupID)
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
	if b.Root != "" {
		if err := os.Remove(seHandlePath(b.Root, lookupID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
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
