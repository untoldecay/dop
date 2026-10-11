// Package sopsfile reads and writes SOPS-encrypted YAML files in-process,
// for age keys only — the subset dop uses (dop-bki). Linking the SOPS Go
// library pulls in every cloud KMS SDK (+40 MB, 2026-09-25 devlog), so
// this re-implements the file format instead.
//
// The output must stay readable by the `sops` CLI (teammates on older dop
// builds still shell out to it), and files written by `sops` must open
// here. The format, from sops v3 (sops.go, aes/cipher.go, stores/yaml):
//
//   - a random 32-byte data key, age-encrypted (ASCII armor) to each
//     recipient under sops.age[].enc;
//   - every leaf value encrypted with AES-256-GCM, 32-byte IV, additional
//     data = the key path joined by ":" plus a trailing ":", written as
//     ENC[AES256_GCM,data:…,iv:…,tag:…,type:str|int|float|bool|…];
//     list items share their list's path; empty strings and nulls stay
//     as they are; keys ending in "_unencrypted" are left in clear;
//   - a MAC: uppercase hex SHA-512 over every value in walk order,
//     encrypted like a value with additional data = sops.lastmodified.
//
// Comments are dropped: every dop caller parses the plaintext into its
// vault struct, which keeps none.
package sopsfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gopkg.in/yaml.v3"
)

// Version is written to sops.version: the sops release whose format
// this package follows.
const Version = "3.13.3"

const (
	metadataKey              = "sops"
	defaultUnencryptedSuffix = "_unencrypted"
	nonceSize                = 32
	indent                   = 4
)

// ErrNotEncrypted: the input has no top-level sops metadata.
var ErrNotEncrypted = errors.New("not a sops-encrypted file (no sops metadata)")

// ErrNoMatchingKey: none of the given identities opens the data key.
// The message keeps the phrase older callers match on.
var ErrNoMatchingKey = errors.New("no master key was able to decrypt the file: this machine's age key is not one of its recipients")

var encRe = regexp.MustCompile(`^ENC\[AES256_GCM,data:(.*),iv:(.*),tag:(.*),type:(.*)\]$`)

type ageEntry struct {
	Enc       string `yaml:"enc"`
	Recipient string `yaml:"recipient"`
}

type metadata struct {
	Age                     []ageEntry `yaml:"age"`
	LastModified            string     `yaml:"lastmodified"`
	MAC                     string     `yaml:"mac"`
	UnencryptedSuffix       string     `yaml:"unencrypted_suffix"`
	EncryptedSuffix         string     `yaml:"encrypted_suffix"`
	UnencryptedRegex        string     `yaml:"unencrypted_regex"`
	EncryptedRegex          string     `yaml:"encrypted_regex"`
	UnencryptedCommentRegex string     `yaml:"unencrypted_comment_regex"`
	EncryptedCommentRegex   string     `yaml:"encrypted_comment_regex"`
	MACOnlyEncrypted        bool       `yaml:"mac_only_encrypted"`
	ShamirThreshold         int        `yaml:"shamir_threshold"`
	KeyGroups               []any      `yaml:"key_groups"`
	PGP                     []any      `yaml:"pgp"`
	KMS                     []any      `yaml:"kms"`
	GCPKMS                  []any      `yaml:"gcp_kms"`
	AzureKV                 []any      `yaml:"azure_kv"`
	HCVault                 []any      `yaml:"hc_vault"`
	HCKMS                   []any      `yaml:"hckms"`
	Version                 string     `yaml:"version"`
}

// rules decides which paths are encrypted (sops Tree.shouldBeEncrypted,
// path rules only — comment rules are refused at load).
type rules struct {
	unencSuffix, encSuffix string
	unencRe, encRe         *regexp.Regexp
}

func (r rules) encrypted(path []string) bool {
	enc := true
	if r.unencSuffix != "" {
		for _, p := range path {
			if strings.HasSuffix(p, r.unencSuffix) {
				enc = false
				break
			}
		}
	}
	if r.encSuffix != "" {
		enc = false
		for _, p := range path {
			if strings.HasSuffix(p, r.encSuffix) {
				enc = true
				break
			}
		}
	}
	if r.unencRe != nil {
		for _, p := range path {
			if r.unencRe.MatchString(p) {
				enc = false
				break
			}
		}
	}
	if r.encRe != nil {
		enc = false
		for _, p := range path {
			if r.encRe.MatchString(p) {
				enc = true
				break
			}
		}
	}
	return enc
}

// Encrypt encrypts a plaintext YAML document (or stream) to the given
// age recipients, the way `sops --encrypt --age r1,r2 --input-type yaml`
// does with default settings.
func Encrypt(plain []byte, recipients []string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("sops encrypt: no age recipients")
	}
	parsed := make([]age.Recipient, 0, len(recipients))
	for _, r := range recipients {
		p, err := age.ParseX25519Recipient(strings.TrimSpace(r))
		if err != nil {
			return nil, fmt.Errorf("sops encrypt: recipient %q: %w", r, err)
		}
		parsed = append(parsed, p)
	}
	docs, err := parseDocs(plain)
	if err != nil {
		return nil, err
	}
	for _, d := range docs {
		if mappingGet(d, metadataKey) != nil {
			return nil, errors.New("sops encrypt: the file already has a top-level \"sops\" key (already encrypted?)")
		}
	}

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, err
	}
	w := walker{key: dataKey, rules: rules{unencSuffix: defaultUnencryptedSuffix}, mac: sha512.New(), encrypt: true}
	out := make([]*yaml.Node, len(docs))
	for i, d := range docs {
		if out[i], err = w.mapping(d, nil); err != nil {
			return nil, fmt.Errorf("sops encrypt: %w", err)
		}
	}

	lastModified := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	mac, err := encryptValue(fmt.Sprintf("%X", w.mac.Sum(nil)), dataKey, lastModified)
	if err != nil {
		return nil, err
	}
	md := metadata{LastModified: lastModified, MAC: mac, UnencryptedSuffix: defaultUnencryptedSuffix, Version: Version}
	for i, r := range parsed {
		var buf bytes.Buffer
		aw := armor.NewWriter(&buf)
		ew, err := age.Encrypt(aw, r)
		if err != nil {
			return nil, err
		}
		if _, err := ew.Write(dataKey); err != nil {
			return nil, err
		}
		if err := ew.Close(); err != nil {
			return nil, err
		}
		if err := aw.Close(); err != nil {
			return nil, err
		}
		md.Age = append(md.Age, ageEntry{Enc: buf.String(), Recipient: strings.TrimSpace(recipients[i])})
	}
	mdNode := metadataNode(md)
	for _, m := range out {
		m.Content = append(m.Content, scalar(metadataKey), mdNode)
	}
	return emit(out)
}

// Decrypt opens a SOPS-encrypted YAML file with any of the identities
// and returns the plaintext YAML, after checking the file's MAC.
func Decrypt(in []byte, ids ...age.Identity) ([]byte, error) {
	docs, err := parseDocs(in)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, ErrNotEncrypted
	}
	mdNode := mappingGet(docs[0], metadataKey)
	if mdNode == nil {
		return nil, ErrNotEncrypted
	}
	var md metadata
	if err := mdNode.Decode(&md); err != nil {
		return nil, fmt.Errorf("sops decrypt: bad metadata: %w", err)
	}
	for _, d := range docs {
		mappingDelete(d, metadataKey)
	}
	r, err := md.rules()
	if err != nil {
		return nil, err
	}
	dataKey, err := md.dataKey(ids)
	if err != nil {
		return nil, err
	}

	w := walker{key: dataKey, rules: r, mac: sha512.New(), macOnlyEncrypted: md.MACOnlyEncrypted}
	if md.MACOnlyEncrypted {
		// sops MACOnlyEncryptedInitialization: a fixed prefix so the two
		// MAC modes never collide.
		w.mac.Write(macOnlyEncryptedInit)
	}
	out := make([]*yaml.Node, len(docs))
	for i, d := range docs {
		if out[i], err = w.mapping(d, nil); err != nil {
			return nil, fmt.Errorf("sops decrypt: %w", err)
		}
	}

	lm, err := time.Parse(time.RFC3339, md.LastModified)
	if err != nil {
		return nil, fmt.Errorf("sops decrypt: bad lastmodified %q: %w", md.LastModified, err)
	}
	if md.MAC == "" {
		return nil, errors.New("sops decrypt: the file has no MAC")
	}
	fileMAC, err := decryptValue(md.MAC, dataKey, lm.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("sops decrypt: cannot decrypt MAC: %w", err)
	}
	if computed := fmt.Sprintf("%X", w.mac.Sum(nil)); fileMAC != computed {
		return nil, errors.New("sops decrypt: MAC mismatch — the file was changed outside sops/dop or is corrupted")
	}
	return emit(out)
}

// IsEncrypted reports whether raw YAML carries top-level sops metadata.
func IsEncrypted(raw []byte) bool {
	return bytes.HasPrefix(raw, []byte("sops:")) || bytes.Contains(raw, []byte("\nsops:"))
}

// The 32 bytes sops writes first into the MAC when mac_only_encrypted
// is set (sops.MACOnlyEncryptedInitialization).
var macOnlyEncryptedInit = []byte{0x8a, 0x3f, 0xd2, 0xad, 0x54, 0xce, 0x66, 0x52, 0x7b, 0x10, 0x34, 0xf3, 0xd1, 0x47, 0xbe, 0xb, 0xb, 0x97, 0x5b, 0x3b, 0xf4, 0x4f, 0x72, 0xc6, 0xfd, 0xad, 0xec, 0x81, 0x76, 0xf2, 0x7d, 0x69}

func (md metadata) rules() (rules, error) {
	if md.UnencryptedCommentRegex != "" || md.EncryptedCommentRegex != "" {
		return rules{}, errors.New("sops decrypt: comment-based encryption rules aren't supported")
	}
	n := 0
	for _, s := range []string{md.UnencryptedSuffix, md.EncryptedSuffix, md.UnencryptedRegex, md.EncryptedRegex} {
		if s != "" {
			n++
		}
	}
	if n > 1 {
		return rules{}, errors.New("sops decrypt: more than one encryption rule in the file")
	}
	r := rules{unencSuffix: md.UnencryptedSuffix, encSuffix: md.EncryptedSuffix}
	if n == 0 {
		r.unencSuffix = defaultUnencryptedSuffix
	}
	var err error
	if md.UnencryptedRegex != "" {
		if r.unencRe, err = regexp.Compile(md.UnencryptedRegex); err != nil {
			return rules{}, err
		}
	}
	if md.EncryptedRegex != "" {
		if r.encRe, err = regexp.Compile(md.EncryptedRegex); err != nil {
			return rules{}, err
		}
	}
	return r, nil
}

func (md metadata) dataKey(ids []age.Identity) ([]byte, error) {
	if len(md.KeyGroups) > 0 || md.ShamirThreshold > 0 {
		return nil, errors.New("sops decrypt: key groups / Shamir sharing aren't supported (age recipients only)")
	}
	if len(md.Age) == 0 {
		return nil, errors.New("sops decrypt: the file has no age recipients (other key types aren't supported)")
	}
	if len(ids) == 0 {
		return nil, ErrNoMatchingKey
	}
	for _, e := range md.Age {
		r, err := age.Decrypt(armor.NewReader(strings.NewReader(e.Enc)), ids...)
		if err != nil {
			continue
		}
		k, err := io.ReadAll(r)
		if err == nil && len(k) == 32 {
			return k, nil
		}
	}
	return nil, ErrNoMatchingKey
}

// walker turns parsed nodes into fresh output nodes, encrypting or
// decrypting leaves and feeding the MAC in sops walk order.
type walker struct {
	key              []byte
	rules            rules
	mac              hash.Hash
	macOnlyEncrypted bool
	encrypt          bool
}

func (w *walker) mapping(n *yaml.Node, path []string) (*yaml.Node, error) {
	n = resolve(n)
	if n.Kind != yaml.MappingNode {
		if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" {
			return &yaml.Node{Kind: yaml.MappingNode}, nil // empty document
		}
		return nil, errors.New("only YAML mappings are supported at the top level")
	}
	out := &yaml.Node{Kind: yaml.MappingNode}
	for i := 0; i+1 < len(n.Content); i += 2 {
		var k any
		if err := resolve(n.Content[i]).Decode(&k); err != nil {
			return nil, err
		}
		ks, ok := k.(string)
		if !ok {
			return nil, fmt.Errorf("non-string key %v (%T): only string keys are supported", k, k)
		}
		v, err := w.value(n.Content[i+1], append(append([]string{}, path...), ks))
		if err != nil {
			return nil, err
		}
		out.Content = append(out.Content, scalar(ks), v)
	}
	return out, nil
}

func (w *walker) value(n *yaml.Node, path []string) (*yaml.Node, error) {
	n = resolve(n)
	switch n.Kind {
	case yaml.MappingNode:
		return w.mapping(n, path)
	case yaml.SequenceNode:
		out := &yaml.Node{Kind: yaml.SequenceNode}
		for _, item := range n.Content {
			v, err := w.value(item, path)
			if err != nil {
				return nil, err
			}
			if v != nil {
				out.Content = append(out.Content, v)
			}
		}
		return out, nil
	case yaml.ScalarNode:
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		return w.leaf(v, path)
	}
	return nil, fmt.Errorf("unsupported YAML node at %s", strings.Join(path, "."))
}

// leaf mirrors the onLeaves callbacks of sops Tree.Encrypt / Decrypt.
// A nil return drops the item (a decrypted list comment).
func (w *walker) leaf(v any, path []string) (*yaml.Node, error) {
	if v == nil {
		return encodeNode(nil)
	}
	switch v.(type) {
	case string, int, float64, bool, time.Time:
	default:
		return nil, fmt.Errorf("cannot handle value of type %T at %s", v, strings.Join(path, "."))
	}
	enc := w.rules.encrypted(path)
	ad := strings.Join(path, ":") + ":"
	if w.encrypt {
		if !w.macOnlyEncrypted || enc {
			w.mac.Write(toBytes(v))
		}
		if !enc {
			return encodeNode(v)
		}
		s, err := encryptValue(v, w.key, ad)
		if err != nil {
			return nil, err
		}
		return encodeNode(s)
	}
	if enc {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("expected an encrypted value at %s, got %T", strings.Join(path, "."), v)
		}
		pv, isComment, err := decryptTyped(s, w.key, ad)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt value at %s: %w", strings.Join(path, "."), err)
		}
		if isComment {
			return nil, nil
		}
		v = pv
	}
	if !w.macOnlyEncrypted || enc {
		w.mac.Write(toBytes(v))
	}
	return encodeNode(v)
}

func toBytes(v any) []byte {
	switch v := v.(type) {
	case string:
		return []byte(v)
	case int:
		return []byte(strconv.Itoa(v))
	case float64:
		return []byte(strconv.FormatFloat(v, 'f', -1, 64))
	case bool:
		if v {
			return []byte("True")
		}
		return []byte("False")
	case []byte:
		return v
	case time.Time:
		b, _ := v.MarshalText()
		return b
	}
	return nil
}

func encryptValue(v any, key []byte, ad string) (string, error) {
	var typ string
	var plain []byte
	switch x := v.(type) {
	case string:
		if x == "" {
			return "", nil
		}
		typ, plain = "str", []byte(x)
	case int:
		typ, plain = "int", toBytes(x)
	case float64:
		typ, plain = "float", toBytes(x)
	case bool:
		typ, plain = "bool", toBytes(x)
	case time.Time:
		typ, plain = "time", toBytes(x)
	default:
		return "", fmt.Errorf("cannot encrypt value of type %T", v)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, nonceSize)
	if err != nil {
		return "", err
	}
	iv := make([]byte, nonceSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	out := gcm.Seal(nil, iv, plain, []byte(ad))
	tag := len(out) - aes.BlockSize
	return fmt.Sprintf("ENC[AES256_GCM,data:%s,iv:%s,tag:%s,type:%s]",
		base64.StdEncoding.EncodeToString(out[:tag]),
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(out[tag:]),
		typ), nil
}

// decryptValue decrypts a str-typed value (the MAC).
func decryptValue(s string, key []byte, ad string) (string, error) {
	v, _, err := decryptTyped(s, key, ad)
	if err != nil {
		return "", err
	}
	str, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("expected a string, got %T", v)
	}
	return str, nil
}

func decryptTyped(s string, key []byte, ad string) (v any, isComment bool, err error) {
	if s == "" {
		return "", false, nil
	}
	m := encRe.FindStringSubmatch(s)
	if m == nil {
		return nil, false, errors.New("not in sops ENC[…] format")
	}
	var parts [3][]byte
	for i := range parts {
		if parts[i], err = base64.StdEncoding.DecodeString(m[i+1]); err != nil {
			return nil, false, err
		}
	}
	data, iv, tag := parts[0], parts[1], parts[2]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, false, err
	}
	plain, err := gcm.Open(nil, iv, append(data, tag...), []byte(ad))
	if err != nil {
		return nil, false, errors.New("authentication failed (wrong key, or the value was moved or changed)")
	}
	p := string(plain)
	switch m[4] {
	case "str":
		return p, false, nil
	case "int":
		v, err = strconv.Atoi(p)
	case "float":
		v, err = strconv.ParseFloat(p, 64)
	case "bool":
		v, err = strconv.ParseBool(p)
	case "bytes":
		v = p
	case "time":
		var t time.Time
		err = t.UnmarshalText(plain)
		v = t
	case "comment":
		return nil, true, nil
	default:
		return nil, false, fmt.Errorf("unknown value type %q", m[4])
	}
	return v, false, err
}

// --- YAML helpers ---

func parseDocs(in []byte) ([]*yaml.Node, error) {
	if len(bytes.TrimSpace(in)) > 0 {
		// Reject duplicate keys like sops does (decoding into a map checks).
		if err := yaml.NewDecoder(bytes.NewReader(in)).Decode(&map[string]any{}); err != nil && err != io.EOF {
			return nil, fmt.Errorf("invalid YAML: %w", err)
		}
	}
	dec := yaml.NewDecoder(bytes.NewReader(in))
	var docs []*yaml.Node
	for {
		var d yaml.Node
		err := dec.Decode(&d)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid YAML: %w", err)
		}
		root := &d
		if d.Kind == yaml.DocumentNode && len(d.Content) == 1 {
			root = d.Content[0]
		}
		docs = append(docs, root)
	}
	return docs, nil
}

func resolve(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	return n
}

func mappingGet(n *yaml.Node, key string) *yaml.Node {
	n = resolve(n)
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func mappingDelete(n *yaml.Node, key string) {
	n = resolve(n)
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content = append(n.Content[:i], n.Content[i+2:]...)
			return
		}
	}
}

func scalar(s string) *yaml.Node {
	n, _ := encodeNode(s)
	return n
}

func encodeNode(v any) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return &n, nil
}

// metadataNode writes the sops block with keys in the order sops emits
// them (alphabetical): age (enc, recipient), lastmodified, mac,
// unencrypted_suffix, version.
func metadataNode(md metadata) *yaml.Node {
	ages := &yaml.Node{Kind: yaml.SequenceNode}
	for _, e := range md.Age {
		item := &yaml.Node{Kind: yaml.MappingNode}
		item.Content = append(item.Content, scalar("enc"), scalar(e.Enc), scalar("recipient"), scalar(e.Recipient))
		ages.Content = append(ages.Content, item)
	}
	n := &yaml.Node{Kind: yaml.MappingNode}
	n.Content = append(n.Content,
		scalar("age"), ages,
		scalar("lastmodified"), scalar(md.LastModified),
		scalar("mac"), scalar(md.MAC),
		scalar("unencrypted_suffix"), scalar(md.UnencryptedSuffix),
		scalar("version"), scalar(md.Version),
	)
	return n
}

func emit(docs []*yaml.Node) ([]byte, error) {
	var b bytes.Buffer
	e := yaml.NewEncoder(&b)
	e.SetIndent(indent)
	for _, d := range docs {
		if err := e.Encode(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{d}}); err != nil {
			return nil, err
		}
	}
	if err := e.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
