package hawk

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var MaxTimestampSkew = time.Minute

var Now = time.Now

type CredentialErrorType int

const (
	UnknownID CredentialErrorType = iota
	UnknownApp
	IDAppMismatch
)

func (t CredentialErrorType) String() string {
	switch t {
	case UnknownApp:
		return "unknown app"
	case IDAppMismatch:
		return "id/app mismatch"
	}
	return "unknown id"
}

type CredentialError struct {
	Type CredentialErrorType
	ID   string
	App  string
}

func (e *CredentialError) Error() string {
	return fmt.Sprintf("hawk: credential error with id %s and app %s: %s", e.ID, e.App, e.Type)
}

type Credentials struct {
	ID   string
	Key  []byte
	Hash func() hash.Hash
	Data interface{}
}

func (creds *Credentials) MAC() hash.Hash { return hmac.New(creds.Hash, creds.Key) }

type AuthType int

const (
	AuthHeader AuthType = iota
	AuthResponse
	AuthBewit
)

func (a AuthType) String() string {
	switch a {
	case AuthResponse:
		return "response"
	case AuthBewit:
		return "bewit"
	default:
		return "header"
	}
	return "header"
}

type CredentialsLookupFunc func(id, app string) (Credentials, error)

type NonceCheckFunc func(nonce string, ts time.Time) bool

type AuthFormatError struct {
	Field string
	Err   string
}

func (e AuthFormatError) Error() string { return "hawk: invalid " + e.Field + ", " + e.Err }

func NewAuthFromRequestHeader(header string) (*Auth, error) {
	auth := &Auth{ActualTimestamp: Now()}
	err := auth.ParseHeader(header, AuthHeader)
	if err != nil {
		return nil, err
	}

	if auth.Credentials.ID == "" {
		return nil, AuthFormatError{"id", "missing or empty"}
	}
	if auth.Timestamp.IsZero() {
		return nil, AuthFormatError{"ts", "missing, empty, or zero"}
	}
	if auth.Nonce == "" {
		return nil, AuthFormatError{"nonce", "missing or empty"}
	}

	return auth, nil
}

func NewAuthFromBewit(bewit string) (*Auth, error) {
	if len(bewit)%4 != 0 {
		bewit += strings.Repeat("=", 4-len(bewit)%4)
	}
	decoded, err := base64.URLEncoding.DecodeString(bewit)
	if err != nil {
		return nil, AuthFormatError{"bewit", "malformed base64 encoding"}
	}
	components := bytes.SplitN(decoded, []byte(`\`), 4)
	if len(components) != 4 {
		return nil, AuthFormatError{"bewit", "missing components"}
	}

	auth := &Auth{
		Credentials:     Credentials{ID: string(components[0])},
		Ext:             string(components[3]),
		Method:          "GET",
		ActualTimestamp: Now(),
		IsBewit:         true,
	}

	ts, err := strconv.ParseInt(string(components[1]), 10, 64)
	if err != nil {
		return nil, AuthFormatError{"ts", "not an integer"}
	}
	auth.Timestamp = time.Unix(ts, 0)

	auth.MAC = make([]byte, base64.StdEncoding.DecodedLen(len(components[2])))
	n, err := base64.StdEncoding.Decode(auth.MAC, components[2])
	if err != nil {
		return nil, AuthFormatError{"mac", "malformed base64 encoding"}
	}
	auth.MAC = auth.MAC[:n]

	return auth, nil
}

var ErrNoAuth = errors.New("hawk: no Authorization header or bewit parameter found")
var ErrReplay = errors.New("hawk: request nonce is being replayed")

var ErrInvalidBewitMethod = errors.New("hawk: bewit only allows HEAD and GET requests")

func NewAuthFromRequest(req *http.Request, creds CredentialsLookupFunc, nonce NonceCheckFunc) (*Auth, error) {
	header := req.Header.Get("Authorization")
	bewit := req.URL.Query().Get("bewit")

	var auth *Auth
	var err error
	if header != "" {
		auth, err = NewAuthFromRequestHeader(header)
		if err != nil {
			return nil, err
		}
	}
	if auth == nil && bewit != "" {
		if req.Method != "GET" && req.Method != "HEAD" {
			return nil, ErrInvalidBewitMethod
		}
		auth, err = NewAuthFromBewit(bewit)
		if err != nil {
			return nil, err
		}
	}
	if auth == nil {
		return nil, ErrNoAuth
	}

	auth.Method = req.Method
	auth.Path = req.RequestURI
	if bewit != "" {
		auth.Method = "GET"
		bewitPattern, _ := regexp.Compile(`\?bewit=` + bewit + `\z|bewit=` + bewit + `&|&bewit=` + bewit + `\z`)
		auth.Path = bewitPattern.ReplaceAllString(auth.Path, "")
	}
	auth.Host, auth.Port = extractHostPort(req)
	if creds != nil {
		auth.Credentials, err = creds(auth.Credentials.ID, auth.App)
		if err != nil {
			return nil, err
		}
	}
	if nonce != nil && !auth.IsBewit && !nonce(auth.Nonce, auth.Timestamp) {
		return nil, ErrReplay
	}
	return auth, nil
}

func extractHostPort(req *http.Request) (host string, port string) {
	if idx := strings.Index(req.Host, ":"); idx != -1 {
		host, port, _ = net.SplitHostPort(req.Host)
	} else {
		host = req.Host
	}
	if req.RemoteAddr != "" && (host == "" || port == "") {
		addrHost, addrPort, _ := net.SplitHostPort(req.RemoteAddr)
		if host == "" {
			host = addrHost
		}
		if port == "" {
			port = addrPort
		}
	}
	if req.URL.Host != "" {
		if idx := strings.Index(req.Host, ":"); idx != -1 {
			host, port, _ = net.SplitHostPort(req.Host)
		} else {
			host = req.URL.Host
		}
	}
	if port == "" {
		if req.URL.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return
}

func NewRequestAuth(req *http.Request, creds *Credentials, tsOffset time.Duration) *Auth {
	auth := &Auth{
		Method:      req.Method,
		Credentials: *creds,
		Timestamp:   Now().Add(tsOffset),
		Nonce:       nonce(),
		Path:        req.URL.Path,
	}
	if req.URL.RawQuery != "" {
		auth.Path += "?" + req.URL.RawQuery
	}
	auth.Host, auth.Port = extractHostPort(req)
	return auth
}

func nonce() string {
	b := make([]byte, 8)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)[:8]
}

const headerVersion = "1"

type Auth struct {
	Credentials Credentials

	Method string
	Path   string
	Host   string
	Port   string

	MAC   []byte
	Nonce string
	Ext   string
	App   string
	Hash  []byte

	IsBewit   bool
	Delegate  string
	Timestamp time.Time

	ActualTimestamp time.Time
}

var headerRegex = regexp.MustCompile(`(id|ts|nonce|hash|ext|mac|app|dlg)="([ !#-\[\]-~]+)"`) // character class is ASCII printable [\x20-\x7E] without \ and "

func (auth *Auth) ParseHeader(header string, t AuthType) error {
	if len(header) < 4 || strings.ToLower(header[:4]) != "hawk" {
		return AuthFormatError{"scheme", "must be Hawk"}
	}

	matches := headerRegex.FindAllStringSubmatch(header, 8)

	var err error
	for _, match := range matches {
		switch match[1] {
		case "hash":
			auth.Hash, err = base64.StdEncoding.DecodeString(match[2])
			if err != nil {
				return AuthFormatError{"hash", "malformed base64 encoding"}
			}
		case "ext":
			auth.Ext = match[2]
		case "mac":
			auth.MAC, err = base64.StdEncoding.DecodeString(match[2])
			if err != nil {
				return AuthFormatError{"mac", "malformed base64 encoding"}
			}
		default:
			if t == AuthHeader {
				switch match[1] {
				case "app":
					auth.App = match[2]
				case "dlg":
					auth.Delegate = match[2]
				case "id":
					auth.Credentials.ID = match[2]
				case "ts":
					ts, err := strconv.ParseInt(match[2], 10, 64)
					if err != nil {
						return AuthFormatError{"ts", "not an integer"}
					}
					auth.Timestamp = time.Unix(ts, 0)
				case "nonce":
					auth.Nonce = match[2]

				}
			}
		}

	}

	if len(auth.MAC) == 0 {
		return AuthFormatError{"mac", "missing or empty"}
	}

	return nil
}

var ErrTimestampSkew = errors.New("hawk: timestamp skew too high")
var ErrInvalidMAC = errors.New("hawk: invalid MAC")
var ErrBewitExpired = errors.New("hawk: bewit expired")

func (auth *Auth) Valid() error {
	t := AuthHeader
	if auth.IsBewit {
		t = AuthBewit
		if auth.Method != "GET" && auth.Method != "HEAD" {
			return ErrInvalidBewitMethod
		}
		if auth.ActualTimestamp.After(auth.Timestamp) {
			return ErrBewitExpired
		}
	} else {
		skew := auth.ActualTimestamp.Sub(auth.Timestamp)
		if abs(skew) > MaxTimestampSkew {
			return ErrTimestampSkew
		}
	}
	if !hmacEqual(auth.mac(t), auth.MAC) {
		return ErrInvalidMAC
	}
	return nil
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

var ErrMissingServerAuth = errors.New("hawk: missing Server-Authentication header")

func (auth *Auth) ValidResponse(header string) error {
	if header == "" {
		return ErrMissingServerAuth
	}
	err := auth.ParseHeader(header, AuthResponse)
	if err != nil {
		return err
	}
	if !hmacEqual(auth.mac(AuthResponse), auth.MAC) {
		return ErrInvalidMAC
	}
	return nil
}

func (auth *Auth) PayloadHash(contentType string) hash.Hash {
	h := auth.Credentials.Hash()
	h.Write([]byte("hawk." + headerVersion + ".payload\n" + contentType + "\n"))
	return h
}

func (auth *Auth) ValidHash(h hash.Hash) bool {
	h.Write([]byte("\n"))
	return bytes.Equal(h.Sum(nil), auth.Hash)
}

func (auth *Auth) SetHash(h hash.Hash) {
	h.Write([]byte("\n"))
	auth.Hash = h.Sum(nil)
}

func (auth *Auth) ResponseHeader(ext string) string {
	auth.Ext = ext

	h := `Hawk mac="` + base64.StdEncoding.EncodeToString(auth.mac(AuthResponse)) + `"`
	if auth.Ext != "" {
		h += `, ext="` + auth.Ext + `"`
	}
	if auth.Hash != nil {
		h += `, hash="` + base64.StdEncoding.EncodeToString(auth.Hash) + `"`
	}

	return h
}

func (auth *Auth) RequestHeader() string {
	auth.MAC = auth.mac(AuthHeader)

	h := `Hawk id="` + auth.Credentials.ID +
		`", mac="` + base64.StdEncoding.EncodeToString(auth.MAC) +
		`", ts="` + strconv.FormatInt(auth.Timestamp.Unix(), 10) +
		`", nonce="` + auth.Nonce + `"`

	if len(auth.Hash) > 0 {
		h += `, hash="` + base64.StdEncoding.EncodeToString(auth.Hash) + `"`
	}
	if auth.Ext != "" {
		h += `, ext="` + auth.Ext + `"`
	}
	if auth.App != "" {
		h += `, app="` + auth.App + `"`
	}
	if auth.Delegate != "" {
		h += `, dlg="` + auth.Delegate + `"`
	}

	return h
}

func (auth *Auth) Bewit() string {
	auth.Method = "GET"
	auth.Nonce = ""
	return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(auth.Credentials.ID+`\`+
		strconv.FormatInt(auth.Timestamp.Unix(), 10)+`\`+
		base64.StdEncoding.EncodeToString(auth.mac(AuthBewit))+`\`+
		auth.Ext)), "=")
}

func (auth *Auth) NormalizedString(t AuthType) string {
	str := "hawk." + headerVersion + "." + t.String() + "\n" +
		strconv.FormatInt(auth.Timestamp.Unix(), 10) + "\n" +
		auth.Nonce + "\n" +
		auth.Method + "\n" +
		auth.Path + "\n" +
		auth.Host + "\n" +
		auth.Port + "\n" +
		base64.StdEncoding.EncodeToString(auth.Hash) + "\n" +
		auth.Ext + "\n"

	if auth.App != "" {
		str += auth.App + "\n"
		str += auth.Delegate + "\n"
	}

	return str
}

func (auth *Auth) mac(t AuthType) []byte {
	mac := auth.Credentials.MAC()
	mac.Write([]byte(auth.NormalizedString(t)))
	return mac.Sum(nil)
}

func (auth *Auth) tsMac(ts string) []byte {
	mac := auth.Credentials.MAC()
	mac.Write([]byte("hawk." + headerVersion + ".ts\n" + ts + "\n"))
	return mac.Sum(nil)
}

func (auth *Auth) StaleTimestampHeader() string {
	ts := strconv.FormatInt(Now().Unix(), 10)
	return `Hawk ts="` + ts +
		`", tsm="` + base64.StdEncoding.EncodeToString(auth.tsMac(ts)) +
		`", error="Stale timestamp"`
}

var tsHeaderRegex = regexp.MustCompile(`(ts|tsm|error)="([ !#-\[\]-~]+)"`) // character class is ASCII printable [\x20-\x7E] without \ and "

func (auth *Auth) UpdateOffset(header string) (time.Duration, error) {
	if len(header) < 4 || strings.ToLower(header[:4]) != "hawk" {
		return 0, AuthFormatError{"scheme", "must be Hawk"}
	}

	matches := tsHeaderRegex.FindAllStringSubmatch(header, 3)

	var err error
	var ts time.Time
	var tsm []byte
	var errMsg string

	for _, match := range matches {
		switch match[1] {
		case "ts":
			t, err := strconv.ParseInt(match[2], 10, 64)
			if err != nil {
				return 0, AuthFormatError{"ts", "not an integer"}
			}
			ts = time.Unix(t, 0)
		case "tsm":
			tsm, err = base64.StdEncoding.DecodeString(match[2])
			if err != nil {
				return 0, AuthFormatError{"tsm", "malformed base64 encoding"}
			}
		case "error":
			errMsg = match[2]
		}
	}

	if errMsg != "Stale timestamp" {
		return 0, AuthFormatError{"error", "missing or unknown"}
	}

	if !hmacEqual(tsm, auth.tsMac(strconv.FormatInt(ts.Unix(), 10))) {
		return 0, ErrInvalidMAC
	}

	offset := ts.Sub(Now())
	auth.Timestamp = ts
	auth.Nonce = nonce()
	return offset, nil
}

// Replace with hmac.Equal when Go 1.1 is released
func hmacEqual(mac1, mac2 []byte) bool {
	return len(mac1) == len(mac2) && subtle.ConstantTimeCompare(mac1, mac2) == 1
}
