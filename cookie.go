package workos

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	stateCookieName       = "__vango_workos_state"
	cookieEnvelopeVersion = byte(1)
	stateCookieMaxAge     = 10 * time.Minute
)

type cookieSession struct {
	V            int       `json:"v"`
	IssuedAtUnix int64     `json:"iat_unix_ms"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IdentityHint *Identity `json:"identity_hint,omitempty"`
}

func cookieKeyFromSecret(secret string) [32]byte {
	return sha256.Sum256([]byte(secret))
}

func sameSiteFromConfig(v string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func setStateCookie(w http.ResponseWriter, state string, cfg Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: sameSiteFromConfig(cfg.CookieSameSite),
		MaxAge:   int(stateCookieMaxAge.Seconds()),
	})
}

func validateStateCookie(r *http.Request, wantState string, _ Config) bool {
	if wantState == "" {
		return false
	}
	c, err := r.Cookie(stateCookieName)
	if err != nil || c == nil || c.Value == "" {
		return false
	}
	return c.Value == wantState
}

func clearStateCookie(w http.ResponseWriter, cfg Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: sameSiteFromConfig(cfg.CookieSameSite),
		MaxAge:   -1,
	})
}

func sealCookieSession(sess *cookieSession, secret string, aad string) (string, error) {
	if sess == nil {
		return "", errors.New("workos: nil session")
	}
	key := cookieKeyFromSecret(secret)

	plain, err := json.Marshal(sess)
	if err != nil {
		return "", &SafeError{msg: "workos: failed to serialize cookie session", cause: err}
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", &SafeError{msg: "workos: failed to initialize cookie cipher", cause: err}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", &SafeError{msg: "workos: failed to initialize cookie AEAD", cause: err}
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", &SafeError{msg: "workos: failed to generate cookie nonce", cause: err}
	}

	ciphertext := gcm.Seal(nil, nonce, plain, []byte(aad))

	raw := make([]byte, 0, 1+len(nonce)+len(ciphertext))
	raw = append(raw, cookieEnvelopeVersion)
	raw = append(raw, nonce...)
	raw = append(raw, ciphertext...)

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func openCookieSession(value string, secret string, aad string) (*cookieSession, error) {
	if value == "" {
		return nil, errors.New("workos: empty cookie value")
	}

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, &SafeError{msg: "workos: invalid cookie encoding", cause: err}
	}
	if len(raw) < 1 {
		return nil, errors.New("workos: invalid cookie payload")
	}
	if raw[0] != cookieEnvelopeVersion {
		return nil, errors.New("workos: unsupported cookie version")
	}

	key := cookieKeyFromSecret(secret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, &SafeError{msg: "workos: failed to initialize cookie cipher", cause: err}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &SafeError{msg: "workos: failed to initialize cookie AEAD", cause: err}
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < 1+nonceSize+gcm.Overhead() {
		return nil, errors.New("workos: invalid cookie payload")
	}

	nonce := raw[1 : 1+nonceSize]
	ciphertext := raw[1+nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, &SafeError{msg: "workos: cookie decryption failed", cause: err}
	}

	var sess cookieSession
	if err := json.Unmarshal(plain, &sess); err != nil {
		return nil, &SafeError{msg: "workos: cookie decode failed", cause: err}
	}
	return &sess, nil
}

func setSessionCookie(w http.ResponseWriter, sess *cookieSession, cfg Config) error {
	if sess == nil {
		return errors.New("workos: nil cookie session")
	}
	sess.V = 1
	if sess.IssuedAtUnix == 0 {
		sess.IssuedAtUnix = time.Now().UnixMilli()
	}

	if cfg.CookieName == "" {
		cfg.CookieName = "__vango_workos_session"
	}
	if cfg.CookieMaxAge == 0 {
		cfg.CookieMaxAge = 7 * 24 * time.Hour
	}
	if cfg.CookieSameSite == "" {
		cfg.CookieSameSite = "lax"
	}

	val, err := sealCookieSession(sess, cfg.CookieSecret, cfg.CookieName)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: sameSiteFromConfig(cfg.CookieSameSite),
		MaxAge:   int(cfg.CookieMaxAge.Seconds()),
	})
	return nil
}

func readSessionCookie(r *http.Request, cfg Config) (*cookieSession, error) {
	if cfg.CookieName == "" {
		cfg.CookieName = "__vango_workos_session"
	}

	c, err := r.Cookie(cfg.CookieName)
	if err != nil || c == nil || c.Value == "" {
		return nil, err
	}

	aad := cfg.CookieName
	if sess, err := openCookieSession(c.Value, cfg.CookieSecret, aad); err == nil {
		return sess, nil
	}
	for _, fb := range cfg.CookieSecretFallbacks {
		sess, err := openCookieSession(c.Value, fb, aad)
		if err == nil {
			return sess, nil
		}
	}
	return nil, errors.New("workos: cookie invalid")
}

func clearSessionCookie(w http.ResponseWriter, cfg Config) {
	if cfg.CookieName == "" {
		cfg.CookieName = "__vango_workos_session"
	}
	if cfg.CookieSameSite == "" {
		cfg.CookieSameSite = "lax"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: sameSiteFromConfig(cfg.CookieSameSite),
		MaxAge:   -1,
	})
}
