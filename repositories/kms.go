// Package repositories provides data access implementations for keys and external services.
package repositories

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime/secret"
	"time"
)

type KMSAuth struct {
	cert   *string
	key    *string
	cacert *string
}

func NewKMSClientCertificateAuth(cert, key, cacert string) *KMSAuth {
	if cert == "" || key == "" || cacert == "" {
		return nil
	}
	return &KMSAuth{
		cert:   &cert,
		key:    &key,
		cacert: &cacert,
	}
}

func (a *KMSAuth) IsClientCertAuth() bool {
	if a == nil {
		return false
	}
	return a.cert != nil && a.key != nil && a.cacert != nil
}

type kmsKey struct {
	ID  string `json:"key_ID"`
	Key string `json:"key"`
}

type kmsResponse struct {
	Keys []kmsKey `json:"keys"`
}

type HTTPKMSRepository struct {
	baseURL          string
	maxRetries       int
	backoffBaseDelay time.Duration
	conn             *http.Client
	Managed          bool
}

func NewHTTPKMSRepository(url string, timeout time.Duration, maxRetries int, backoffBaseDelay time.Duration, auth *KMSAuth) *HTTPKMSRepository {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// InsecureSkipVerify: true, // removed as fix for GHSA-rc6v-5rmx-w5mv 
			MinVersion: tls.VersionTLS12,
		},
		Proxy: http.ProxyFromEnvironment,
	}
	if auth.IsClientCertAuth() {
		clientCert, err := tls.LoadX509KeyPair(*auth.cert, *auth.key)
		if err != nil {
			log.Fatal(err)
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
		caCert, err := os.ReadFile(*auth.cacert)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tr.TLSClientConfig.RootCAs = caCertPool
	}
	return &HTTPKMSRepository{
		baseURL:          url,
		maxRetries:       maxRetries,
		backoffBaseDelay: backoffBaseDelay,
		conn: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
		Managed: true,
	}
}

func (r *HTTPKMSRepository) GetNewKey() (keyID string, key []byte, err error) {
	return r.kmsRequest("/enc_keys?number=1&size=256")
}

func (r *HTTPKMSRepository) GetKeyByID(keyID *string) (key []byte, err error) {
	if keyID == nil || *keyID == "" {
		return nil, fmt.Errorf("keyID is empty")
	}
	_, key, err = r.kmsRequest("/dec_keys?key_ID=" + *keyID)
	return key, err
}

func (r *HTTPKMSRepository) kmsRequest(path string) (id string, key []byte, err error) {
	var kmsResp kmsResponse
	var res *http.Response

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		res, err = r.conn.Get(r.baseURL + path)
		if err == nil && res.StatusCode == http.StatusOK {
			break
		}
		// Close and clear before deciding whether to retry, so that a body is
		// never carried out of the loop after being closed. Previously the
		// close happened after the retry decision and res kept its value, so
		// a non-OK status on the final attempt left a closed body in res --
		// and because a 4xx/5xx is a successful HTTP transaction, err was nil
		// and the check below did not return. io.ReadAll then failed with
		// "http: read on closed response body".
		if res != nil {
			_ = res.Body.Close()
			res = nil
		}
		if attempt < r.maxRetries {
			delay := r.backoffBaseDelay * time.Duration(1<<uint(attempt))
			log.Printf("Attempt %d: Retrying in %s...", attempt+1, delay)
			time.Sleep(delay)
		}
	}
	if err != nil {
		return "", nil, err
	}
	// A retry loop that never saw a 200 leaves res nil. Without this the
	// caller could not distinguish "the KMS refused" from a successful fetch,
	// because a non-OK status sets no error of its own.
	if res == nil {
		return "", nil, fmt.Errorf("KMS did not return %d after %d attempt(s)",
			http.StatusOK, r.maxRetries+1)
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", nil, err
	}
	defer clear(body)
	if err := json.Unmarshal(body, &kmsResp); err != nil {
		return "", nil, fmt.Errorf("cant parse KMS response: %w", err)
	}
	if len(kmsResp.Keys) == 0 || kmsResp.Keys[0].ID == "" || kmsResp.Keys[0].Key == "" {
		return "", nil, fmt.Errorf("unable to fetch key from KMS")
	}

	var rawKey []byte
	secret.Do(func() {
		rawKey, err = base64.StdEncoding.DecodeString(kmsResp.Keys[0].Key)
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode KMS key: %w", err)
	}
	return kmsResp.Keys[0].ID, rawKey, nil
}
