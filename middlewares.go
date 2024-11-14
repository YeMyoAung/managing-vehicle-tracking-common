package common

import (
    "bytes"
    "crypto/hmac"
    "errors"
    "net/http"

    "github.com/goccy/go-json"
)

var (
    ErrSignatureMismatch = errors.New("signature mismatch")
)

// VerifySignatureMiddleware verifies the signature of the request
func VerifySignatureMiddleware(signatureKey string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(
            func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")

                providedSignature := r.Header.Get("X-Signature")

                params := r.URL.Query()

                buf := new(bytes.Buffer)

                _, err := buf.ReadFrom(r.Body)
                if err != nil {
                    w.WriteHeader(http.StatusUnprocessableEntity)
                    err := json.NewEncoder(w).Encode(DefaultErrorResponse(err))
                    if err != nil {
                        return
                    }
                    return
                }

                if len(params) == 0 && buf.String() == "" && providedSignature == "" {
                    next.ServeHTTP(w, r)
                    return
                }

                expectedSignature, err := GenerateSignature(params, buf.Bytes(), signatureKey)

                if err != nil {
                    w.WriteHeader(http.StatusUnprocessableEntity)
                    err := json.NewEncoder(w).Encode(DefaultErrorResponse(err))
                    if err != nil {
                        return
                    }
                    return
                }

                if !hmac.Equal([]byte(providedSignature), []byte(expectedSignature)) {
                    w.WriteHeader(http.StatusBadRequest)
                    err := json.NewEncoder(w).Encode(DefaultErrorResponse(ErrSignatureMismatch))
                    if err != nil {
                        return
                    }
                    return
                }
                next.ServeHTTP(w, r)
            },
        )
    }
}
