package common

import (
    "bytes"
    "context"
    "crypto/hmac"
    "errors"
    "net/http"
    "time"

    "github.com/goccy/go-json"
)

var (
    ErrSignatureMismatch = errors.New("signature mismatch")
)

type CorsConfig struct {
    AllowedOrigins string
    AllowedMethods string
    AllowedHeaders string
}

func CorsMiddleware(
    config *CorsConfig,
) func(http.Handler) http.Handler {
    if config == nil {
        config = &CorsConfig{
            AllowedOrigins: "*",
            AllowedMethods: "GET, POST, PUT, DELETE, OPTIONS",
            AllowedHeaders: "*",
        }
    }
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(
            func(w http.ResponseWriter, r *http.Request) {
                // Allow all origins for simplicity
                w.Header().Set("Access-Control-Allow-Origin", config.AllowedOrigins)
                w.Header().Set("Access-Control-Allow-Methods", config.AllowedMethods)
                w.Header().Set("Access-Control-Allow-Headers", config.AllowedHeaders)

                // If it's a preflight request, return 200 OK
                if r.Method == http.MethodOptions {
                    w.WriteHeader(http.StatusOK)
                    return
                }

                // Call the next handler
                next.ServeHTTP(w, r)
            },
        )
    }
}

type RequestLogger interface {
    Println(v ...any)
}

func LoggingMiddleware(
    logger RequestLogger,
) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(
            func(w http.ResponseWriter, r *http.Request) {
                logger.Println(
                    time.Now(),
                    r.Method,
                    r.URL.Path,
                    r.RemoteAddr,
                    r.Header,
                )
                next.ServeHTTP(w, r)
            },
        )
    }
}

// VerifySignatureMiddleware verifies the signature of the request
func VerifySignatureMiddleware(signatureKey string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(
            func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set(ContentType, ApplicationJSON)

                providedSignature := r.Header.Get(XSignature)

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

                body := buf.Bytes()

                r = r.WithContext(context.WithValue(r.Context(), Body, body))

                if len(params) == 0 && buf.String() == "" && providedSignature == "" {
                    next.ServeHTTP(w, r)
                    return
                }

                expectedSignature, err := GenerateSignature(params, body, signatureKey)

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
