package common

import (
    "bytes"
    "context"
    "crypto/hmac"
    "errors"
    "log"
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

// CorsMiddleware adds CORS headers to the response
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

// LoggingMiddleware logs the request
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

                expectedSignature, err := GenerateSignature(r.Method, r.URL.Path, params, body, signatureKey)

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

// AuthorizationMiddleware is a middleware that verifies the token
// and sets the result in the context
func AuthorizationMiddleware[T any](url string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(
            func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set(ContentType, ApplicationJSON)
                request, err := http.NewRequest(
                    http.MethodGet,
                    url,
                    nil,
                )
                if err != nil {
                    w.WriteHeader(http.StatusInternalServerError)
                    if err = json.NewEncoder(w).Encode(DefaultErrorResponse(err)); err != nil {
                        log.Println("Failed to encode response", err)
                    }
                    return
                }

                token := r.Header.Get(Authorization)

                request.Header.Set(ContentType, ApplicationJSON)
                request.Header.Set(Authorization, token)
                sign, err := GenerateSignature(request.Method, request.URL.Path, nil, nil, token)
                if err != nil {
                    w.WriteHeader(http.StatusInternalServerError)
                    if err = json.NewEncoder(w).Encode(DefaultErrorResponse(err)); err != nil {
                        log.Println("Failed to encode response", err)
                    }
                    return
                }

                request.Header.Set(XSignature, sign)

                res, err := http.DefaultClient.Do(request)
                if err != nil {
                    w.WriteHeader(http.StatusInternalServerError)
                    if err = json.NewEncoder(w).Encode(DefaultErrorResponse(err)); err != nil {
                        log.Println("Failed to encode response", err)
                    }
                    return
                }

                if res.StatusCode != http.StatusOK {
                    w.WriteHeader(res.StatusCode)
                    if err = json.NewEncoder(w).Encode(DefaultErrorResponse(errors.New("unauthorized"))); err != nil {
                        log.Println("Failed to encode response", err)
                    }
                    return
                }

                buf := new(bytes.Buffer)

                if _, err = buf.ReadFrom(res.Body); err != nil {
                    w.WriteHeader(http.StatusBadRequest)
                    if err = json.NewEncoder(w).Encode(DefaultErrorResponse(err)); err != nil {
                        log.Println("Failed to encode response", err)
                    }
                    return
                }

                var user T

                if err = json.Unmarshal(buf.Bytes(), &user); err != nil {
                    w.WriteHeader(http.StatusBadRequest)
                    if err = json.NewEncoder(w).Encode(DefaultErrorResponse(err)); err != nil {
                        log.Println("Failed to encode response", err)
                    }
                    return
                }

                r = r.WithContext(context.WithValue(r.Context(), UserContextKey, &user))

                next.ServeHTTP(w, r)
            },
        )
    }
}
