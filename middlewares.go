package common

import (
    "bytes"
    "context"
    "crypto/hmac"
    "errors"
    "io"
    "log"
    "net/http"
    "time"

    "github.com/goccy/go-json"
)

var (
    ErrSignatureMismatch = errors.New("signature mismatch")
)

// handleError is a helper function to handle error responses
func handleError(statusCode int, w http.ResponseWriter, err error) {
    w.WriteHeader(statusCode)
    if err := json.NewEncoder(w).Encode(DefaultErrorResponse(err)); err != nil {
        log.Println("Failed to encode error response", err)
    }
}

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

                // Get signature from the header
                providedSignature := r.Header.Get(XSignature)

                if providedSignature == "" {
                    handleError(http.StatusBadRequest, w, ErrSignatureMismatch)
                    return
                }

                params := r.URL.Query()

                defer func(Body io.ReadCloser) {
                    err := Body.Close()
                    if err != nil {
                        log.Println("Error closing request body", err)
                    }
                }(r.Body)

                buf := new(bytes.Buffer)

                _, err := buf.ReadFrom(r.Body)
                if err != nil {
                    handleError(http.StatusUnprocessableEntity, w, err)
                    return
                }

                body := buf.Bytes()

                // Since the body is read, we can't read it again
                // So we put it back in the request
                r = r.WithContext(context.WithValue(r.Context(), Body, body))

                expectedSignature, err := GenerateSignature(r.Method, r.URL.Path, params, body, signatureKey)

                if err != nil {
                    handleError(http.StatusUnprocessableEntity, w, err)
                    return
                }

                if !hmac.Equal([]byte(providedSignature), []byte(expectedSignature)) {
                    handleError(http.StatusBadRequest, w, ErrSignatureMismatch)
                    return
                }

                next.ServeHTTP(w, r)
            },
        )
    }
}

// AuthorizationMiddleware is a middleware that verifies the token
// and sets the result in the context
func AuthorizationMiddleware[T any](url, signatureKey string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(
            func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set(ContentType, ApplicationJSON)

                // Prepare the request to validate the token
                request, err := http.NewRequest(http.MethodGet, url, nil)
                if err != nil {
                    handleError(http.StatusInternalServerError, w, err)
                    return
                }

                // Add authorization header to the request 
                token := r.Header.Get(Authorization)
                request.Header.Set(ContentType, ApplicationJSON)
                request.Header.Set(Authorization, token)

                // Sign the request 
                sign, err := GenerateSignature(request.Method, request.URL.Path, nil, nil, signatureKey)
                if err != nil {
                    handleError(http.StatusInternalServerError, w, err)
                    return
                }
                request.Header.Set(XSignature, sign)

                // Send the request
                res, err := http.DefaultClient.Do(request)
                if err != nil {
                    handleError(http.StatusInternalServerError, w, err)
                    return
                }
                defer func(Body io.ReadCloser) {
                    err := Body.Close()
                    if err != nil {
                        log.Println("Error closing response body", err)
                    }
                }(res.Body)

                buf := new(bytes.Buffer)
                if _, err = buf.ReadFrom(res.Body); err != nil {
                    handleError(http.StatusInternalServerError, w, err)
                    return
                }

                // If the status code is not OK, return the response 
                if res.StatusCode != http.StatusOK {
                    w.WriteHeader(res.StatusCode)
                    if err = json.NewEncoder(w).Encode(buf.Bytes()); err != nil {
                        log.Println("Failed to encode response", err)
                    }
                    return
                }

                // Unmarshal the response into user struct
                var user T
                if err = json.Unmarshal(buf.Bytes(), &user); err != nil {
                    handleError(http.StatusInternalServerError, w, err)
                    return
                }

                // Add user data to context
                r = r.WithContext(context.WithValue(r.Context(), UserContextKey, &user))

                next.ServeHTTP(w, r)
            },
        )
    }
}
