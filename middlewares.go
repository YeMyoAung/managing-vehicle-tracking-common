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

var (
    HttpClient = &http.Client{
        // 4 seconds is more than enough 
        Timeout: 4 * time.Second,
    }
)

// HandleError is a helper function to handle error responses
func HandleError(statusCode int, w http.ResponseWriter, err error) {
    w.WriteHeader(statusCode)
    if err := json.NewEncoder(w).Encode(DefaultErrorResponse(err)); err != nil {
        log.Println("Failed to encode error response", err)
    }
}

type middlewareChan[T any] struct {
    Err        error
    StatusCode int
    Value      T
}

type middlewareResponse middlewareChan[[]byte]

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
                    HandleError(http.StatusBadRequest, w, ErrSignatureMismatch)
                    return
                }

                params := r.URL.Query()

                defer func(Body io.ReadCloser) {
                    err := Body.Close()
                    if err != nil {
                        log.Println("Error closing request body", err)
                    }
                }(r.Body)

                // instead of io.ReadAll, we use a buffer to read the body (more efficient)
                buf := new(bytes.Buffer)

                _, err := buf.ReadFrom(r.Body)
                if err != nil {
                    HandleError(http.StatusUnprocessableEntity, w, err)
                    return
                }

                body := buf.Bytes()

                // Since the body is read, we can't read it again
                // So we put it back in the request
                r = r.WithContext(context.WithValue(r.Context(), Body, body))

                expectedSignature, err := GenerateSignature(r.Method, r.URL.Path, params, body, signatureKey)

                if err != nil {
                    HandleError(http.StatusUnprocessableEntity, w, err)
                    return
                }

                if !hmac.Equal([]byte(providedSignature), []byte(expectedSignature)) {
                    HandleError(http.StatusBadRequest, w, ErrSignatureMismatch)
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

                result := make(chan middlewareResponse, 1)

                // For concurrency, we run the request in a goroutine 
                go func(url, authorization, signatureKey string, result chan<- middlewareResponse) {
                    defer close(result)
                    // Prepare the request to validate the token
                    request, err := http.NewRequest(http.MethodGet, url, nil)
                    if err != nil {
                        result <- middlewareResponse{Err: err, StatusCode: http.StatusInternalServerError}
                        // HandleError(http.StatusInternalServerError, w, err)
                        return
                    }
                    request.Header.Set(ContentType, ApplicationJSON)
                    // Add authorization header to the request 
                    request.Header.Set(Authorization, authorization)
                    // Sign the request 
                    sign, err := GenerateSignature(request.Method, request.URL.Path, nil, nil, signatureKey)
                    if err != nil {
                        result <- middlewareResponse{Err: err, StatusCode: http.StatusInternalServerError}
                        // HandleError(http.StatusInternalServerError, w, err)
                        return
                    }
                    // Add the signature to the request header
                    request.Header.Set(XSignature, sign)
                    // Send the request
                    res, err := HttpClient.Do(request)
                    if err != nil {
                        result <- middlewareResponse{Err: err, StatusCode: http.StatusInternalServerError}
                        // HandleError(http.StatusInternalServerError, w, err)
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
                        // HandleError(http.StatusInternalServerError, w, err)
                        result <- middlewareResponse{Err: err, StatusCode: http.StatusInternalServerError}
                        return
                    }
                    result <- middlewareResponse{Value: buf.Bytes(), StatusCode: res.StatusCode}
                }(url, r.Header.Get(Authorization), signatureKey, result)

                res := <-result

                if res.Err != nil {
                    HandleError(res.StatusCode, w, res.Err)
                    return
                }

                // If the status code is not OK, return the response 
                if res.StatusCode != http.StatusOK {
                    w.WriteHeader(res.StatusCode)
                    var response Response
                    if err := json.Unmarshal(res.Value, &response); err != nil {
                        HandleError(http.StatusInternalServerError, w, err)
                        return
                    }
                    if err := json.NewEncoder(w).Encode(response); err != nil {
                        log.Println("Failed to encode response", err)
                    }
                    return
                }

                // Unmarshal the response into user struct
                var user T
                if err := json.Unmarshal(res.Value, &user); err != nil {
                    HandleError(http.StatusInternalServerError, w, err)
                    return
                }

                // Add user data to context
                r = r.WithContext(context.WithValue(r.Context(), UserContextKey, &user))

                next.ServeHTTP(w, r)
            },
        )
    }
}
