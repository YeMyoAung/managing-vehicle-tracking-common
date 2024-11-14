package common

import (
    "errors"

    "github.com/dgrijalva/jwt-go"
)

var (
    ErrTokenExpired     = errors.New("token is expired")
    ErrorInvalidToken   = errors.New("token is invalid")
    ErrInvalidSecretKey = errors.New("invalid secret key")
    ErrClaimsInvalid    = errors.New("failed to parse claims")
)

type PayloadInterface interface {
    Valid() error
}

type TokenMaker interface {
    CreateToken(payload PayloadInterface, secretKey string) (string, error)
    VerifyToken(token string, secretKey string, payload PayloadInterface) (PayloadInterface, error)
}

const minSecretKeySize = 32

type JwtMaker struct {
}

func NewJwtMaker() TokenMaker {
    return &JwtMaker{}
}

func (t *JwtMaker) isValidSecretKey(secretKey string) error {
    if len(secretKey) < minSecretKeySize {
        return ErrInvalidSecretKey
    }
    return nil
}

// CreateToken creates a new JWT token
func (t *JwtMaker) CreateToken(payload PayloadInterface, secretKey string) (string, error) {
    if err := t.isValidSecretKey(secretKey); err != nil {
        return "", err
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
    return token.SignedString([]byte(secretKey))
}

// VerifyToken verifies the JWT token
func (t *JwtMaker) VerifyToken(
    tokenString,
    secretKey string,
    payload PayloadInterface,
) (PayloadInterface, error) {
    if err := t.isValidSecretKey(secretKey); err != nil {
        return nil, err
    }

    keyFunc := func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, ErrorInvalidToken
        }
        return []byte(secretKey), nil
    }

    token, err := jwt.ParseWithClaims(tokenString, payload, keyFunc)

    if err != nil {
        var errObj *jwt.ValidationError
        ok := errors.As(err, &errObj)
        if ok && errObj.Errors == jwt.ValidationErrorClaimsInvalid {
            return nil, ErrClaimsInvalid
        }
        if ok && errObj.Errors == jwt.ValidationErrorExpired {
            return nil, ErrTokenExpired
        }
        return nil, err
    }
    return token.Claims, nil
}
