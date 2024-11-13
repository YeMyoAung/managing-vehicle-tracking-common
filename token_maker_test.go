package common

import (
    "testing"
    "time"

    "github.com/dgrijalva/jwt-go"
)

type CustomPayload struct {
    ID        string
    ExpiredAt time.Time
}

func (p *CustomPayload) Valid() error {
    if time.Now().After(p.ExpiredAt) {
        return ErrTokenExpired
    }
    return nil
}

func TestJwtMaker_CreateToken(t *testing.T) {
    maker := jwtMaker.Get().(*JwtMaker)
    _, err := maker.CreateToken(
        &CustomPayload{
            ID:        "123",
            ExpiredAt: time.Now().Add(5 * time.Minute),
        }, secretKey,
    )
    if err != nil {
        t.Fatalf("Failed to create token: %v", err)
    }
    jwtMaker.Put(maker)
}

func TestJwtMaker_VerifyToken(t *testing.T) {
    maker := jwtMaker.Get().(*JwtMaker)
    token, err := maker.CreateToken(
        &CustomPayload{
            ID:        "123",
            ExpiredAt: time.Now().Add(5 * time.Minute),
        }, secretKey,
    )
    if err != nil {
        t.Fatalf("Failed to create token: %v", err)
    }
    jwtMaker.Put(maker)
    payload, err := maker.VerifyToken(token, secretKey, &CustomPayload{})

    if err != nil {
        t.Fatalf("Failed to verify token: %v", err)
    }

    if _, ok := payload.(*CustomPayload); !ok {
        t.Fatalf("Invalid payload")
    }
}

func TestJwtMakerMustInvalid(t *testing.T) {
    maker := jwtMaker.Get().(*JwtMaker)
    token, err := maker.CreateToken(
        &jwt.StandardClaims{
            Id:        "123",
            ExpiresAt: time.Now().Add(-5 * time.Minute).Unix(),
        }, secretKey,
    )
    if err != nil {
        t.Fatalf("Failed to create token: %v", err)
    }
    _, err = maker.VerifyToken(token, secretKey, &jwt.StandardClaims{})
    if err == nil {
        t.Fatalf("Token should be invalid")
    }
    jwtMaker.Put(maker)
}
