package common

import (
    "testing"
)

func TestHashPassword(t *testing.T) {
    hashPassword, err := HashPassword(password)
    if err != nil {
        t.Fatal(err)
    }

    if hashPassword == "" {
        t.Fatal("Hash password should not be empty")
    }

    if hashPassword == password {
        t.Fatal("Hash password should not be equal to password")
    }

    if len(hashPassword) < 60 {
        t.Fatal("Hash password should be at least 60 characters")
    }
}

func TestCheckPasswordHash(t *testing.T) {
    hashPassword, err := HashPassword(password)
    if err != nil {
        t.Fatal(err)
    }

    if hashPassword == "" {
        t.Fatal("Hash password should not be empty")
    }

    if hashPassword == password {
        t.Fatal("Hash password should not be equal to password")
    }

    if len(hashPassword) < 60 {
        t.Fatal("Hash password should be at least 60 characters")
    }

    if !CheckPasswordHash(password, hashPassword) {
        t.Fatal("Hash password should be valid")
    }
}

func TestCheckPasswordHash_MustFail(t *testing.T) {
    if CheckPasswordHash(password, hashPassword) {
        t.Fatal("Hash password should be invalid")
    }
}
