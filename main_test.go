package common

import (
    "sync"
    "testing"
)

const (
    password     = ""
    hashPassword = ""
    secretKey    = ""
    signatureKey = ""
    rabbitURL    = ""
)

var (
    jwtMaker = sync.Pool{
        New: func() interface{} {
            return NewJwtMaker()
        },
    }
)

func TestMain(t *testing.M) {
    t.Run()
}
