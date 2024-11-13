package common

import (
    "sync"
    "testing"
)

const (
    password     = "admin@123"
    hashPassword = "$2a$10$rCV7ee/Jr1VqHMAHCkTDgus2DsrrBXyFJHSOMKAMNL0nXSNkz/l2S"
    secretKey    = "abcdefghijklmnopqrstuvwfdakjfasklfjdasxyz"
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
