package common

import (
    "net/url"
    "testing"
)

func TestGenerateSignature_WithoutBody(t *testing.T) {
    params := url.Values{}
    params.Add("key", "value")
    var body []byte

    signature1, err := GenerateSignature(params, body, secretKey)
    if err != nil {
        return
    }

    if signature1 == "" {
        t.Errorf("Signature is empty")
    }

    signature2, err := GenerateSignature(params, body, secretKey)

    if signature1 != signature2 {
        t.Errorf("Signatures are not equal")
    }
}

func TestGenerateSignature_WithoutParam(t *testing.T) {
    params := url.Values{}

    body1 := []byte("{  " +
        "\"key\":\"value\"}")
    body2 := []byte("{" +
        "\"key\": \"value\"" +
        "}")

    signature1, err := GenerateSignature(params, body1, secretKey)
    if err != nil {
        return
    }

    if signature1 == "" {
        t.Errorf("Signature is empty")
    }

    signature2, err := GenerateSignature(params, body2, secretKey)

    if signature1 != signature2 {
        t.Errorf("Signatures are not equal")
    }
}

func TestGenerateSignature(t *testing.T) {
    params := url.Values{}
    params.Add("key", "value")
    body1 := []byte("{\"key\": \"value\"}")
    body2 := []byte("{" +
        "\"key\": \"value\"" +
        "}")

    signature1, err := GenerateSignature(params, body1, secretKey)
    if err != nil {
        return
    }

    if signature1 == "" {
        t.Errorf("Signature is empty")
    }

    signature2, err := GenerateSignature(params, body2, secretKey)

    if signature1 != signature2 {
        t.Errorf("Signatures are not equal")
    }
}
