package common

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "net/url"
    "sort"
    "strings"
)

// GenerateSignature generates a signature for the given parameters and body
func GenerateSignature(params url.Values, body []byte, secretKey string) (string, error) {
    keys := make([]string, 0, len(params))
    for k := range params {
        keys = append(keys, k)
    }
    sort.Strings(keys)

    var concatenatedString string
    for _, k := range keys {
        concatenatedString += k + "=" + params.Get(k) + "&"
    }
    concatenatedString += strings.ReplaceAll(strings.ReplaceAll(string(body), " ", ""), "\n", "")

    h := hmac.New(sha256.New, []byte(secretKey))
    h.Write([]byte(concatenatedString))
    signature := hex.EncodeToString(h.Sum(nil))

    return signature, nil
}
