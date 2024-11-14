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
    // sort the parameters, if not sorted, the signature will be different
    keys := make([]string, 0, len(params))
    for k := range params {
        keys = append(keys, k)
    }
    sort.Strings(keys)

    // concatenate the parameters and body
    var concatenatedString string
    for _, k := range keys {
        concatenatedString += k + "=" + params.Get(k) + "&"
    }

    // removing all spaces and new lines is important, otherwise the signature will be different
    concatenatedString += strings.ReplaceAll(strings.ReplaceAll(string(body), " ", ""), "\n", "")

    // generate the signature
    h := hmac.New(sha256.New, []byte(secretKey))
    h.Write([]byte(concatenatedString))
    signature := hex.EncodeToString(h.Sum(nil))

    return signature, nil
}
