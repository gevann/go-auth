package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func Generate(payloadMap map[string]string, secret string) (string, error) {
	// create a new hash of type sha256. We pass the secret key as the key
	h := hmac.New(sha256.New, []byte(secret))

	headerMap := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	header, err := json.Marshal(headerMap)
	if err != nil {
		return "", err
	}

	header64 := base64.StdEncoding.EncodeToString([]byte(header))

	// We then Marshal the payload, which is a map. This converts it to a string of JSON.
	payload, err := json.Marshal(payloadMap)
	if err != nil {
		fmt.Println("Error marshalling payload:", err)
		return "", err
	}
	payload64 := base64.StdEncoding.EncodeToString(payload)

	// Now add the encoded string.
	message := header64 + "." + payload64

	//we have the unsiged message ready
	unsignedStr := string(header) + string(payload)

	// We write this to the SHA256 to hash it.
	h.Write([]byte(unsignedStr))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Finally we have the token
	token := message + "." + signature

	return token, nil
}
