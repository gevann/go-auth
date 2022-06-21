package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
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

func Validate(token, secret string) (bool, error) {
	// We split the token into its parts
	parts := strings.Split(token, ".")

	// We check that the token is of the right length
	if len(parts) != 3 {
		return false, fmt.Errorf("Token is not of the correct length")
	}

	// decode header and payload back to strings
	header64 := parts[0]
	payload64 := parts[1]

	header, err := base64.StdEncoding.DecodeString(header64)
	if err != nil {
		return false, err
	}
	payload, err := base64.StdEncoding.DecodeString(payload64)
	if err != nil {
		return false, err
	}

	// again create the signature
	unsignedStr := string(header) + string(payload)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(unsignedStr))

	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// check if the signature is correct
	if signature != parts[2] {
		return false, fmt.Errorf("Signature is not correct")
	}

	// unmarshal the payload
	var payloadMap map[string]string
	err = json.Unmarshal(payload, &payloadMap)
	if err != nil {
		return false, err
	}

	// check if the token is expired
	if payloadMap["exp"] != "" {
		exp, err := strconv.ParseInt(payloadMap["exp"], 10, 64)
		if err != nil {
			return false, err
		}
		if time.Now().Unix() > exp {
			return false, fmt.Errorf("Token is expired")
		}
	}

	return true, nil
}

// Generates refresh token.
func RefreshToken() (string, error) {
	// This is no securely random, but it's good enough for POC.
	bytes := base64.StdEncoding.EncodeToString([]byte(strconv.FormatInt(time.Now().Unix(), 10)))

	m := map[string]string{
		"exp":   strconv.FormatInt(time.Now().Add(time.Hour*24).Unix(), 10),
		"ref":   bytes,
		"scope": "refresh",
	}

	return Generate(m, "secret")
}

func Unmarshal(token string) (map[string]string, error) {
	// We split the token into its parts
	parts := strings.Split(token, ".")

	// We check that the token is of the right length
	if len(parts) != 3 {
		return nil, fmt.Errorf("Token is not of the correct length")
	}

	// decode header and payload back to strings
	payload64 := parts[1]

	payload, err := base64.StdEncoding.DecodeString(payload64)
	if err != nil {
		return nil, err
	}

	// unmarshal the payload
	var payloadMap map[string]string
	err = json.Unmarshal(payload, &payloadMap)
	if err != nil {
		return nil, err
	}

	return payloadMap, nil
}
