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

func generate(payloadMap map[string]string, secret string) (string, error) {
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

	if err != nil {
		return "", err
	}

	return token, nil
}

func Generate(payloadMap map[string]string, secret string) (string, string, error) {
	accessToken, err := generate(payloadMap, secret)

	if err != nil {
		return "", "", err
	}

	refreshTokenPayloadMap := map[string]string{
		"exp":   strconv.FormatInt(time.Now().Add(time.Hour*24).Unix(), 10),
		"ref":   base64.StdEncoding.EncodeToString([]byte(strconv.FormatInt(time.Now().Unix(), 10))),
		"scope": "refresh",
	}

	refreshToken, err := generate(refreshTokenPayloadMap, secret)

	if err != nil {
		return "", "", err
	}

	// Persist the refresh token in the database with the accessToken
	_, err = InsertRefreshTokenNewFamily(refreshToken, accessToken)

	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func GenerateFromRefreshToken(refreshTokenContent, accessToken, secret string) (string, string, error) {
	var refreshToken RefreshToken
	var newAccessToken string
	var newRefreshToken string
	var err error
	var payload map[string]string
	var refreshTokenPayloadMap map[string]string
	duration := time.Duration(1 * time.Minute)

	refreshToken, err = GetRefreshTokenByContents(refreshTokenContent)

	if err != nil {
		goto INVALIDATE
	}
	if refreshToken.AuthToken != accessToken {
		goto INVALIDATE
	}
	if refreshToken.Valid == false {
		err = fmt.Errorf("Refresh token is not valid")
		goto INVALIDATE
	}

	payload, err = Unmarshal(refreshToken.AuthToken)

	if err != nil {
		goto INVALIDATE
	}

	payload["exp"] = strconv.FormatInt(time.Now().Add(duration).Unix(), 10)

	newAccessToken, err = generate(payload, secret)

	if err != nil {
		goto INVALIDATE
	}

	refreshTokenPayloadMap = map[string]string{
		"exp":   strconv.FormatInt(time.Now().Add(time.Hour*24).Unix(), 10),
		"ref":   base64.StdEncoding.EncodeToString([]byte(strconv.FormatInt(time.Now().Unix(), 10))),
		"scope": "refresh",
	}

	newRefreshToken, err = generate(refreshTokenPayloadMap, secret)

	if err != nil {
		goto INVALIDATE
	}

	// Persist the refresh token in the database with the accessToken
	_, err = InsertRefreshTokenExistingFamily(newRefreshToken, accessToken)
	if err != nil {
		goto INVALIDATE
	}

	return newAccessToken, newRefreshToken, nil

INVALIDATE:
	_ = InvalidateRefreshTokenTree(accessToken)

	return newAccessToken, newRefreshToken, err
}

func validate(token, secret string) (map[string]string, error) {
	// We split the token into its parts
	parts := strings.Split(token, ".")

	// We check that the token is of the right length
	if len(parts) != 3 {
		return nil, fmt.Errorf("Token is not of the correct length")
	}

	// decode header and payload back to strings
	header64 := parts[0]
	payload64 := parts[1]

	header, err := base64.StdEncoding.DecodeString(header64)
	if err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(payload64)
	if err != nil {
		return nil, err
	}

	// again create the signature
	unsignedStr := string(header) + string(payload)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(unsignedStr))

	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// check if the signature is correct
	if signature != parts[2] {
		return nil, fmt.Errorf("Signature is not correct")
	}

	// unmarshal the payload
	var payloadMap map[string]string
	err = json.Unmarshal(payload, &payloadMap)
	if err != nil {
		return nil, err
	}

	return payloadMap, nil
}

func Validate(token, secret string) (bool, error) {
	payload, err := validate(token, secret)
	if err != nil {
		return false, err
	}

	// check if the token is expired
	if payload["exp"] != "" {
		exp, err := strconv.ParseInt(payload["exp"], 10, 64)
		if err != nil {
			return false, err
		}
		if time.Now().Unix() > exp {
			return false, fmt.Errorf("Token is expired")
		}
	}

	return true, nil
}

func ValidateWithoutExpiration(token, secret string) (map[string]string, error) {
	payload, err := validate(token, secret)

	if err != nil {
		return payload, err
	}

	return payload, nil
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
