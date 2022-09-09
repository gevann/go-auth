package web

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/gevann/go-auth/jwt"
)

func PostRefreshHandler(w http.ResponseWriter, r *http.Request) {
	// extract the access token from the header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		// if not, write a 401
		http.Error(w, "authorization header required", http.StatusUnauthorized)
		return
	}

	// check if the authorization header is in the format `Bearer {token}`
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		// if not, write a 401
		http.Error(w, "invalid authorization header", http.StatusUnauthorized)
		return
	}

	// parse the token
	accessToken := parts[1]

	// extract the refresh token from the body
	decoder := json.NewDecoder(r.Body)
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}

	err := decoder.Decode(&body)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	newAccessToken, newRefreshToken, err := jwt.GenerateFromRefreshToken(
		body.RefreshToken,
		accessToken,
		secret,
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// create the response
	type response struct {
		AccessToken  string  `json:"access_token"`
		TokenType    string  `json:"token_type"`
		ExpiresIn    float64 `json:"expires_in"`
		RefreshToken string  `json:"refresh_token"`
	}

	resp := response{
		AccessToken:  newAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: newRefreshToken,
	}
	w.Header().Set("content-type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache") // For http 1.0 compatibility

	encoder := json.NewEncoder(w)
	err = encoder.Encode(resp)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		log.Println(err)
		return
	}
}
