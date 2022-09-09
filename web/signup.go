package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gevann/go-auth/jwt"
	"github.com/gevann/go-auth/user"
)

// This is not secure. It is just for testing purposes.
var secret = "secret"

func GetSignupHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		http.ServeFile(w, r, "./web/static/signup.html")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func PostSignupHandler(w http.ResponseWriter, r *http.Request) {
	// Get the form values
	email := r.FormValue("email")
	password := user.HashPassword(r.FormValue("password"))

	fullName := r.FormValue("fullName")

	_, err := user.InsertUser(email, fullName, password, 0)

	if err != nil {
		// write a bad request response
		fmt.Printf("Error adding users object: %s", err)
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	// write a 201 response
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write([]byte("User created"))
	if err != nil {
		http.Error(w, "Error writing response", http.StatusInternalServerError)
		return
	}
}

func getSignedToken(user user.User) (string, string, time.Duration, error) {
	duration := time.Duration(1 * time.Minute)
	claimsMap := map[string]string{
		"aud": "frontend.app.com",
		"iss": "go-auth.app.com",
		"sub": user.DbData.ID.String(),
		"exp": fmt.Sprint(time.Now().Add(duration).Unix()),
		"iat": fmt.Sprint(time.Now().Unix()),
	}

	token, refreshToken, err := jwt.Generate(claimsMap, secret)

	if err != nil {
		return "", "", duration, err
	}

	return token, refreshToken, duration, nil
}

func SigninHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		http.ServeFile(w, r, "./web/static/signin.html")
	case "POST":
		// Get the form values
		email := r.FormValue("email")
		password := r.FormValue("password")
		user, err := user.GetUserByEmail(email)

		if err != nil || !user.ValidatePasswordHash(password) {
			// write a bad request response
			http.Error(w, "email or password does not exist or match", http.StatusBadRequest)
			return
		}

		token, refreshToken, duration, err := getSignedToken(user)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			log.Println(err)
			return
		}
		w.Header().Set("content-type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache") // For http 1.0 compatibility
		type response struct {
			AccessToken  string  `json:"access_token"`
			TokenType    string  `json:"token_type"`
			ExpiresIn    float64 `json:"expires_in"`
			RefreshToken string  `json:"refresh_token"`
		}

		resp := response{
			AccessToken:  token,
			TokenType:    "Bearer",
			ExpiresIn:    duration.Seconds(),
			RefreshToken: refreshToken,
		}

		encoder := json.NewEncoder(w)
		err = encoder.Encode(resp)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			log.Println(err)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func tokenValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check if the request has an authorization header
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
		tokenString := parts[1]
		check, err := jwt.Validate(tokenString, secret)
		if err != nil {
			// if there is an error, write a 500
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !check {
			// if there is no error but the token is not valid, write a 401
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// if there is no error, call the next handler
		next.ServeHTTP(w, r)
	})
}
