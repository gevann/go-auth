package web

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gevann/go-auth/jwt"
	"github.com/gevann/go-auth/user"
	"github.com/google/uuid"
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

	_, err := user.AddUserObject(email, fullName, password, 0)

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

func getSignedToken(user user.User) (string, string, error) {
	claimsMap := map[string]string{
		"aud": "frontend.app.com",
		"iss": "go-auth.app.com",
		"sub": user.DbData.ID.String(),
		"exp": fmt.Sprint(time.Now().Add(time.Minute * 1).Unix()),
		"iat": fmt.Sprint(time.Now().Unix()),
	}

	token, err := jwt.Generate(claimsMap, secret)

	if err != nil {
		return "", "", err
	}

	refreshToken, err := jwt.RefreshToken()

	if err != nil {
		return "", "", err
	}

	return token, refreshToken, nil
}

func SigninHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		http.ServeFile(w, r, "./web/static/signin.html")
	case "POST":
		// Get the form values
		email := r.FormValue("email")
		password := r.FormValue("password")
		user, err := user.GetUserObject(email)

		if err != nil || !user.ValidatePasswordHash(password) {
			// write a bad request response
			http.Error(w, "email or password does not exist or match", http.StatusBadRequest)
			return
		}

		token, refreshToken, err := getSignedToken(user)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			log.Println(err)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.Header().Add("X-AuthToken", token)
		cookie := http.Cookie{
			Name:     "X-RefreshToken",
			Value:    refreshToken,
			Expires:  time.Now().Add(time.Hour * 24 * 7),
			HttpOnly: true,
		}
		http.SetCookie(w, &cookie)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	// get the refresh token from the cookie jar
	cookie, err := r.Cookie("X-RefreshToken")
	if err != nil {
		http.Error(w, "No refresh token", http.StatusUnauthorized)
		return
	}

	// validate the refresh token
	check, err := jwt.Validate(cookie.Value, secret)
	if !check || err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// get access token from the header
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		http.Error(w, "No access token", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")

	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	accessToken := parts[1]
	// validate the access token, allowing expired tokens
	payload, err := jwt.ValidateWithoutExpiration(accessToken, secret)

	if err != nil {
		log.Println(err)
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	// get the user from the payload
	if sub, ok := payload["sub"]; ok {
		uuid, err := uuid.Parse(sub)
		if err != nil {
			http.Error(w, "unable to get user", http.StatusUnauthorized)
			return
		}
		user, err := user.GetUserById(uuid)
		if err != nil {
			http.Error(w, "unable to get user", http.StatusUnauthorized)
			return
		}
		token, refreshToken, err := getSignedToken(user)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			log.Println(err)
			return
		}

		w.Header().Set("content-type", "application/json")
		w.Header().Add("X-AuthToken", token)
		cookie := http.Cookie{
			Name:     "X-RefreshToken",
			Value:    refreshToken,
			Expires:  time.Now().Add(time.Hour * 24 * 7),
			HttpOnly: true,
		}
		http.SetCookie(w, &cookie)
		w.WriteHeader(http.StatusOK)
	} else {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
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
