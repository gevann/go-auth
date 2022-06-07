package web

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gevann/go-auth/jwt"
	"github.com/gevann/go-auth/user"
)

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

func getSignedToken(user user.User) (string, error) {
	claimsMap := map[string]string{
		"aud": "frontend.app.com",
		"iss": "go-auth.app.com",
		"sub": user.DbData.ID.String(),
		"exp": fmt.Sprint(time.Now().Add(time.Minute * 1).Unix()),
		"iat": fmt.Sprint(time.Now().Unix()),
	}

	secret := "secret"
	token, err := jwt.Generate(claimsMap, secret)

	if err != nil {
		return "", err
	}

	return token, nil
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

		token, err := getSignedToken(user)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			log.Println(err)
			return
		}
		// write a 200 response
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(token))
		if err != nil {
			http.Error(w, "Error writing response", http.StatusInternalServerError)
			return
		}
	}
}

func tokenValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return if request is GET signin
		if r.Method == "GET" && strings.Contains(r.URL.Path, "signin") {
			fmt.Println("GET signin")
			_, err := w.Write([]byte(`
            <!DOCTYPE html>
<html>
    <head>
        <title>Sign In</title>
    </head>
    <body>
        <form action="/auth/signin" method="POST">
            <input type="text" name="email" placeholder="Email" />
            <input type="password" name="password" placeholder="Password" />
            <input type="submit" value="Sign In" />
        </form>
    </body>
</html>`))

			if err != nil {
				http.Error(w, "Error writing response", http.StatusInternalServerError)
				return
			}
			return
		}
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
		check, err := jwt.Validate(tokenString, "secret")
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

		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte("Authorized Token"))
		if err != nil {
			http.Error(w, "Error writing response", http.StatusInternalServerError)
			return
		}
	})
}
