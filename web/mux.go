package web

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/gevann/go-auth/jwt"
	"github.com/gevann/go-auth/user"
	"github.com/google/uuid"

	"github.com/gorilla/mux"

	"net/http"
)

func StartServer() {
	r := mux.NewRouter()
	api := r.PathPrefix("/api").Subrouter()
	v1 := api.PathPrefix("/v1").Subrouter()

	r.HandleFunc("/signup", PostSignupHandler).Methods("POST")
	r.HandleFunc("/signup", GetSignupHandler).Methods("GET")
	r.HandleFunc("/signin", SigninHandler).Methods("POST", "GET")
	r.HandleFunc("/refresh", RefreshTokenHandler).Methods("POST")
	v1.Use(tokenValidationMiddleware)

	v1.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("test"))
		if err != nil {
			log.Println(err)
		}
	})
	v1.HandleFunc("/me", GetMeHandler).Methods("GET")

	r.Use(loggingMiddleware)

	log.Fatal(http.ListenAndServe(":8080", r))
}

func GetMeHandler(w http.ResponseWriter, r *http.Request) {
	// extract the token from the request
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
	token := parts[1]
	// unmarshal the token payload
	claims, err := jwt.Unmarshal(token)

	if err != nil {
		http.Error(w, "unable to parse token", http.StatusUnauthorized)
		return
	}

	if sub, ok := claims["sub"]; ok {
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

		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		// encode user as JSON and write it to the response
		err = json.NewEncoder(w).Encode(user)

		if err != nil {
			http.Error(w, "unable to write user", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "unable to get user", http.StatusUnauthorized)
	}
}
