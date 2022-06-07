package web

import (
	"log"

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

	v1.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("test"))
		if err != nil {
			log.Println(err)
		}
	})
	api.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("test"))
		if err != nil {
			log.Println(err)
		}
	})
	v1.Use(tokenValidationMiddleware)
	r.Use(loggingMiddleware)

	log.Fatal(http.ListenAndServe(":8080", r))
}
