package web

import (
	"net/http"
	"os"

	"github.com/gorilla/handlers"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		handlers.LoggingHandler(os.Stdout, next)
		next.ServeHTTP(w, r)
	})
}
