package authz

import (
	"context"
	"github.com/itsabgr/authz/db"
	"log"
	"net/http"
	"time"
)

type AuthorizationResult struct {
	User      string     `json:"user"`
	Relation  string     `json:"relation"`
	Entity    string     `json:"entity"`
	ExpireAt  *time.Time `json:"expire_at"`
	CreatedAt time.Time  `json:"created_at"`
}

var _ http.Handler = &Server{}

type Server struct {
	mux      *http.ServeMux
	database *db.Database
}

func NewServer(database *db.Database) *Server {
	serv := &Server{
		mux:      http.NewServeMux(),
		database: database,
	}
	serv.init()
	return serv
}

func (serv *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	serv.mux.ServeHTTP(writer, request)
	return
}

func (serv *Server) checkHandler(writer http.ResponseWriter, request *http.Request, user, relation, entity string) {
	switch request.Method {
	case http.MethodGet, http.MethodHead:
	default:
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("Cache-Control", "public, max-age=60")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if user == "" || relation == "" || entity == "" {
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("Cache-Control", "public, max-age=60")
		http.Error(writer, "empty argument", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), time.Second*2)
	defer cancel()

	n, err := serv.database.Check(ctx, user, relation, entity)

	if err != nil {
		log.Println("failed to check", err)
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("Cache-Control", "public, max-age=5")
		http.Error(writer, "internal server errors", http.StatusInternalServerError)
		return
	}

	if n <= 0 {
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("Cache-Control", "public, max-age=5")
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}

	writer.WriteHeader(http.StatusOK)

	writer.Header().Set("Cache-Control", "public, max-age=1")
	writer.Header().Set("Cache-Control", "public, max-age=1")

}

func (serv *Server) init() {

	serv.mux.HandleFunc("GET /authz", func(writer http.ResponseWriter, request *http.Request) {
		serv.checkHandler(writer, request, request.URL.Query().Get("user"), request.URL.Query().Get("rel"), request.URL.Query().Get("ent"))
	})

	serv.mux.HandleFunc("GET /authz/{u}", func(writer http.ResponseWriter, request *http.Request) {
		serv.checkHandler(writer, request, request.PathValue("u"), request.URL.Query().Get("rel"), request.URL.Query().Get("ent"))
	})

	serv.mux.HandleFunc("GET /authz/{u}/{r}", func(writer http.ResponseWriter, request *http.Request) {
		serv.checkHandler(writer, request, request.PathValue("u"), request.PathValue("r"), request.URL.Query().Get("ent"))
	})

	serv.mux.HandleFunc("GET /authz/{u}/{r}/{e}", func(writer http.ResponseWriter, request *http.Request) {
		serv.checkHandler(writer, request, request.PathValue("u"), request.PathValue("r"), request.PathValue("e"))
	})

}
