package main

import (
	"context"
	"database/sql"
	"github.com/itsabgr/authz"
	"github.com/itsabgr/authz/db"
	_ "github.com/joho/godotenv/autoload"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {

	pgSourceURI := os.Getenv("PG_URI")
	tlsCert, tlsKey := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY")
	serverAddr := os.Getenv("SERVER_ADDR")

	client, err := sql.Open("postgres", pgSourceURI)

	if err != nil {
		log.Panicln("failed to connect to database", err)
	}

	func() {
		timeout, cancel := context.WithTimeout(context.Background(), time.Second*2)
		defer cancel()
		if err = client.PingContext(timeout); err != nil {
			log.Panicln("failed to ping database", err)
		}
	}()

	database := db.NewDatabase(client)

	httpServer := http.Server{
		Addr:                         serverAddr,
		Handler:                      authz.NewServer(database),
		DisableGeneralOptionsHandler: false,
		ReadTimeout:                  time.Second * 3,
		ReadHeaderTimeout:            time.Second * 3,
		WriteTimeout:                 time.Second * 3,
		IdleTimeout:                  time.Second * 5,
		MaxHeaderBytes:               5000,
		ErrorLog:                     log.Default(),
	}

	log.Println("start")

	if tlsCert != "" || tlsKey != "" {
		err = httpServer.ListenAndServeTLS(tlsCert, tlsKey)
	} else {
		err = httpServer.ListenAndServe()
	}

	if err != nil {
		log.Panicln("failed to serve http", err)
	}

}
