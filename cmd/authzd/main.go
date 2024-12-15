package main

import (
	"context"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/itsabgr/authz"
	"github.com/itsabgr/authz/db"
	"github.com/itsabgr/authz/db/model"
	_ "github.com/joho/godotenv/autoload"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {

	dbDriverName, dbSourceURI := os.Getenv("DB_DRIVER"), os.Getenv("DB_URI")
	tlsCert, tlsKey := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY")
	serverAddr := os.Getenv("SERVER_ADDR")

	client, err := model.Open(dbDriverName, dbSourceURI)

	if err != nil {
		log.Panicln("failed to connect to database", err)
	}

	func() {
		timeout, cancel := context.WithTimeout(context.Background(), time.Second*2)
		defer cancel()
		if err = client.Schema.Create(timeout); err != nil {
			log.Panicln("failed to migrate database", err)
		}
	}()

	database := db.NewDatabase(client)

	go func() {
		for {
			err = database.Clean(context.Background())
			if err != nil {
				log.Panicln("failed to clean database", err)
			}
			time.Sleep(time.Second * 1)
		}
	}()

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

	fmt.Println(1)

}
