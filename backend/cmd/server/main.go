package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"identity-center/backend/internal/app"
	"identity-center/backend/internal/config"
	"identity-center/backend/internal/db"
	"identity-center/backend/internal/programcli"
	"identity-center/backend/internal/security"
	"identity-center/backend/internal/store"
)

func main() {
	if handled, err := programcli.Run(os.Args[1:], os.Stdout, os.Stderr); handled {
		if err != nil {
			_, _ = os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		return
	}

	logger := log.New(os.Stdout, "[backend] ", log.LstdFlags|log.Lmicroseconds)
	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("load config failed: %v", err)
	}
	conn, err := db.Open(cfg.DBPath)
	if err != nil {
		logger.Fatalf("open db failed: %v", err)
	}
	defer conn.Close()

	schemaPath := strings.TrimSpace(os.Getenv("AUTH_SCHEMA_PATH"))
	if schemaPath != "" {
		if err := db.InitSchema(conn, schemaPath); err != nil {
			logger.Fatalf("init schema failed: %v", err)
		}
	} else if err := db.InitEmbeddedSchema(conn); err != nil {
		logger.Fatalf("init embedded schema failed: %v", err)
	}

	st := store.New(conn)
	keys := security.NewKeyManager(conn)
	server, err := app.New(cfg, st, keys, logger)
	if err != nil {
		logger.Fatalf("init app failed: %v", err)
	}
	defer server.Close()

	httpServer := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.ServerPort),
		Handler:           app.NewProgramHandler(cfg.FrontendDistDir, server.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		logger.Printf("listening on %s", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("listen failed: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = httpServer.Close()
}
