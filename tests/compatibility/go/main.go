package main

/*
#include <unistd.h>
static int native_answer(void) { return getpid() > 0 ? 42 : 0; }
*/
import "C"

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func main() {
	if int(C.native_answer()) != 42 {
		log.Fatal("CGO call failed")
	}
	if err := checkGit(); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok","runtime":"go","native":true,"answer":42,"git":true}`)
	})
	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func checkGit() error {
	repository, err := os.MkdirTemp("", "tailor-git-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(repository)
	defer os.RemoveAll(repository + "-clone")
	if err := runGit("init", "--quiet", repository); err != nil {
		return err
	}
	if err := runGit(
		"-C",
		repository,
		"-c",
		"user.name=Tailor Fixture",
		"-c",
		"user.email=fixture@example.invalid",
		"commit",
		"--quiet",
		"--allow-empty",
		"-m",
		"fixture",
	); err != nil {
		return err
	}
	return runGit(
		"clone",
		"--quiet",
		repository,
		repository+"-clone",
	)
}

func runGit(args ...string) error {
	output, err := exec.Command("git", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("git failed: %w: %s", err, output)
	}
	return nil
}
