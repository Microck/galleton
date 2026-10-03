package main

import (
	"context"
	"fmt"
	"github.com/Microck/galleton/client"
	"os"
)

func main() {
	dir := os.Getenv("GALLETON_DIR")
	if dir == "" {
		dir = "./state"
	}
	sessions, err := client.FromDir(os.Getenv("GALLETON_URL"), dir)
	if err != nil {
		panic(err)
	}
	response, err := sessions.Request(context.Background(), "demo", "GET", "http://127.0.0.1:9909/me", nil, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(response.Status, string(response.Body))
}
