package main

// Author: David Vanhoucke <dvanhoucke@redborder.com>

import (
	"fmt"
	"net/http"
)

func main() {
	fmt.Println("[+] Go Web Server starting inside the container on port 8080...")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello David! You are hitting a native Go binary running inside an isolated container namespace.\n")
	})

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("[-] Server failed: %v\n", err)
	}
}
