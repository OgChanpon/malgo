package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("No API Key")
	}

	hashFlag := flag.String("hash", "", "Target malware hash")
	nameFlag := flag.String("name", "", "Target malware name")
	fileFlag := flag.String("file", "", "File name")
	flag.Parse()
	if *hashFlag != "" {
		b, err := getFileReport(*hashFlag, apiKey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(b))
	} else if *nameFlag != "" {
		fmt.Println("開発中")
	} else if *fileFlag != "" {
		fmt.Println("開発中")
	} else {
		log.Fatal("Input hash or name or file")
	}
}
