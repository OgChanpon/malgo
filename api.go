package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

func getFileReport(hash string, apiKey string) ([]byte, error) {
	var result VTResponse

	url := "https://www.virustotal.com/api/v3/files/"
	url += hash
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("x-apikey", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println(string(b))

	err = json.Unmarshal(b, &result)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println(result.Data.Attributes.PeInfo.ImportList)

	b, err = json.MarshalIndent(result.Data.Attributes.PeInfo.ImportList, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	return b, nil
}
