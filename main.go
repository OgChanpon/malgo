package main

import(
	"fmt"
	"net/http"
	"log"
	"io"
	"encoding/json"
)

type VTResponse struct{
	Data struct{
		Attributes struct{
			LastAnalysisStats struct{
				Malicious int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless int `json:"harmless"`
				Timeout int `json:"timeout"`
				ConfirmedTimeout int `json:"confirmed-timeout"`
				Failure int `json:"failure"`
				TypeUnsupported int `json:"type-unsupported"`
			} `json:"last_analysis_stats"`

			PopularThreatClassification struct{
				SuggestedThreatLabel string `json:"suggested_threat_label"`
			} `json:"popular_threat_classification"`

			Reputation int `json:"reputation"`

			PeInfo struct{
				ImportList []struct{
					LibraryName string `json:"library_name"`
					ImportedFunctions []string `json:"imported_functions"`
				} `json:"import_list"`
			} `json:"pe_info"`

			Tags []string `json:"tags"`
		} `json:"attributes"`
	} `json:"data"`
}

func main(){
	var result VTResponse

	url := "https://www.virustotal.com/api/v3/files/"
	hash := "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
	url += hash
	req, err := http.NewRequest("GET", url, nil)
	if err != nil{
		log.Fatal(err)
	}
	
	req.Header.Add("x-apikey", "api")
	
	resp, err :=http.DefaultClient.Do(req)
	if err != nil{
		log.Fatal(err)
	}
	defer resp.Body.Close()	

	b, err := io.ReadAll(resp.Body)
	if err != nil{
		log.Fatal(err)
	}
	//fmt.Println(string(b))

	err = json.Unmarshal(b, &result)
	if err!= nil {
		log.Fatal(err)
	}
	//fmt.Println(result.Data.Attributes.PeInfo.ImportList)

	b, err = json.MarshalIndent(result.Data.Attributes.PeInfo.ImportList, "", " ")
	if err!= nil{
		log.Fatal(err)
	}
	fmt.Println(string(b))
}
