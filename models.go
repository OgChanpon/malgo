package main

type VTResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious        int `json:"malicious"`
				Suspicious       int `json:"suspicious"`
				Undetected       int `json:"undetected"`
				Harmless         int `json:"harmless"`
				Timeout          int `json:"timeout"`
				ConfirmedTimeout int `json:"confirmed-timeout"`
				Failure          int `json:"failure"`
				TypeUnsupported  int `json:"type-unsupported"`
			} `json:"last_analysis_stats"`

			PopularThreatClassification struct {
				SuggestedThreatLabel string `json:"suggested_threat_label"`
			} `json:"popular_threat_classification"`

			Reputation int `json:"reputation"`

			PeInfo struct {
				ImportList []struct {
					LibraryName       string   `json:"library_name"`
					ImportedFunctions []string `json:"imported_functions"`
				} `json:"import_list"`
			} `json:"pe_info"`

			Tags []string `json:"tags"`
		} `json:"attributes"`
	} `json:"data"`
}
