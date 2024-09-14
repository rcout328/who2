package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/lissy93/who-dat/lib"
)

// DomainInfo represents the domain details, including registration length and age
type DomainInfo struct {
	lib.WhoisInfo
	DomainAge           int    `json:"domain_age,omitempty"`
	DomainRegLength     int    `json:"domain_registration_length,omitempty"`
	Error               string `json:"error,omitempty"`
}

// MultiHandler handles Whois requests for multiple domains
func MultiHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure it's a GET request
	if r.Method != http.MethodGet {
		http.Error(w, "Please use a GET request", http.StatusMethodNotAllowed)
		return
	}

	// Extract domains from the query parameter
	domainsQuery := r.URL.Query().Get("domains")
	if domainsQuery == "" {
		http.Error(w, "No domains specified", http.StatusBadRequest)
		return
	}
	domains := strings.Split(domainsQuery, ",")

	// Set up a timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get Whois data for all domains
	allWhois, err := lib.GetMultiWhois(ctx, domains)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Prepare response data with additional domain info
	var domainInfos []DomainInfo
	for _, whois := range allWhois {
		// Calculate domain age and registration length
		domainAge := calculateDomainAge(whois.CreatedDate)
		regLength := calculateDomainRegistrationLength(whois.CreatedDate, whois.ExpirationDate)

		// Create domain info with added details
		domainInfo := DomainInfo{
			WhoisInfo:          whois,
			DomainAge:          domainAge,
			DomainRegLength:    regLength,
		}

		domainInfos = append(domainInfos, domainInfo)
	}

	// Convert Whois data to JSON and send the response
	respondWithJSON(w, http.StatusOK, domainInfos)
}

// calculateDomainAge calculates the age of the domain in days based on the creation date
func calculateDomainAge(createdDate *time.Time) int {
	if createdDate == nil {
		return 0
	}
	return int(time.Since(*createdDate).Hours() / 24)
}

// calculateDomainRegistrationLength calculates the registration length of the domain in days
func calculateDomainRegistrationLength(createdDate, expirationDate *time.Time) int {
	if createdDate == nil || expirationDate == nil {
		return 0
	}
	return int(expirationDate.Sub(*createdDate).Hours() / 24)
}

// respondWithError sends an error response in JSON format
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

// respondWithJSON sends a response in JSON format
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
