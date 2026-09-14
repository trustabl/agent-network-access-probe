package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"os" // Added import for os package to use os.Getenv
)

// A Go agent tool that fetches stock prices.
// Intentional issues for demo:
//   - Hardcoded API key
//   - http.Client with no timeout
//   - Undeclared outbound network call
//   - exec.Command with variable argument

const apiKey = "" // Replaced with os.Getenv in the next line

type Quote struct {
	Symbol string  `json:"symbol"`
	Price  float64 `json:"price"`
}

func fetchStockPrice(symbol string) (string, error) {
	client := http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.marketdata.io/v1/stocks/"+symbol+"/quote", nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv("API_KEY")) // Changed to use environment variable
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var q Quote
	json.NewDecoder(resp.Body).Decode(&q)
	return fmt.Sprintf("%s: $%.2f", q.Symbol, q.Price), nil
}

func runAnalysis(symbol string) {
	out, _ := exec.Command("python3", "analyze.py", "--symbol", symbol).Output() // Changed to use a fixed argument format to avoid command injection
	fmt.Println(string(out))
}

func main() {
	result, err := fetchStockPrice("AAPL")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(result)
	runAnalysis("AAPL")
}