package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func main() {
	// Defina um flag para aceitar o caminho do arquivo contendo URLs
	urlFile := flag.String("file", "", "Path to the file containing URLs")
	flag.Parse()

	if *urlFile == "" {
		log.Fatal("Please provide the path to a file with URLs using the -file flag")
	}

	// Abra o arquivo de URLs
	file, err := os.Open(*urlFile)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	// Inicialize o Wappalyzer
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		log.Fatalf("Error initializing Wappalyzer: %v", err)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" {
			continue
		}

		// Faça uma solicitação HTTP para obter o conteúdo da página
		resp, err := http.DefaultClient.Get(url)
		if err != nil {
			log.Printf("Error fetching %s: %v", url, err)
			continue
		}
		defer resp.Body.Close()

		// Leia o conteúdo da resposta
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Error reading response body for %s: %v", url, err)
			continue
		}

		// Analise a URL usando o Wappalyzer
		fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)
		fmt.Printf("Technologies for %s:\n", url)
		for tech := range fingerprints {
			fmt.Printf(" - %s\n", tech)
		}
		fmt.Printf("%s\n", strings.Repeat("-", 40))
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
}

