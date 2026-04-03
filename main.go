package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"webhookimageanalysis/trivycheckcves"
	"webhookimageanalysis/utils"
)

var severitiesthreshold map[string]int = make(map[string]int, 0)

func envThresholdsParse(severitiesthreshold map[string]int) {
	envs := os.Environ()
	// Checking env vars to replace or add new severity thresholds
	for _, env := range envs {
		if strings.HasPrefix(env, "TRIVY") {
			splitKeyValue := strings.Split(env, "=")
			if strings.HasSuffix(splitKeyValue[0], "THRESHOLD") && len(splitKeyValue) == 2 {
				newSeverityValue, err := strconv.Atoi(splitKeyValue[1])
				if err == nil {
					// could convert to integer so now just assigning
					sev := strings.Split(splitKeyValue[0], "_")[1]
					if _, exists := severitiesthreshold[sev]; exists {
						severitiesthreshold[sev] = newSeverityValue
					}
				}
			}
		}
	}
}

func init() {
	// Setting default for severity thresholds
	severitiesthreshold[string(utils.Critical)] = 0
	severitiesthreshold[string(utils.High)] = 10
	severitiesthreshold[string(utils.Medium)] = 20 
	severitiesthreshold[string(utils.Low)] = 50
	envThresholdsParse(severitiesthreshold)
	log.Printf("threshold settings : %v", severitiesthreshold)
}

func main() {
	// check if trivy binacy exists
	binaryPath, err := trivycheckcves.CheckIfBinaryIsPresent("trivy")
	if err != nil {
		log.Fatal("trivy binary not present")
	}
	server := &http.Server{Addr: ":443"}
	splitBinaryPath := strings.Split(binaryPath.String(), "/")
	binary := strings.TrimRight(splitBinaryPath[len(splitBinaryPath)-1], "\n")
	http.HandleFunc("/validation", trivycheckcves.HandlerCheckCVEsTryvi(binary, severitiesthreshold))
	log.Println("starting webhook")
	log.Fatal(server.ListenAndServeTLS("ca-certs/tls.crt", "ca-certs/tls.key"))
}
