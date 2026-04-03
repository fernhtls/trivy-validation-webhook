// Package trivycheckcves - images checks by using the trivy binary
package trivycheckcves

import (
	"bytes"
	"encoding/json"
	"fmt"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"log"
	"net/http"
	"os/exec"
	"strings"
)

type TrivyCVEs struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	Severity        string `json:"Severity"`
}

type TrivyVulnerabilities struct {
	Vulnerabilities []TrivyCVEs `json:"Vulnerabilities"`
}

type TrivyResults struct {
	Results []TrivyVulnerabilities `json:"Results"`
}

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	_ = corev1.AddToScheme(scheme)
	_ = admissionv1.AddToScheme(scheme)
}

func CheckIfBinaryIsPresent(binary string) (*bytes.Buffer, error) {
	cmd := exec.Command("which", binary)
	var out bytes.Buffer
	cmd.Stderr = &out
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return &out, nil
}

func TrivyArguments(severities []string, imageRef string) []string {
	defaultArgs := make([]string, 0)
	defaultArgs = append(defaultArgs, "image")
	defaultArgs = append(defaultArgs, "--format")
	defaultArgs = append(defaultArgs, "json")
	defaultArgs = append(defaultArgs, "--quiet")
	defaultArgs = append(defaultArgs, "--severity")
	defaultArgs = append(defaultArgs, strings.Join(severities, ","))
	defaultArgs = append(defaultArgs, imageRef)
	return defaultArgs
}

func executeTryviProcess(binaryPath string, args []string) (*bytes.Buffer, error) {
	cmd := exec.Command(binaryPath, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return &out, err
	}
	return &out, nil
}

func unmarshallTrivyOutPut(out *bytes.Buffer) (TrivyResults, error) {
	var trivyResults TrivyResults
	if err := json.Unmarshal(out.Bytes(), &trivyResults); err != nil {
		return trivyResults, err
	}
	return trivyResults, nil
}

func checkSeverityCriteria(severityCriteria map[string]int, trivyResults TrivyResults) (bool, map[string]int) {
	sr := make(map[string]int, 0)
	for _, tr := range trivyResults.Results {
		for _, v := range tr.Vulnerabilities {
			sr[v.Severity]++
		}
	}
	for k := range severityCriteria {
		if _, exists := sr[k]; exists {
			if sr[k] > severityCriteria[k] {
				log.Printf("Comparing criteria %s - %v with %v", k, sr[k], severityCriteria[k])
				return false, sr
			}
		}
	}
	return true, sr
}

func HandlerCheckCVEsTryvi(binaryPath string, severityThresholds map[string]int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if method is post
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		// Getting the whole json yaml request admission review from body
		var admissionReview admissionv1.AdmissionReview
		if err := json.NewDecoder(r.Body).Decode(&admissionReview); err != nil {
			http.Error(w, fmt.Sprintf("could not decode request: %v", err), http.StatusBadRequest)
			return
		}
		// Getting pod details
		req := admissionReview.Request
		var pod corev1.Pod
		if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
			http.Error(w, fmt.Sprintf("could not unmarshal pod object: %v", err), http.StatusBadRequest)
			return
		}
		// Log the Pod name and namespace
		log.Printf("Validating Pod: %s in Namespace: %s", pod.Name, pod.Namespace)
		// Severities logic
		severities := make([]string, len(severityThresholds))
		i := 0
		for k := range severityThresholds {
			severities[i] = k
			i++
		}
		allContainers := make([]corev1.Container, 0)
		if len(pod.Spec.InitContainers) > 0 {
			allContainers = append(allContainers, pod.Spec.InitContainers...)
		}
		allContainers = append(allContainers, pod.Spec.Containers...)
		// Checking containers
		for _, c := range allContainers {
			// Call to trivy process
			out, err := executeTryviProcess(binaryPath, TrivyArguments(severities, c.Image))
			if err != nil {
				http.Error(w, fmt.Sprintf("Error executing %s: %s", binaryPath, err), http.StatusInternalServerError)
				return
			}
			trivyResult, err := unmarshallTrivyOutPut(out)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error on unmarshalling trivy json: %s", err), http.StatusInternalServerError)
			}
			log.Printf("Validating Pod: %s in Namespace: %s / Trivy results: %v", pod.Name, pod.Namespace, trivyResult)
			passCriteria, resultSeverityCriteria := checkSeverityCriteria(severityThresholds, trivyResult)
			admissionResponse := &admissionv1.AdmissionResponse{
				UID:     req.UID,
				Allowed: passCriteria,
			}
			if passCriteria {
				admissionResponse.Result = &metav1.Status{
					Message: fmt.Sprintf(
						"image does comply with security scan criteria. Criteria: %v / Results: %v",
						severityThresholds, resultSeverityCriteria),
				}
				log.Printf(
					"Validating Pod: %s in Namespace %s: / image %s pass the severity criteria - criteria: %v / result: %v",
					pod.Name, pod.Namespace, c.Image, severityThresholds, resultSeverityCriteria)
			} else {
				admissionResponse.Result = &metav1.Status{
					Message: fmt.Sprintf(
						"image does not comply with security scan criteria. Criteria: %v / Results: %v",
						severityThresholds, resultSeverityCriteria),
					Code: http.StatusForbidden,
				}
				log.Printf(
					"Validating Pod: %s in Namespace %s: / image %s doesn't pass the severity criteria - criteria: %v / result: %v",
					pod.Name, pod.Namespace, c.Image, severityThresholds, resultSeverityCriteria)
			}
			response := admissionv1.AdmissionReview{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "admission.k8s.io/v1",
					Kind:       "AdmissionReview",
				},
				Response: admissionResponse,
			}

			respBytes, err := json.Marshal(response)
			if err != nil {
				http.Error(w, fmt.Sprintf("could not marshal response: %v", err), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(respBytes)
		}
	}
}
