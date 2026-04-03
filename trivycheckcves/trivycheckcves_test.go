package trivycheckcves

import (
	"fmt"
	"testing"

	"webhookimageanalysis/utils"

	"github.com/stretchr/testify/assert"
)

func TestTrivyARguments(t *testing.T) {
	bargs := TrivyArguments([]string{string(utils.Critical), string(utils.High), string(utils.Low)}, "myimage")
	args := []string{"image", "--format", "json", "--quiet", "--severity", fmt.Sprintf("%s,%s,%s", utils.Critical, utils.High, utils.Low), "myimage"}
	assert.Equal(t, bargs, args)
}

func TestCheckBinaryExists(t *testing.T) {
	_, errDontExist := CheckIfBinaryIsPresent("idontexist")
	assert.Error(t, errDontExist)
	_, errExists := CheckIfBinaryIsPresent("bash")
	assert.NoError(t, errExists)
}

func TestExecuteTrivy(t *testing.T) {
	args := TrivyArguments([]string{string(utils.Critical), string(utils.High)}, "postgres:14.22-trixie")
	out, err := executeTryviProcess("trivy", args)
	assert.NoError(t, err)
	_, errUnmarshall := unmarshallTrivyOutPut(out)
	assert.NoError(t, errUnmarshall)
}

func TestCheckSeverityPass(t *testing.T) {
	severityCriteria := map[string]int{
		string(utils.Critical): 0,
		string(utils.High):     10,
		string(utils.Low):      20,
	}
	cve1 := TrivyCVEs{
		VulnerabilityID: "CVE-BLA1",
		Severity:        string(utils.High),
	}
	cve2 := TrivyCVEs{
		VulnerabilityID: "CVE-BLA1",
		Severity:        string(utils.High),
	}
	vs := TrivyVulnerabilities{}
	vs.Vulnerabilities = append(vs.Vulnerabilities, cve1, cve2)
	tr := TrivyResults{}
	tr.Results = append(tr.Results, vs)
	checkResult, resultMap := checkSeverityCriteria(severityCriteria, tr)
	assert.Equal(t, checkResult, true)
	assert.Len(t, resultMap, 1)
}

func TestCheckSeverityNoPass(t *testing.T) {
	severityCriteria := map[string]int{
		string(utils.Critical): 0,
		string(utils.High):     10,
		string(utils.Low):      20,
	}
	cve1 := TrivyCVEs{
		VulnerabilityID: "CVE-BLA1",
		Severity:        string(utils.Critical),
	}
	cve2 := TrivyCVEs{
		VulnerabilityID: "CVE-BLA1",
		Severity:        string(utils.High),
	}
	vs := TrivyVulnerabilities{}
	vs.Vulnerabilities = append(vs.Vulnerabilities, cve1, cve2)
	tr := TrivyResults{}
	tr.Results = append(tr.Results, vs)
	checkResult, resultMap := checkSeverityCriteria(severityCriteria, tr)
	assert.Equal(t, checkResult, false)
	assert.Len(t, resultMap, 2)
}
