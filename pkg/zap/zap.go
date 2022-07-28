package zap

import (
	"bytes"
	"fmt"
	"github.com/zaproxy/zap-api-go/zap"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Context holds the ZAP context data and the list of ZAP users.
type Context struct {
	ContextID   string
	ContextName string
	Users       []User
}

// User holds the ZAP user identifier and a Credential.
type User struct {
	UserID     string
	Credential Credential
}

// RunZap starts the ZAP program to make its API available via the specified key.
func RunZap(zapPath string, apiKey string, waitTime time.Duration, stdoutWriter io.Writer, stderrWriter io.Writer, ready chan string, quit chan int, wg *sync.WaitGroup) {
	defer wg.Done()

	cmd := exec.Command(zapPath, "-daemon", "-config", "api.key=api-key")

	workingDir := filepath.Dir(zapPath)
	cmd.Dir = workingDir

	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter

	err := cmd.Start()
	if err != nil {
		log.Printf("Unable to start ZAP at path %s", zapPath)
		close(ready)
		return
	}

	client, err := MakeClient(apiKey)
	if err != nil {
		log.Printf("Unable to create new ZAP client with API key %s", apiKey)
		close(ready)
		return
	}

	giveUpTime := time.Now().Add(waitTime)

	version, err := (*client).Core().Version()
	for err != nil {

		if time.Now().After(giveUpTime) {
			log.Println("Giving up on wait for ZAP API")
			close(ready)
			if err := cmd.Process.Kill(); err != nil {
				log.Println(err)
			}
			return
		}

		log.Println("ZAP API not ready. Retrying...")
		time.Sleep(time.Second)

		version, err = (*client).Core().Version()
	}

	ready <- version["version"].(string)
	<-quit

	log.Println("Killing ZAP process...")
	if err := cmd.Process.Kill(); err != nil {
		log.Println(err)
	}
	log.Println("ZAP killed")
}

// MakeClient creates a new ZAP API client using the specified API key.
func MakeClient(apiKey string) (*zap.Interface, error) {
	cfg := &zap.Config{
		Proxy:  "http://127.0.0.1:8080",
		APIKey: apiKey,
	}

	z, err := zap.NewClient(cfg)
	return &z, err
}

// ConfigureContext defines a ZAP context, an authentication approach, and a list of users.
// It returns a Context and an error if a failure occurs.
func ConfigureContext(zap *zap.Interface, cfg *Config) (Context, error) {

	var ctx Context

	if !cfg.isValid() {
		return ctx, fmt.Errorf("cannot configure context because ZAP configuration is invalid")
	}

	result, err := (*zap).Context().NewContext(cfg.Context.Name)
	if err != nil {
		return ctx, err
	}

	ctx.ContextName = cfg.Context.Name
	ctx.ContextID, err = getZapStringResult("contextId", result)
	if err != nil {
		return ctx, err
	}

	if err := addContextIncludes(cfg.Context.IncludeRegularExpressions, cfg.Context.Name, zap); err != nil {
		return ctx, err
	}

	if err := addContextExcludes(cfg.Context.ExcludeRegularExpressions, cfg.Context.Name, zap); err != nil {
		return ctx, err
	}

	if !cfg.isAuthenticationEnabled() {
		return ctx, nil
	}

	var credentialString string

	if cfg.useFormAuthentication() {

		if err := configureFormsAuthentication(cfg.FormAuthentication, zap, &ctx); err != nil {
			return ctx, err
		}
		credentialString = "password=%s&username=%s&type=UsernamePasswordAuthenticationCredentials"
	}

	if cfg.useScriptAuthentication() {

		if err := configureScriptAuthentication(cfg.ScriptAuthentication, "", zap, &ctx, true); err != nil {
			return ctx, err
		}
		credentialString = "Password=%s&Username=%s&type=GenericAuthenticationCredentials"
	}

	if _, err := (*zap).Authentication().SetLoggedInIndicator(ctx.ContextID, cfg.Authentication.LoginIndicatorRegex); err != nil {
		return ctx, err
	}

	if err := addUsers(cfg, zap, &ctx, credentialString); err != nil {
		return ctx, err
	}

	return ctx, nil
}

func ConfigureApiScanContext(zap *zap.Interface, cfg *ApiConfig, authScriptFile string) (Context, error) {
	var ctx Context

	result, err := (*zap).Context().NewContext(cfg.Context.Name)
	if err != nil {
		return ctx, err
	}

	ctx.ContextName = cfg.Context.Name
	ctx.ContextID, err = getZapStringResult("contextId", result)
	if err != nil {
		return ctx, err
	}

	if err := addContextIncludes(cfg.Context.IncludeRegularExpressions, cfg.Context.Name, zap); err != nil {
		return ctx, err
	}

	if err := addContextExcludes(cfg.Context.ExcludeRegularExpressions, cfg.Context.Name, zap); err != nil {
		return ctx, err
	}

	if !cfg.IsContextAuthRequired() {
		return ctx, nil
	}

	var credentialString string

	if cfg.UseFormAuthentication() {
		if err := configureFormsAuthentication(cfg.FormAuthentication, zap, &ctx); err != nil {
			return ctx, err
		}
		credentialString = "password=%s&username=%s&type=UsernamePasswordAuthenticationCredentials"
	}

	if cfg.UseScriptAuthentication() {
		if err := configureScriptAuthentication(cfg.ScriptAuthentication, authScriptFile, zap, &ctx, false); err != nil {
			return ctx, err
		}
		credentialString = "Password=%s&Username=%s&type=GenericAuthenticationCredentials"
	}

	if _, err := (*zap).Authentication().SetLoggedInIndicator(ctx.ContextID, cfg.Authentication.LoginIndicatorRegex); err != nil {
		return ctx, err
	}

	cred := cfg.credential
	userID, err := addUser(zap, ctx.ContextID, cred.Username, cred.Password, credentialString)
	if err != nil {
		return ctx, err
	}
	user := User{
		UserID:     userID,
		Credential: *cred,
	}
	ctx.Users = append(ctx.Users, user)

	return ctx, nil
}

func addContextIncludes(exps []string, contextName string, zap *zap.Interface) error {
	for _, e := range exps {
		if len(e) <= 0 {
			continue
		}
		if _, err := (*zap).Context().IncludeInContext(contextName, e); err != nil {
			return err
		}
	}
	return nil
}

func addContextExcludes(exps []string, contextName string, zap *zap.Interface) error {
	for _, e := range exps {
		if len(e) <= 0 {
			continue
		}
		if _, err := (*zap).Context().ExcludeFromContext(contextName, e); err != nil {
			return err
		}
	}
	return nil
}

func configureFormsAuthentication(formAuth formAuthentication, zap *zap.Interface, ctx *Context) error {

	loginRequestData := fmt.Sprintf("%s={%%username%%}&%s={%%password%%}",
		formAuth.FormUsernameFieldName,
		formAuth.FormPasswordFieldName)

	antiCrossSiteRequestForgery := formAuth.FormAntiCrossSiteRequestForgeryFieldName
	if len(antiCrossSiteRequestForgery) > 0 {
		loginRequestData += fmt.Sprintf("&%s={%%token%%}", antiCrossSiteRequestForgery)

		// The antiCrossSiteRequestForgery value may not be included in ZAP's default list, so
		// add it now - adding duplicate tokens appears to be a no-op.
		if _, err := (*zap).Acsrf().AddOptionToken(antiCrossSiteRequestForgery); err != nil {
			return err
		}
	}

	extraPostData := formAuth.FormExtraPostData
	if len(extraPostData) > 0 {
		if !strings.HasPrefix(extraPostData, "&") {
			extraPostData = "&" + extraPostData
		}
		loginRequestData += extraPostData
	}

	loginRequestData = url.QueryEscape(loginRequestData)
	formAuthConfigParams := fmt.Sprintf("loginUrl=%s&loginRequestData=%s", formAuth.FormURL, loginRequestData)
	_, err := (*zap).Authentication().SetAuthenticationMethod(ctx.ContextID,
		"formBasedAuthentication",
		formAuthConfigParams)

	return err
}

func configureScriptAuthentication(scriptAuth scriptAuthentication, authScriptFile string, zap *zap.Interface, ctx *Context, deleteFile bool) error {
	var xf *os.File
	var err error
	if authScriptFile == "" {
		xf, err = ioutil.TempFile("", "authScript")
		if err != nil {
			return err
		}
		defer func() {
			if err := xf.Close(); err != nil {
				log.Println(err)
			}
			if err := os.Remove(xf.Name()); err != nil {
				log.Println(err)
			}
		}()
	} else {
		xf, err = os.Create(authScriptFile)
		if err != nil {
			return err
		}
	}

	if _, err = xf.WriteString(scriptAuth.AuthenticationScriptContent); err != nil {
		return err
	}

	if _, err = (*zap).Script().Load("authScript", "authentication", "Mozilla Zest", xf.Name(), "", ""); err != nil {
		return err
	}

	_, err = (*zap).Authentication().SetAuthenticationMethod(ctx.ContextID,
		"scriptBasedAuthentication",
		"scriptName=authScript")

	log.Println("Created /zap/wrk/authScript")

	return err
}

func addUser(zap *zap.Interface, contextID string, username string, password string, credentialString string) (string, error) {
	result, err := (*zap).Users().NewUser(contextID, username)
	if err != nil {
		return "", err
	}

	userID, err := getZapIntResult("userId", result)
	if err != nil {
		return "", err
	}
	userIDString := strconv.Itoa(userID)

	passwordEncoded := url.QueryEscape(password)
	usernameEncoded := url.QueryEscape(username)
	authConfigParams := fmt.Sprintf(credentialString, passwordEncoded, usernameEncoded)

	_, err = (*zap).Users().SetAuthenticationCredentials(contextID, userIDString, authConfigParams)

	if err != nil {
		return "", err
	}

	_, err = (*zap).Users().SetUserEnabled(contextID, userIDString, "True")
	if err != nil {
		return "", err
	}

	return userIDString, nil
}

func addUsers(cfg *Config, zap *zap.Interface, ctx *Context, credentialString string) error {
	for i := range cfg.credentials {
		cred := cfg.credentials[i]
		userID, err := addUser(zap, ctx.ContextID, cred.Username, cred.Password, credentialString)
		if err != nil {
			return err
		}

		user := User{
			UserID:     userID,
			Credential: cred,
		}
		ctx.Users = append(ctx.Users, user)
	}
	return nil
}

func getZapResult(resultKey string, result map[string]interface{}) (interface{}, error) {
	code, ok := result["code"]
	if ok {
		errorStr := fmt.Sprintf("Expected data for key %s, but found error code '%s'", resultKey, code.(string))
		msg, ok := result["message"]
		if ok {
			errorStr += fmt.Sprintf(" with message '%s'", msg.(string))
		}
		return "", fmt.Errorf(errorStr)
	}
	return result[resultKey], nil
}

func getZapStringResult(resultKey string, result map[string]interface{}) (string, error) {
	zapResult, err := getZapResult(resultKey, result)
	if err != nil {
		return "", err
	}
	return zapResult.(string), err
}

func getZapIntResult(resultKey string, result map[string]interface{}) (int, error) {
	str, err := getZapStringResult(resultKey, result)
	if err != nil {
		return 0, err
	}

	val, err := strconv.Atoi(str)
	if err != nil {
		return 0, err
	}
	return val, err
}

// Spider runs a spider as an anonymous user.
// It returns an error when a failure occurs.
func Spider(zap *zap.Interface, targetURL string, contextName string) (cnt int, e error) {
	return runSpider(zap, targetURL, "", "", contextName)
}

// SpiderAsUser runs a spider as a specific user.
// It returns an error when a failure occurs.
func SpiderAsUser(zap *zap.Interface, targetURL string, contextID string, userID string) (cnt int, e error) {
	return runSpider(zap, targetURL, userID, contextID, "")
}

// ForceUser enables forced user mode for the specified user.
// It returns an error when a failure occurs.
func ForceUser(zap *zap.Interface, contextID string, userID string) error {

	if _, err := (*zap).ForcedUser().SetForcedUserModeEnabled(userID != ""); err != nil {
		return err
	}

	if userID != "" {
		if _, err := (*zap).ForcedUser().SetForcedUser(contextID, userID); err != nil {
			return err
		}
	}
	return nil
}

func runSpider(zap *zap.Interface, targetURL string, userID string, contextID string, contextName string) (cnt int, e error) {

	var err error
	var resultKey string
	var result map[string]interface{}

	// note: an empty string parameter gets dropped from the request
	if userID == "" {
		resultKey = "scan"
		result, err = (*zap).Spider().Scan(targetURL, "", "True", contextName, "True")
		if err != nil {
			return 0, err
		}
	} else {
		resultKey = "scanAsUser"
		result, err = (*zap).Spider().ScanAsUser(contextID, userID, targetURL, "", "True", "True")
		if err != nil {
			return 0, err
		}
	}

	scanID, err := getZapStringResult(resultKey, result)
	if err != nil {
		return 0, err
	}

	for {
		result, err = (*zap).Spider().Status(scanID)
		if err != nil {
			return 0, err
		}

		status, err := getZapIntResult("status", result)
		if err != nil {
			return 0, err
		}
		if status >= 100 {
			break
		}
		time.Sleep(2 * time.Second)
	}

	for {
		result, err = (*zap).Pscan().RecordsToScan()
		if err != nil {
			return 0, err
		}

		records, err := getZapIntResult("recordsToScan", result)
		if err != nil {
			return 0, err
		}
		if records == 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}

	addedNodes, err := (*zap).Spider().AddedNodes(scanID)
	if err != nil {
		return 0, err
	}
	return readAddedNodes(addedNodes), nil
}

func readAddedNodes(addedNodes map[string]interface{}) int {
	nodeCount := 0
	c, ok := addedNodes["addedNodes"]
	if ok {
		n, isArray := c.([]interface{})
		if isArray {
			nodeCount = len(n)
		}
	}
	return nodeCount
}

// Scan runs a scan as an anonymous user.
// It returns an error when a failure occurs.
func Scan(zap *zap.Interface, targetURL string, contextID string) error {
	return runScan(zap, targetURL, contextID, "")
}

// ScanAsUser runs a scan as a specific user.
// It returns an error when a failure occurs.
func ScanAsUser(zap *zap.Interface, targetURL string, contextID string, userID string) error {
	return runScan(zap, targetURL, contextID, userID)
}

func runScan(zap *zap.Interface, targetURL string, contextID string, userID string) error {

	var err error
	var resultKey string
	var result map[string]interface{}

	if userID == "" {
		resultKey = "scan"
		result, err = (*zap).Ascan().Scan(targetURL, "True", "True", "", "", "", contextID)
	} else {
		resultKey = "scanAsUser"
		result, err = (*zap).Ascan().ScanAsUser(targetURL, contextID, userID, "True", "", "", "")
	}

	if err != nil {
		return err
	}

	scanID, err := getZapStringResult(resultKey, result)
	if err != nil {
		return err
	}

	for {
		result, err = (*zap).Ascan().Status(scanID)
		if err != nil {
			return err
		}

		status, err := getZapIntResult("status", result)
		if err != nil {
			return err
		}
		if status >= 100 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	return nil
}

// SaveReport generates an XML ZAP report and runs an XSLT to filter results that do not meet the minimum risk and
// confidence values specified.
// It returns an error when a failure occurs.
func SaveReport(zap *zap.Interface, xsltProgram string, outputFile string, minimumRiskCode int, minimumConfidence int) error {

	reportBytes, err := (*zap).Core().Xmlreport()
	if err != nil {
		return err
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return err
	}

	_, err = f.Write(reportBytes)
	if err != nil {
		if err := f.Close(); err != nil {
			log.Println(err)
		}
		return err
	}

	err = f.Close()
	if err != nil {
		return err
	}
	return ApplyXslt(xsltProgram, outputFile, minimumRiskCode, minimumConfidence)
}

func ApplyXslt(xsltProgram string, outputFile string, minimumRiskCode int, minimumConfidence int) error {

	f, err := os.Open(outputFile)
	if err != nil {
		log.Println("save report; err4.1")
		return err
	}

	xslt := `<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>
  <xsl:template match="OWASPZAPReport/site/alerts/alertitem[riskcode &lt; %d]"/>
  <xsl:template match="OWASPZAPReport/site/alerts/alertitem[confidence &lt; %d]"/>
</xsl:stylesheet>`

	xf, err := ioutil.TempFile("", "report-filter-xslt")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(xf.Name()); err != nil {
			log.Println(err)
		}
	}()

	_, err = xf.WriteString(fmt.Sprintf(xslt, minimumRiskCode, minimumConfidence))
	if err != nil {
		if err := xf.Close(); err != nil {
			log.Println(err)
		}
		return err
	}

	err = xf.Close()
	if err != nil {
		return err
	}

	var cmd *exec.Cmd

	if strings.HasSuffix(xsltProgram, "xsltproc") {
		cmd = exec.Command(xsltProgram,
			"-o",
			f.Name(),
			xf.Name(),
			f.Name())
	} else if strings.HasSuffix(xsltProgram, "msxsl") || strings.HasSuffix(xsltProgram, "msxsl.exe") {
		cmd = exec.Command(xsltProgram,
			f.Name(),
			xf.Name(),
			"-o",
			f.Name())
	} else {
		return fmt.Errorf("the specified xslt program (%s) is unsupported", xsltProgram)
	}

	var stdoutBuffer, stderrBuffer bytes.Buffer
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer

	err = cmd.Run()
	if err != nil {
		log.Println(stdoutBuffer.String())
		log.Println(stderrBuffer.String())
		return err
	}

	return nil
}
