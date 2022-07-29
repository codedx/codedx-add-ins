#
# This script takes the following steps to obtain a report from a Checkmarx scanner.
#
# Step 1: Obtain bearer token
# Step 2: Upload source
# Step 3: Start scan
# Step 4: Wait for scan to complete
# Step 5: Create new XML report
# Step 6: Wait for report to complete
# Step 7: Fetch XML report
#
param (
	[Parameter(Mandatory=$true)][string] $scanRequestFilePath
)

Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

. $PSScriptRoot/add-in.ps1

write-verbose "Reading scan request file ($scanRequestFilePath)..."
$scanRequestConfig = Get-Config $scanRequestFilePath

$workDirectory = $scanRequestConfig.request.workdirectory
write-verbose "Using work directory $workDirectory"

$checkmarxProjectId = $scanRequestConfig.checkmarx.projectId
if ($checkmarxProjectId -eq 0) {
	throw 'A project ID of 0 indicates an incomplete Checkmarx configuration'
}

$checkmarxUsername = Get-FileContents (join-path $workDirectory 'workflow-secrets/checkmarx-project-credential/username')
$checkmarxPassword = Get-FileContents (join-path $workDirectory 'workflow-secrets/checkmarx-project-credential/password')

Set-Tlsv12

$checkmarxBaseUrl = $scanRequestConfig.checkmarx.baseurl
$tokenUrl = "$checkmarxBaseUrl/cxrestapi/auth/identity/connect/token"

write-verbose "Step 1: Obtaining bearer token from $tokenUrl..."

# Note: The Checkmarx documentation states that this parameter must have the value specified here
$clientSecret = '014DF517-39D1-4453-B7B3-9930C563627C'

$tokenBody = @{
	'username'=$checkmarxUsername
	'password'=$checkmarxPassword
	'grant_type'='password'
	'scope'='sast_rest_api'
	'client_id'='resource_owner_client'
	'client_secret'=$clientSecret
}

$tokenResponse = Invoke-RestMethod -Uri $tokenUrl `
	-Method Post `
	-Body $tokenBody

$accessToken = $tokenResponse.access_token

$authorizationHeader = @{
	'Authorization' = "Bearer $accessToken"
}

$inputDirectory = join-path $scanRequestConfig.request.workdirectory 'input'
$sourcePath = (Get-ChildItem $inputDirectory | Select-Object -First 1).FullName

write-verbose "Step 2: Uploading source $sourcePath..."
$form = @{zippedSource=(Get-ChildItem $sourcePath)}
Invoke-RestMethod "$checkmarxBaseUrl/cxrestapi/projects/$checkmarxProjectId/sourceCode/attachments" -Method Post -Form $form -Headers @{Authorization="Bearer $accessToken"}

write-verbose 'Step 3: Starting scan...'
$startScanUrl = "$checkmarxBaseUrl/cxrestapi/sast/scans"

$startScanBody = @{
	'projectId' = "$checkmarxProjectId"
	'isIncremental' = 'false'
	'isPublic' = 'true'
	'forceScan' = 'true'
	'comment' = "$checkmarxProjectId"
}

$startScanResponse = Invoke-RestMethod -Uri $startScanUrl `
	-Method Post `
	-Body (ConvertTo-Json $startScanBody) `
	-Header $authorizationHeader `
	-ContentType 'application/json'

$scanId = $startScanResponse.id

$waitForCompletionSleepTimeInSeconds = $scanRequestConfig.scan.checkscanstatusdelay
write-verbose "Step 4: Wait for scan to complete (using check-status delay $($waitForCompletionSleepTimeInSeconds))..."

$waitForScanUrl = "$checkmarxBaseUrl/cxrestapi/sast/scans/$scanId"
$waitForScanResponse = Invoke-RestMethod -Uri $waitForScanUrl `
	-Method Get `
	-Header $authorizationHeader

while ($waitForScanResponse.status.name -ne 'Finished') {
	write-verbose "  Waiting for scan completion..."
	Start-Sleep -seconds $waitForCompletionSleepTimeInSeconds
	$waitForScanResponse = Invoke-RestMethod -Uri $waitForScanUrl `
		-Method Get `
		-Header $authorizationHeader
}

write-verbose 'Step 5: Creating new XML report...'
$createReportUrl = "$checkmarxBaseUrl/cxrestapi/reports/sastScan"

$createReportBody = @{
	'reportType' = 'XML'
	'scanId' = "$scanId"
}

$createReportResponse = Invoke-RestMethod -Uri $createReportUrl `
	-Method Post `
	-Header $authorizationHeader `
	-Body $createReportBody

$reportId = $createReportResponse.reportId

write-verbose 'Step 6: Waiting for report to complete...'
$getReportStatusUrl = "$checkmarxBaseUrl/cxrestapi/reports/sastScan/$reportId/status"

$getReportStatusResponse = Invoke-RestMethod -Uri $getReportStatusUrl `
	-Method Get `
	-Header $authorizationHeader

while ($getReportStatusResponse.status.value -ne 'Created') {
	write-verbose "  Waiting for report completion..."
	Start-Sleep -seconds $waitForCompletionSleepTimeInSeconds
	$getReportStatusResponse = Invoke-RestMethod -Uri $getReportStatusUrl `
		-Method Get `
		-Header $authorizationHeader
}

write-verbose 'Step 7: Fetching XML report...'
$fetchReportUrl = "$checkmarxBaseUrl/cxrestapi/reports/sastScan/$reportId"

$fetchReportResponse = Invoke-RestMethod -Uri $fetchReportUrl `
	-Method Get `
	-Header $authorizationHeader

$reportOutputPath = $scanRequestConfig.request.resultfilepath
write-verbose "Saving report to $reportOutputPath..."

# Due to 'Invoke-RestMethod' possibly converting a string response into a more representative data type, and we want to work with a String,
# convert XML back to String
if ($fetchReportResponse -is [xml]) {
	[string] $fetchReportStrResponse = $fetchReportResponse.OuterXml
}

$reportStart = $fetchReportStrResponse.IndexOf('<?xml ')

[io.file]::WriteAllText($reportOutputPath, $fetchReportStrResponse.Substring($reportStart))
