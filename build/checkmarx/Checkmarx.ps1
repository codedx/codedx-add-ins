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

. ./add-in.ps1

function ConvertTo-JsonEscape($table) {
	(ConvertTo-Json -Compress $table) -replace '"','\"'
}

function ConvertTo-FormUrlEncoded($table) {
	[string]::join('&', ($table.keys | ForEach-Object { "$([Web.HttpUtility]::urlencode($_))=$([Web.HttpUtility]::urlencode($table[$_]))" }))
}

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
$tokenBodyContent = ConvertTo-FormUrlEncoded $tokenBody
$tokenResponse = curl -s -X POST $tokenUrl -d $tokenBodyContent | ConvertFrom-Json

$accessToken = $tokenResponse.access_token

$inputDirectory = join-path $scanRequestConfig.request.workdirectory 'input'
$sourcePath = (Get-ChildItem $inputDirectory | Select-Object -First 1).FullName

write-verbose "Step 2: Uploading source $sourcePath..."
curl -X POST -H "Authorization: Bearer $accessToken" --form "zippedSource=@$(Get-ChildItem $sourcePath)" "$checkmarxBaseUrl/cxrestapi/projects/$checkmarxProjectId/sourceCode/attachments"

write-verbose 'Step 3: Starting scan...'
$startScanUrl = "$checkmarxBaseUrl/cxrestapi/sast/scans"

$startScanBody = @{
	'projectId' = "$checkmarxProjectId"
	'isIncremental' = 'false'
	'isPublic' = 'true'
	'forceScan' = 'true'
	'comment' = "$checkmarxProjectId"
}

$startScanResponse = curl -s -X POST -H "Authorization: Bearer $accessToken" -H "Content-Type: application/json" -d "$(ConvertTo-JsonEscape $startScanBody)" $startScanUrl | ConvertFrom-Json

$scanId = $startScanResponse.id

$waitForCompletionSleepTimeInSeconds = $scanRequestConfig.scan.checkscanstatusdelay
write-verbose "Step 4: Wait for scan to complete (using check-status delay $($waitForCompletionSleepTimeInSeconds))..."

$waitForScanUrl = "$checkmarxBaseUrl/cxrestapi/sast/scans/$scanId"
$waitForScanResponse = curl -s -H "Authorization: Bearer $accessToken" $waitForScanUrl | ConvertFrom-Json

while ($waitForScanResponse.status.name -ne 'Finished') {
	write-verbose "  Waiting for scan completion..."
	Start-Sleep -seconds $waitForCompletionSleepTimeInSeconds
	$waitForScanResponse = curl -s -H "Authorization: Bearer $accessToken" $waitForScanUrl | ConvertFrom-Json
}

write-verbose 'Step 5: Creating new XML report...'
$createReportUrl = "$checkmarxBaseUrl/cxrestapi/reports/sastScan"

$createReportBody = @{
	'reportType' = 'XML'
	'scanId' = "$scanId"
}

# Note: Current documentation shows this as an application/json content-type (instead of application/x-www-form-urlencoded)
#       Switch to application/json if required
$createReportBodyContent = ConvertTo-FormUrlEncoded $createReportBody
$createReportResponse = curl -s -H "Authorization: Bearer $accessToken" -X POST $createReportUrl -d $createReportBodyContent | ConvertFrom-Json

$reportId = $createReportResponse.reportId

write-verbose 'Step 6: Waiting for report to complete...'
$getReportStatusUrl = "$checkmarxBaseUrl/cxrestapi/reports/sastScan/$reportId/status"

$getReportStatusResponse = curl -s -H "Authorization: Bearer $accessToken" $getReportStatusUrl | ConvertFrom-Json

while ($getReportStatusResponse.status.value -ne 'Created') {
	write-verbose "  Waiting for report completion..."
	Start-Sleep -seconds $waitForCompletionSleepTimeInSeconds
	$getReportStatusResponse = curl -s -H "Authorization: Bearer $accessToken" $getReportStatusUrl | ConvertFrom-Json
}

write-verbose 'Step 7: Fetching XML report...'
$fetchReportUrl = "$checkmarxBaseUrl/cxrestapi/reports/sastScan/$reportId"

$fetchReportResponse = curl -s -H "Authorization: Bearer $accessToken" $fetchReportUrl

$reportOutputPath = $scanRequestConfig.request.resultfilepath
write-verbose "Saving report to $reportOutputPath..."

$reportStart = $fetchReportResponse.IndexOf('<?xml ')
[io.file]::WriteAllText($reportOutputPath, $fetchReportResponse.Substring($reportStart))
