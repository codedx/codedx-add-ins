﻿#
# This script takes the following steps to obtain an output zip from a Black Duck server.
#
# Step 1: Unzip source
# Step 2: Run Synopsys Detect on source
# Step 3: Run Black-Duck-Scrape to pull results
#
param (
	[Parameter(Mandatory=$true)][string] $sourcePath,
	[Parameter(Mandatory=$true)][string] $scanRequestFilePath
)

Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

. ./add-in.ps1

write-verbose "Reading scan request file ($scanRequestFilePath)..."
$scanRequestConfig = Get-Config $scanRequestFilePath

$workDirectory = $scanRequestConfig.request.workdirectory
write-verbose "Using work directory $workDirectory"

$blackDuckProjectName = $scanRequestConfig.blackduck.projectName
$blackDuckVersionName = $scanRequestConfig.blackduck.versionName

$blackDuckApiToken = Get-FileContents (join-path $workDirectory 'workflow-secrets/blackduck-credential/api-token')

Set-Tlsv12

$blackDuckBaseUrl = $scanRequestConfig.blackduck.baseurl

$sourceDirectory = join-path $scanRequestConfig.request.workdirectory 'source'

write-verbose "Step 1: Unpack source code..."
Expand-SourceArchive $sourcePath $sourceDirectory -restoreGitDirectory

$sourceCode = $scanRequestConfig.'source-code'
$sourceDirectory = Push-BaseSourceCodeDirectory $sourceDirectory $sourceCode.relativeDirectory $sourceCode.projectFileDirectoryPatterns

Add-TrustedCertsJava $scanRequestConfig.request.workdirectory '/etc/ssl/certs/java/cacerts' 'changeit'

write-verbose "Step 2: Invoking Synopsys Detect"

$detectOptions = $scanRequestConfig.detect.options
if($null -eq $detectOptions) {
	$detectOptions = @()
}

# List of regexes for options keys we want to disallow
$invalidOptionRegex = @(
	'blackduck\.url',
	'blackduck\.api\.token',
	'detect\.wait\.for\.results',
	'detect\.cleanup',
	'detect\.source\.path',
	'detect\.output\.path',
	'detect\.phone\.home\.passthrough\.invoked\.by\.image'
) -join '|'
# Check that the user didn't set any options that we do already, with the exception of the project
# and version names, which are handled below.
$invalidOptions = $detectOptions -match "^\s*--($invalidOptionRegex)=.*$"
if($invalidOptions.count -gt 0) {
	write-verbose "The following detect options conflict with options set by Code Dx: $invalidOptions"
	throw "Invalid options"
}

# The project and version names don't need to be provided -- if either are absent Black Duck will
# pick a name for them. If a user wants to just provide all the args in the options field, they can
# technically set the project and version names there too, but we should at least make sure it's
# not also set in the corresponding config field.
if($blackDuckProjectName -ne "") {
	if(($detectOptions -match '^\s*--detect\.project\.name=.*$').count -gt 0) {
		write-verbose "blackduck.projectName and --detect.project.name options both set. Only one may be set"
		throw "Invalid options"
	}
	$detectOptions += "--detect.project.name=`"'$blackDuckProjectName'`""
}

if($blackDuckVersionName -ne "") {
	if(($detectOptions -match '^\s*--detect\.project\.version\.name=.*$').count -gt 0) {
		write-verbose "blackduck.versionName and --detect.project.version.name options both set. Only one may be set"
		throw "Invalid options"
	}
	$detectOptions += "--detect.project.version.name=`"'$blackDuckVersionName'`""
}

$optionsYaml = $scanRequestConfig.detect.optionsYaml
if ($optionsYaml -ne "") {

	$optionsYamlPath = join-path $workDirectory 'detect-options.yaml'
	$optionsYaml | out-file $optionsYamlPath
	$detectOptions += "--spring.config.location=""$optionsYamlPath"""
}

if ([Convert]::ToBoolean($scanRequestConfig.detect.skipSynopsysPhoneHome)) {
	[Environment]::SetEnvironmentVariable("SYNOPSYS_SKIP_PHONE_HOME", "true")
}

$preDetectCmdLine = $scanRequestConfig.detect.preDetectCmdLine
if (-not ([string]::IsNullOrWhitespace($preDetectCmdLine))) {
	write-verbose "Running prebuild command $preDetectCmdLine..."
	Invoke-Expression -Command $preDetectCmdLine
}

$outputDirectory = join-path $workDirectory 'output'

write-verbose 'Step 3: Running synopsys-detect.jar with specified command arguments...'
java -jar /synopsys-detect.jar --blackduck.url=$blackDuckBaseUrl --blackduck.api.token=$blackDuckApiToken --detect.wait.for.results=true --detect.cleanup=false --detect.source.path=$sourceDirectory --detect.output.path=$outputDirectory --detect.phone.home.passthrough.invoked.by.image=true @($detectOptions)

# The status file in $outputDirectory/runs/<date-time>/status/status.json contains the location
# of the resulting Black Duck project
$detectStatusFile = join-path (Get-ChildItem (join-path $outputDirectory 'runs') | Select-Object -First 1).FullName 'status/status.json'
$detectStatusText = (Get-Content $detectStatusFile) -join "`n"
write-verbose $detectStatusText

if($LASTEXITCODE -ne 0) {
	# Write the status file if detect fails
	write-verbose $detectStatusText
	throw "The synopsys-detect.jar run failed with exit code $LASTEXITCODE"
}

$detectStatus = ConvertFrom-Json $detectStatusText

$reportOutputPath = $scanRequestConfig.request.resultfilepath

# There can be multiple other locations (such as reports), but only one of them should be a BD project
$locationRegex = '/api/projects/([A-Za-z\d\-]+)/versions/([A-Za-z\d\-]+)/components'

if ($detectStatus.results.location -match $locationRegex) {

	$projectId = $Matches.1
	$versionId = $Matches.2
	write-verbose "Step 3: Invoking Black Duck Scraper on project $projectId version $versionId"
	$tmpDir = Join-Path $scanRequestConfig.request.workDirectory "tmp_dir"
	java -jar /opt/codedx/blackduck/bin/Black-Duck-Scrape.jar -u $blackDuckBaseUrl -p $projectId -v $versionId -o $reportOutputPath -t $tmpDir -a $blackDuckApiToken @($scanRequestConfig.scraper.options)

} else {

	$now = [datetime]::now

	# Create an empty file for Code Dx to import
	$props = @"
# $($now.ToString("ddd MMM dd HH:mm:ss zzz"))
generated.by=CodeDx-Black Duck Hub Connector
generated.time=$($now.subtract([datetime]::UnixEpoch).TotalSeconds)
tool-data-provider.num-primary-inputs=0
generated.version=0.1
"@

	$emptyDir = Join-Path $scanRequestConfig.request.workDirectory "empty"
	New-Item $emptyDir -ItemType Container

	Push-Location $emptyDir
	$props | out-file .props

	New-Item 'aux' -ItemType Container
	Push-Location 'aux'

	$emptyId = [Guid]::Empty.Guid

	$blackDuckBaseUrl | out-file 'server_url.txt.data' -NoNewLine
	$emptyId          | out-file 'project_version.txt.data' -NoNewLine
	$emptyId          | out-file 'project_id.txt.data' -NoNewLine
	'EXTERNAL'        | out-file "project_distribution_$emptyId.txt.data" -NoNewLine
	'info'            | out-file 'minimum_severity.txt.data' -NoNewLine
	'true'            | out-file 'include_operational_risks.txt.data' -NoNewLine
	'true'            | out-file 'include_license_risks.txt.data' -NoNewLine
	Pop-Location

	# Compress-Archive calls Get-Item w/o -Force, so it cannot find "hidden" .props file
	zip $reportOutputPath .props aux/*
}