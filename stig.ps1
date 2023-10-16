#requires -version 7

<#
        .SYNOPSIS
        Uses an ONTAP STIG checklist as input, and checks the ONTAP system for each vulnerability. Results are saved to a completed STIG checkist as output (.ckl).

        .DESCRIPTION
        Uses an ONTAP STIG checklist as input, and checks the ONTAP system for each vulnerability. Results are saved to a completed STIG checkist as output (.ckl). 

		See stig_template.ini for details on the parameters 

		Workflow:

		1. Verify blank STIG checklist and .ini file path/name
        2. Create subdirectory for STIG files/checklists
        3. Process {stig}.ini file
        4. Ping cluster IP (verify reachable)
        5. Check REST API connection to cluster - Get cluster name and ONTAP version
        6. Open a new checklist file (XML) for output using blank as template
        7. Add host name, host IP, domain, and ONTAP version
        8. Process (loop) through each vulnerability in the checklist
        9. Check the settings in the .ini file related to the current vulnerability number
        11. If 'override_status' is NOT BLANK, then skip the check and use the override_status, details, and comments in the .ini
        12. If 'override_status' is BLANK, then run the compliance check
        13. Update the new checklist with the result (Open, Not A Finding, Not Applicable, Not Reviewed) along with any Details or Comments
        14. Once all vulnerabilities have been processed - save/close the new checklist
        15. Screen output shows the name of the saved checklist - ontapstig_{clustername}_YYYYMMDD.ckl and totals for each type of finding
        16. To view the completed checklist, use the DISA STIG Viewer

        .PARAMETER Stigfile
        The {configuration}.ini file that contains settings for each specifiv vulnerability # in the checklist (V-######)

        .EXAMPLE
        PS>  .\stig.ps1 -StigFile stig_cluster1.ini -ClusterIP 10.0.0.10 -Login admin

		Processes stig_cluster1.ini for settings and checks each vulernability for compliance.  A ONTAP STIG checklist is generated with each finding.
        The .ini settings provide a method to 'override' the check to allow the admin to mark a vulnerability to any status with details and comments.

        .LINK
        ONTAP 9 Documentation: https://docs.netapp.com/ontap-9/index.jsp

        .LINK
        ONTAP 9 REST API: https://{ClusterIP}/docs/api

#>

[cmdletbinding()]
param (
	[Parameter(Mandatory = $True)]
	[string]$StigFile,
    [Parameter(Mandatory = $True)]
    [ipaddress]$ClusterIP,
    [Parameter(Mandatory = $True)]
    [string]$Login
)

# --------------------- TODO LIST ---------------------

# Verify .INI Settings

# --------------------- Functions ---------------------

function Get-ConfigSettings ($file) {

    # Processes a standard .ini file into hash key/values and returns the object

	$ini = @{ }
	$section = "NO_SECTION"
	$ini[$section] = @{ }
	
	switch -regex -file $file {
		"^\[(.+)\]$" {
			$section = $matches[1].Trim()
			$ini[$section] = @{ }
		}
		"^\s*([^#].+?)\s*=\s*(.*)" {
			$name, $value = $matches[1 .. 2]
			if (!($name.StartsWith(";")))
			{
				$ini[$section][$name] = $value.Trim()
			}
		}
	}
	return $ini
}
function Invoke-ONTAP {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $True)]
	    [ValidateSet('Get', 'Post', 'Patch', 'Delete')]$Method,
        [Parameter(Mandatory = $True)]
        [string]$URL,
        [string]$Body = '{}',
        [switch]$ReturnNullOnError
    )

    # Inputs:
    #   - Method [Get|Post|Patch|Delete]
    #   - URL
    #   - Body
    #   - ReturnNullOnError
    #
    # Outputs:
    #   - Result of REST API call
    #
    # Notes:
    #   - Body is only required for Post|Patch - a default of an empty JSON body {} can be used depending on the DELETE API requirements
    #   - If ReturnNullOnError = TRUE, then a NULL result is returned instead of exiting script with error messages
    #   - If the XML checklist is defined, DISPOSE() XML (closes output and allows script to be re-run)
    #
    # Errors:
    #   - Exception Messages are displayed and script is terminated
    #   - If XML checklist is open the results are disposed
    #

    try {

        if ($Method -eq 'Get') {

            $_result = Invoke-RestMethod -Method $Method -Uri $URL -Credential $script:Credential -Headers $script:header -SkipCertificateCheck -ErrorAction Stop

        } else {

            $_result = Invoke-RestMethod -Method $Method -Uri $URL -Credential $script:Credential -Headers $script:header -Body $Body -SkipCertificateCheck -ErrorAction Stop 

        }

    } catch {

        if ($ReturnNullOnError) {

            $_result = $null

        } else { 

            Write-Host -ForegroundColor Red "`n $_.Exception.Message `n"
            Write-Host -ForegroundColor Yellow " $($error[0].ErrorDetails.Message) `n"

            Write-Host

            if ( Test-Path variable:script:xml ) {
                $script:xml.dispose()
            }

            Exit

        }

    }

    return $_result

}
function Write-Text {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$LineText,
		[int]$Width = 80,
		[int]$Pad = 0,
		[string]$Color = "White"
	)

	$_words = $LineText -split "\s+"
	$_col = 0
	$_padspaces = ""

	for ($_i = 0; $_i -lt $Pad; $_i++) { $_padspaces = $_padspaces + " " }

	foreach ($_word in $_words)
	{

		$_col += $_word.Length + 1

		if ($_col -gt $Width)
		{
			Write-Host
			Write-Host "$_padspaces" -NoNewline
			$_col = $_word.Length + 1
		}

		Write-Host -ForegroundColor $Color "$_word " -NoNewline

	}

	Write-Host

}
function Get-Status {
    [CmdletBinding()]
	param
	(
		[string]$StatusCode = ""
	)

    if ($StatusCode -eq 'O') {
        $s = 'Open'
    } elseif ($StatusCode -eq 'NAF') {
        $s = 'NotAFinding'
    } elseif ($StatusCode -eq 'NA' ) {
        $s = 'Not_Applicable'
    } elseif ($StatusCode -eq 'NR' ) {
        $s = 'Not_Reviewed'
    } else {
        $s = ''
    }

    return $s

}
function Get-StatusSentence {
    [CmdletBinding()]
	param
	(
		[string]$StatusWord = ""
	)

    if ($StatusWord -eq 'Open') {
        $s = 'OPEN'
    } elseif ($StatusWord -eq 'NotAFinding') {
        $s = 'NOT A FINDING'
    } elseif ($StatusWord -eq 'Not_Applicable' ) {
        $s = 'NOT APPLICABLE'
    } elseif ($StatusWord -eq 'Not_Reviewed' ) {
        $s = 'NOT REVIEWED'
    } else {
        $s = 'UNKNOWN'
    }

    return $s
}
function Get-CatLevel {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $True)]
	    [ValidateSet('low', 'medium', 'high')]$Level
    )

    if ( $Level -eq 'medium' ) {
        $cat = 'CAT II'
    } elseif ( $Level -eq 'high' ) {
        $cat = 'CAT I'
    } else {
        $cat = 'CAT III'
    }

    return $cat

}

# --------------------- Test Configuration File ---------------------

if (!(Test-Path $StigFile)){

    Write-Host -ForegroundColor Red "Configuration File ($StigFile) Not Found"
    Write-Host
    Exit

}

# --------------------- Test for Blank Checklist and load if found ---------------------

# Check for blank checklist / template

if (Test-Path -Path "$PSScriptRoot/stig.ckl") {

    [xml]$checklist = Get-Content -Path "$PSScriptRoot/stig.ckl"

} else { 

    Write-Host "EXIT - Cannot find $PSScriptRoot/stig.ckl file"
    Write-Host

    exit

}

# --------------------- Create subdirectory for findings ---------------------

# Check for subfolder to store checklists / create if missing

$resultpath = "$PSScriptRoot/stig_findings"

if (!(Test-Path $resultpath)){

    New-Item -Path $resultpath -ItemType Directory -Force | Out-Null

}

# --------------------- Process configuration file ---------------------

# Process configuration file

$config = Get-ConfigSettings "$StigFile"

# Cluster

$domain = ($config["CLUSTER"]).domain

# --------------------- Start ---------------------

Clear-Host

# --------------------- Ping Cluster IP ---------------------

# Check if cluster IP is reachable on network (ping)

if (!(Test-Connection -Ping $clusterip -Count 2 -Quiet )) {

    Write-Host -ForegroundColor Yellow " Cluster $ClusterIP Did Not Respond to PING test"
    Exit

}

# --------------------- Build Header ---------------------

# Create a standard HEADER object
# - $script: makes the variable available to functions in the script so they do not need to be passed in
# - Setting to 'application/json' removes HAL references from result (_link)

$script:header = @{
    'Accept' = "application/json"
    'Content-Type' = 'application/json'
}

# --------------------- Build Credential ---------------------

# Prompt for Password

Write-Host
$pass = Read-Host " Enter [$Login] Password " -AsSecureString

Clear-Host
Write-Host
Write-Host -ForegroundColor Gray    " ---------------------------------------------------------------------------------"
Write-Host -ForegroundColor Magenta " NetAPP ONTAP DSC 9.x STIG                                    Version 1, Release 3"
Write-Host -ForegroundColor Gray    " ---------------------------------------------------------------------------------"

# Generate the authorization credential
# - $script: makes the variable available to the functions in the script so they do not need to be passed in

$script:Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$Login", $pass

# --------------------- Check Cluster ---------------------

# Build REST API URL

$apiUri = "https://$clusterip/api"

# Query the 'cluster' category

$uri = $apiUri + '/cluster'

# Get cluster details

$result = Invoke-ONTAP -Method Get -URL $uri

# Save cluster name

$ClusterName = $result.name

# Save Cluster Version

$ClusterVersion = $result.version.full

Write-Host -ForegroundColor White "              $ClusterVersion"

# --------------------- Open copy of checklist for output ---------------------

$doc_date = Get-Date -Format yyyy_MM_dd
$cklfilename = "ontapstig_" + $ClusterName + "_" + $doc_date + ".ckl"
$checklist_file = "$resultpath/" + $cklfilename

$script:xml = [System.Xml.XmlWriter]::Create($checklist_file)

# --------------------- Set Host Name, IP Address, and FQDN in Checklist ---------------------

$checklist.CHECKLIST.ASSET.HOST_NAME = $ClusterName.ToString()
$checklist.CHECKLIST.ASSET.HOST_IP = $ClusterIP.ToString()

if ( $domain.Length -gt 0 ) { $checklist.CHECKLIST.ASSET.HOST_FQDN = "$ClusterName.$domain" }

$checklist.CHECKLIST.ASSET.TARGET_COMMENT = "$ClusterVersion"

# --------------------- Build list of vulnerabilities from checklist ---------------------

$vulnerability_numbers = @()
$severity_levels = @()
$rule_titles = @()

for ($i=0; $i -lt ($checklist.CHECKLIST.STIGS.iSTIG.VULN).count; $i++) { 

    $vulnerability_numbers += $checklist.CHECKLIST.STIGS.iSTIG.VULN[$i].stig_data.attribute_data[0]
    $severity_levels       += $checklist.CHECKLIST.STIGS.iSTIG.VULN[$i].stig_data.attribute_data[1]
    $rule_titles           += $checklist.CHECKLIST.STIGS.iSTIG.VULN[$i].stig_data.attribute_data[5]

}

# --------------------- Process Each STIG Vulnerability ---------------------

# Initialize Totals

$open_count = 0
$not_finding_count = 0
$not_applicable_count = 0
$not_reviewed_count = 0

$cat1_open_count = 0
$cat2_open_count = 0
$cat3_open_count = 0

$total_count = $vulnerability_numbers.Count

# Loop through each vulnerability number and "Check/Fix"

For ( $i=0; $i -lt $total_count; $i++ ) {

    # Reset 

    $f_status = "Not_Reviewed"
    $f_details = ""
    $f_comments = ""

    $vulnerability = $vulnerability_numbers[$i]
    $severity = Get-CatLevel -Level $severity_levels[$i]
    $rule = $rule_titles[$i]

    # Get associated settings from STIG .INI file for this cluster

    $v = $config[$vulnerability]

    # Common settings for all [V-######]

    foreach ($key IN $v.keys) {

        $status   = $v['override_status']
        $status   = Get-Status -StatusCode $status
        $details  = $v['details']
        $comments = $v['comments']

    }

    # Display current Vulnerability, CAT level, and Rule from checklist

    Write-Host -ForegroundColor Gray  " ---------------------------------------------------------------------------------"
    Write-Host -ForegroundColor Cyan  " $vulnerability ($severity) "
    Write-Host -ForegroundColor Gray  " -----------------"
    Write-Text -LineText " $rule" -Pad 1
    Write-Host -ForegroundColor Gray  " -----------------"

    # If the 'override_status' is SET, skip the check and use settings in .INI (override_status, details, comments)

    if ($status -ne '') {

        $statuslong = Get-StatusSentence -StatusWord $status

        Write-Host -ForegroundColor Green " $statuslong *"

        $f_status = $status
        $f_details = "$details"
        $f_comments = "$comments"

    } else {

        $finding = $false

        # Check vulnerability number and save results to checklist

        switch ($vulnerability) {

# ---------- ONTAP must be configured to limit the number of concurrent sessions (1)

            'V-246922' {

                # Get current setting

                $vUrl = $apiUri + "/private/cli/security/session/limit?interface=cli&category=application&fields=max-active-limit"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                if ($vResult.num_records -gt 0) {

                    foreach ($v in $vResult.Records) {

                        # Check if not set to 1 concurrent session

                        if ( $v.max_active_limit -gt 1 ) {

                            Write-Host -ForegroundColor Red " OPEN: Current Setting is $($v.max_active_limit) - Required Limit is 1 Session"

                            $f_status = 'Open'
                            $f_details = "Current Setting is $($v.max_active_limit) sessions"
                            $f_comments = ''

                            $finding = $true

                        }

                    }

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "Limit Set to 1 Session"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must be configured to create a session lock after 15 minutes

            'V-246923' {

                # Get current setting

                $vUrl = $apiUri + "/private/cli/system/timeout?fields=timeout"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # Check if timeout is greater than 15 minutes

                if ( $vResult.timeout -gt 15) {

                    Write-Host -ForegroundColor Red " OPEN: Current Setting is $($vResult.timeout) - Required Timeout is 15 minutes"

                    $f_status = 'Open'
                    $f_details = "Current Setting is $($vResult.timeout) minutes"
                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "Timeout Set to $($vResult.timeout) minutes"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must automatically audit account-enabling actions

            'V-246925' {

                # Get current destinations

                $vUrl = $apiUri + "/security/audit/destinations"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # Check if a destination is configured

                if ( $vResult.num_records -eq 0) {

                    Write-Host -ForegroundColor Red " OPEN: Log Forwarding Not Configured"

                    $f_status = 'Open'
                    $f_details = "Log Forwarding Not Configured"
                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "Log Forwarding Configured"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable

            'V-246926' {

                # Get all local accounts with admin role (and not locked)

                $vUrl = $apiUri + "/security/accounts?role.name=admin&applications.authentication_methods=password&locked=false"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # Check if more than one local admin account

                if ( $vResult.num_records -ne 1) {

                    Write-Host -ForegroundColor Red " OPEN: More than 1 Account with Admin Role ($($vResult.num_records) Found)"

                    $f_status = 'Open'
                    $f_details = "More than 1 Account with Admin Role and Authentication Method of 'password' ($($vResult.num_records) Found)"
                    $f_comments = "Reduce the number of local Admin accounts to one (1)"

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"
    
                    $f_status = 'NotAFinding'
                    $f_details = "Only 1 Account with Admin Role and Authentication Method of 'password'"
                    $f_comments = ""
    
                }

                Write-Host

            }

# ---------- ONTAP must enforce administrator privileges based on their defined roles

            'V-246927' {

                # Manual Review - override using .INI input file

                Write-Host -ForegroundColor Red " OPEN : Requires MANUAL REVIEW"

                $f_status = 'Open'
                $f_details = ""
                $f_comments = "Requires MANUAL REVIEW"

                Write-Host

            }

# ---------- ONTAP must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures

            'V-246930' {

                # Manual Review - override using .INI input file

                Write-Host -ForegroundColor Red " OPEN : Requires MANUAL REVIEW"

                $f_status = 'Open'
                $f_details = ""
                $f_comments = "Requires MANUAL REVIEW"

                Write-Host

            }

# ---------- ONTAP must be configured to enforce the limit of three consecutive failed logon attempts

            'V-246931' {

                # Get current setting

                $vUrl = $apiUri + "/private/cli/security/login/role/config?fields=max-failed-login-attempts"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # Check each role setting

                $roles = @()
                foreach ($rec IN $vResult.records) {

                    # Save role name to array if role has more than 3 failed login attempts

                    if ($rec.max_failed_login_attempts -ne 3) {
                        $roles += $rec.role
                    }

                }

                # List each role with more than 3 failed login attempts in the checklist 'Details'

                if ( $roles.Count -gt 0 ) {

                    Write-Host -ForegroundColor Red " OPEN: $($roles.Count) Roles Found with Max Failed Attempts Not Set to 3"

                    $f_status = 'Open'
                    $f_details = "$($roles.Count) Roles Found with Max Failed Attempts Greater than 3 :`n"

                    foreach ($r IN $roles) { 
                        $f_details += "- $r `n" 
                    }

                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "All Roles Set to Maximum of 3 Failed Attempts"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must be configured to display the Standard Mandatory DoD Notice and Consent Banner before 

            'V-246932' {

                # Get current setting

                $banner = $v['banner']

                $vUrl = $apiUri + '/private/cli/security/login/banner?vserver=' + $ClusterName + '&fields=message'

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                if ($vResult.num_records -eq 0) { 
                    $current_banner = ""
                } else {
                    $current_banner = $vResult.records[0].message
                }

                # Compare current setting to .INI setting

                if (!($current_banner).Contains($banner)) {

                    Write-Host -ForegroundColor Red " OPEN: Missing Standard Mandatory DoD Notice and Consent Banner"

                    $f_status = 'Open'
                    $f_details = "Missing Standard Mandatory DoD Notice and Consent Banner"
                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "Standard Mandatory DoD Notice and Consent Banner"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements

            'V-246933' {

                # Get MDV_* volumes at 100%

                $vUrl = $apiUri + '/private/cli/df?fields=percent-used-space&percent-used-space=100&volume=MDV*'

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # If any, mark 'Open' and add to 'Details' in checklist

                if ($vResult.num_records -gt 0) {

                    Write-Host -ForegroundColor Red " OPEN: MDV volumes at 100 Percent Capacity"

                    $f_status = 'Open'
                    $f_details = "$($vResult.num_records) MDV volumes at 100 Percent Capacity"

                    foreach ($rec IN $vResult.records) {
                        $f_details += "`n- $($rec.volume)"
                    }
                    
                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = "NotAFinding"
                    $f_details = "No MDV_* Volumes Found at 100% Capacity"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must have audit guarantee enabled

            'V-246935' {

                # Get SVMs

                $vUrl = $apiUri + '/svm/svms?fields=cifs.enabled,nfs.enabled'

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                $nas_count = 0

                $svm_audit_false = @()

                # Check each NAS SVM if an audit guarantee is set to 'false'

                foreach ($svm IN $vResult.records) {

                    if ($svm.cifs.enabled -or $svm.nfs.enabled) {

                        $vUrl2 = $apiUri + "/private/cli/vserver/audit?audit-guarantee=false&vserver=$($svm.name)"

                        $vResult2 = Invoke-ONTAP -Method Get -URL $vUrl2

                        # If found, save SVM name to array to add to 'Details' in checklist

                        if ($vResult2.num_records -gt 0) {

                            if ($svm.audit_guarantee -eq $false) {
                                $svm_audit_false += $svm.name
                            }

                        }

                        $nas_count++

                    }

                }

                # If any NAS SVMs were found with audit guarantee false ...

                if ($svm_audit_false.Count -gt 0) {

                    Write-Host -ForegroundColor Gray " OPEN: NAS SVMs Found with Audit Guarantee False"

                    $f_status = 'Open'
                    $f_details = 'NAS SVMs Found with Audit Guarantee False'

                    foreach ($svmaudit IN $svm_audit_false) {
                        $f_details += "`n- $svmaudit"
                    }

                    $f_comments = ""

                } else {

                    Write-Host -ForegroundColor Green " NOT A FINDING"

                    $f_status = "NotAFinding"
                    $f_details = "NAS SVMs have Audit Guarantee Set to True"
                    $f_comments = ""

                }

                if ($nas_count -eq 0) {

                    Write-Host -ForegroundColor Yellow " NOT APPLICABLE: No SVMs with NAS Protocols Enabled"

                    $f_status = "Not_Applicable"
                    $f_details = "No SVMs with NAS Protocols Enabled"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must be configured to synchronize internal information system clocks using redundant authoritative time sources (at least 3)

            'V-246936' {

                # Get NTP Servers

                $vUrl = $apiUri + "/cluster/ntp/servers?"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # If less than 3, mark 'Open' and add current NTP servers to 'Details' in checklist

                if ( $vResult.num_records -lt 3 ) {

                    Write-Host -ForegroundColor Red " OPEN: $($vResult.num_records) NTP Server(s) Found - Requires at least 3"

                    $f_status = 'Open'
                    $f_details = "$($vResult.num_records) NTP Server(s) Found - Requires at least 3: `n"

                    foreach ($rec IN $vResult.records) { 
                        $f_details += "- $($rec.server) `n"
                    }

                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "$($vResult.num_records) NTP Servers Found: `n"

                    foreach ($rec IN $vResult.records) { 
                        $f_details += "- $($rec.server) `n"
                    }

                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT)

            'V-246938' {

                # Get current timezone

                $valid_timezones = @('UTC','GMT','Etc/UTC','GMT+0','GMT-0','GMT0','Greenwich')

                $vUrl = $apiUri + "/cluster?fields=timezone"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # Check if it is a valid timezone

                if (!($valid_timezones.contains($vResult.timezone.name))) {

                    Write-Host -ForegroundColor Red " OPEN: Timezone Set to $($vResult.timezone.name) - Required to be UTC or GMT"

                    $f_status = 'Open'
                    $f_details = "Timezone Set to $($vResult.timezone.name) - Required to be UTC or GMT"
                    $f_comments = "Valid timezones:"

                    foreach($tz In $valid_timezones) {
                        $f_comments += "`n$tz"
                    }

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "Timezone is Set to $($vResult.timezone.name)"
                    $f_comments = ""

                }

                Write-Host 

            }

# ---------- ONTAP must enforce access restrictions associated with changes to the device configuration

            'V-246939' {

                # Manual Review - override using .INI input file

                Write-Host -ForegroundColor Red " OPEN : Requires MANUAL REVIEW"

                $f_status = 'Open'
                $f_details = ""
                $f_comments = "Requires MANUAL REVIEW"

                Write-Host

            }

# ---------- ONTAP must be configured to use an authentication server to provide multifactor authentication

            'V-246940' {

                # CHECK 1 - Domain Tunnel

                $domain_tunnel = $false

                $vUrl = $apiUri + '/private/cli/security/login/domain-tunnel'

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl -ReturnNullOnError

                # If a domain tunnel does not exist ...

                if ($null -eq $vResult) {

                    Write-Host -ForegroundColor Red " OPEN: No Domain Tunnel Exists"

                    $f_status = 'Open'
                    $f_details = "No Domain Tunnel Exists"
                    $f_comments = ""

                    $finding = $true

                } else {

                    $domain_tunnel = $true
                }

                # CHECK 2 - Get accounts using domain authentication

                if ($domain_tunnel) {

                    $vUrl = $apiUri + "/security/accounts?applications.authentication_methods=domain"

                    $vResult2 = Invoke-ONTAP -Method Get -URL $vUrl

                    # If no domain accounts found ...

                    if ($vResult2.num_records -eq 0) {

                        Write-Host -ForegroundColor Red " OPEN: No Accounts Using Domain Authentication"

                        $f_status = 'Open'
                        $f_details = "No Accounts Using Domain Authentication"
                        $f_comments = "Domain Tunnel: $($vResult.vserver)"

                        $finding = $true

                    }

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "Domain Tunnel and Accounts Using Domain Authentication Found"
                    $f_comments = "Domain Tunnel: $($vResult.vserver)"

                }

                Write-Host

            }

# ---------- ONTAP must be configured to conduct backups of system level information

            'V-246944' {

                # Get cluster level configuration backups

                $vUrl = $apiUri + "/support/configuration-backup/backups?type=cluster"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # If not found, mark 'Open' and update checklist

                if ($vResult.num_records -eq 0) {

                    Write-Host -ForegroundColor Red " OPEN: No Cluster Backups Found"

                    $f_status = 'Open'
                    $f_details = "No Cluster Backups Found"
                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "$($vResult.num_records) Cluster Backup(s) Found"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must use DoD-approved PKI rather than proprietary or self-signed device certificates

            'V-246945' {

                # Get client CA certificates

                $valid_ca_list = ($v['valid_ca_list']).Split(',')

                $invalid_ca_list = @()

                $vUrl = $apiUri + "/security/certificates?type=client_ca"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # Check each client CA for Approved PKI (not self-signed, issued internally, etc)

                foreach ($ca IN $vResult.records) {

                    # Save to array to add to 'Comments' in checklist

                    if ($valid_ca_list.contains($ca)){
                        $invalid_ca_list += $ca.name
                    }

                }

                # If any invalid client CAs ...

                if ($invalid_ca_list.Count -gt 0) {

                    Write-Host -ForegroundColor Red " OPEN: Client Certificates Found with Non-Approved PKI"

                    $f_status = 'Open'
                    $f_details = "Client Certificates Found with Non-Approved PKI"
                    $f_comments = "Invalid Client CA Certificates:"

                    foreach ($invalid_ca IN $invalid_ca_list) {
                        $f_comments += "`n$invalid_ca"
                    }

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "No Invalid Client CA Certificates Found"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services

            'V-246946' {

                $data_protocol_services = @('data-nfs','data-iscsi','data-cifs','data-nvme-tcp','data-s3-server')
                $data_protocol_hit = $false
                $hitlist = @()

                # Get all LIFs with service policy name

                $vUrl = $apiUri + '/private/cli/network/interface/?fields=service-policy'

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl 

                # Check each LIF service policy / service allowable addresses

                foreach ($rec IN $vResult.records) {

                    $curr_svm = $rec.vserver
                    $curr_lif = $rec.lif
                    $curr_policy = $rec.service_policy

                    # Get the service policy settings associated with the current LIF

                    $vUrl2 = $apiUri + "/private/cli/network/interface/service-policy?fields=vserver,policy,service-allowed-addresses&vserver=$curr_svm&policy=$curr_policy"

                    $vResult2 = Invoke-ONTAP -Method Get -URL $vUrl2

                    foreach ( $rec2 IN $vResult2.records ) {

                        foreach ($allowed IN $rec2.service_allowed_addresses) {

                            $service_rule = $allowed.Split(':')

                            $_service = ($service_rule[0]).Trim()
                            $_rule    = ($service_rule[1]).Trim()

                            if ( $data_protocol_services.Contains($_service) -or ($curr_svm -eq 'Cluster' -and $curr_policy -eq 'default-cluster') ) {

                                # ONTAP is unable to perform packet filtering based on the source address for data protocols

                                $data_protocol_hit = $true

                            }
                            
                            if ($_rule -eq '0.0.0.0/0') {

                                $hitlist += $_service + "`t" + $_rule + "`t" + $rec2.vserver + "`t" + $curr_lif
                                $finding = $true

                            }

                        }

                    }

                }

                if ($finding) {

                    Write-Host -ForegroundColor Red " OPEN: In-Use Service Policies Found Without Prohibitions (Packet Filtering)"

                    $f_status = 'Open'
                    $f_details = "In-Use Service Policies Found Without Prohibitions (Packet Filtering)"

                    foreach ($hit IN $hitlist) {
                        $f_details += "`n - $hit"
                    }

                } else {

                    Write-Host -ForegroundColor Green "NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = ""
                    $f_comments = ""
                }

                if ($data_protocol_hit) {

                    # https://kb.netapp.com/onprem/ontap/os/Unable_to_create_a_service_policy_to_limit_data_access_using_the_allowed-addresses_option

                    $f_comments  = "ONTAP is unable to perform packet filtering based on the source address for data protocols and vServer Cluster / default-cluster Service Policy `n"
                    $f_comments += "A physical or virtual firewall should be used if packet filtering for data protocols is needed`n`n"
                    $f_comments += "Data Protocol Services Include:"

                    foreach ($dps In $data_protocol_services) {
                        $f_comments += "`n - $dps"
                    }
                    $f_comments += "`n`nCluster Services Include:`n - default-cluster : cluster-core"

                    $f_comments += "`n`nRef: https://kb.netapp.com/onprem/ontap/os/Unable_to_create_a_service_policy_to_limit_data_access_using_the_allowed-addresses_option"

                }

                Write-Host

            }

# ---------- ONTAP must be configured to authenticate each administrator prior to authorizing privileges based on assignment of group or role

            'V-246947' {

                # Get domain accounts with admin role

                $vUrl = $apiUri + "/security/accounts?role.name=admin&applications.authentication_methods=domain"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # Check if any found ...

                if ( $vResult.num_records -eq 0) {

                    Write-Host -ForegroundColor Red " OPEN: No Accounts with Admin Role and Domain Authentication Exist"

                    $f_status = 'Open'
                    $f_details = "No Accounts with Admin Role and Domain Authentication Exist"
                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"
    
                    $f_status = 'NotAFinding'
                    $f_details = "Accounts with Admin Role and Domain Authentication Found"
                    $f_comments = ""
    
                }

                Write-Host

            }

# ---------- ONTAP must implement replay-resistant authentication mechanisms for network access to privileges accounts

            'V-246948' {

                # Get domain accounts with admin role

                $vUrl = $apiUri + "/security/accounts?role.name=admin&applications.authentication_methods=domain"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # Check if any found ...

                if ( $vResult.num_records -eq 0) {

                    Write-Host -ForegroundColor Red " OPEN: No Accounts with Admin Role and Domain Authentication Exist"

                    $f_status = 'Open'
                    $f_details = "No Accounts with Admin Role and Domain Authentication Exist"
                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"
    
                    $f_status = 'NotAFinding'
                    $f_details = "Accounts with Admin Role and Domain Authentication Found"
                    $f_comments = ""
    
                }

                Write-Host

            }

# ---------- ONTAP must be configured to authenticate SNMP messages using FIPS-validated Keyed-HMAC

            'V-246949' {

                # Get SNMP Status

                $vUrl = $apiUri + "/support/snmp?fields=enabled"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # If Enabled, check for USM account

                if ($vResult.enabled) {

                    $vUrl = $apiUri + "/support/snmp/users?authentication_method=usm"

                    $vResult2 = Invoke-ONTAP -Method Get -URL $vUrl

                    if ($vResult2.num_records -eq 0) {

                        Write-Host -ForegroundColor Red " OPEN: SNMP is Enabled - MANUALLY create an SNMPv3 User with AuthMethod of USM"

                        $f_status = 'Open'
                        $f_details = "SNMP is Enabled and NO SNMP v3 Users with Authentication Method USM"
                        $f_comments = "MANUALLY create an SNMPv3 User with AuthMethod of USM"

                        $finding = $true

                    } else {
                        $msg = "SNMP v3 Users with Authentication Method USM Found"
                    }

                } else {

                    $msg = "SNMP is Disabled"

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "$msg"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must authenticate NTP sources using authentication that is cryptographically based

            'V-246950' {

                # Get NTP Servers without Authentication (keys)

                $vUrl = $apiUri + "/cluster/ntp/servers?authentication_enabled=false"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # If found, mark 'Open' and list in the 'Details' section of checklist

                if ( $vResult.num_records -gt 0 ) {

                    Write-Host -ForegroundColor Red " OPEN: $($vResult.num_records) NTP Server(s) Found with Authentication Disabled"

                    $f_status = 'Open'
                    $f_details = "$($vResult.num_records) NTP Server(s) Found with Authentication Disabled `n"

                    $current_ntp_servers = @()

                    foreach ($rec IN $vResult.records) { 
                        $f_details += "- $($rec.server) `n"
                        $current_ntp_servers += $rec.server
                    }

                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "All NTP Servers Have Authentication Enabled"
                    $f_comments = ""

                }

                $vUrl = $apiUri + "/cluster/ntp/servers"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                if ($vResult.num_records -eq 0) {

                    $f_status = 'Open'
                    $f_details = "No NTP Servers Found - See V-246936"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must enforce a minimum 15-character password length

            'V-246951' {

                # Get Minimum Password Length Setting

                $vUrl = $apiUri + "/private/cli/security/login/role/config?role=admin&fields=passwd-minlength"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # Check if less than 15...

                if ($vResult.records[0].passwd_minlength -lt 15) {

                    Write-Host -ForegroundColor Red " OPEN: Minimum Password Length is $($vResult.records[0].passwd_minlength) - Must be at least 15 characters"

                    $f_status = 'Open'
                    $f_details = "Minimum Password Length is $($vResult.records[0].passwd_minlength) - Must be at least 15 characters"
                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "Minimum Password Length is $($vResult.records[0].passwd_minlength)"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must enforce password complexity by requiring that at least one uppercase character be used

            'V-246952' {

                # Get Minimum Uppercase Setting
    
                $vUrl = $apiUri + "/private/cli/security/login/role/config?role=admin&fields=passwd-min-uppercase-chars"
    
                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # If not at least 1 mark 'Open' in checklist ...
    
                if ($vResult.records[0].passwd_min_uppercase_chars -eq 0) {
    
                    Write-Host -ForegroundColor Red " OPEN: Minimum Uppercase Characters is $($vResult.records[0].passwd_min_uppercase_chars) - Must be at least 1"
    
                    $f_status = 'Open'
                    $f_details = "Minimum Uppercase Characters is $($vResult.records[0].passwd_min_uppercase_chars) - Must be at least 1"
                    $f_comments = ""
    
                    $finding = $true
    
                }
    
                if (!($finding)) {
    
                    Write-Host -ForegroundColor GREEN " NOT A FINDING"
    
                    $f_status = 'NotAFinding'
                    $f_details = "Minimum Uppercase Characters is $($vResult.records[0].passwd_min_uppercase_chars)"
                    $f_comments = ""
    
                }
        
                Write-Host

            }

# ---------- ONTAP must enforce password complexity by requiring that at least one lowercase character be used

            'V-246953' {

                # Get Minimum Lowercase Setting
    
                $vUrl = $apiUri + "/private/cli/security/login/role/config?role=admin&fields=passwd-min-lowercase-chars"
    
                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # If not at least 1, mark 'Open'
    
                if ($vResult.records[0].passwd_min_lowercase_chars -eq 0) {
    
                    Write-Host -ForegroundColor Red " OPEN: Minimum Lowercase Characters is $($vResult.records[0].passwd_min_lowercase_chars) - Must be at least 1"
    
                    $f_status = 'Open'
                    $f_details = "Minimum Lowercase Characters is $($vResult.records[0].passwd_min_lowercase_chars) - Must be at least 1"
                    $f_comments = ""
    
                    $finding = $true
    
                }
    
                if (!($finding)) {
    
                    Write-Host -ForegroundColor GREEN " NOT A FINDING"
    
                    $f_status = 'NotAFinding'
                    $f_details = "Minimum Lowercase Characters is $($vResult.records[0].passwd_min_lowercase_chars)"
                    $f_comments = ""
    
                }
        
                Write-Host

            }

# ---------- ONTAP must enforce password complexity by requiring that at least one numeric character be used

            'V-246954' {

                # Get Alphanumeric Setting (Enabled/Disabled)
    
                $vUrl = $apiUri + "/private/cli/security/login/role/config?role=admin&fields=passwd-alphanum"
    
                $vResult = Invoke-ONTAP -Method Get -URL $vUrl
    
                # If Disabled, mark 'Open'

                if ($vResult.records[0].passwd_alphanum -eq 'disabled') {
    
                    Write-Host -ForegroundColor Red " OPEN: Alphanumeric Characters Are Not Enabled"
    
                    $f_status = 'Open'
                    $f_details = "Alphanumeric Characters Not Enabled"
                    $f_comments = ""
    
                    $finding = $true
    
                }
    
                if (!($finding)) {
    
                    Write-Host -ForegroundColor GREEN " NOT A FINDING"
    
                    $f_status = 'NotAFinding'
                    $f_details = "Alphanumeric Characters are Required"
                    $f_comments = ""
    
                }
        
                Write-Host

            }

# ---------- ONTAP must enforce password complexity by requiring that at least one special character be used

            'V-246955' {

                # Get Minimum Special Characters Setting
    
                $vUrl = $apiUri + "/private/cli/security/login/role/config?role=admin&fields=passwd-min-special-chars"
    
                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # If not at least 1, mark 'Open'
    
                if ($vResult.records[0].passwd_min_special_chars -eq 0) {
    
                    Write-Host -ForegroundColor Red " OPEN: Minimum Special Characters is $($vResult.records[0].passwd_min_special_chars) - Must be at least 1"
    
                    $f_status = 'Open'
                    $f_details = "Minimum special Characters is $($vResult.records[0].passwd_min_special_chars) - Must be at least 1"
                    $f_comments = ""
    
                    $finding = $true
    
                }
    
                if (!($finding)) {
    
                    Write-Host -ForegroundColor GREEN " NOT A FINDING"
    
                    $f_status = 'NotAFinding'
                    $f_details = "Minimum special Characters is $($vResult.records[0].passwd_min_special_chars)"
                    $f_comments = ""
    
                }
        
                Write-Host

            }

# ---------- ONTAP must be configured to implement cryptographic mechanisms using FIPS 140-2

            'V-246958' {

                # Get FIPS-140-2 Setting (Enabled/Disabled)

                $vUrl = $apiUri + "/security?fields=fips.enabled"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # If not Enabled, mark 'Open'

                if (!($vResult.fips.enabled)) {

                    Write-Host -ForegroundColor Red " OPEN: FIPS 140-2 is Disabled"

                    $f_status = 'Open'
                    $f_details = "FIPS 140-2 is Disabled"
                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "FIPS 140-2 is Enabled"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements

            'V-246959' {

                # Get Session Timeout

                $vUrl = $apiUri + "/private/cli/system/timeout?fields=timeout"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # If more than 10 minutes, mark 'Open'

                if ( $vResult.timeout -gt 10) {

                    Write-Host -ForegroundColor Red " OPEN: Current Setting is $($vResult.timeout) - Required Timeout is 10 minutes"

                    $f_status = 'Open'
                    $f_details = "Current Setting is $($vResult.timeout) minutes"
                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "Timeout Set to $($vResult.timeout) minutes"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- ONTAP must be configured to send audit log data to a central log server

            'V-246964' {

                # Check for Audit Destinations

                $vUrl = $apiUri + "/security/audit/destinations"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                # If not found, mark 'Open'

                if ( $vResult.num_records -eq 0) {

                    Write-Host -ForegroundColor Red " OPEN: Log Forwarding Not Configured"

                    $f_status = 'Open'
                    $f_details = "Log Forwarding Not Configured"
                    $f_comments = ""

                    $finding = $true

                }

                if (!($finding)) {

                    Write-Host -ForegroundColor GREEN " NOT A FINDING"

                    $f_status = 'NotAFinding'
                    $f_details = "Log Forwarding Configured"
                    $f_comments = ""

                }

                Write-Host

            }

# ---------- Default - Unknown Vulnerability Number 

            default {

                Write-Host -ForegroundColor Yellow " NOT REVIEWED"
                Write-Host

                $f_status = 'Not_Reviewed'
                $f_details = ""
                $f_comments = ""

            }

        }

    }

    # ---------- Update Totals ---------- 

    if ( $f_status -eq 'Open' ) {
        $open_count++
        if ($severity -eq 'CAT I') {
            $cat1_open_count++
        } elseif ($severity -eq 'CAT II') {
            $cat2_open_count++
        } elseif ($severity -eq 'CAT III') {
            $cat3_open_count++
        }
    } elseif ( $f_status -eq 'NotAFinding' ) {
        $not_finding_count++
    } elseif ( $f_status -eq 'Not_Applicable' ) {
        $not_applicable_count++
    } elseif ( $f_status -eq 'Not_Reviewed' ) {
        $not_reviewed_count++
    }

    # ---------- Update Checklist ---------- 

    $finding_vul = ($checklist.CHECKLIST.STIGS.iSTIG.VULN.stig_data | Where-Object { $_.attribute_data -like $vulnerability }).parentnode

    $finding_vul.STATUS = $f_status.ToString()
    $finding_vul.FINDING_DETAILS = $f_details.ToString()
    $finding_vul.COMMENTS = $f_comments.ToString()

}

# ---------- Save checklist and cleanup ---------- 

$checklist.Save($xml)
$script:xml.dispose()

# --------------------- Display Checklist filename and Totals ---------------------

Write-Host -ForegroundColor Gray " ---------------------------------------------------------------------------------"
Write-Host -ForegroundColor Magenta " Checklist Saved To : " -NoNewline
Write-Host -ForegroundColor White "./ontap_stig_findings/$cklfilename"
Write-Host -ForegroundColor Gray " ---------------------------------------------------------------------------------"
Write-Host -ForegroundColor Magenta " Vulnerabilities"
Write-Host
Write-Host -ForegroundColor Cyan "   Open           : " -NoNewline
Write-Host -ForegroundColor Red "$open_count `t" -NoNewline
Write-Host -ForegroundColor Cyan " CAT I: " -NoNewline
Write-Host -ForegroundColor Red $cat1_open_count -NoNewline
Write-Host -ForegroundColor Cyan "  II: " -NoNewline
Write-Host -ForegroundColor Yellow $cat2_open_count -NoNewline
Write-Host -ForegroundColor Cyan "  III: " -NoNewline
Write-Host -ForegroundColor White $cat3_open_count

Write-Host -ForegroundColor Cyan "   Not A Finding  : " -NoNewline
Write-Host -ForegroundColor Green "$not_finding_count"


Write-Host -ForegroundColor Cyan "   Not Applicable : " -NoNewline
Write-Host -ForegroundColor Yellow "$not_applicable_count"

Write-Host -ForegroundColor Cyan "   Not Reviewed   : " -NoNewline
Write-Host -ForegroundColor Gray $not_reviewed_count

Write-Host -ForegroundColor Gray " ----------------------"
Write-Host -ForegroundColor Cyan "   Total          : " -NoNewline
Write-Host -ForegroundColor White $total_count
Write-Host

# --------------------- END ---------------------

Write-Host -ForegroundColor Gray " ---------------------------------------------------------------------------------"
Write-Host 

# --------------------- END ---------------------