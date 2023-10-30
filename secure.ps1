#requires -version 7

<#
        .SYNOPSIS
        Applies security-related settings based on an input file {secure}.ini. Security settings are based on DISA ONTAP STIG v1r3.

        .DESCRIPTION
        Applies security-related settings based on an input file {secure}.ini. Security settings are based on DISA ONTAP STIG v1r3.

		See 'secure_template.ini' for details on the parameters 

		Workflow:

		1. Test for configuration file
        2. Process configuration file
        3. Verify Settings
        4. Ping cluster IP (verify reachable)
        5. Check REST API connection to cluster - Get cluster name and ONTAP version
        6. Set Concurrent Sessions                                      [Session Limit        ]
        7. Set Session Timeout                                          [Session Timeout      ]
        8. Configure Audit Account-enabling actions                     [Cluster Logging      ]
        9. Set Consecutive Failed Logon Attempts                        [Login Attempts       ]
        10. Set Banner & Message of the Day for Cluster and SVMs        [Banner & MOTD        ]
        11. ONTAP Audit Protocols                                       [ONTAP Audit          ]
        12. SVM Audit Configuration (NAS SVMs)                          [SVM Audit - SMB/NFS  ]
        13. Add NTP Servers                                             [NTP Servers          ]
        14. Set Time Stamp for Audit Records (UTC/GMT)                  [Time Zone            ]
        15. Configure MultiFactor Authentication                        [MultiFactor Auth     ]
        16. On-Demand Cluster Configuration Backup                      [Config Backup        ]
        17. Service Policies (Packet Filtering)                         [Service Policies     ]
        18. Add Domain Accounts with Admin Role                         [Domain Accounts      ]
        19. Enable/Disable FIPS 140-2                                   [FIPS 140-2           ]        
        20. Enable & Configure SNMP                                     [Configure SNMP       ]
        21. Set Password Complexity Minimums                            [Password Complexity  ]
        22. Create Account of Last Resort (1 Local Admin Account)       [Local Admin          ]
        23. Check if Reboot Required
        24. Lock / Unlock Default admin Account                         [Default Admin Account]

        .PARAMETER SecureFile
        The {configuration}.ini file that contains settings for each specific STIG and Hardening Guide item.

        .EXAMPLE
        PS>  .\secure.ps1 -SecureFile secure_cluster1.ini -ClusterIP 10.0.10.10 -Login admin

		Processes secure_cluster1.ini for settings and checks each security item for compliance  

        .LINK
        ONTAP 9 Documentation: https://docs.netapp.com/ontap-9/index.jsp

        .LINK
        ONTAP 9 REST API: https://{ClusterIP}/docs/api

#>

[cmdletbinding()]
param (
	[Parameter(Mandatory = $True)]
	[string]$SecureFile,
    [Parameter(Mandatory = $True)]
    [ipaddress]$ClusterIP,
    [Parameter(Mandatory = $True)]
    [string]$Login
)

# -------------------- TODO LIST --------------------

# Check if only 1 local admin account before locking

# -------------------- Functions --------------------

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
    #
    # Outputs:
    #   - Result of REST API call
    #
    # Body is only required for Post|Patch - a default of an empty JSON body {} can be used depending on the DELETE API requirements
    #
    # Errors:
    #   - Exception Messages are displayed and script is terminated
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

            Exit

        }

    }

    return $_result

}
function Get-TrueFalse {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$YesNo
    )

    # Returns True if value equals 'yes|true' - not case sensitive
    # Any other value will return False

    if (($YesNo -eq 'yes') -or ($YesNo -eq 'true')) { 
        return $true 
    } else { 
        return $false
    }

}
function Convert-UnitsToBytes {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $True)]
        [uint64]$Size,
        [Parameter(Mandatory = $True)]
	    [ValidateSet('MB', 'GB', 'TB')]$Unit
    )

    # Converts BYTES to a specified UNIT (MB|GB|TB)
    #   - Any other Unit will return the original value passed in

    $Unit = $Unit.ToUpper()

    switch ($Unit) {
        'MB' {
            $bytes = $size * 1MB
        }
        'GB' {
            $bytes = $size * 1GB
        }
        'TB' {
            $bytes = $size * 1TB
        }
        Default {
            $bytes = $size
        }
    }

    return $bytes

}
# -------------------- Test for configuration file --------------------

if (!(Test-Path $SecureFile)){

    Write-Host -ForegroundColor Red "Configuration File ($SecureFile) Not Found"
    Write-Host

    Exit

}

# -------------------- Process configuration file --------------------

# Process configuration file

$config = Get-ConfigSettings "$SecureFile"

# SECURITY

$concurrent_sessions = ($config["SECURITY"]).concurrent_sessions
$session_timeout     = ($config["SECURITY"]).session_timeout
$max_login_attempts  = ($config["SECURITY"]).max_login_attempts
$banner              = ($config["SECURITY"]).banner
$motd                = ($config["SECURITY"]).motd
$set_timezone        = ($config["SECURITY"]).set_timezone
if ($set_timezone.Length -eq 0) { $set_timezone = 'Etc/UTC'}
$fips                = (($config["SECURITY"]).fips).ToLower()
$service_policies    = (($config["SECURITY"]).service_policies).ToLower()

# NTP

$ntp_servers = (($config["NTP"]).ntp_servers).Split(',')
$ntp_keys    = (($config["NTP"]).ntp_keys).Split(',')

# SNMP

$snmp_enable    = Get-TrueFalse -YesNo (($config["SNMP"]).snmp_enable)
$traps_enable   = Get-TrueFalse -YesNo (($config["SNMP"]).traps_enable)
$trap_host      = ($config["SNMP"]).trap_host
$snmp_community = ($config["SNMP"]).community

# SNMP v3

$snmpv3_host          = ($config["SNMPV3"]).snmpv3_host
$usm_user_name        = ($config["SNMPV3"]).usm_user_name
$usm_auth_password    = ($config["SNMPV3"]).usm_auth_password
$usm_privacy_password = ($config["SNMPV3"]).usm_privacy_password

# PASSWORDCOMPLEXITY

$minlength    = ($config["PASSWORDCOMPLEXITY"]).minlength
$minuppercase = ($config["PASSWORDCOMPLEXITY"]).minuppercase
$minlowercase = ($config["PASSWORDCOMPLEXITY"]).minlowercase
$minspecial   = ($config["PASSWORDCOMPLEXITY"]).minspecial
$alphanum     = (($config["PASSWORDCOMPLEXITY"]).alphanum).ToLower()

# LOCALADMIN

$local_account      = ($config["LOCALADMIN"]).account
$local_password     = ($config["LOCALADMIN"]).password
$lock_default_admin = Get-TrueFalse -YesNo (($config["LOCALADMIN"]).lock_default_admin)

# DOMAINAUTH

$auth_svm_name            = ($config["DOMAINAUTH"]).svm_name
$auth_ad_name             = ($config["DOMAINAUTH"]).ad_name
$auth_ad_fqdn             = ($config["DOMAINAUTH"]).ad_fqdn
$auth_ad_join_account     = ($config["DOMAINAUTH"]).ad_join_account
$auth_ad_join_password    = ($config["DOMAINAUTH"]).ad_join_password
$auth_lif_name            = ($config["DOMAINAUTH"]).lif_name
$auth_lif_ip              = ($config["DOMAINAUTH"]).lif_ip
$auth_lif_netmask         = ($config["DOMAINAUTH"]).lif_netmask
$auth_lif_gateway         = ($config["DOMAINAUTH"]).lif_gateway
$auth_lif_ipspace         = ($config["DOMAINAUTH"]).lif_ipspace
$auth_lif_broadcastdomain = ($config["DOMAINAUTH"]).lif_broadcastdomain
$auth_lif_homenode        = ($config["DOMAINAUTH"]).lif_homenode
$auth_dns_domains         = (($config["DOMAINAUTH"]).dns_domains).Split(',')
$auth_dns_servers         = (($config["DOMAINAUTH"]).dns_servers).Split(',')

# DOMAINACCOUNTS

$auth_domain_accounts = (($config["DOMAINACCOUNTS"]).accounts).Split(',')

# AUDIT

$audit_cli    = Get-TrueFalse -YesNo (($config["AUDIT"]).cli)
$audit_http   = Get-TrueFalse -YesNo (($config["AUDIT"]).http)
$audit_ontapi = Get-TrueFalse -YesNo (($config["AUDIT"]).ontapi)

# AUDITSVM

$audit_volume_name = ($config["AUDITSVM"]).volume_name
$audit_volume_sizeGB = ($config["AUDITSVM"]).volume_sizeGB
$audit_volsize = Convert-UnitsToBytes -Size $audit_volume_sizeGB -Unit GB
$audit_path = ($config["AUDITSVM"]).path
$audit_rotate_sizeMB = ($config["AUDITSVM"]).rotate_sizeMB
$audit_rotate_size = Convert-UnitsToBytes -Size $audit_rotate_sizeMB -Unit MB
$audit_rotate_limit = ($config["AUDITSVM"]).rotate_limit
$audit_log_format = (($config["AUDITSVM"]).log_format).ToLower()

# LOGGING

$log_ipaddress = ($config["LOGGING"]).ipaddress
$log_facility  = ($config["LOGGING"]).facility
$log_ipspace   = ($config["LOGGING"]).ipspace
$log_dest_port = ($config["LOGGING"]).dest_port
$log_protocol  = ($config["LOGGING"]).protocol
$log_verify    = Get-TrueFalse -YesNo (($config["LOGGING"]).verify)

# -------------------- Validation Lists --------------------

$valid_timezones    = @('Etc/UTC','UTC','GMT','GMT+0','GMT-0','GMT0','Greenwich')
$valid_Enabled      = @('enabled','disabled')
$valid_Enable       = @('enable','disable')
$valid_Filter       = @('filter','unfilter')
$valid_Format       = @('evtx','xml')
$valid_log_facility = @('kern','user','local0','local1','local2','local3','local4','local5','local6','local7')
$valid_log_protocol = @('udp_unencrypted','tcp_unencrypted','tcp_encrypted')

# -------------------- Validate Settings --------------------

$err_msgs = @()

if (!($concurrent_sessions -match "\d+"))         { $err_msgs += " Invalid Concurrent Sessions Setting ($concurrnet_sessions)"}
if (!($session_timeout -match "\d+"))             { $err_msgs += " Invalid Session Timeout Setting ($session_timeout)"}
if (!($max_login_attempts -match "\d+"))          { $err_msgs += " Invalid Max Login Attempts Setting ($max_login_attempts)"}
if (!($valid_timezones.Contains($set_timezone)))  { $err_msgs += " Time Zone $set_timezone Not Valid ($set_timezone)" }
if (!($valid_Enable.Contains($fips)))             { $err_msgs += " FIPS 140-2 Setting Not Valid ($fips) - Must Be 'Enable' or 'Disable'" }
if (!($valid_Filter).Contains($service_policies)) { $err_msgs += " Invalid Service Policy Filter Settting - Must Be 'filter' or 'unfilter'" }
if (!($minlength -match "\d+"))                   { $err_msgs += " Invalid Password Minimum Length Setting ($minlength)"}
if (!($minuppercase -match "\d+"))                { $err_msgs += " Invalid Password Minimum Uppercase Characters Setting ($minuppercase)"}
if (!($minlowercase -match "\d+"))                { $err_msgs += " Invalid Password Minimum Lowercase Characters Setting ($minlowercase)"}
if (!($minspecial -match "\d+"))                  { $err_msgs += " Invalid Password Minimum Special Characters Setting ($minspecial)"}
if (!($valid_Enabled).Contains($alphanum))        { $err_msgs += " Password Complexity AlphaNum Invalid - Must Be 'Enabled' or 'Disabled'" }
if ((!($trap_host -as [IPAddress] -as [Bool])) -and $trap_host.Length -gt 0 ) { $err_msgs += " INvalid Trap Host IP Address ($trap_host)"}

foreach($ntp IN $ntp_servers) { 
    if ((!($ntp -as [IPAddress] -as [Bool])) -and $ntp -ne '') { 
        $err_msgs += " Invalid NTP Server IP Address ($ntp)" 
    } 
}

# Configure Logging
if (($log_ipaddress.Length -gt 0) -and ($log_facility.Length -gt 0) -and ($log_ipspace.Length -gt 0) -and `
    ($log_dest_port.Length -gt 0) -and ($log_protocol.Length -gt 0) -and ($log_verify.Length -gt 0)) 
{

    $config_logging = $true

    if (!($log_ipaddress -as [IPAddress] -as [Bool]))   { $err_msgs += " Invalid Cluster Log IP Address ($log_ipaddress)"}
    if (!($valid_log_facility.Contains($log_facility))) { $err_msgs += " Invalid Cluster Log Facility ($log_facility)"}
    if (!($valid_log_protocol.Contains($log_protocol))) { $err_msgs += " Invalid Cluster Log Protocol ($log_protocol)"}

} else {

    $config_logging = $false

}

# Configure Domain Tunnel (Domain Authentication)
if (($auth_svm_name.Length -gt 0)     -and ($auth_ad_name.Length -gt 0)             -and `
    ($auth_ad_fqdn.Length -gt 0)      -and ($auth_ad_join_account.Length -gt 0)     -and `
    ($auth_lif_name.Length -gt 0)     -and ($auth_lif_ip.Length -gt 0)              -and `
    ($auth_lif_netmask.Length -gt 0)  -and ($auth_lif_gateway.Length -gt 0)         -and `
    ($auth_lif_ipspace.Length -gt 0)  -and ($auth_lif_broadcastdomain.Length -gt 0) -and`
    ($auth_lif_homenode.Length -gt 0) -and ($auth_dns_domains.Length -gt 0)         -and `
    ($auth_dns_servers.Length -gt 0))
{

    $auth_tunnel = $true

    if (!($auth_lif_ip -as [IPAddress] -as [Bool]))      { $err_msgs += " Invalid Domain Auth IP Address ($auth_lif_ip)"}
    if (!($auth_lif_gateway -as [IPAddress] -as [Bool])) { $err_msgs += " Invalid Domain Auth Gateway ($auth_lif_gateway)"}

} else {

    $auth_tunnel = $false

}

# Configure Auditing
if (($audit_volume_name.Length -gt 0)   -and ($audit_volume_sizeGB.Length -gt 0) -and `
    ($audit_volsize.Length -gt 0)       -and ($audit_path.Length -gt 0)          -and `
    ($audit_rotate_sizeMB.Length -gt 0) -and ($audit_rotate_limit.Length -gt 0)  -and `
    ($audit_log_format.Length -gt 0))
{
    $config_audit = $true

    if (!($audit_volume_sizeGB -match "\d+"))         { $err_msgs += " Invalid Audit Volume Size Setting ($audit_volume_sizeGB)"}
    if (!($audit_rotate_sizeMB -match "\d+"))         { $err_msgs += " Invalid Audit Rotate Size Setting ($audit_rotate_sizeMB)"}
    if (!($audit_rotate_limit -match "\d+"))          { $err_msgs += " Invalid Audit Rotate Limit Setting ($audit_rotate_limit)"}
    if (!($valid_Format.Contains($audit_log_format))) { $err_mesgs += " Invalid Audit Log Format ($audit_log_format)"}

} else {

    $config_audit = $false

}

# -------------------- Display Error Messages - Exit if Errors --------------------

if ($err_msgs.Count -gt 0) {
    Clear-Host
    Write-Host
    foreach ($msg IN $err_msgs) {
        Write-Host -ForegroundColor Yellow " *** $msg "
    }
    Write-Host
    exit
}

# -------------------- Start --------------------

$inc = 1
Clear-Host

# -------------------- Ping Cluster IP --------------------

if (!(Test-Connection -Ping $clusterip -Count 2 -Quiet )) {

    Write-Host -ForegroundColor Yellow "Cluster $ClusterIP Did Not Respond to PING test"
    Exit

}

# -------------------- Build Header --------------------

# Create a standard HEADER object
# - $script: makes the variable available to the functions in the script so they do not need to passed in

$script:header = @{
    'Accept' = "application/json"
    'Content-Type' = 'application/json'
}

# -------------------- Build Credential --------------------

# Prompt for Password

Write-Host
$pass = Read-Host " Enter [$Login] Password " -AsSecureString

# If Domain Tunnel Settings validated and AD Join Account Password is missing...
if ($auth_tunnel -and ($auth_ad_join_password.Length -eq 0)) {
    Write-Host
    $ad_pass = Read-Host " Enter [$auth_ad_name\$auth_ad_join_account] Password " -AsSecureString
    $auth_ad_join_password = = ConvertFrom-SecureString -SecureString $ad_pass  -AsPlainText
}

Clear-Host
Write-Host
Write-Host -ForegroundColor Gray    " ---------------------------------------------------------------------------------"
Write-Host -ForegroundColor Magenta " Secure ONTAP Cluster                                                         v1.0"
Write-Host -ForegroundColor Gray    " ---------------------------------------------------------------------------------"

# Generate the authorization credential
# - $script: makes the variable available to the functions in the script so they do not need to be passed in

$script:Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$Login", $pass

# -------------------- Check Cluster --------------------

# Build REST API URL

$apiUri = "https://$clusterip/api"

# Query the 'cluster' category

$uri = $apiUri + '/cluster'

# Get cluster details

$result = Invoke-ONTAP -Method Get -URL $uri

# Save cluster name

$ClusterName = $result.name

# -------------------- Save Cluster Version --------------------

$ClusterVersion = $result.version.full

Write-Host -ForegroundColor White "              $ClusterVersion"
Write-Host -ForegroundColor Gray    " ---------------------------------------------------------------------------------"

# -------------------- STIG V-246922: Concurrent Sessions --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Session Limit   `t`t" -NoNewline

# Set session limit

$vUrl = $apiUri + "/private/cli/security/session/limit?interface=cli&category=application"

$vBody = @{

    max_active_limit = $concurrent_sessions

}

$body = $vBody | ConvertTo-Json -Depth 5

$vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

Write-Host -ForegroundColor White $concurrent_sessions

# -------------------- STIG V-246923/V-246959 : Session Timeout (Lock) --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Session Timeout   `t`t" -NoNewline

# Set Session Timeout

$vUrl = $apiUri + "/private/cli/system/timeout"

$vBody = @{
    timeout = $session_timeout
}

$body = $vBody | ConvertTo-Json -Depth 5

$vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

Write-Host -ForegroundColor White "$session_timeout minutes"

# -------------------- STIG V-246925/V-246964 : Audit Account-enabling actions --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Cluster Logging `t`t" -NoNewline

# If .INI settings are sufficient...

if ($config_logging) {

    # Check if already configured

    $vUrl = $apiUri + "/security/audit/destinations/$log_ipaddress/$log_port"

    $vResult = Invoke-ONTAP -Method Get -URL $vUrl

    if ($vResult.num_records -ne 0) {
        
        Write-Host -ForegroundColor Yellow "EXISTS"

    } else {

        # Configure cluster logging

        $vUrl = $apiUri + "/security/audit/destinations?force=true"
        
        $vBody = @{
            address = $log_ipaddress
            facility = $log_facility
            ipspace = @{
                name = $log_ipspace
            }
            port = $log_dest_port
            protocol = $log_protocol
            verify_server = $log_verify
        }
        
        $body = $vBody | ConvertTo-Json -Depth 5

        $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

        Write-Host -ForegroundColor Green 'CONFIGURED'

    }

} else {

    Write-Host -ForegroundColor Yellow 'NOT CONFIGURED - Insufficient Settings'

}

# -------------------- STIG V-246931 :  Consecutive Failed Logon Attempts --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Login Attempts    `t`t" -NoNewline

# Get each role with Maximum Failed Login Attempts

$vUrl = $apiUri + "/private/cli/security/login/role/config?fields=max-failed-login-attempts"

$vResult = Invoke-ONTAP -Method Get -URL $vUrl

$roles = @()

foreach ($rec IN $vResult.records) {

    if ($rec.max_failed_login_attempts -ne 3) {

        $roles += $rec.role

    }

}

# Set each role to 3 attempts if current setting is less than 3

foreach ($rec IN $vResult.records) {

    if ($rec.max_failed_login_attempts -ne 3) {

        $vBody = @{
            max_failed_login_attempts = $max_login_attempts
        }

        $body = $vBody | ConvertTo-Json -Depth 5

        $vUrl = $apiUri + '/private/cli/security/login/role/config?role=' + $rec.role + '&vserver=' + $rec.vserver

        $vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

    }

}

Write-Host -ForegroundColor White $max_login_attempts

# -------------------- STIG V-246932 : Banner & Message of the Day --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Banner & MOTD    `t`t" -NoNewline

# Set Banner and MOTD for Cluster

$vUrl = $apiUri + "/security/login/messages?scope=cluster"

$vBody = @{
    banner = $banner
    message = $motd
}

$body = $vBody | ConvertTo-Json -Depth 5

$vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

# Set Banner and MOTD for Existing SVMs

$vUrl = $apiUri + "/svm/svms"

$vResultSvms = Invoke-ONTAP -Method Get -URL $vUrl

foreach ($sn IN $vResultSvms.records) {

    $svm_name = $sn.name

    $vUrl = $apiUri + "/security/login/messages?svm.name=$svm_name"
    
    $vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

}

Write-Host -ForegroundColor Green "SET"

# -------------------- STIG:  V-246935 : Audit Guarantee --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " ONTAP Audit  `t`t" -NoNewline

# Enable/Disable Auditing for CLI, HTTP, and ONTAPI

$vUrl = $apiUri + "/security/audit"

$vBody = @{
    cli = $audit_cli
    http = $audit_http
    ontapi = $audit_ontapi
}
$body = $vBody | ConvertTo-Json -Depth 5

$vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

Write-Host -ForegroundColor White "CLI: $audit_cli  HTTP: $audit_http  ONTAPI: $audit_ontapi"

# -------------------- Configure Auditing on NAS SVMs --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline
Write-Host -ForegroundColor Cyan " SVM Audit - NAS`t`t" -NoNewline

if ($config_audit) {

    Write-Host

    $eligible = 0

    # Get SVMs

    $vUrl = $apiUri + "/svm/svms?fields=name,cifs.enabled,nfs.enabled,aggregates&subtype=default"
    $svms = Invoke-ONTAP -Method Get -URL $vUrl

    foreach ($rec IN $svms.records){

        $svmname = $rec.name
        $cifs    = $rec.cifs.enabled
        $nfs     = $rec.nfs.enabled
        $aggr    = $rec.aggregates[0].name

        # Get Audit Settings for SVM

        $vUrl = $apiUri + "/protocols/audit?fields=*&svm.name=$svmname"
        $audit = Invoke-ONTAP -Method Get -URL $vUrl

        # No audit settings found and SVM is cifs or nfs enabled

        if ( ($audit.num_records -eq 0) -and (($cifs -or $nfs)) ) {

            # Get '{svmname}_audit' Export Policy with Rule

            $audit_policy = $svmname + '_audit'

            $vUrl = $apiUri + "/protocols/nfs/export-policies?svm.name=$svmname&name=$audit_policy&return_records=false"

            $vResult = Invoke-ONTAP -Method Get -URL $vUrl

            # Policy Does Not Exist - Create Policy

            if ($VResult.num_records -eq 0) {

                $vUrl = $apiUri + "/protocols/nfs/export-policies"

                $vBody = @{
                    name = $audit_policy
                    svm = @{
                        name = "$svmname"
                    }
                }

                $body = $vBody | ConvertTo-Json -Depth 5

                $vUrl = $apiUri + "/protocols/nfs/export-policies"
                $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

                # Get ID for export policy

                $vUrl = $apiUri + "/protocols/nfs/export-policies?svm.name=$svmname&name=$audit_policy&fields=*&return_records=true"

                $vResult = Invoke-ONTAP -Method Get -URL $vUrl

                $exp_ID = $vResult.records[0].id

                # Add Export Policy Rule

                $vRule = @{
                    clients = @(
                        @{
                            match = "0.0.0.0/0"
                        }
                    )
                    protocols = @(
                        "any"
                    )
                    ro_rule = @(
                        "sys"
                    )
                    rw_rule = @(
                        "never"
                    )
                    superuser = @(
                        "sys"
                    )
                }

                $body = $vRule | ConvertTo-Json -Depth 5
                $vUrl = $apiUri + "/protocols/nfs/export-policies/" + $exp_ID + '/rules'

                $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

            }

            # Get Volume 

            $svmvolume = $svmname + '_' + $audit_volume_name

            $vUrl = $apiUri + "/storage/volumes?fields=name,nas.path&name=$svmvolume"
            $vResult = Invoke-ONTAP -Method Get -URL $vUrl

            # Volume Does Not Exist - Create Volume with Export Policy

            if ($vResult.num_records -eq 0) {

                $vBody = @{
                    name = $svmvolume
                    aggregates = @(
                        @{
                            name = $aggr
                        }
                    )
                    svm = @{
                        name = $svmname
                    }
                    size = $audit_volsize
                    nas = @{
                        export_policy = @{
                            name = $audit_policy
                        }
                        path = $audit_path
                        security_style = 'mixed'
                    }
                    guarantee = @{
                        type = "volume"
                    }
                }

                $body = $vBody | ConvertTo-Json -Depth 5

                $vUrl = $apiUri + "/storage/volumes"
                $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

                # Monitor Job

                $vUrl = $apiUri + "/cluster/jobs/$($vResult.job.uuid)"
                $more = $true
                $pause = 10

                while ($more) {

                    $jobResult = Invoke-ONTAP -Method Get -URL $vUrl

                    if ($jobResult.state -eq 'failure') {

                        Write-Host -ForegroundColor Red "`n`n $($jobResult.Message) `n`n"
                        Exit

                    } elseif ($jobResult.state -eq 'success') {

                        $pause = 1
                        $more = $false

                    } else {

                        $more = $true

                    }

                    Start-Sleep -Seconds $pause

                }

            }

            # Create Audit Configuration

            $vBody = @{
                svm = @{
                    name = $svmname
                }
                log_path = $audit_path
                log = @{
                    format = $audit_log_format
                    rotation = @{
                        size = $audit_rotate_size
                    }
                    retention = @{
                        count = $audit_rotate_limit
                    }
                }
                guarantee = $true
                enabled = $true
            }

            $body = $vBody | ConvertTo-Json -Depth 5

            # Create/Enable Auditing

            $vUrl = $apiUri + "/protocols/audit"
            $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

            Write-Host -ForegroundColor White "    - $svmname`t`t`t" -NoNewline
            Write-Host -ForegroundColor Green "CONFIGURED"

            $eligible++

        }

        # Audit settings found and SVM is cifs or nfs enabled

        if ( ($audit.num_records -eq 1) -and (($cifs -or $nfs)) ) {

            $svm_uuid        = $audit.records[0].svm.uuid
            $audit_enabled   = $audit.records[0].enabled
            $audit_path      = $audit.records[0].log_path
            $audit_guarantee = $audit.records[0].guarantee

            if (!($audit_guarantee)) {

                # Guarantee - vserver audit modify -vserver $svmname -audit-guarantee true

                $vUrlAudit = $apiUri + "/protocols/audit/$svm_uuid"

                $vBody = @{
                    guarantee = $true
                }
                $body = $vBody | ConvertTo-Json -Depth 5

                $aResult = Invoke-ONTAP -Method Patch -URL $vUrlAudit -Body $body

                $audit_guarantee = $true

            }

            if (!($audit_enabled)) {

                # Enable Auditing

                $vUrlAudit = $apiUri + "/protocols/audit/$svm_uuid"

                $vBody = @{
                    enabled = $true
                }
                $body = $vBody | ConvertTo-Json -Depth 5

                $aResult = Invoke-ONTAP -Method Patch -URL $vUrlAudit -Body $body

                $audit_enabled = $true

            }

            Write-Host -ForegroundColor White "    - $svmname`t`t`t" -NoNewline
            Write-Host -ForegroundColor White "CONFIGURED - Guarantee: $audit_guarantee  Enabled: $audit_enabled"

            $eligible++

        }

    }

    if ($eligible -eq 0) {

        Write-Host -ForegroundColor White "    - No Eligible SVMs Found"

    }

} else {

    Write-Host -ForegroundColor Yellow "NOT CONFIGURED - Insufficient Settings"

}

# -------------------- STIG V-246936 : NTP Servers --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " NTP Servers     `t`t" -NoNewline

# Get NTP Servers

$vUrl = $apiUri + "/cluster/ntp/servers?"

$vResult = Invoke-ONTAP -Method Get -URL $vUrl

$current_ntp_servers = @()

if ( $vResult.num_records -lt 3 ) {

    $current_ntp_servers = @()

    foreach ($rec IN $vResult.records) { 
        $current_ntp_servers += $rec.server
    }

}

$i = 0
$ntp_added = $false

# Add NTP servers from .INI (if any)

foreach ($ntp IN $ntp_servers) {

    if ((!($current_ntp_servers.contains($ntp))) -and ($ntp -ne '')) {

        $vBody = @{
            server = $ntp
        }

        # Include KEY if in .INI 

        if ($ntp_keys[$i] -ne '') {

            $vKey = @{
                key_id = $ntp_keys[$i]
            }

            $vBody += $vKey

        }

        $body = $vBody | ConvertTo-Json -Depth 5

        $vUrl = $apiUri + '/private/cli/cluster/time-service/ntp/server'

        $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

        $ntp_added = $true

    }
    
    $i++

}

if ($ntp_added) {

    Write-Host -ForegroundColor White "SERVERS ADDED"

} else {

    Write-Host -ForegroundColor Yellow "NO SERVERS ADDED"

}

# -------------------- STIG V-246938 : Time Stamp for Audit Records (UTC/GMT)  --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Time Zone       `t`t" -NoNewline

# Set Time Zone

$vUrl = $apiUri + '/cluster'

$vBody = @{
    timezone = @{
        name = $set_timezone
    }
}

$body = $vBody | ConvertTo-Json -Depth 5

$vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

Write-Host -ForegroundColor White $set_timezone

# -------------------- STIG V-246940 : MultiFactor Authentication (Domain Tunnel) --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " MultiFactor Auth `t`t" -NoNewline

$domain_tunnel = $false

# Check if domain tunnel exists

$vUrl = $apiUri + '/private/cli/security/login/domain-tunnel'

$vResult = Invoke-ONTAP -Method Get -URL $vUrl -ReturnNullOnError

if ($vResult) {

    $domain_tunnel = $true

    Write-Host -ForegroundColor White 'DOMAIN TUNNEL EXISTS'

} elseif ($auth_tunnel) {

    $create_tunnel = $false

    # Check if SVM exists...

    $vUrl = $apiUri + "/svm/svms?name=$auth_svm_name&fields=cifs"

    $vResult = Invoke-ONTAP -Method Get -URL $vUrl

    if ($vResult.num_records -gt 0) {

        # If CIFS is Enabled...

        if ($vResult.records[0].cifs.enabled -eq $true) {

            $create_tunnel = $true

        } else {

            Write-Host -ForegroundColor Yellow "CIFS Protocol NOT Enabled ($auth_svm_name)"

        }

    } else {

        # Create CIFS SVM for Domain Tunnel

        $vLif = @{
            name = $auth_lif_name
            ip = @{
                address = $auth_lif_ip
                netmask = $auth_lif_netmask
            }
            ipspace = $auth_lif_ipspace
            location = @{
                broadcast_domain = @{
                    name = $auth_lif_broadcastdomain
                }
                home_node = @{
                    name = $auth_lif_homenode
                }
            }
            service_policy = "default-management"
        }

        $vRoute = @{
            destination = @{
                address = "0.0.0.0"
                netmask = "0"
            }
            gateway = $auth_lif_gateway
        }

        $lifs = @($vLif)
        $routes = @($vRoute)

        $vBody = @{
            name = $auth_svm_name
            cifs = @{
                name = $auth_ad_name
                ad_domain = @{
                    fqdn = $auth_ad_fqdn
                    user = $auth_ad_join_account
                    password = $auth_ad_join_password
                }
            }
            ip_interfaces = $lifs
            routes = $routes
            dns = @{
                domains = $auth_dns_domains
                servers = $auth_dns_servers
            }
        }

        $vUrl = $apiUri + "/svm/svms"
        $body = $vBody | ConvertTo-Json -Depth 5

        $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

        # Monitor Job

        $vUrl = $apiUri + "/cluster/jobs/$($vResult.job.uuid)"
        $more = $true
        $pause = 15

        while ($more) {

            $jobResult = Invoke-ONTAP -Method Get -URL $vUrl

            if ($jobResult.state -eq 'failure') {

                Write-Host -ForegroundColor Red "FAILED to Create $auth_svm_name"

                $pause = 1
                $more = $false
                $create_tunnel = $false

            } elseif ($jobResult.state -eq 'success') {

                $pause = 1
                $more = $false
                $create_tunnel = $true

            } else {

                $more = $true

            }

            Start-Sleep -Seconds $pause
        }

    }

    if ($create_tunnel) {

        $vUrl = $apiUri + "/private/cli/security/login/domain-tunnel"

        $vBody = @{
            vserver = $auth_svm_name
        }

        $body = $vBody | ConvertTo-Json -Depth 5

        $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

        Write-Host -ForegroundColor Green "CREATED Domain Tunnel"

        $domain_tunnel = $true

    }

} else {

    Write-Host -ForegroundColor Yellow "NOT CONFIGURED - Insufficent Settings"

}

# -------------------- STIG V-246944 : On-Demand Cluster Configuration Backup --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Config Backup   `t`t" -NoNewline

# Check for backups

$vUrl = $apiUri + '/support/configuration-backup/backups?type=cluster&return_records=false'

$vResult = Invoke-ONTAP -Method Get -URL $vUrl

# If no cluster-level backups found, create an on-demand backup - {nodename}.secure.script.{datetime}.7z

if ($vResult.num_records -eq 0) {

    # Get Node Names

    $vUrl = $apiUri + "/cluster/nodes"

    $vResultNodes = Invoke-ONTAP -Method Get -URL $vUrl

    # Create On Demand Backup

    $vUrl = $apiUri + '/support/configuration-backup/backups?fields=name'

    $backup_datetime = Get-Date -Format yyyy_MM_dd.HH_mm_ss

    foreach ($node IN $vResultNodes.records) {

        $node_name = $node.name

        $backup_file = $node_name + '.secure.script.' + $backup_datetime + ".7z"

        $vBody = @{
            name = $backup_file
            node = @{
                name = $node_name
            }
        }

        $body = $vBody | ConvertTo-Json -Depth 5

        $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

    }

    Write-Host -ForegroundColor White "CREATED"

} else {

    Write-Host -ForegroundColor White "EXISTS"

}

# -------------------- STIG V-246946 : Service Policies --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Service Policies `t`t" -NoNewline

# Get In-Use Service Policies for each LIF

$vUrl = $apiUri + '/private/cli/network/interface/?fields=service-policy,address,netmask-length'

$vResult = Invoke-ONTAP -Method Get -URL $vUrl 

# Check each LIF service policy settings

foreach ($rec IN $vResult.records) {

    $allowed_addresses = @()

    $curr_svm = $rec.vserver
    $curr_policy = $rec.service_policy
    $curr_address = $rec.address
    $curr_netmask_length = $rec.netmask_length

    $ipsections = $curr_address.Split('.')

    if ($service_policies -eq 'filter') {

        if ($curr_netmask_length -lt 16) {

            $allowed_addresses += "$($ipsections[0]).0.0.0/8"

        } elseif ($curr_netmask_length -lt 24) {

            $allowed_addresses += "$($ipsections[0]).$($ipsections[1]).0.0/16"

        } else {

            $allowed_addresses += "$($ipsections[0]).$($ipsections[1]).$($ipsections[2]).0/24"

        }

    } else {

        $allowed_addresses += '0.0.0.0/0'

    }

    # Get the service policy settings associated with the current LIF

    $vUrl2 = $apiUri + "/private/cli/network/interface/service-policy?fields=vserver,policy,service-allowed-addresses&vserver=$curr_svm&policy=$curr_policy"

    $vResult2 = Invoke-ONTAP -Method Get -URL $vUrl2

    foreach ( $rec2 IN $vResult2.records ) {

        foreach ( $rec3 IN $rec2.service_allowed_addresses ) {

            $service_rule = $rec3.Split(':')

            $_service = ($service_rule[0]).Trim()

            $vBody = @{
                "allowed-addresses" = $allowed_addresses
            }

            $body = $vBody | ConvertTo-Json -Depth 5

            $vUrl3 = $apiUri + "/private/cli/network/interface/service-policy?vserver=$curr_svm&policy=$curr_policy&service=$_service"

            $allowed_result = Invoke-ONTAP -Method Patch -Url $vUrl3 -Body $body -ReturnNullOnError

        }

    }

}

Write-Host -ForegroundColor Green "UPDATED"

# -------------------- STIG V-246948 : Domain Account with Admin Role --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Domain Accounts `t`t" -NoNewline

# If a domain tunnel exists...

if ($domain_tunnel) {

    # Get Existing Accounts Using Domain Authentication

    $vUrl = $apiUri + "/security/accounts?applications.authentication_methods=domain"

    $vResult = Invoke-ONTAP -Method Get -URL $vUrl

    $current_domain_accounts = @()

    foreach($da In $vResult.records) {
        $current_domain_accounts += $da.name
    }

    # Add Domain Accounts in .INI with admin role and applications http,ontapi,ssh

    $vUrl = $apiUri + "/security/accounts"

    $newAccounts = $false

    foreach ($acct In $auth_domain_accounts) {

        $testAcct = $acct.Replace('\','%5C')

        $vUrl2 = $vUrl + "?name=$testAcct&return_records=false"

        $vResultTest = Invoke-ONTAP -Method Get -URL $vUrl2

        if ($vResultTest.num_records -eq 0) {

            $applications = @()

            $vHttps = @{
                application = "http"
                authentication_methods = @('domain')
            }
            $vOntapi = @{
                application = "ontapi"
                authentication_methods = @('domain')
            }
            $vSsh = @{
                application = "ssh"
                authentication_methods = @('domain')
            }

            $applications += $vHttps
            $applications += $vOntapi
            $applications += $vSsh

            $vBody = @{
                applications = $applications
                name = "$acct"
                role = @{
                    name = "admin"
                }
            }

            $body = $vBody | ConvertTo-Json -Depth 5 -Compress

            $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

            $newAccounts = $True

        }
    }

    if ($newAccounts) { 

        Write-Host -ForegroundColor White "ACCOUNTS ADDED"

    } else {

        Write-Host -ForegroundColor White "NO NEW ACCOUNTS"

    }

} else {

    Write-Host -ForegroundColor Yellow "NO DOMAIN TUNNEL"

}

# -------------------- STIG V-246958 : Enable/Disable FIPS 140-2 --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " FIPS 140-2     `t`t" -NoNewline

$body = ''

# Get Current FIPS Setting

$vUrl = $apiUri + "/security?fields=fips.enabled"

$vResult = Invoke-ONTAP -Method Get -URL $vUrl

if ($vResult.fips.enabled) {

    if ($fips -eq 'enable') {
        $msg = "ENABLED"
    } else { 
        $msg = "DISABLED"
        $vBody = @{
            fips = @{
                enabled = $false
            }
        }
        $body = $vBody | ConvertTo-Json -Depth 5
    }

} else {

    if ($fips -eq 'enable') {
        $msg = "ENABLED"
        $vBody = @{
            fips = @{
                enabled = $true
            }
        }
        $body = $vBody | ConvertTo-Json -Depth 5
    } else {
        $msg = "DISABLED" 
    }

}

if ($body -ne '') {

    $vUrl = $apiUri + "/security"

    $vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

    # Monitor Job

    $vUrl = $apiUri + "/cluster/jobs/$($vResult.job.uuid)"
    $more = $true
    $pause = 15

    while ($more) {

        $jobResult = Invoke-ONTAP -Method Get -URL $vUrl

        if ($jobResult.state -eq 'failure') {

            Write-Host -ForegroundColor Red "FAILED"
            Write-Host -ForegroundColor Yellow "`n $($jobResult.Message) `n"

            $pause = 1
            $more = $false

        } elseif ($jobResult.state -eq 'success') {

            Write-Host -ForegroundColor Green "$msg"

            $pause = 1
            $more = $false

        } else {
            $more = $true
        }

        Start-Sleep -Seconds $pause

    }

} else {

    Write-Host -ForegroundColor Green "$msg"

}

# -------------------- STIG V-246949 : Enable & Configure SNMP --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " SNMP`t`t`t" -NoNewline

$vUrl = $apiUri + '/support/snmp'

$vBody = @{
    enabled = $snmp_enable
    traps_enabled = $traps_enable
}

$body = $vBody | ConvertTo-Json -Depth 5

$vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

Write-Host -ForegroundColor White "Enabled: $snmp_enable   Traps: $traps_enable"

# Get Current FIPS 140-2 Setting

$vUrl = $apiUri + "/security?fields=fips.enabled"

$vResult = Invoke-ONTAP -Method Get -URL $vUrl

$fips_state = $vResult.fips.enabled

# Check SNMPv3 Settings

if (($snmpv3_host.Length -eq 0) -or ($usm_user_name.Length -eq 0) -or ($usm_auth_password.Length -lt 8) -or ($usm_privacy_password.Length -lt 8)) {

    $snmpv3 = $false

} else {

    $snmpv3 = $true

}

# Check SNMP Settings

if (($trap_host.Length -eq 0) -or ($fips_state)) {

    $snmp = $false

} else {

    $snmp = $true
}

# If both TRUE, default to SNMP v3

if ($snmp -and $snmpv3) { 
    
    $snmp = $false 

}

# Configue SNMP Server

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline
Write-Host -ForegroundColor Cyan " Configure SNMP`t`t" -NoNewline

if ($snmp_enable -and $traps_enable ) {

    if ($snmpv3) {

        # Create USM Account

        $vUrl = $apiUri + "/support/snmp/users?name=$usm_user_name&authentication_method=usm&return_records=false"

        $vResult = Invoke-ONTAP -Method Get -URL $vUrl

        if ($vResult.num_records -eq 0) {

            $vUrl = $apiUri + "/support/snmp/users"

            $vBody = @{
                authentication_method = "usm"
                name = "$usm_user_name"
                owner = @{
                    name = "$ClusterName"
                }
                snmpv3 = @{
                    authentication_password = "$usm_auth_password"
                    authentication_protocol = "sha2_256"
                    privacy_password = "$usm_privacy_password"
                    privacy_protocol = "aes128"
                }
            }

            $body = $vBody | ConvertTo-Json -Depth 5

            $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

        }

        # Configure SNMPv3

        $vUrl = $apiUri + "/support/snmp/traphosts?host=$snmpv3_host&return_records=false"

        $vResult = Invoke-ONTAP -Method Get -URL $vUrl

        if ($vResult.num_records -eq 0) {

            $vUrl = $apiUri + "/support/snmp/traphosts"

            $vBody = @{
                host = $snmpv3_host
                user = @{
                    name = $usm_user_name
                }
            }

            $body = $vBody | ConvertTo-Json -Depth 5

            $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

            Write-Host -ForegroundColor Green "SNMPv3 Configured ($snmpv3_host)"

        } else {

            Write-Host -ForegroundColor Yellow "SNMPv3 ($snmpv3_host) Exists"

        }

    } 
    
    if ($snmp) {

        if ($snmp_community.Length -eq 0) { $snmp_community = $ClusterName}

        # Community Name

        $vUrl = $apiUri + "/private/cli/system/snmp/community?community-name=$snmp_community&return_records=false"

        $vResult = Invoke-ONTAP -Method Get -URL $vUrl

        if ($vResult.num_records -eq 0) {

            $vUrl = $apiUri + "/private/cli/system/snmp/community/add"

            $vBody = @{
                community_name = $snmp_community
                type = "ro"
                vserver = "$ClusterName"
            }

            $body = $vBody | ConvertTo-Json -Depth 5

            $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

        }

        $vUrl = $apiUri + "/support/snmp/traphosts?host=$trap_host"

        $vResult = Invoke-ONTAP -Method Get -URL $vUrl

        if ($vResult.num_records -eq 0) {

            # Trap Host

            $vBody = @{
                host = $trap_host
            }

            $body = $vBody | ConvertTo-Json -Depth 5

            $vUrl = $apiUri + "/support/snmp/traphosts"

            $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

            Write-Host -ForegroundColor Green "SNMP Trap Host ($trap_host) Added"

        } else {

            Write-Host -ForegroundColor Yellow "SNMP Trap Host ($trap_host) Exists"

        } else {

            Write-Host -ForegroundColor Yellow "SNMP Trap Host Not Provided"

        }

    }

    if ( (!($snmp)) -and (!($snmpv3)) ) {

        Write-Host -ForegroundColor Yellow "NOT CONFIGURED - Insufficient Settings"

    }

} else {

    Write-Host -ForegroundColor Yellow "SNMP and/or Trap Host Not Enabled"

}

# -------------------- STIG V-246951-V-246955 : Password Complexity --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Password Complexity `t" -NoNewline

$vUrl = $apiUri + "/private/cli/security/login/role/config?role=admin"

$vBody = @{
    passwd_alphanum = $alphanum
    passwd_minlength = $minlength
    passwd_min_special_chars = $minspecial
    passwd_min_lowercase_chars = $minlowercase
    passwd_min_uppercase_chars = $minuppercase
}

$body = $vBody | ConvertTo-Json -Depth 5

$vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

Write-Host -ForegroundColor White "APPLIED"

# -------------------- STIG V-246926 : Account of Last Resort (Local Admin Account) --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Local Admin    `t`t" -NoNewline

if ($local_admin.Length -gt 0) {

    $vUrl = $apiUri + "/security/accounts?name=$local_account&return_records=false"

    $vResult = Invoke-ONTAP -Method Get -URL $vUrl

    # Account Exists?

    if ($vResult.num_records -eq 1) {

        Write-Host -ForegroundColor White "$local_account EXISTS"

    } else {

        # Create New Local Admin Account

        $app_amqp = @{
            application = "amqp"
            authentication_methods = @("password")
        }
        $app_console = @{
            application = "console"
            authentication_methods = @("password")
        }
        $app_http = @{
            application = "http"
            authentication_methods = @("password")
        }
        $app_ontapi = @{
            application = "ontapi"
            authentication_methods = @("password")
        }
        $app_sp = @{
            application = "service_processor"
            authentication_methods = @("password")
        }
        $app_ssh = @{
            application = "ssh"
            authentication_methods = @("password")
        }

        $apps = @($app_amqp,$app_console,$app_http,$app_ontapi,$app_sp,$app_ssh)

        $vBody = @{
            applications = $apps
            locked = $false
            name = $local_account
            password = $local_password
            role = @{
                name = "admin"
            }
        }

        $body = $vBody | ConvertTo-Json -Depth 5 

        $vUrl = $apiUri + "/security/accounts"

        $vResult = Invoke-ONTAP -Method Post -URL $vUrl -Body $body

        Write-Host -ForegroundColor White "CREATED $local_account"

    }

} else {

    Write-Host -ForegroundColor White "No Account Specified"

}

# -------------------- Reboot Required? --------------------

# Check system status to see if a reboot is needed on any node after configuration changes

$vUrl = $apiUri + '/private/cli/security/config/status?privilege_level=advanced&fields=reboot-needed'

$result = Invoke-ONTAP -Method Get -URL $vUrl

foreach ($rec IN $result.records) {

    if ($rec.reboot_needed) {

        
        $inc++
        Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline
        Write-Host -ForegroundColor Cyan " $($rec.node)  `t`t" -NoNewline
        Write-Host -ForegroundColor Yellow "`t`t REBOOT NEEDED"

    }
}

# -------------------- Lock/Unlock default admin account --------------------

Write-Host -ForegroundColor Gray " $(($inc++))`." -NoNewline

Write-Host -ForegroundColor Cyan " Default Admin Account `t" -NoNewline

$vUrl = $apiUri + "/security/accounts?name=admin&fields=locked"

$vResult = Invoke-ONTAP -Method Get -URL $vUrl

if ($vResult.num_records -gt 0) {

    if ($lock_default_admin) {

        if ($vResult.records[0].locked) {

            Write-Host -ForegroundColor White "LOCKED"

        } else {

            # Check if the only local admin account


            $owner_id = $vResult.records[0].owner.uuid

            $vUrl = $apiUri + "/security/accounts/$owner_id/admin"

            $body = "{ `"locked`": true }"

            $vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

            Write-Host -ForegroundColor White "LOCKED"

        }

    } else {

        if (!($vResult.records[0].locked)) {

            Write-Host -ForegroundColor Yellow "UNLOCKED"

        } else {

            $owner_id = $vResult.records[0].owner.uuid

            $vUrl = $apiUri + "/security/accounts/$owner_id/admin"

            $body = "{ `"locked`": false }"

            $vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

            Write-Host -ForegroundColor Yellow "UNLOCKED"

        }

    } 

} else {

    Write-Host -ForegroundColor Yellow "ACCOUNT NOT FOUND"

}

# -------------------- END --------------------

Write-Host -ForegroundColor Gray " ---------------------------------------------------------------------------------"
Write-Host

# -------------------- END --------------------