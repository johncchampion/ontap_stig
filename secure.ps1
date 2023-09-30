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
        11. Add NTP Servers                                             [NTP Servers          ]
        12. Set Time Stamp for Audit Records (UTC/GMT)                  [Time Zone            ]
        13. Configure MultiFactor Authentication                        [MultiFactor Auth     ]
        14. On-Demand Cluster Configuration Backup                      [Config Backup        ]
        15. Service Policies (Packet Filtering)                         [Service Policies     ]
        16. Add Domain Accounts with Admin Role                         [Domain Accounts      ]
        17. Enable & Configure SNMP                                     [Configure SNMP       ]
        18. Set Password Complexity Minimums                            [Password Complexity  ]
        19. Enable/Disable FIPS 140-2                                   [FIPS 140-2           ]
        20. Create Account of Last Resort (1 Local Admin Account)       [Local Admin          ]
        21. Check if Reboot Required
        22. Lock / Unlock Default admin Account                         [Default Admin Account]

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

# Verify .INI settings
# Configure Auditing / SNMP server (Audit Guarantee)
# Check if only 1 local admin account before locking
# V-246933 : ONTAP must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements

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
$valid_timezones     = (($config["SECURITY"]).valid_timezones).Split(',')
$set_timezone        = ($config["SECURITY"]).set_timezone
$fips                = ($config["SECURITY"]).fips
$service_policies    = ($config["SECURITY"]).service_policies

# NTP

$ntp_servers = (($config["NTP"]).ntp_servers).Split(',')
$ntp_keys    = (($config["NTP"]).ntp_keys).Split(',')

# SNMP

$snmp_enable  = Get-TrueFalse -YesNo (($config["SNMP"]).snmp_enable)
$traps_enable = Get-TrueFalse -YesNo (($config["SNMP"]).traps_enable)
$trap_host    = ($config["SNMP"]).trap_host
$snmp_version = ($config["SNMP"]).snmp_version

# PASSWORDCOMPLEXITY

$minlength    = ($config["PASSWORDCOMPLEXITY"]).minlength
$minuppercase = ($config["PASSWORDCOMPLEXITY"]).minuppercase
$minlowercase = ($config["PASSWORDCOMPLEXITY"]).minlowercase
$minspecial   = ($config["PASSWORDCOMPLEXITY"]).minspecial
$alphanum     = ($config["PASSWORDCOMPLEXITY"]).alphanum

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

# LOGGING

$log_ipaddress = ($config["LOGGING"]).ipaddress
$log_facility  = ($config["LOGGING"]).facility
$log_ipspace   = ($config["LOGGING"]).ipspace
$log_dest_port = ($config["LOGGING"]).dest_port
$log_protocol  = ($config["LOGGING"]).protocol
$log_verify    = Get-TrueFalse -YesNo (($config["LOGGING"]).verify)

# -------------------- Verify Settings --------------------

# Time Zone

if (!($valid_timezones.contains($set_timezone))) {

    Write-Host -ForegroundColor Red " Time Zone $set_timezone Not Valid"
    exit

}

# Password Complexity

$valid_alphanum = @('enabled','disabled')
if (!($valid_alphanum.Contains($alphanum))) {

    Write-Host -ForegroundColor Red ' Password Complexity AlphaNum Invalid - Must Be enabled or disabled'
    exit

}

# Configure Logging

if (($log_ipaddress.Length -gt 0) -and ($log_facility.Length -gt 0) -and ($log_ipspace.Length -gt 0) -and ($log_dest_port.Length -gt 0) -and ($log_protocol.Length -gt 0) -and ($log_verify.Length -gt 0)) {

    $config_logging = $true
} else {

    $config_logging = $false

}

# -------------------- Start --------------------

$inc = 0
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

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

Write-Host -ForegroundColor Cyan " Audit Guarantee  `t`t" -NoNewline

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

<#

# Check for SMB SVMs

$vUrl = $apiUri + '/svm/svms?cifs.enabled=true'

$vResult = Invoke-ONTAP -Method Get -URL $vUrl

# Check each SMB SVM...

if ($vResult.num_records -gt 0) {

    $svm_audit_false = @()

    foreach ($svm IN $vResult.records) {

            $vUrl2 = $apiUri + "/private/cli/vserver/audit?audit-guarantee=false&vserver=$($svm.name)"

            $vResult2 = Invoke-ONTAP -Method Get -URL $vUrl2

            if ($vResult2.num_records -gt 0) {

                if ($svm.audit_guarantee -eq $false) {
                    $svm_audit_false += $svm.name
                }

            }

    }

    if ($svm_audit_false.Count -gt 0) {

        Write-Host -ForegroundColor Gray " OPEN: SMB SVMs Found with Audit Guarantee False"

        $f_status = 'Open'
        $f_details = 'SMB SVMs Found with Audit Guarantee False'

        foreach ($svmaudit IN $svm_audit_false) {
            $f_details += "`n- $svmaudit"
        }

        $f_comments = ""

    } else {

        Write-Host -ForegroundColor Green " NOT A FINDING"

        $f_status = "NotAFinding"
        $f_details = "SMB SVMs have Audit Guarantee Set to True"
        $f_comments = ""

    }

} else {

    Write-Host -ForegroundColor Gray " NOT APPLICABLE: No SVMs with SMB Protocol Enabled"

    $f_status = "NotApplicable"
    $f_details = "No SVMs with SMB Protocol Enabled"
    $f_comments = ""

}
#>

# -------------------- STIG V-246936 : NTP Servers --------------------

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

Write-Host -ForegroundColor Cyan " MultiFactor Auth `t`t" -NoNewline

$domain_tunnel = $false

# Check if domain tunnel exists

$vUrl = $apiUri + '/private/cli/security/login/domain-tunnel'

$vResult = Invoke-ONTAP -Method Get -URL $vUrl -ReturnNullOnError

if ($vResult) {

    $domain_tunnel = $true

    Write-Host -ForegroundColor White 'DOMAIN TUNNEL EXISTS'

} elseif ($auth_svm_name.Length -gt 0) {

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

        $vUrl = $apiUri + "/svm/svms
        "
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

    Write-Host -ForegroundColor Yellow "Auth SVM Not Specified"

}

# -------------------- STIG V-246944 : On-Demand Cluster Configuration Backup --------------------

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

Write-Host -ForegroundColor Cyan " Service Policies `t`t" -NoNewline

# Get In-Use Service Policies for each LIF

$vUrl = $apiUri + '/private/cli/network/interface/?fields=service-policy,address,netmask-length'

$vResult = Invoke-ONTAP -Method Get -URL $vUrl 

# Check each LIF service policy settings

foreach ($rec IN $vResult.records) {

    $allowed_addresses = @()

    $curr_svm = $rec.vserver
    #$curr_lif = $rec.lif
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
            #$_rule = ($service_rule[1]).Trim()

            $vBody = @{
                "allowed-addresses" = $allowed_addresses
            }

            $body = $vBody | ConvertTo-Json -Depth 5

            $vUrl3 = $apiUri + "/private/cli/network/interface/service-policy?vserver=$curr_svm&policy=$curr_policy&service=$_service"

            $allowed_result = Invoke-ONTAP -Method Patch -Url $vUrl3 -Body $body -ReturnNullOnError

            # https://kb.netapp.com/onprem/ontap/os/Unable_to_create_a_service_policy_to_limit_data_access_using_the_allowed-addresses_option

        }

    }

}

Write-Host -ForegroundColor Green "UPDATED"

# -------------------- STIG V-246948 : Domain Account with Admin Role --------------------

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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

# -------------------- STIG V-246949 : Enable & Configure SNMP --------------------

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

Write-Host -ForegroundColor Cyan " SNMP`t`t`t" -NoNewline

$vUrl = $apiUri + '/support/snmp'

$vBody = @{
    enabled = $snmp_enable
    traps_enabled = $traps_enable
}

$body = $vBody | ConvertTo-Json -Depth 5

$vResult = Invoke-ONTAP -Method Patch -URL $vUrl -Body $body

Write-Host -ForegroundColor White "Enabled: $snmp_enable   Traps: $traps_enable"

# Configue SNMP Server



# -------------------- STIG V-246951-V-246955 : Password Complexity --------------------

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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

# -------------------- STIG V-246958 : Enable/Disable FIPS 140-2 --------------------

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

Write-Host -ForegroundColor Cyan " FIPS 140-2     `t`t" -NoNewline

# Get Current FIPS Setting

$vUrl = $apiUri + "/security?fields=fips.enabled"

$vResult = Invoke-ONTAP -Method Get -URL $vUrl

$body = ''

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

    $vBody = @{
        fips = @{
            enabled = $true
        }
    }

    $body = $vBody | ConvertTo-Json -Depth 5

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

            Write-Host -ForegroundColor White "$msg"

            $pause = 1
            $more = $false

        } else {
            $more = $true
        }

        Start-Sleep -Seconds $pause

    }

} else {

    Write-Host -ForegroundColor White "$msg"

}

# -------------------- STIG V-246926 : Account of Last Resort (Local Admin Account) --------------------

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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
        Write-Host -ForegroundColor Gray " $inc." -NoNewline
        Write-Host -ForegroundColor Cyan " $($rec.node)  `t`t" -NoNewline
        Write-Host -ForegroundColor Yellow "`t`t REBOOT NEEDED"

    }
}

# -------------------- Lock/Unlock default admin account --------------------

$inc++
Write-Host -ForegroundColor Gray " $inc." -NoNewline

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