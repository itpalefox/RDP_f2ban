param([switch]$task)
if ($task) {
	schtasks /create /tn "RDP fail2ban" /sc minute /mo 10 /rl highest /ru system /tr "powershell.exe -file C:\rdpf2b.ps1" /f
	schtasks /create /tn "Clear EventViewer Security Log" /sc weekly /rl highest /ru system /tr "powershell.exe -command Clear-EventLog -LogName Security" /f
	Clear-EventLog -LogName Security
} else {

function WriteLog
{
    Param ([string]$LogString)
    $LogFile = "C:\rdpf2b_" + (Get-Date).tostring("yyyyMMdd") + ".log"
    $DateTime = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    $LogMessage = "$Datetime $LogString"
    Add-content $LogFile -value $LogMessage
}

# Specify the path to the event log containing information about failed login attempts
$logPath = "Security"

# Specify the event ID corresponding to a failed login attempt
$logonFailureEventID = 4625

# Specify the list of allowed users
$allowedUsers = (Get-LocalUser | Where-Object { $_.Enabled -eq $true }).Name

# Define the time frame for the last 24 hours
$startTime = (Get-Date).AddMinutes(-11)

# Create a hash set to store unique blocked IP addresses
$blockedIPsHash = [System.Collections.Generic.HashSet[string]]::New()

# Get all events from the event log for failed login attempts in the last 24 hours
$events = Get-WinEvent -LogName $logPath | Where-Object { $_.Id -eq $logonFailureEventID -and $_.TimeCreated -ge $startTime }

# Iterate through each event
foreach ($event in $events) {
    # Get the event data
    $message = $event.Message
    $ipAddress = [regex]::Matches($message, "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b") | ForEach-Object { $_.Value }
    $userName = ((($event).Properties)[5]).Value

    # Check if the user is allowed
    if ($userName -notin $allowedUsers) {
        # Add the IP addresses to the hash set of blocked IP addresses
        foreach ($ip in $ipAddress) {
            if ($blockedIPsHash.Add($ip)) {
                WriteLog "Added IP address to block list: $ip"
 
                # Check if a firewall rule exists for blocking IP addresses
                $ruleName = "BlockedIPsRule"
                $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                
                if (-not $events) {
                	WriteLog "No IP addresses to add to the firewall rule."
                } else {
                # If the rule does not exist, create a new rule
                if (-not $existingRule) {
                    WriteLog "Creating a new firewall rule for blocking IP addresses..."
                    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -RemoteAddress $blockedIPsHash -Profile Any -Enabled True
                } else {
                    # Get the list of IP addresses from the existing rule
                    $existingRemoteAddresses = ($existingRule | Get-NetFirewallAddressFilter).RemoteAddress
                
                    # Add missing IP addresses from the $blockedIPsHash
                    $addressesToAdd = $blockedIPsHash | Where-Object { $_ -notin $existingRemoteAddresses }
                
                    if ($addressesToAdd) {
                        WriteLog "Adding IP addresses to the existing firewall rule..."
                        $updatedAddresses = $existingRemoteAddresses + $addressesToAdd
                        Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $updatedAddresses
                        WriteLog "Added IP addresses: $($addressesToAdd -join ', ')"
                    } else {
                        WriteLog "No IP addresses to add to the existing firewall rule."
                    }
				}
			  }
            }
        }
    }
  }
}