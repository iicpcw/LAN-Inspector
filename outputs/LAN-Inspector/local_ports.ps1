param(
    [ValidateSet('scan','block','remove')][string]$Action = 'scan',
    [string]$Payload = 'W10='
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ProgressPreference = 'SilentlyContinue'
$groupName = 'LAN Inspector Local Port Blocks v1'
$rulePrefix = 'LANInspector.LocalPortBlock.v1.'

function Read-Requests {
    $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload)) | ConvertFrom-Json
    $validated = @()
    foreach ($item in @($decoded)) {
        $proto = [string]$item.protocol
        $portText = [string]$item.port
        if ($proto -cnotin @('TCP','UDP') -or $portText -notmatch '^[0-9]{1,5}$') { throw 'Invalid protocol or port' }
        $portNumber = [int]$portText
        if ($portNumber -lt 1 -or $portNumber -gt 65535) { throw 'Port out of range' }
        $validated += [pscustomobject]@{ protocol=$proto; port=$portNumber; name=($rulePrefix+$proto+'.'+$portNumber) }
    }
    return @($validated | Sort-Object name -Unique)
}

function Owned-Rule($name) {
    $r = Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue
    if ($r -and $r.Group -cne $groupName) { throw 'Rule name collision: rule is not owned by this tool' }
    return $r
}

function Inventory {
    $warnings = @()
    $processes = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $processes[[int]$_.Id] = $_.ProcessName }
    $endpoints = @()
    try {
        # Query all states to handle an empty Listen set without a no-match error.
        foreach ($conn in @(Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' })) {
            $endpoints += [pscustomobject]@{ protocol='TCP'; port=[int]$conn.LocalPort; address=$conn.LocalAddress; pid=[int]$conn.OwningProcess; process=$processes[[int]$conn.OwningProcess]; state='TCP listening' }
        }
        foreach ($conn in @(Get-NetUDPEndpoint)) {
            $endpoints += [pscustomobject]@{ protocol='UDP'; port=[int]$conn.LocalPort; address=$conn.LocalAddress; pid=[int]$conn.OwningProcess; process=$processes[[int]$conn.OwningProcess]; state='UDP bound' }
        }
    } catch {
        $warnings += ('CIM inventory unavailable; using netstat fallback: '+$_.Exception.Message)
        $endpoints = @()
        $netstatPath = Join-Path $env:SystemRoot 'System32/netstat.exe'
        $netstatOutput = @(& $netstatPath -ano)
        if ($LASTEXITCODE -ne 0) { throw 'Both CIM and netstat endpoint inventory failed' }
        foreach ($line in $netstatOutput) {
            $fields = @($line.Trim() -split '\s+')
            $proto = $fields[0]
            $valid = ($proto -eq 'TCP' -and $fields.Count -eq 5 -and $fields[3] -match '(?i)LISTENING|侦听|监听') -or ($proto -eq 'UDP' -and $fields.Count -eq 4)
            if (-not $valid) { continue }
            if ($fields[1] -notmatch '^(.*):([0-9]+)$') { continue }
            $address = $Matches[1] -replace '^\[|\]$',''
            $portNumber = [int]$Matches[2]
            $owner = [int]$fields[-1]
            $state = if ($proto -eq 'TCP') { 'TCP listening (netstat)' } else { 'UDP bound (netstat)' }
            $endpoints += [pscustomobject]@{protocol=$proto;port=$portNumber;address=$address;pid=$owner;process=$processes[$owner];state=$state}
        }
    }
    $profiles = @()
    $rules = @()
    try {
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
            [pscustomobject]@{ name=[string]$_.Name; enabled=[string]$_.Enabled; localMerge=[string]$_.AllowLocalFirewallRules }
        })
        $active = @{}
        Get-NetFirewallRule -PolicyStore ActiveStore -Name ($rulePrefix+'*') -ErrorAction SilentlyContinue | ForEach-Object { $active[$_.Name] = $_ }
        foreach ($r in @(Get-NetFirewallRule -PolicyStore PersistentStore -Name ($rulePrefix+'*') -ErrorAction SilentlyContinue | Where-Object { $_.Group -ceq $groupName })) {
            $filter = $r | Get-NetFirewallPortFilter
            $rules += [pscustomobject]@{ name=$r.Name; protocol=[string]$filter.Protocol; port=([string]($filter.LocalPort -join ',')); enabled=[string]$r.Enabled; activeStore=$active.ContainsKey($r.Name); direction=[string]$r.Direction; action=[string]$r.Action; profile=[string]$r.Profile }
        }
    } catch { $warnings += ('Firewall status unavailable: '+$_.Exception.Message) }
    return @{ endpoints=@($endpoints | Sort-Object protocol,port,address,pid); rules=@($rules); profiles=@($profiles); warnings=@($warnings) }
}

try {
    $results = @()
    if ($Action -ne 'scan') {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator privileges required' }
        $requests = @(Read-Requests)
        if ($requests.Count -eq 0) { throw 'No ports selected' }
        foreach ($item in $requests) {
            try {
                $existing = Owned-Rule $item.name
                if ($Action -eq 'block') {
                    if ($existing) {
                        $filter = $existing | Get-NetFirewallPortFilter
                        $expectedProtocol = if ($item.protocol -eq 'TCP') { @('TCP','6') } else { @('UDP','17') }
                        if ([string]$filter.Protocol -notin $expectedProtocol -or @($filter.LocalPort).Count -ne 1 -or [string]$filter.LocalPort -ne [string]$item.port -or $existing.Action -ne 'Block' -or $existing.Direction -ne 'Inbound') {
                            throw 'Existing owned rule differs from expected scope; remove it first'
                        }
                        # Do not widen or silently replace an existing rule.
                        $message = 'Rule already exists; inspect status and scope in Windows Firewall'
                    } else {
                        New-NetFirewallRule -PolicyStore PersistentStore -Name $item.name -DisplayName ('LAN Inspector block '+$item.protocol+' '+$item.port) -Group $groupName -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol $item.protocol -LocalPort $item.port -LocalAddress Any -RemoteAddress Any -Description 'Created by LAN Inspector local port manager; inbound port-wide block' | Out-Null
                        $verify = Owned-Rule $item.name
                        if (-not $verify -or $verify.Enabled -ne 'True') { throw 'Rule read-back verification failed' }
                        $message = 'Rule created and read back; effective reachability requires external verification'
                    }
                } else {
                    if ($existing) {
                        $existing | Remove-NetFirewallRule
                        if (Owned-Rule $item.name) { throw 'Rule still exists after removal' }
                        $message = 'Owned rule removed; other firewall rules remain in effect'
                    } else { $message = 'Owned rule already absent' }
                }
                $results += [pscustomobject]@{ protocol=$item.protocol; port=$item.port; success=$true; message=$message }
            } catch {
                $results += [pscustomobject]@{ protocol=$item.protocol; port=$item.port; success=$false; message=$_.Exception.Message }
            }
        }
    }
    try { $inventory = Inventory }
    catch {
        if ($Action -eq 'scan') { throw }
        $inventory = @{ endpoints=@(); rules=@(); profiles=@(); warnings=@('Rule operation returned results, but inventory refresh failed: '+$_.Exception.Message) }
    }
    @{ok=$true;data=$inventory;results=@($results)} | ConvertTo-Json -Depth 8 -Compress
} catch {
    @{ok=$false;error=$_.Exception.Message} | ConvertTo-Json -Depth 4 -Compress
    exit 1
}
