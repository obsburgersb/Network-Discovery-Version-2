<#
.SYNOPSIS
    Shared functions for system diagnostics (specs, storage, performance,
    network diagnostics, event log issues, security status). Dot-sourcing
    this file has no side effects — it only defines functions. Some data
    (BitLocker, full physical-disk health) is limited or unavailable without
    running as Administrator; functions degrade gracefully rather than throw.
#>

function Get-SystemSpecs {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $board = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
    $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)

    $uptime = ''
    if ($os -and $os.LastBootUpTime) {
        $span = (Get-Date) - $os.LastBootUpTime
        $uptime = "{0}d {1}h {2}m" -f $span.Days, $span.Hours, $span.Minutes
    }

    $gpuNames = @($gpus | ForEach-Object {
        $ramGb = if ($_.AdapterRAM) { [Math]::Round($_.AdapterRAM / 1GB, 1) } else { $null }
        if ($ramGb) { "$($_.Name) ($ramGb GB)" } else { "$($_.Name)" }
    })

    [PSCustomObject]@{
        ComputerName   = $cs.Name
        Manufacturer   = $cs.Manufacturer
        Model          = $cs.Model
        OS             = "$($os.Caption) ($($os.OSArchitecture))"
        OSVersion      = $os.Version
        Uptime         = $uptime
        CPU            = $cpu.Name
        Cores          = $cpu.NumberOfCores
        LogicalProcs   = $cpu.NumberOfLogicalProcessors
        RAMTotalGB     = if ($cs.TotalPhysicalMemory) { [Math]::Round($cs.TotalPhysicalMemory / 1GB, 1) } else { $null }
        GPUs           = ($gpuNames -join '; ')
        Motherboard    = "$($board.Manufacturer) $($board.Product)"
        BIOSVersion    = $bios.SMBIOSBIOSVersion
        BIOSDate       = $bios.ReleaseDate
    }
}

function Get-DiskInfo {
    $volumes = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue | ForEach-Object {
        $totalGb = [Math]::Round($_.Size / 1GB, 1)
        $freeGb = [Math]::Round($_.FreeSpace / 1GB, 1)
        $pctFree = if ($_.Size -gt 0) { [Math]::Round(($_.FreeSpace / $_.Size) * 100, 1) } else { 0 }
        [PSCustomObject]@{
            Drive      = $_.DeviceID
            Label      = $_.VolumeName
            FileSystem = $_.FileSystem
            TotalGB    = $totalGb
            FreeGB     = $freeGb
            PercentFree = $pctFree
        }
    })

    $physicalDisks = @()
    try {
        $physicalDisks = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                FriendlyName      = $_.FriendlyName
                MediaType         = $_.MediaType
                SizeGB            = [Math]::Round($_.Size / 1GB, 1)
                HealthStatus      = $_.HealthStatus
                OperationalStatus = ($_.OperationalStatus -join ',')
            }
        })
    } catch {
        # Storage module cmdlets may be unavailable or require elevation; leave empty.
    }

    [PSCustomObject]@{
        Volumes       = $volumes
        PhysicalDisks = $physicalDisks
    }
}

function Get-PerformanceSnapshot {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpuLoad = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Measure-Object -Property LoadPercentage -Average).Average

    $totalMemKb = $os.TotalVisibleMemorySize
    $freeMemKb = $os.FreePhysicalMemory
    $usedMemKb = $totalMemKb - $freeMemKb
    $pctMemUsed = if ($totalMemKb -gt 0) { [Math]::Round(($usedMemKb / $totalMemKb) * 100, 1) } else { 0 }

    $topByMemory = @(Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 |
        ForEach-Object {
            [PSCustomObject]@{
                Name       = $_.ProcessName
                Id         = $_.Id
                MemoryMB   = [Math]::Round($_.WorkingSet64 / 1MB, 1)
                CpuSeconds = if ($_.CPU) { [Math]::Round($_.CPU, 1) } else { 0 }
            }
        })

    $topByCpu = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.CPU } | Sort-Object CPU -Descending | Select-Object -First 10 |
        ForEach-Object {
            [PSCustomObject]@{
                Name       = $_.ProcessName
                Id         = $_.Id
                MemoryMB   = [Math]::Round($_.WorkingSet64 / 1MB, 1)
                CpuSeconds = [Math]::Round($_.CPU, 1)
            }
        })

    $startupItems = @()
    try {
        $startupItems = @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Name = $_.Name; Command = $_.Command; Location = $_.Location; User = $_.User }
        })
    } catch {}

    [PSCustomObject]@{
        CpuLoadPercent = $cpuLoad
        MemUsedMB      = [Math]::Round($usedMemKb / 1KB, 0)
        MemTotalMB     = [Math]::Round($totalMemKb / 1KB, 0)
        MemPercentUsed = $pctMemUsed
        TopByMemory    = $topByMemory
        TopByCpu       = $topByCpu
        StartupItems   = $startupItems
    }
}

function Test-TcpReachable {
    param([string]$TargetHost, [int]$Port, [int]$TimeoutMs)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $task = $client.ConnectAsync($TargetHost, $Port)
        $ok = $task.Wait($TimeoutMs) -and $client.Connected
        $client.Close()
        return $ok
    } catch { return $false }
}

function Get-NetworkDiagnostics {
    param([hashtable]$Sync = $null)
    function Set-Status([string]$Message) { if ($Sync) { $Sync.Status = $Message } }

    Set-Status "Enumerating network adapters..."
    $adapters = @()
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_.Name
                Description = $_.InterfaceDescription
                Status      = $_.Status
                LinkSpeed   = $_.LinkSpeed
                MacAddress  = $_.MacAddress
            }
        })
    } catch {}

    Set-Status "Reading IP configuration..."
    $gateway = $null
    $dnsServers = @()
    $ipConfig = @()
    try {
        $configs = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway }
        foreach ($c in $configs) {
            $ipConfig += [PSCustomObject]@{
                Adapter = $c.InterfaceAlias
                IPv4    = ($c.IPv4Address.IPAddress -join ',')
                Gateway = ($c.IPv4DefaultGateway.NextHop -join ',')
                DNS     = ($c.DNSServer.ServerAddresses -join ',')
            }
            if (-not $gateway -and $c.IPv4DefaultGateway) { $gateway = $c.IPv4DefaultGateway[0].NextHop }
            if ($c.DNSServer.ServerAddresses) { $dnsServers += $c.DNSServer.ServerAddresses }
        }
    } catch {}

    $results = @()

    if ($gateway) {
        Set-Status "Pinging default gateway ($gateway)..."
        $p = New-Object System.Net.NetworkInformation.Ping
        try {
            $reply = $p.Send($gateway, 1500)
            $results += [PSCustomObject]@{ Test = "Ping default gateway ($gateway)"; Result = $(if ($reply.Status -eq 'Success') { "OK ($($reply.RoundtripTime) ms)" } else { "FAILED ($($reply.Status))" }) }
        } catch { $results += [PSCustomObject]@{ Test = "Ping default gateway ($gateway)"; Result = "FAILED (error)" } }
    } else {
        $results += [PSCustomObject]@{ Test = "Ping default gateway"; Result = "No gateway found" }
    }

    Set-Status "Testing internet connectivity (1.1.1.1)..."
    $p2 = New-Object System.Net.NetworkInformation.Ping
    try {
        $reply2 = $p2.Send("1.1.1.1", 2000)
        $results += [PSCustomObject]@{ Test = "Ping internet (1.1.1.1)"; Result = $(if ($reply2.Status -eq 'Success') { "OK ($($reply2.RoundtripTime) ms)" } else { "FAILED ($($reply2.Status))" }) }
    } catch { $results += [PSCustomObject]@{ Test = "Ping internet (1.1.1.1)"; Result = "FAILED (error)" } }

    Set-Status "Testing DNS resolution..."
    try {
        $dnsTask = [System.Net.Dns]::GetHostEntryAsync("www.microsoft.com")
        if ($dnsTask.Wait(3000) -and -not $dnsTask.IsFaulted) {
            $entry = $dnsTask.Result
            $results += [PSCustomObject]@{ Test = "DNS resolution (www.microsoft.com)"; Result = "OK ($($entry.AddressList[0]))" }
        } else {
            $results += [PSCustomObject]@{ Test = "DNS resolution (www.microsoft.com)"; Result = "FAILED (timeout)" }
        }
    } catch {
        $results += [PSCustomObject]@{ Test = "DNS resolution (www.microsoft.com)"; Result = "FAILED (error)" }
    }

    Set-Status "Done."
    [PSCustomObject]@{
        Adapters  = $adapters
        IpConfig  = $ipConfig
        Tests     = $results
    }
}

function Get-RecentEventLogIssues {
    param([int]$MaxEvents = 50, [int]$DaysBack = 7, [hashtable]$Sync = $null)
    if ($Sync) { $Sync.Status = "Querying Windows Event Log (last $DaysBack days)..." }

    $events = @()
    try {
        $filter = @{
            LogName   = @('System', 'Application')
            Level     = @(1, 2)
            StartTime = (Get-Date).AddDays(-$DaysBack)
        }
        $raw = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
        $events = @($raw | ForEach-Object {
            $levelText = switch ($_.Level) { 1 { 'Critical' } 2 { 'Error' } default { "Level $($_.Level)" } }
            $msg = $_.Message
            if ($msg -and $msg.Length -gt 200) { $msg = $msg.Substring(0, 200) + '...' }
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                LogName     = $_.LogName
                Level       = $levelText
                Source      = $_.ProviderName
                Id          = $_.Id
                Message     = ($msg -replace '[\r\n]+', ' ')
            }
        })
    } catch {
        if ($Sync) { $Sync.Status = "No matching events found or access denied." }
    }
    if ($Sync) { $Sync.Status = "Done. $($events.Count) event(s) found." }
    return $events
}

function Get-SecurityStatus {
    $defender = $null
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defender = [PSCustomObject]@{
            AntivirusEnabled       = $mp.AntivirusEnabled
            RealTimeProtection     = $mp.RealTimeProtectionEnabled
            SignatureLastUpdated   = $mp.AntivirusSignatureLastUpdated
        }
    } catch {}

    $firewall = @()
    try {
        $firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Profile = $_.Name; Enabled = $_.Enabled }
        })
    } catch {}

    $bitlocker = @()
    try {
        $bitlocker = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ MountPoint = $_.MountPoint; VolumeStatus = $_.VolumeStatus; ProtectionStatus = $_.ProtectionStatus }
        })
    } catch {}

    $recentUpdates = @()
    try {
        $fixes = @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop | ForEach-Object {
            $installedOn = $null
            try { $installedOn = $_.InstalledOn } catch {}
            [PSCustomObject]@{ HotFixID = $_.HotFixID; Description = $_.Description; InstalledOn = $installedOn }
        })
        $recentUpdates = @($fixes | Sort-Object InstalledOn -Descending | Select-Object -First 10)
    } catch {}

    [PSCustomObject]@{
        Defender      = $defender
        Firewall      = $firewall
        BitLocker     = $bitlocker
        RecentUpdates = $recentUpdates
    }
}
