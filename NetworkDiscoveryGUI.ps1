<#
.SYNOPSIS
    Windows Forms GUI for the network discovery tool. Double-click to run, or:
        powershell -ExecutionPolicy Bypass -File .\NetworkDiscoveryGUI.ps1

    Scans run on a background runspace so the window stays responsive, and can
    be cancelled mid-scan. Requires NetworkDiscoveryCore.ps1 and
    VulnCheckCore.ps1 in the same folder.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic

$corePath = Join-Path $PSScriptRoot 'NetworkDiscoveryCore.ps1'
$vulnCorePath = Join-Path $PSScriptRoot 'VulnCheckCore.ps1'
$sysInfoCorePath = Join-Path $PSScriptRoot 'SystemInfoCore.ps1'
if (-not (Test-Path $corePath)) {
    [System.Windows.Forms.MessageBox]::Show("Cannot find NetworkDiscoveryCore.ps1 next to this script.", "Missing file", 'OK', 'Error') | Out-Null
    return
}
if (-not (Test-Path $vulnCorePath)) {
    [System.Windows.Forms.MessageBox]::Show("Cannot find VulnCheckCore.ps1 next to this script.", "Missing file", 'OK', 'Error') | Out-Null
    return
}
if (-not (Test-Path $sysInfoCorePath)) {
    [System.Windows.Forms.MessageBox]::Show("Cannot find SystemInfoCore.ps1 next to this script.", "Missing file", 'OK', 'Error') | Out-Null
    return
}
. $corePath
. $sysInfoCorePath

$profilesDir = Join-Path $PSScriptRoot 'profiles'
$historyPath = Join-Path $PSScriptRoot 'scan-history.json'

# ---------------------------------------------------------------------------
# Static port sets
# ---------------------------------------------------------------------------

$CommonPorts = @(21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443)
$PortGroups = [ordered]@{
    'Web'            = @(80,443,8000,8080,8443,8888)
    'Remote Access'  = @(22,23,3389,5900)
    'File Sharing'   = @(21,139,445,2049)
    'Mail'           = @(25,110,143,465,587,993,995)
    'Database'       = @(1433,1521,3306,5432,6379,27017)
    'IoT / Other'    = @(53,67,68,123,1900,5353,8009)
}

# ---------------------------------------------------------------------------
# Helper functions (defined before the form so event handlers can call them)
# ---------------------------------------------------------------------------

function ConvertTo-PortArray {
    param([string]$CsvText)
    if (-not $CsvText) { return @() }
    return @($CsvText -split ',' | Where-Object { $_.Trim() -ne '' } | ForEach-Object { [int]$_.Trim() } | Sort-Object -Unique)
}

function ConvertTo-ExcludeArray {
    param([string]$CsvText)
    if (-not $CsvText) { return @() }
    return @($CsvText -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
}

function Set-ControlTheme {
    param($Control, [bool]$Dark)
    if ($Dark) {
        $panelBack = [System.Drawing.Color]::FromArgb(37, 37, 38)
        $fieldBack = [System.Drawing.Color]::FromArgb(45, 45, 48)
        $fore = [System.Drawing.Color]::Gainsboro
        $border = [System.Drawing.Color]::FromArgb(70, 70, 74)
    } else {
        $panelBack = [System.Drawing.SystemColors]::Control
        $fieldBack = [System.Drawing.SystemColors]::Window
        $fore = [System.Drawing.SystemColors]::ControlText
        $border = [System.Drawing.SystemColors]::ControlLight
    }

    $altBack = if ($Dark) { [System.Drawing.Color]::FromArgb(40, 40, 43) } else { [System.Drawing.Color]::FromArgb(245, 247, 250) }

    $typeName = $Control.GetType().Name
    if ($typeName -eq 'DataGridView') {
        $Control.BackgroundColor = $panelBack
        $Control.DefaultCellStyle.BackColor = $fieldBack
        $Control.DefaultCellStyle.ForeColor = $fore
        $Control.DefaultCellStyle.SelectionBackColor = $accentColor
        $Control.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
        $Control.AlternatingRowsDefaultCellStyle.BackColor = $altBack
        $Control.AlternatingRowsDefaultCellStyle.ForeColor = $fore
        $Control.ColumnHeadersDefaultCellStyle.BackColor = $panelBack
        $Control.ColumnHeadersDefaultCellStyle.ForeColor = $fore
        $Control.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
        $Control.GridColor = $border
        $Control.EnableHeadersVisualStyles = $false
        $Control.RowHeadersVisible = $false
        $Control.BorderStyle = 'None'
        return
    }
    if ($typeName -in @('TextBox', 'ComboBox', 'NumericUpDown', 'ListBox')) {
        $Control.BackColor = $fieldBack
        $Control.ForeColor = $fore
    } else {
        $Control.BackColor = $panelBack
        try { $Control.ForeColor = $fore } catch {}
    }
    foreach ($child in @($Control.Controls)) { Set-ControlTheme -Control $child -Dark $Dark }
}

function Add-LogLine {
    param([string]$Message)
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $Message"
    $txtLog.AppendText("$line`r`n")
}

function Get-ProfileNames {
    if (-not (Test-Path $profilesDir)) { return @() }
    return @(Get-ChildItem -Path $profilesDir -Filter '*.json' -ErrorAction SilentlyContinue | ForEach-Object { $_.BaseName })
}

function Save-CurrentProfile {
    param([string]$Name)
    if (-not (Test-Path $profilesDir)) { New-Item -ItemType Directory -Path $profilesDir | Out-Null }
    $profile = [PSCustomObject]@{
        Target         = $txtTarget.Text
        ExcludeHosts   = $txtExclude.Text
        PortMode       = $cmbPortMode.SelectedIndex
        Ports          = $txtPorts.Text
        TimeoutMs      = [int]$numTimeout.Value
        Concurrency    = [int]$numConcurrency.Value
        Retries        = [int]$numRetries.Value
        NoPortScan     = [bool]$chkNoPortScan.Checked
        NoResolve      = [bool]$chkNoResolve.Checked
        LookupVendor   = [bool]$chkVendor.Checked
        AutoVuln       = [bool]$chkAutoVuln.Checked
    }
    $path = Join-Path $profilesDir "$Name.json"
    $profile | ConvertTo-Json | Set-Content -Path $path -Encoding utf8
}

function Import-Profile {
    param([string]$Name)
    $path = Join-Path $profilesDir "$Name.json"
    if (-not (Test-Path $path)) { return }
    $p = Get-Content $path -Raw | ConvertFrom-Json
    $txtTarget.Text = $p.Target
    $txtExclude.Text = $p.ExcludeHosts
    $cmbPortMode.SelectedIndex = [int]$p.PortMode
    $txtPorts.Text = $p.Ports
    $numTimeout.Value = [int]$p.TimeoutMs
    $numConcurrency.Value = [int]$p.Concurrency
    $numRetries.Value = [int]$p.Retries
    $chkNoPortScan.Checked = [bool]$p.NoPortScan
    $chkNoResolve.Checked = [bool]$p.NoResolve
    $chkVendor.Checked = [bool]$p.LookupVendor
    $chkAutoVuln.Checked = [bool]$p.AutoVuln
}

function Save-HistoryToDisk {
    try {
        $script:scanHistory | Select-Object -Last 20 | ConvertTo-Json -Depth 5 | Set-Content -Path $historyPath -Encoding utf8
    } catch {}
}

function Import-HistoryFromDisk {
    if (-not (Test-Path $historyPath)) { return @() }
    try {
        $data = Get-Content $historyPath -Raw | ConvertFrom-Json
        return @($data)
    } catch { return @() }
}

function Update-HistoryGrid {
    $gridHistory.Rows.Clear()
    for ($i = 0; $i -lt $script:scanHistory.Count; $i++) {
        $h = $script:scanHistory[$i]
        $openTotal = 0
        foreach ($r in $h.Results) { if ($r.OpenPorts) { $openTotal += @($r.OpenPorts -split ',' | Where-Object { $_ -ne '' }).Count } }
        $gridHistory.Rows.Add($h.Timestamp, $h.Target, @($h.Results).Count, $openTotal) | Out-Null
    }
}

function Add-HistoryEntry {
    param([string]$Target, [array]$Results)
    $entry = [PSCustomObject]@{
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Target    = $Target
        Results   = $Results
    }
    $script:scanHistory = @($script:scanHistory) + $entry
    if ($script:scanHistory.Count -gt 20) {
        $script:scanHistory = @($script:scanHistory | Select-Object -Last 20)
    }
    Update-HistoryGrid
    Save-HistoryToDisk
}

function Update-ResultsGrid {
    param([array]$Results)
    $grid.Rows.Clear()
    foreach ($r in $Results) {
        $grid.Rows.Add($r.IPAddress, $r.Hostname, $r.MACAddress, $r.Vendor, $r.OpenPorts) | Out-Null
    }
    $btnExportCsv.Enabled = ($Results.Count -gt 0)
    $btnExportJson.Enabled = ($Results.Count -gt 0)
    $btnCheckVulns.Enabled = ($Results.Count -gt 0) -and (-not $script:vulnScanning) -and (-not $script:scanning)
}

function Update-VulnGrid {
    param([array]$Findings)
    $vgrid.Rows.Clear()
    if ($Findings.Count -eq 0) {
        $vgrid.Rows.Add("", "", "", "Info", "No findings on the scanned open ports.", "", "") | Out-Null
        return
    }
    foreach ($f in $Findings) {
        $rowIdx = $vgrid.Rows.Add($f.IPAddress, $f.Port, $f.Service, $f.Severity, $f.Finding, $f.Recommendation, $f.Banner)
        $color = switch ($f.Severity) {
            'Critical' { [System.Drawing.Color]::FromArgb(255, 138, 128) }
            'High'     { [System.Drawing.Color]::FromArgb(255, 183, 77) }
            'Medium'   { [System.Drawing.Color]::FromArgb(255, 241, 118) }
            'Low'      { [System.Drawing.Color]::FromArgb(129, 212, 250) }
            default    { $null }
        }
        if ($color) {
            $vgrid.Rows[$rowIdx].DefaultCellStyle.BackColor = $color
            $vgrid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
        }
    }
    $btnVulnCsv.Enabled = $true
    $btnVulnJson.Enabled = $true
}

# ---------------------------------------------------------------------------
# Form + top bar
# ---------------------------------------------------------------------------

$form = New-Object System.Windows.Forms.Form
$form.Text = "Network & System Toolkit"
$form.Size = New-Object System.Drawing.Size(1150, 800)
$form.MinimumSize = New-Object System.Drawing.Size(900, 580)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)

$accentColor = [System.Drawing.Color]::FromArgb(0, 120, 215)

$topBar = New-Object System.Windows.Forms.Panel
$topBar.Dock = 'Top'
$topBar.Height = 38
$form.Controls.Add($topBar)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "Network & System Toolkit"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = $accentColor
$lblTitle.Location = New-Object System.Drawing.Point(10, 7)
$lblTitle.AutoSize = $true
$topBar.Controls.Add($lblTitle)

$lblTheme = New-Object System.Windows.Forms.Label
$lblTheme.Text = "Theme:"
$lblTheme.Location = New-Object System.Drawing.Point(900, 9)
$lblTheme.AutoSize = $true
$lblTheme.Anchor = 'Top,Right'
$topBar.Controls.Add($lblTheme)

$cmbTheme = New-Object System.Windows.Forms.ComboBox
$cmbTheme.DropDownStyle = 'DropDownList'
$cmbTheme.Items.AddRange(@("Light", "Dark"))
$cmbTheme.SelectedIndex = 0
$cmbTheme.Location = New-Object System.Drawing.Point(955, 6)
$cmbTheme.Width = 100
$cmbTheme.Anchor = 'Top,Right'
$topBar.Controls.Add($cmbTheme)

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.Multiline = $true
$form.Controls.Add($tabs)
$tabs.BringToFront()

$tabScan = New-Object System.Windows.Forms.TabPage; $tabScan.Text = "Scan Settings"
$tabResults = New-Object System.Windows.Forms.TabPage; $tabResults.Text = "Results"
$tabVuln = New-Object System.Windows.Forms.TabPage; $tabVuln.Text = "Vulnerabilities"
$tabHistory = New-Object System.Windows.Forms.TabPage; $tabHistory.Text = "History"
$tabSysInfo = New-Object System.Windows.Forms.TabPage; $tabSysInfo.Text = "System Info"
$tabPerf = New-Object System.Windows.Forms.TabPage; $tabPerf.Text = "Performance"
$tabNetDiag = New-Object System.Windows.Forms.TabPage; $tabNetDiag.Text = "Network Diagnostics"
$tabEvents = New-Object System.Windows.Forms.TabPage; $tabEvents.Text = "Event Logs"
$tabSecurity = New-Object System.Windows.Forms.TabPage; $tabSecurity.Text = "Security & Updates"
$allTabPages = @($tabScan, $tabResults, $tabVuln, $tabHistory, $tabSysInfo, $tabPerf, $tabNetDiag, $tabEvents, $tabSecurity)
$tabs.TabPages.AddRange($allTabPages)
foreach ($tp in $allTabPages) { $tp.AutoScroll = $true }

# --- Scan Settings tab ---

$grpTarget = New-Object System.Windows.Forms.GroupBox
$grpTarget.Text = "Target"
$grpTarget.Location = New-Object System.Drawing.Point(10, 10)
$grpTarget.Size = New-Object System.Drawing.Size(520, 100)
$tabScan.Controls.Add($grpTarget)

$lblTarget = New-Object System.Windows.Forms.Label
$lblTarget.Text = "Target (CIDR, range, or comma list):"
$lblTarget.Location = New-Object System.Drawing.Point(10, 22)
$lblTarget.AutoSize = $true
$grpTarget.Controls.Add($lblTarget)

$txtTarget = New-Object System.Windows.Forms.TextBox
$txtTarget.Location = New-Object System.Drawing.Point(10, 42)
$txtTarget.Width = 320
$grpTarget.Controls.Add($txtTarget)

$btnAutoDetect = New-Object System.Windows.Forms.Button
$btnAutoDetect.Text = "Auto-detect"
$btnAutoDetect.Location = New-Object System.Drawing.Point(340, 40)
$btnAutoDetect.Width = 100
$grpTarget.Controls.Add($btnAutoDetect)

$lblExclude = New-Object System.Windows.Forms.Label
$lblExclude.Text = "Exclude IPs (comma separated):"
$lblExclude.Location = New-Object System.Drawing.Point(10, 70)
$lblExclude.AutoSize = $true
$grpTarget.Controls.Add($lblExclude)

$txtExclude = New-Object System.Windows.Forms.TextBox
$txtExclude.Location = New-Object System.Drawing.Point(200, 67)
$txtExclude.Width = 240
$grpTarget.Controls.Add($txtExclude)

$grpPorts = New-Object System.Windows.Forms.GroupBox
$grpPorts.Text = "Ports"
$grpPorts.Location = New-Object System.Drawing.Point(540, 10)
$grpPorts.Size = New-Object System.Drawing.Size(520, 220)
$tabScan.Controls.Add($grpPorts)

$lblPortMode = New-Object System.Windows.Forms.Label
$lblPortMode.Text = "Port mode:"
$lblPortMode.Location = New-Object System.Drawing.Point(10, 25)
$lblPortMode.AutoSize = $true
$grpPorts.Controls.Add($lblPortMode)

$cmbPortMode = New-Object System.Windows.Forms.ComboBox
$cmbPortMode.DropDownStyle = 'DropDownList'
$cmbPortMode.Items.AddRange(@("Common services (default)", "Well-known (1-1024)", "All ports (1-65535)", "Custom / service groups"))
$cmbPortMode.SelectedIndex = 0
$cmbPortMode.Location = New-Object System.Drawing.Point(100, 22)
$cmbPortMode.Width = 220
$grpPorts.Controls.Add($cmbPortMode)

$txtPorts = New-Object System.Windows.Forms.TextBox
$txtPorts.Location = New-Object System.Drawing.Point(10, 52)
$txtPorts.Width = 490
$txtPorts.Text = ($CommonPorts -join ',')
$txtPorts.Enabled = $false
$grpPorts.Controls.Add($txtPorts)

$lblGroups = New-Object System.Windows.Forms.Label
$lblGroups.Text = "Quick-add service groups (Custom mode only):"
$lblGroups.Location = New-Object System.Drawing.Point(10, 82)
$lblGroups.AutoSize = $true
$grpPorts.Controls.Add($lblGroups)

$script:groupCheckboxes = @{}
$gx = 10; $gy = 102
foreach ($gname in $PortGroups.Keys) {
    $chk = New-Object System.Windows.Forms.CheckBox
    $chk.Text = $gname
    $chk.Location = New-Object System.Drawing.Point($gx, $gy)
    $chk.AutoSize = $true
    $chk.Enabled = $false
    $chk.Tag = $gname
    $grpPorts.Controls.Add($chk)
    $script:groupCheckboxes[$gname] = $chk
    $gy += 22
    if ($gy -gt 190) { $gy = 102; $gx += 170 }
}

$grpTiming = New-Object System.Windows.Forms.GroupBox
$grpTiming.Text = "Timing"
$grpTiming.Location = New-Object System.Drawing.Point(10, 120)
$grpTiming.Size = New-Object System.Drawing.Size(520, 110)
$tabScan.Controls.Add($grpTiming)

$lblTimeout = New-Object System.Windows.Forms.Label
$lblTimeout.Text = "Timeout (ms):"
$lblTimeout.Location = New-Object System.Drawing.Point(10, 28)
$lblTimeout.AutoSize = $true
$grpTiming.Controls.Add($lblTimeout)

$numTimeout = New-Object System.Windows.Forms.NumericUpDown
$numTimeout.Location = New-Object System.Drawing.Point(120, 25)
$numTimeout.Width = 80
$numTimeout.Minimum = 100
$numTimeout.Maximum = 10000
$numTimeout.Increment = 100
$numTimeout.Value = 800
$grpTiming.Controls.Add($numTimeout)

$lblConcurrency = New-Object System.Windows.Forms.Label
$lblConcurrency.Text = "Concurrency:"
$lblConcurrency.Location = New-Object System.Drawing.Point(220, 28)
$lblConcurrency.AutoSize = $true
$grpTiming.Controls.Add($lblConcurrency)

$numConcurrency = New-Object System.Windows.Forms.NumericUpDown
$numConcurrency.Location = New-Object System.Drawing.Point(320, 25)
$numConcurrency.Width = 80
$numConcurrency.Minimum = 1
$numConcurrency.Maximum = 512
$numConcurrency.Value = 128
$grpTiming.Controls.Add($numConcurrency)

$lblRetries = New-Object System.Windows.Forms.Label
$lblRetries.Text = "Ping retries:"
$lblRetries.Location = New-Object System.Drawing.Point(10, 60)
$lblRetries.AutoSize = $true
$grpTiming.Controls.Add($lblRetries)

$numRetries = New-Object System.Windows.Forms.NumericUpDown
$numRetries.Location = New-Object System.Drawing.Point(120, 57)
$numRetries.Width = 80
$numRetries.Minimum = 1
$numRetries.Maximum = 10
$numRetries.Value = 1
$grpTiming.Controls.Add($numRetries)
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.SetToolTip($numRetries, "Extra ping attempts for hosts that don't respond the first time.")

$grpOptions = New-Object System.Windows.Forms.GroupBox
$grpOptions.Text = "Options"
$grpOptions.Location = New-Object System.Drawing.Point(540, 240)
$grpOptions.Size = New-Object System.Drawing.Size(520, 130)
$tabScan.Controls.Add($grpOptions)

$chkNoPortScan = New-Object System.Windows.Forms.CheckBox
$chkNoPortScan.Text = "Skip port scan"
$chkNoPortScan.Location = New-Object System.Drawing.Point(10, 25)
$chkNoPortScan.AutoSize = $true
$grpOptions.Controls.Add($chkNoPortScan)

$chkNoResolve = New-Object System.Windows.Forms.CheckBox
$chkNoResolve.Text = "Skip DNS lookup"
$chkNoResolve.Location = New-Object System.Drawing.Point(10, 50)
$chkNoResolve.AutoSize = $true
$grpOptions.Controls.Add($chkNoResolve)

$chkVendor = New-Object System.Windows.Forms.CheckBox
$chkVendor.Text = "Look up MAC vendor"
$chkVendor.Location = New-Object System.Drawing.Point(10, 75)
$chkVendor.AutoSize = $true
$grpOptions.Controls.Add($chkVendor)
$toolTip.SetToolTip($chkVendor, "Best-effort offline lookup against a small local table of common vendor MAC prefixes.")

$chkAutoVuln = New-Object System.Windows.Forms.CheckBox
$chkAutoVuln.Text = "Auto-run vulnerability check after scan"
$chkAutoVuln.Location = New-Object System.Drawing.Point(10, 100)
$chkAutoVuln.AutoSize = $true
$grpOptions.Controls.Add($chkAutoVuln)

$grpProfile = New-Object System.Windows.Forms.GroupBox
$grpProfile.Text = "Scan Profiles"
$grpProfile.Location = New-Object System.Drawing.Point(10, 240)
$grpProfile.Size = New-Object System.Drawing.Size(520, 70)
$tabScan.Controls.Add($grpProfile)

$cmbProfiles = New-Object System.Windows.Forms.ComboBox
$cmbProfiles.DropDownStyle = 'DropDownList'
$cmbProfiles.Location = New-Object System.Drawing.Point(10, 28)
$cmbProfiles.Width = 220
$grpProfile.Controls.Add($cmbProfiles)

$btnLoadProfile = New-Object System.Windows.Forms.Button
$btnLoadProfile.Text = "Load"
$btnLoadProfile.Location = New-Object System.Drawing.Point(240, 26)
$btnLoadProfile.Width = 70
$grpProfile.Controls.Add($btnLoadProfile)

$btnSaveProfile = New-Object System.Windows.Forms.Button
$btnSaveProfile.Text = "Save As..."
$btnSaveProfile.Location = New-Object System.Drawing.Point(320, 26)
$btnSaveProfile.Width = 90
$grpProfile.Controls.Add($btnSaveProfile)

$btnScan = New-Object System.Windows.Forms.Button
$btnScan.Text = "Start Scan"
$btnScan.Location = New-Object System.Drawing.Point(10, 380)
$btnScan.Width = 110
$btnScan.Height = 32
$btnScan.FlatStyle = 'Flat'
$btnScan.FlatAppearance.BorderSize = 0
$btnScan.BackColor = $accentColor
$btnScan.ForeColor = [System.Drawing.Color]::White
$btnScan.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$tabScan.Controls.Add($btnScan)

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = "Cancel"
$btnCancel.Location = New-Object System.Drawing.Point(130, 380)
$btnCancel.Width = 110
$btnCancel.Height = 32
$btnCancel.Enabled = $false
$tabScan.Controls.Add($btnCancel)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Style = 'Marquee'
$progressBar.MarqueeAnimationSpeed = 0
$progressBar.Location = New-Object System.Drawing.Point(250, 385)
$progressBar.Width = 300
$progressBar.Height = 20
$tabScan.Controls.Add($progressBar)

$lblLog = New-Object System.Windows.Forms.Label
$lblLog.Text = "Log:"
$lblLog.Location = New-Object System.Drawing.Point(10, 420)
$lblLog.AutoSize = $true
$tabScan.Controls.Add($lblLog)

$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Location = New-Object System.Drawing.Point(10, 440)
$txtLog.Size = New-Object System.Drawing.Size(1050, 180)
$txtLog.Multiline = $true
$txtLog.ScrollBars = 'Vertical'
$txtLog.ReadOnly = $true
$txtLog.Anchor = 'Top,Left,Right,Bottom'
$txtLog.Font = New-Object System.Drawing.Font("Consolas", 8.5)
$tabScan.Controls.Add($txtLog)

# --- Results tab ---

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(10, 10)
$grid.Size = New-Object System.Drawing.Size(1050, 560)
$grid.Anchor = 'Top,Left,Right,Bottom'
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.SelectionMode = 'FullRowSelect'
$grid.AutoSizeColumnsMode = 'Fill'
$grid.Columns.Add("IPAddress", "IP Address") | Out-Null
$grid.Columns.Add("Hostname", "Hostname") | Out-Null
$grid.Columns.Add("MACAddress", "MAC Address") | Out-Null
$grid.Columns.Add("Vendor", "Vendor") | Out-Null
$grid.Columns.Add("OpenPorts", "Open Ports") | Out-Null
$tabResults.Controls.Add($grid)

$script:contextMenuIp = $null

$gridContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$miGoScan = $gridContextMenu.Items.Add("Scan Settings (rescan this host)")
$miGoResults = $gridContextMenu.Items.Add("Results")
$miGoVuln = $gridContextMenu.Items.Add("Vulnerabilities (jump to findings)")
$miGoHistory = $gridContextMenu.Items.Add("History")
$grid.ContextMenuStrip = $gridContextMenu

$grid.Add_CellMouseDown({
    param($sender, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right -and $e.RowIndex -ge 0) {
        $grid.ClearSelection()
        $grid.Rows[$e.RowIndex].Selected = $true
        $grid.CurrentCell = $grid.Rows[$e.RowIndex].Cells[0]
        $script:contextMenuIp = $grid.Rows[$e.RowIndex].Cells["IPAddress"].Value
    }
})

$miGoScan.Add_Click({
    if ($script:contextMenuIp) { $txtTarget.Text = $script:contextMenuIp }
    $tabs.SelectedTab = $tabScan
})

$miGoResults.Add_Click({
    $tabs.SelectedTab = $tabResults
})

$miGoVuln.Add_Click({
    $tabs.SelectedTab = $tabVuln
    if ($script:contextMenuIp) {
        $vgrid.ClearSelection()
        $firstMatch = $null
        foreach ($row in $vgrid.Rows) {
            if ($row.Cells["IPAddress"].Value -eq $script:contextMenuIp) {
                $row.Selected = $true
                if (-not $firstMatch) { $firstMatch = $row.Index }
            }
        }
        if ($firstMatch -ne $null) { $vgrid.FirstDisplayedScrollingRowIndex = $firstMatch }
    }
})

$miGoHistory.Add_Click({
    $tabs.SelectedTab = $tabHistory
})

$btnCheckVulns = New-Object System.Windows.Forms.Button
$btnCheckVulns.Text = "Check Vulnerabilities"
$btnCheckVulns.Location = New-Object System.Drawing.Point(10, 580)
$btnCheckVulns.Width = 150
$btnCheckVulns.Enabled = $false
$btnCheckVulns.Anchor = 'Bottom,Left'
$tabResults.Controls.Add($btnCheckVulns)

$btnExportCsv = New-Object System.Windows.Forms.Button
$btnExportCsv.Text = "Export CSV"
$btnExportCsv.Location = New-Object System.Drawing.Point(890, 580)
$btnExportCsv.Width = 80
$btnExportCsv.Enabled = $false
$btnExportCsv.Anchor = 'Bottom,Right'
$tabResults.Controls.Add($btnExportCsv)

$btnExportJson = New-Object System.Windows.Forms.Button
$btnExportJson.Text = "Export JSON"
$btnExportJson.Location = New-Object System.Drawing.Point(980, 580)
$btnExportJson.Width = 80
$btnExportJson.Enabled = $false
$btnExportJson.Anchor = 'Bottom,Right'
$tabResults.Controls.Add($btnExportJson)

# --- Vulnerabilities tab ---

$vgrid = New-Object System.Windows.Forms.DataGridView
$vgrid.Location = New-Object System.Drawing.Point(10, 10)
$vgrid.Size = New-Object System.Drawing.Size(1050, 560)
$vgrid.Anchor = 'Top,Left,Right,Bottom'
$vgrid.ReadOnly = $true
$vgrid.AllowUserToAddRows = $false
$vgrid.AllowUserToDeleteRows = $false
$vgrid.SelectionMode = 'FullRowSelect'
$vgrid.AutoSizeColumnsMode = 'Fill'
$vgrid.Columns.Add("IPAddress", "IP") | Out-Null
$vgrid.Columns.Add("Port", "Port") | Out-Null
$vgrid.Columns.Add("Service", "Service") | Out-Null
$vgrid.Columns.Add("Severity", "Severity") | Out-Null
$vgrid.Columns.Add("Finding", "Finding") | Out-Null
$vgrid.Columns.Add("Recommendation", "Recommendation") | Out-Null
$vgrid.Columns.Add("Banner", "Banner") | Out-Null
$tabVuln.Controls.Add($vgrid)

$btnVulnCsv = New-Object System.Windows.Forms.Button
$btnVulnCsv.Text = "Export CSV"
$btnVulnCsv.Location = New-Object System.Drawing.Point(890, 580)
$btnVulnCsv.Width = 80
$btnVulnCsv.Enabled = $false
$btnVulnCsv.Anchor = 'Bottom,Right'
$tabVuln.Controls.Add($btnVulnCsv)

$btnVulnJson = New-Object System.Windows.Forms.Button
$btnVulnJson.Text = "Export JSON"
$btnVulnJson.Location = New-Object System.Drawing.Point(980, 580)
$btnVulnJson.Width = 80
$btnVulnJson.Enabled = $false
$btnVulnJson.Anchor = 'Bottom,Right'
$tabVuln.Controls.Add($btnVulnJson)

# --- History tab ---

$gridHistory = New-Object System.Windows.Forms.DataGridView
$gridHistory.Location = New-Object System.Drawing.Point(10, 10)
$gridHistory.Size = New-Object System.Drawing.Size(1050, 560)
$gridHistory.Anchor = 'Top,Left,Right,Bottom'
$gridHistory.ReadOnly = $true
$gridHistory.AllowUserToAddRows = $false
$gridHistory.AllowUserToDeleteRows = $false
$gridHistory.SelectionMode = 'FullRowSelect'
$gridHistory.MultiSelect = $false
$gridHistory.AutoSizeColumnsMode = 'Fill'
$gridHistory.Columns.Add("Timestamp", "Timestamp") | Out-Null
$gridHistory.Columns.Add("Target", "Target") | Out-Null
$gridHistory.Columns.Add("HostCount", "Hosts Found") | Out-Null
$gridHistory.Columns.Add("OpenPortsTotal", "Total Open Ports") | Out-Null
$tabHistory.Controls.Add($gridHistory)

$btnLoadHistory = New-Object System.Windows.Forms.Button
$btnLoadHistory.Text = "Load Selected into Results"
$btnLoadHistory.Location = New-Object System.Drawing.Point(10, 580)
$btnLoadHistory.Width = 180
$btnLoadHistory.Anchor = 'Bottom,Left'
$tabHistory.Controls.Add($btnLoadHistory)

$btnClearHistory = New-Object System.Windows.Forms.Button
$btnClearHistory.Text = "Clear History"
$btnClearHistory.Location = New-Object System.Drawing.Point(980, 580)
$btnClearHistory.Width = 80
$btnClearHistory.Anchor = 'Bottom,Right'
$tabHistory.Controls.Add($btnClearHistory)

function New-PropGrid {
    param([System.Windows.Forms.TabPage]$Parent, [int]$X, [int]$Y, [int]$W, [int]$H)
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Location = New-Object System.Drawing.Point($X, $Y)
    $g.Size = New-Object System.Drawing.Size($W, $H)
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.AutoSizeColumnsMode = 'Fill'
    $g.Columns.Add("Property", "Property") | Out-Null
    $g.Columns.Add("Value", "Value") | Out-Null
    $Parent.Controls.Add($g)
    return $g
}

function New-SectionLabel {
    param([System.Windows.Forms.TabPage]$Parent, [string]$Text, [int]$X, [int]$Y)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
    $l.Location = New-Object System.Drawing.Point($X, $Y)
    $l.AutoSize = $true
    $Parent.Controls.Add($l)
    return $l
}

function New-DataGrid {
    param([System.Windows.Forms.TabPage]$Parent, [int]$X, [int]$Y, [int]$W, [int]$H, [string[]]$Columns)
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Location = New-Object System.Drawing.Point($X, $Y)
    $g.Size = New-Object System.Drawing.Size($W, $H)
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.AutoSizeColumnsMode = 'Fill'
    foreach ($c in $Columns) { $g.Columns.Add($c, $c) | Out-Null }
    $Parent.Controls.Add($g)
    return $g
}

# --- System Info tab ---

$btnRefreshSysInfo = New-Object System.Windows.Forms.Button
$btnRefreshSysInfo.Text = "Refresh"
$btnRefreshSysInfo.Location = New-Object System.Drawing.Point(10, 10)
$btnRefreshSysInfo.Width = 100
$tabSysInfo.Controls.Add($btnRefreshSysInfo)

New-SectionLabel -Parent $tabSysInfo -Text "Specs" -X 10 -Y 48 | Out-Null
$gridSpecs = New-PropGrid -Parent $tabSysInfo -X 10 -Y 68 -W 600 -H 300

New-SectionLabel -Parent $tabSysInfo -Text "Volumes" -X 10 -Y 380 | Out-Null
$gridVolumes = New-DataGrid -Parent $tabSysInfo -X 10 -Y 400 -W 1080 -H 140 -Columns @("Drive", "Label", "FileSystem", "TotalGB", "FreeGB", "PercentFree")

New-SectionLabel -Parent $tabSysInfo -Text "Physical Disks" -X 10 -Y 550 | Out-Null
$gridPhysicalDisks = New-DataGrid -Parent $tabSysInfo -X 10 -Y 570 -W 1080 -H 140 -Columns @("FriendlyName", "MediaType", "SizeGB", "HealthStatus", "OperationalStatus")

# --- Performance tab ---

$btnRefreshPerf = New-Object System.Windows.Forms.Button
$btnRefreshPerf.Text = "Refresh"
$btnRefreshPerf.Location = New-Object System.Drawing.Point(10, 10)
$btnRefreshPerf.Width = 100
$tabPerf.Controls.Add($btnRefreshPerf)

$chkAutoRefreshPerf = New-Object System.Windows.Forms.CheckBox
$chkAutoRefreshPerf.Text = "Auto-refresh every 3s"
$chkAutoRefreshPerf.Location = New-Object System.Drawing.Point(120, 14)
$chkAutoRefreshPerf.AutoSize = $true
$tabPerf.Controls.Add($chkAutoRefreshPerf)

$lblPerfSummary = New-Object System.Windows.Forms.Label
$lblPerfSummary.Text = "CPU: --   Memory: --"
$lblPerfSummary.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$lblPerfSummary.Location = New-Object System.Drawing.Point(10, 48)
$lblPerfSummary.AutoSize = $true
$tabPerf.Controls.Add($lblPerfSummary)

New-SectionLabel -Parent $tabPerf -Text "Top processes by memory" -X 10 -Y 78 | Out-Null
$gridTopMem = New-DataGrid -Parent $tabPerf -X 10 -Y 98 -W 1080 -H 170 -Columns @("Name", "Id", "MemoryMB", "CpuSeconds")

New-SectionLabel -Parent $tabPerf -Text "Top processes by CPU time" -X 10 -Y 278 | Out-Null
$gridTopCpu = New-DataGrid -Parent $tabPerf -X 10 -Y 298 -W 1080 -H 170 -Columns @("Name", "Id", "MemoryMB", "CpuSeconds")

New-SectionLabel -Parent $tabPerf -Text "Startup programs" -X 10 -Y 478 | Out-Null
$gridStartup = New-DataGrid -Parent $tabPerf -X 10 -Y 498 -W 1080 -H 160 -Columns @("Name", "Command", "Location", "User")

# --- Network Diagnostics tab ---

$btnRefreshNetDiag = New-Object System.Windows.Forms.Button
$btnRefreshNetDiag.Text = "Run Diagnostics"
$btnRefreshNetDiag.Location = New-Object System.Drawing.Point(10, 10)
$btnRefreshNetDiag.Width = 120
$tabNetDiag.Controls.Add($btnRefreshNetDiag)

New-SectionLabel -Parent $tabNetDiag -Text "Adapters" -X 10 -Y 48 | Out-Null
$gridAdapters = New-DataGrid -Parent $tabNetDiag -X 10 -Y 68 -W 1080 -H 110 -Columns @("Name", "Description", "Status", "LinkSpeed", "MacAddress")

New-SectionLabel -Parent $tabNetDiag -Text "IP Configuration" -X 10 -Y 188 | Out-Null
$gridIpConfig = New-DataGrid -Parent $tabNetDiag -X 10 -Y 208 -W 1080 -H 90 -Columns @("Adapter", "IPv4", "Gateway", "DNS")

New-SectionLabel -Parent $tabNetDiag -Text "Connectivity Tests" -X 10 -Y 308 | Out-Null
$gridNetTests = New-DataGrid -Parent $tabNetDiag -X 10 -Y 328 -W 1080 -H 150 -Columns @("Test", "Result")

# --- Event Logs tab ---

$btnRefreshEvents = New-Object System.Windows.Forms.Button
$btnRefreshEvents.Text = "Refresh"
$btnRefreshEvents.Location = New-Object System.Drawing.Point(10, 10)
$btnRefreshEvents.Width = 100
$tabEvents.Controls.Add($btnRefreshEvents)

$lblEventsDays = New-Object System.Windows.Forms.Label
$lblEventsDays.Text = "Days back:"
$lblEventsDays.Location = New-Object System.Drawing.Point(130, 14)
$lblEventsDays.AutoSize = $true
$tabEvents.Controls.Add($lblEventsDays)

$numEventsDays = New-Object System.Windows.Forms.NumericUpDown
$numEventsDays.Location = New-Object System.Drawing.Point(205, 11)
$numEventsDays.Width = 60
$numEventsDays.Minimum = 1
$numEventsDays.Maximum = 90
$numEventsDays.Value = 7
$tabEvents.Controls.Add($numEventsDays)

$lblEventsMax = New-Object System.Windows.Forms.Label
$lblEventsMax.Text = "Max events:"
$lblEventsMax.Location = New-Object System.Drawing.Point(280, 14)
$lblEventsMax.AutoSize = $true
$tabEvents.Controls.Add($lblEventsMax)

$numEventsMax = New-Object System.Windows.Forms.NumericUpDown
$numEventsMax.Location = New-Object System.Drawing.Point(360, 11)
$numEventsMax.Width = 70
$numEventsMax.Minimum = 10
$numEventsMax.Maximum = 500
$numEventsMax.Value = 50
$tabEvents.Controls.Add($numEventsMax)

$gridEvents = New-DataGrid -Parent $tabEvents -X 10 -Y 48 -W 1080 -H 600 -Columns @("TimeCreated", "LogName", "Level", "Source", "Id", "Message")

# --- Security & Updates tab ---

$btnRefreshSecurity = New-Object System.Windows.Forms.Button
$btnRefreshSecurity.Text = "Refresh"
$btnRefreshSecurity.Location = New-Object System.Drawing.Point(10, 10)
$btnRefreshSecurity.Width = 100
$tabSecurity.Controls.Add($btnRefreshSecurity)

New-SectionLabel -Parent $tabSecurity -Text "Windows Defender" -X 10 -Y 48 | Out-Null
$gridDefender = New-PropGrid -Parent $tabSecurity -X 10 -Y 68 -W 500 -H 100

New-SectionLabel -Parent $tabSecurity -Text "Firewall Profiles" -X 10 -Y 178 | Out-Null
$gridFirewall = New-DataGrid -Parent $tabSecurity -X 10 -Y 198 -W 500 -H 100 -Columns @("Profile", "Enabled")

New-SectionLabel -Parent $tabSecurity -Text "BitLocker" -X 10 -Y 308 | Out-Null
$gridBitlocker = New-DataGrid -Parent $tabSecurity -X 10 -Y 328 -W 500 -H 100 -Columns @("MountPoint", "VolumeStatus", "ProtectionStatus")
$toolTip.SetToolTip($gridBitlocker, "May show nothing if not running as Administrator.")

New-SectionLabel -Parent $tabSecurity -Text "Recently Installed Updates" -X 530 -Y 48 | Out-Null
$gridUpdates = New-DataGrid -Parent $tabSecurity -X 530 -Y 68 -W 560 -H 360 -Columns @("HotFixID", "Description", "InstalledOn")

# --- Status bar ---

$statusStrip = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = "Idle."
$statusLabel.Spring = $true
$statusLabel.TextAlign = 'MiddleLeft'
$statusStrip.Items.Add($statusLabel) | Out-Null
$form.Controls.Add($statusStrip)

# ---------------------------------------------------------------------------
# Background scan machinery
# ---------------------------------------------------------------------------

$script:sync = [hashtable]::Synchronized(@{ Status = "Idle."; Cancel = $false })
$script:psInstance = $null
$script:asyncHandle = $null
$script:lastResults = @()
$script:lastTarget = ""
$script:scanning = $false

$script:vulnSync = [hashtable]::Synchronized(@{ Status = "Idle."; Cancel = $false })
$script:vulnPsInstance = $null
$script:vulnAsyncHandle = $null
$script:vulnScanning = $false

$script:scanHistory = @(Import-HistoryFromDisk)

$scanScriptBlock = {
    param($CorePath, $Target, $Ports, $TimeoutMs, $MaxConcurrency, $Retries, $ExcludeHosts, $NoPortScan, $NoResolve, $LookupVendor, $Sync)
    . $CorePath
    Invoke-NetworkDiscovery -Target $Target -Ports $Ports -TimeoutMs $TimeoutMs -MaxConcurrency $MaxConcurrency `
        -Retries $Retries -ExcludeHosts $ExcludeHosts -NoPortScan:$NoPortScan -NoResolve:$NoResolve -LookupVendor:$LookupVendor -Sync $Sync
}

$vulnScanScriptBlock = {
    param($VulnCorePath, $Hosts, $TimeoutMs, $Sync)
    . $VulnCorePath
    Invoke-VulnerabilityScan -Hosts $Hosts -TimeoutMs $TimeoutMs -Sync $Sync
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$vulnTimer = New-Object System.Windows.Forms.Timer
$vulnTimer.Interval = 250

$script:netDiagSync = [hashtable]::Synchronized(@{ Status = "Idle."; Cancel = $false })
$script:netDiagPsInstance = $null
$script:netDiagAsyncHandle = $null

$script:eventsSync = [hashtable]::Synchronized(@{ Status = "Idle."; Cancel = $false })
$script:eventsPsInstance = $null
$script:eventsAsyncHandle = $null

$netDiagScriptBlock = {
    param($SysInfoCorePath, $Sync)
    . $SysInfoCorePath
    Get-NetworkDiagnostics -Sync $Sync
}

$eventsScriptBlock = {
    param($SysInfoCorePath, $MaxEvents, $DaysBack, $Sync)
    . $SysInfoCorePath
    Get-RecentEventLogIssues -MaxEvents $MaxEvents -DaysBack $DaysBack -Sync $Sync
}

$netDiagTimer = New-Object System.Windows.Forms.Timer
$netDiagTimer.Interval = 250
$eventsTimer = New-Object System.Windows.Forms.Timer
$eventsTimer.Interval = 250

$perfAutoTimer = New-Object System.Windows.Forms.Timer
$perfAutoTimer.Interval = 3000

$netDiagTimer.Add_Tick({
    $statusLabel.Text = $script:netDiagSync.Status
    if ($script:netDiagAsyncHandle -and $script:netDiagAsyncHandle.IsCompleted) {
        $netDiagTimer.Stop()
        try {
            $result = @($script:netDiagPsInstance.EndInvoke($script:netDiagAsyncHandle))[0]
            if ($script:netDiagPsInstance.HadErrors) {
                $errMsg = ($script:netDiagPsInstance.Streams.Error | ForEach-Object { $_.ToString() }) -join "`r`n"
                Add-LogLine "ERROR: $errMsg"
            }
            $gridAdapters.Rows.Clear()
            foreach ($a in $result.Adapters) { $gridAdapters.Rows.Add($a.Name, $a.Description, $a.Status, $a.LinkSpeed, $a.MacAddress) | Out-Null }
            $gridIpConfig.Rows.Clear()
            foreach ($c in $result.IpConfig) { $gridIpConfig.Rows.Add($c.Adapter, $c.IPv4, $c.Gateway, $c.DNS) | Out-Null }
            $gridNetTests.Rows.Clear()
            foreach ($t in $result.Tests) {
                $rowIdx = $gridNetTests.Rows.Add($t.Test, $t.Result)
                if ($t.Result -match '^OK') {
                    $gridNetTests.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(0, 130, 0)
                } elseif ($t.Result -match 'FAILED') {
                    $gridNetTests.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(200, 0, 0)
                }
            }
            Add-LogLine "Network diagnostics complete."
        } catch {
            Add-LogLine "ERROR: $($_.Exception.Message)"
        } finally {
            $script:netDiagPsInstance.Dispose()
            $script:netDiagPsInstance = $null
            $script:netDiagAsyncHandle = $null
            $btnRefreshNetDiag.Enabled = $true
        }
    }
})

$eventsTimer.Add_Tick({
    $statusLabel.Text = $script:eventsSync.Status
    if ($script:eventsAsyncHandle -and $script:eventsAsyncHandle.IsCompleted) {
        $eventsTimer.Stop()
        try {
            $result = @($script:eventsPsInstance.EndInvoke($script:eventsAsyncHandle))
            if ($script:eventsPsInstance.HadErrors) {
                $errMsg = ($script:eventsPsInstance.Streams.Error | ForEach-Object { $_.ToString() }) -join "`r`n"
                Add-LogLine "ERROR: $errMsg"
            }
            $gridEvents.Rows.Clear()
            foreach ($ev in $result) {
                $rowIdx = $gridEvents.Rows.Add($ev.TimeCreated, $ev.LogName, $ev.Level, $ev.Source, $ev.Id, $ev.Message)
                if ($ev.Level -eq 'Critical') {
                    $gridEvents.Rows[$rowIdx].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 205, 210)
                    $gridEvents.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
                } elseif ($ev.Level -eq 'Error') {
                    $gridEvents.Rows[$rowIdx].DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 224, 178)
                    $gridEvents.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
                }
            }
            Add-LogLine "Event log query complete: $($result.Count) event(s)."
        } catch {
            Add-LogLine "ERROR: $($_.Exception.Message)"
        } finally {
            $script:eventsPsInstance.Dispose()
            $script:eventsPsInstance = $null
            $script:eventsAsyncHandle = $null
            $btnRefreshEvents.Enabled = $true
        }
    }
})

function Set-UiScanningState {
    $busy = $script:scanning -or $script:vulnScanning
    $btnScan.Enabled = -not $busy
    $btnCancel.Enabled = $script:scanning
    $txtTarget.Enabled = -not $busy
    $txtExclude.Enabled = -not $busy
    $btnAutoDetect.Enabled = -not $busy
    $cmbPortMode.Enabled = -not $busy
    $txtPorts.Enabled = (-not $busy) -and ($cmbPortMode.SelectedIndex -eq 3)
    foreach ($chk in $script:groupCheckboxes.Values) { $chk.Enabled = (-not $busy) -and ($cmbPortMode.SelectedIndex -eq 3) }
    $chkNoPortScan.Enabled = -not $busy
    $chkNoResolve.Enabled = -not $busy
    $chkVendor.Enabled = -not $busy
    $chkAutoVuln.Enabled = -not $busy
    $numTimeout.Enabled = -not $busy
    $numConcurrency.Enabled = -not $busy
    $numRetries.Enabled = -not $busy
    $btnLoadProfile.Enabled = -not $busy
    $btnSaveProfile.Enabled = -not $busy
    $btnExportCsv.Enabled = (-not $busy) -and ($script:lastResults.Count -gt 0)
    $btnExportJson.Enabled = (-not $busy) -and ($script:lastResults.Count -gt 0)
    $btnCheckVulns.Enabled = (-not $busy) -and ($script:lastResults.Count -gt 0)
    $progressBar.MarqueeAnimationSpeed = if ($busy) { 30 } else { 0 }
}

function Start-VulnScanNow {
    if ($script:lastResults.Count -eq 0) { return }
    $script:vulnSync.Status = "Starting vulnerability check..."
    $script:vulnSync.Cancel = $false
    $script:vulnScanning = $true
    Set-UiScanningState
    Add-LogLine "Vulnerability check started on $($script:lastResults.Count) host(s)."

    $timeoutForVuln = [Math]::Max([int]$numTimeout.Value, 1500)

    $script:vulnPsInstance = [powershell]::Create()
    [void]$script:vulnPsInstance.AddScript($vulnScanScriptBlock)
    [void]$script:vulnPsInstance.AddArgument($vulnCorePath)
    [void]$script:vulnPsInstance.AddArgument($script:lastResults)
    [void]$script:vulnPsInstance.AddArgument($timeoutForVuln)
    [void]$script:vulnPsInstance.AddArgument($script:vulnSync)

    $script:vulnAsyncHandle = $script:vulnPsInstance.BeginInvoke()
    $vulnTimer.Start()
}

$timer.Add_Tick({
    $statusLabel.Text = $script:sync.Status

    if ($script:asyncHandle -and $script:asyncHandle.IsCompleted) {
        $timer.Stop()
        try {
            $output = $script:psInstance.EndInvoke($script:asyncHandle)
            if ($script:psInstance.HadErrors) {
                $errMsg = ($script:psInstance.Streams.Error | ForEach-Object { $_.ToString() }) -join "`r`n"
                Add-LogLine "ERROR: $errMsg"
                [System.Windows.Forms.MessageBox]::Show($errMsg, "Scan error", 'OK', 'Error') | Out-Null
            }
            $script:lastResults = @($output)
            Update-ResultsGrid -Results $script:lastResults
            Add-LogLine "Scan finished: $($script:lastResults.Count) host(s) found."
            if ($script:lastResults.Count -gt 0) {
                Add-HistoryEntry -Target $script:lastTarget -Results $script:lastResults
            }
        } catch {
            Add-LogLine "ERROR: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Scan error", 'OK', 'Error') | Out-Null
        } finally {
            $script:psInstance.Dispose()
            $script:psInstance = $null
            $script:asyncHandle = $null
            $script:scanning = $false
            Set-UiScanningState
            if ($chkAutoVuln.Checked -and $script:lastResults.Count -gt 0) {
                $tabs.SelectedTab = $tabVuln
                Start-VulnScanNow
            } else {
                $tabs.SelectedTab = $tabResults
            }
        }
    }
})

$vulnTimer.Add_Tick({
    $statusLabel.Text = $script:vulnSync.Status

    if ($script:vulnAsyncHandle -and $script:vulnAsyncHandle.IsCompleted) {
        $vulnTimer.Stop()
        try {
            $output = $script:vulnPsInstance.EndInvoke($script:vulnAsyncHandle)
            if ($script:vulnPsInstance.HadErrors) {
                $errMsg = ($script:vulnPsInstance.Streams.Error | ForEach-Object { $_.ToString() }) -join "`r`n"
                Add-LogLine "ERROR: $errMsg"
                [System.Windows.Forms.MessageBox]::Show($errMsg, "Vulnerability check error", 'OK', 'Error') | Out-Null
            }
            $findings = @($output)
            Update-VulnGrid -Findings $findings
            Add-LogLine "Vulnerability check finished: $($findings.Count) finding(s)."
        } catch {
            Add-LogLine "ERROR: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Vulnerability check error", 'OK', 'Error') | Out-Null
        } finally {
            $script:vulnPsInstance.Dispose()
            $script:vulnPsInstance = $null
            $script:vulnAsyncHandle = $null
            $script:vulnScanning = $false
            Set-UiScanningState
        }
    }
})

# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------

$btnAutoDetect.Add_Click({
    try {
        $txtTarget.Text = Get-LocalSubnetCidr
        Add-LogLine "Auto-detected subnet: $($txtTarget.Text)"
    } catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Auto-detect failed", 'OK', 'Warning') | Out-Null
    }
})

$cmbPortMode.Add_SelectedIndexChanged({
    $isCustom = ($cmbPortMode.SelectedIndex -eq 3)
    $txtPorts.Enabled = $isCustom
    foreach ($chk in $script:groupCheckboxes.Values) { $chk.Enabled = $isCustom }
    if ($isCustom -and $txtPorts.Text.Trim() -eq '') { $txtPorts.Text = ($CommonPorts -join ',') }
    if ($cmbPortMode.SelectedIndex -eq 2) {
        [System.Windows.Forms.MessageBox]::Show("Scanning all 65535 ports on every live host can take a long time. Consider a smaller target range.", "Heads up", 'OK', 'Information') | Out-Null
    }
})

foreach ($gname in $PortGroups.Keys) {
    $script:groupCheckboxes[$gname].Add_CheckedChanged({
        $name = $this.Tag
        $groupPorts = $PortGroups[$name]
        $current = [System.Collections.Generic.List[int]](ConvertTo-PortArray $txtPorts.Text)
        if ($this.Checked) {
            foreach ($p in $groupPorts) { if (-not $current.Contains($p)) { $current.Add($p) } }
        } else {
            foreach ($p in $groupPorts) { [void]$current.Remove($p) }
        }
        $txtPorts.Text = (($current | Sort-Object -Unique) -join ',')
    }.GetNewClosure())
}

$btnScan.Add_Click({
    $targetText = $txtTarget.Text.Trim()

    $effectivePorts = switch ($cmbPortMode.SelectedIndex) {
        0 { $CommonPorts }
        1 { 1..1024 }
        2 { 1..65535 }
        3 { ConvertTo-PortArray $txtPorts.Text }
        default { $CommonPorts }
    }
    if ($chkNoPortScan.Checked) { $effectivePorts = @() }

    $excludeArr = ConvertTo-ExcludeArray $txtExclude.Text

    Update-ResultsGrid -Results @()
    $vgrid.Rows.Clear()
    $script:lastResults = @()
    $script:lastTarget = $(if ($targetText) { $targetText } else { "(auto-detected)" })
    $script:sync.Status = "Starting..."
    $script:sync.Cancel = $false
    $script:scanning = $true
    Set-UiScanningState
    Add-LogLine "Scan started. Target: $($script:lastTarget); Ports: $($effectivePorts.Count); Retries: $([int]$numRetries.Value)"

    $script:psInstance = [powershell]::Create()
    [void]$script:psInstance.AddScript($scanScriptBlock)
    [void]$script:psInstance.AddArgument($corePath)
    [void]$script:psInstance.AddArgument($targetText)
    [void]$script:psInstance.AddArgument([int[]]$effectivePorts)
    [void]$script:psInstance.AddArgument([int]$numTimeout.Value)
    [void]$script:psInstance.AddArgument([int]$numConcurrency.Value)
    [void]$script:psInstance.AddArgument([int]$numRetries.Value)
    [void]$script:psInstance.AddArgument([string[]]$excludeArr)
    [void]$script:psInstance.AddArgument([bool]$chkNoPortScan.Checked)
    [void]$script:psInstance.AddArgument([bool]$chkNoResolve.Checked)
    [void]$script:psInstance.AddArgument([bool]$chkVendor.Checked)
    [void]$script:psInstance.AddArgument($script:sync)

    $script:asyncHandle = $script:psInstance.BeginInvoke()
    $timer.Start()
})

$btnCancel.Add_Click({
    $script:sync.Cancel = $true
    $btnCancel.Enabled = $false
    $statusLabel.Text = "Cancelling..."
    Add-LogLine "Cancel requested."
})

$btnCheckVulns.Add_Click({
    $tabs.SelectedTab = $tabVuln
    Start-VulnScanNow
})

$btnExportCsv.Add_Click({
    if ($script:lastResults.Count -eq 0) { return }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "CSV files (*.csv)|*.csv"
    $sfd.FileName = "network-discovery.csv"
    if ($sfd.ShowDialog() -eq 'OK') {
        $script:lastResults | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding utf8
        [System.Windows.Forms.MessageBox]::Show("Saved to $($sfd.FileName)", "Exported", 'OK', 'Information') | Out-Null
    }
})

$btnExportJson.Add_Click({
    if ($script:lastResults.Count -eq 0) { return }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "JSON files (*.json)|*.json"
    $sfd.FileName = "network-discovery.json"
    if ($sfd.ShowDialog() -eq 'OK') {
        $script:lastResults | ConvertTo-Json -Depth 3 | Set-Content -Path $sfd.FileName -Encoding utf8
        [System.Windows.Forms.MessageBox]::Show("Saved to $($sfd.FileName)", "Exported", 'OK', 'Information') | Out-Null
    }
})

$btnVulnCsv.Add_Click({
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "CSV files (*.csv)|*.csv"
    $sfd.FileName = "vulnerability-findings.csv"
    if ($sfd.ShowDialog() -eq 'OK') {
        $rows = @()
        foreach ($r in $vgrid.Rows) {
            if ($r.IsNewRow) { continue }
            $rows += [PSCustomObject]@{
                IPAddress = $r.Cells["IPAddress"].Value; Port = $r.Cells["Port"].Value
                Service = $r.Cells["Service"].Value; Severity = $r.Cells["Severity"].Value
                Finding = $r.Cells["Finding"].Value; Recommendation = $r.Cells["Recommendation"].Value
                Banner = $r.Cells["Banner"].Value
            }
        }
        $rows | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding utf8
        [System.Windows.Forms.MessageBox]::Show("Saved to $($sfd.FileName)", "Exported", 'OK', 'Information') | Out-Null
    }
})

$btnVulnJson.Add_Click({
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "JSON files (*.json)|*.json"
    $sfd.FileName = "vulnerability-findings.json"
    if ($sfd.ShowDialog() -eq 'OK') {
        $rows = @()
        foreach ($r in $vgrid.Rows) {
            if ($r.IsNewRow) { continue }
            $rows += [PSCustomObject]@{
                IPAddress = $r.Cells["IPAddress"].Value; Port = $r.Cells["Port"].Value
                Service = $r.Cells["Service"].Value; Severity = $r.Cells["Severity"].Value
                Finding = $r.Cells["Finding"].Value; Recommendation = $r.Cells["Recommendation"].Value
                Banner = $r.Cells["Banner"].Value
            }
        }
        $rows | ConvertTo-Json -Depth 3 | Set-Content -Path $sfd.FileName -Encoding utf8
        [System.Windows.Forms.MessageBox]::Show("Saved to $($sfd.FileName)", "Exported", 'OK', 'Information') | Out-Null
    }
})

$btnSaveProfile.Add_Click({
    $name = [Microsoft.VisualBasic.Interaction]::InputBox("Profile name:", "Save Profile", "default")
    if (-not $name) { return }
    $name = $name -replace '[\\/:*?"<>|]', '_'
    Save-CurrentProfile -Name $name
    $cmbProfiles.Items.Clear()
    $cmbProfiles.Items.AddRange(@(Get-ProfileNames))
    $cmbProfiles.SelectedItem = $name
    Add-LogLine "Saved profile '$name'."
})

$btnLoadProfile.Add_Click({
    if (-not $cmbProfiles.SelectedItem) { return }
    Import-Profile -Name $cmbProfiles.SelectedItem
    Add-LogLine "Loaded profile '$($cmbProfiles.SelectedItem)'."
})

$btnLoadHistory.Add_Click({
    if ($gridHistory.SelectedRows.Count -eq 0) { return }
    $idx = $gridHistory.SelectedRows[0].Index
    if ($idx -lt 0 -or $idx -ge $script:scanHistory.Count) { return }
    $entry = $script:scanHistory[$idx]
    $script:lastResults = @($entry.Results)
    Update-ResultsGrid -Results $script:lastResults
    $tabs.SelectedTab = $tabResults
    Add-LogLine "Loaded history entry from $($entry.Timestamp) into Results."
})

$btnClearHistory.Add_Click({
    $confirm = [System.Windows.Forms.MessageBox]::Show("Clear all scan history?", "Confirm", 'YesNo', 'Question')
    if ($confirm -eq 'Yes') {
        $script:scanHistory = @()
        Update-HistoryGrid
        Save-HistoryToDisk
        Add-LogLine "History cleared."
    }
})

function Invoke-SysInfoRefresh {
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $specs = Get-SystemSpecs
        $gridSpecs.Rows.Clear()
        $gridSpecs.Rows.Add("Computer Name", $specs.ComputerName) | Out-Null
        $gridSpecs.Rows.Add("Manufacturer / Model", "$($specs.Manufacturer) $($specs.Model)") | Out-Null
        $gridSpecs.Rows.Add("Operating System", $specs.OS) | Out-Null
        $gridSpecs.Rows.Add("OS Version", $specs.OSVersion) | Out-Null
        $gridSpecs.Rows.Add("Uptime", $specs.Uptime) | Out-Null
        $gridSpecs.Rows.Add("CPU", $specs.CPU) | Out-Null
        $gridSpecs.Rows.Add("Cores / Logical", "$($specs.Cores) / $($specs.LogicalProcs)") | Out-Null
        $gridSpecs.Rows.Add("RAM Total", "$($specs.RAMTotalGB) GB") | Out-Null
        $gridSpecs.Rows.Add("GPU(s)", $specs.GPUs) | Out-Null
        $gridSpecs.Rows.Add("Motherboard", $specs.Motherboard) | Out-Null
        $gridSpecs.Rows.Add("BIOS", "$($specs.BIOSVersion) ($($specs.BIOSDate))") | Out-Null

        $disks = Get-DiskInfo
        $gridVolumes.Rows.Clear()
        foreach ($v in $disks.Volumes) { $gridVolumes.Rows.Add($v.Drive, $v.Label, $v.FileSystem, $v.TotalGB, $v.FreeGB, $v.PercentFree) | Out-Null }
        $gridPhysicalDisks.Rows.Clear()
        foreach ($d in $disks.PhysicalDisks) { $gridPhysicalDisks.Rows.Add($d.FriendlyName, $d.MediaType, $d.SizeGB, $d.HealthStatus, $d.OperationalStatus) | Out-Null }

        Add-LogLine "System info refreshed."
    } catch {
        Add-LogLine "ERROR refreshing system info: $($_.Exception.Message)"
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

function Invoke-PerfRefresh {
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $perf = Get-PerformanceSnapshot
        $lblPerfSummary.Text = "CPU: $($perf.CpuLoadPercent)%   Memory: $($perf.MemUsedMB) / $($perf.MemTotalMB) MB ($($perf.MemPercentUsed)%)"
        $gridTopMem.Rows.Clear()
        foreach ($p in $perf.TopByMemory) { $gridTopMem.Rows.Add($p.Name, $p.Id, $p.MemoryMB, $p.CpuSeconds) | Out-Null }
        $gridTopCpu.Rows.Clear()
        foreach ($p in $perf.TopByCpu) { $gridTopCpu.Rows.Add($p.Name, $p.Id, $p.MemoryMB, $p.CpuSeconds) | Out-Null }
        $gridStartup.Rows.Clear()
        foreach ($s in $perf.StartupItems) { $gridStartup.Rows.Add($s.Name, $s.Command, $s.Location, $s.User) | Out-Null }
    } catch {
        Add-LogLine "ERROR refreshing performance: $($_.Exception.Message)"
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

function Invoke-SecurityRefresh {
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $sec = Get-SecurityStatus
        $gridDefender.Rows.Clear()
        if ($sec.Defender) {
            $gridDefender.Rows.Add("Antivirus Enabled", $sec.Defender.AntivirusEnabled) | Out-Null
            $gridDefender.Rows.Add("Real-Time Protection", $sec.Defender.RealTimeProtection) | Out-Null
            $gridDefender.Rows.Add("Signatures Last Updated", $sec.Defender.SignatureLastUpdated) | Out-Null
        } else {
            $gridDefender.Rows.Add("Status", "Unavailable (Defender may be off or a third-party AV is active)") | Out-Null
        }
        $gridFirewall.Rows.Clear()
        foreach ($f in $sec.Firewall) { $gridFirewall.Rows.Add($f.Profile, $f.Enabled) | Out-Null }
        $gridBitlocker.Rows.Clear()
        foreach ($b in $sec.BitLocker) { $gridBitlocker.Rows.Add($b.MountPoint, $b.VolumeStatus, $b.ProtectionStatus) | Out-Null }
        $gridUpdates.Rows.Clear()
        foreach ($u in $sec.RecentUpdates) { $gridUpdates.Rows.Add($u.HotFixID, $u.Description, $u.InstalledOn) | Out-Null }
        Add-LogLine "Security status refreshed."
    } catch {
        Add-LogLine "ERROR refreshing security status: $($_.Exception.Message)"
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

$btnRefreshSysInfo.Add_Click({ Invoke-SysInfoRefresh })
$btnRefreshPerf.Add_Click({ Invoke-PerfRefresh })
$btnRefreshSecurity.Add_Click({ Invoke-SecurityRefresh })

$chkAutoRefreshPerf.Add_CheckedChanged({
    if ($chkAutoRefreshPerf.Checked) { $perfAutoTimer.Start() } else { $perfAutoTimer.Stop() }
})
$perfAutoTimer.Add_Tick({ Invoke-PerfRefresh })

$btnRefreshNetDiag.Add_Click({
    $btnRefreshNetDiag.Enabled = $false
    $script:netDiagSync.Status = "Starting network diagnostics..."
    $script:netDiagPsInstance = [powershell]::Create()
    [void]$script:netDiagPsInstance.AddScript($netDiagScriptBlock)
    [void]$script:netDiagPsInstance.AddArgument($sysInfoCorePath)
    [void]$script:netDiagPsInstance.AddArgument($script:netDiagSync)
    $script:netDiagAsyncHandle = $script:netDiagPsInstance.BeginInvoke()
    $netDiagTimer.Start()
    Add-LogLine "Network diagnostics started."
})

$btnRefreshEvents.Add_Click({
    $btnRefreshEvents.Enabled = $false
    $script:eventsSync.Status = "Starting event log query..."
    $script:eventsPsInstance = [powershell]::Create()
    [void]$script:eventsPsInstance.AddScript($eventsScriptBlock)
    [void]$script:eventsPsInstance.AddArgument($sysInfoCorePath)
    [void]$script:eventsPsInstance.AddArgument([int]$numEventsMax.Value)
    [void]$script:eventsPsInstance.AddArgument([int]$numEventsDays.Value)
    [void]$script:eventsPsInstance.AddArgument($script:eventsSync)
    $script:eventsAsyncHandle = $script:eventsPsInstance.BeginInvoke()
    $eventsTimer.Start()
    Add-LogLine "Event log query started."
})

$cmbTheme.Add_SelectedIndexChanged({
    $dark = ($cmbTheme.SelectedIndex -eq 1)
    Set-ControlTheme -Control $form -Dark $dark
    $statusLabel.ForeColor = if ($dark) { [System.Drawing.Color]::Gainsboro } else { [System.Drawing.SystemColors]::ControlText }
    $lblTitle.ForeColor = $accentColor
    if ($dark) {
        $gridContextMenu.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
        $gridContextMenu.ForeColor = [System.Drawing.Color]::Gainsboro
    } else {
        $gridContextMenu.BackColor = [System.Drawing.SystemColors]::Menu
        $gridContextMenu.ForeColor = [System.Drawing.SystemColors]::MenuText
    }
})

$form.Add_Shown({
    try { $txtTarget.Text = Get-LocalSubnetCidr } catch {}
    $cmbProfiles.Items.AddRange(@(Get-ProfileNames))
    Update-HistoryGrid
    Invoke-SysInfoRefresh
    Invoke-PerfRefresh
    Invoke-SecurityRefresh
    Add-LogLine "Ready."
})

$form.Add_FormClosing({
    $script:sync.Cancel = $true
    if ($script:psInstance) { try { $script:psInstance.Stop() } catch {} }
    $script:vulnSync.Cancel = $true
    if ($script:vulnPsInstance) { try { $script:vulnPsInstance.Stop() } catch {} }
    $script:netDiagSync.Cancel = $true
    if ($script:netDiagPsInstance) { try { $script:netDiagPsInstance.Stop() } catch {} }
    $script:eventsSync.Cancel = $true
    if ($script:eventsPsInstance) { try { $script:eventsPsInstance.Stop() } catch {} }
    $perfAutoTimer.Stop()
})

[System.Windows.Forms.Application]::EnableVisualStyles()
[void]$form.ShowDialog()
