# ============================================================
#  Parse-LogFile.ps1
#  Windows Log Parser - Outputs structured JSON to terminal
# ============================================================

#region -------- Helper Functions --------

function Get-LogType
{
  param([string]$FilePath)

  $name = [System.IO.Path]::GetFileName($FilePath).ToLower()

  switch -Wildcard ($name)
  {
    "system"
    { return "WindowsEventLog" 
    }
    "application"
    { return "WindowsEventLog" 
    }
    "security"
    { return "WindowsEventLog" 
    }
    "*.evtx"
    { return "WindowsEventLog" 
    }
    "iis*.log"
    { return "IIS" 
    }
    "u_ex*.log"
    { return "IIS" 
    }
    "*.log"
    { return "Generic" 
    }
    "*.txt"
    { return "Generic" 
    }
    default
    { return "Generic" 
    }
  }
}

# ---------- Windows Event Log (.evtx) ----------
function Parse-EvtxLog
{
  param([string]$FilePath)

  Write-Host "[*] Detected Windows Event Log (.evtx). Reading events..." -ForegroundColor Cyan

  $entries = @()

  try
  {
    $events = Get-WinEvent -Path $FilePath -ErrorAction Stop
    foreach ($e in $events)
    {
      $entries += [PSCustomObject]@{
        TimeCreated  = $e.TimeCreated.ToString("o")
        Id           = $e.Id
        Level        = $e.LevelDisplayName
        ProviderName = $e.ProviderName
        MachineName  = $e.MachineName
        Message      = ($e.Message -replace "\r?\n", " ").Trim()
      }
    }
  } catch
  {
    Write-Warning "Could not read EVTX file: $_"
  }

  return $entries
}

# ---------- IIS W3C Log ----------
function Parse-IISLog
{
  param([string]$FilePath)

  Write-Host "[*] Detected IIS / W3C log. Parsing..." -ForegroundColor Cyan

  $entries  = @()
  $headers  = @()
  $rawLines = Get-Content -Path $FilePath -ErrorAction Stop

  foreach ($line in $rawLines)
  {
    if ($line -match "^#Fields:\s+(.+)")
    {
      $headers = $Matches[1] -split "\s+"
      continue
    }
    if ($line.StartsWith("#"))
    { continue 
    }   # skip other comment lines
    if (-not $headers)
    { continue 
    }   # no header yet

    $parts = $line -split "\s+"
    if ($parts.Count -ne $headers.Count)
    { continue 
    }

    $obj = [ordered]@{}
    for ($i = 0; $i -lt $headers.Count; $i++)
    {
      $obj[$headers[$i]] = $parts[$i]
    }
    $entries += [PSCustomObject]$obj
  }

  return $entries
}

# ---------- Generic / Plain-text Log ----------
function Parse-GenericLog
{
  param([string]$FilePath)

  Write-Host "[*] Parsing as generic log file..." -ForegroundColor Cyan

  $entries  = @()
  $rawLines = Get-Content -Path $FilePath -ErrorAction Stop
  $lineNum  = 0

  # Common timestamp patterns
  $tsPatterns = @(
    # 2024-01-15 12:30:45  or  2024-01-15T12:30:45
    '(?<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)',
    # Jan 15 12:30:45
    '(?<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
    # 15/Jan/2024:12:30:45 +0000  (Apache combined)
    '(?<ts>\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})'
  )

  # Common severity keywords
  $severityPattern = '\b(?<sev>EMERGENCY|ALERT|CRITICAL|CRIT|ERROR|ERR|WARNING|WARN|NOTICE|INFO|DEBUG|TRACE|FATAL|VERBOSE)\b'

  foreach ($line in $rawLines)
  {
    $lineNum++
    if ([string]::IsNullOrWhiteSpace($line))
    { continue 
    }

    $timestamp = $null
    foreach ($pat in $tsPatterns)
    {
      if ($line -match $pat)
      {
        $timestamp = $Matches["ts"]
        break
      }
    }

    $severity = $null
    if ($line -match $severityPattern)
    {
      $severity = $Matches["sev"]
    }

    $entries += [PSCustomObject]@{
      LineNumber = $lineNum
      Timestamp  = $timestamp
      Severity   = $severity
      RawMessage = $line.Trim()
    }
  }

  return $entries
}

#endregion

#region -------- Main Script --------

Clear-Host
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "   Windows Log Parser  |  JSON Output" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

# ----- Prompt for file path -----
do
{
  $inputPath = Read-Host "Enter the file you would like to parse (relative or full path)"
  $inputPath = $inputPath.Trim('"').Trim("'")   # strip accidental quotes

  # Resolve relative paths
  $resolvedPath = $inputPath
  if (-not [System.IO.Path]::IsPathRooted($inputPath))
  {
    $resolvedPath = Join-Path (Get-Location) $inputPath
  }

  if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf))
  {
    Write-Warning "File not found: '$resolvedPath'. Please try again."
    $fileFound = $false
  } else
  {
    $fileFound = $true
  }
} while (-not $fileFound)

Write-Host ""
Write-Host "[+] File found: $resolvedPath" -ForegroundColor Green

# ----- Determine log type & parse -----
$logType = Get-LogType -FilePath $resolvedPath
$entries = @()

switch ($logType)
{
  "WindowsEventLog"
  { $entries = Parse-EvtxLog    -FilePath $resolvedPath 
  }
  "IIS"
  { $entries = Parse-IISLog      -FilePath $resolvedPath 
  }
  default
  { $entries = Parse-GenericLog  -FilePath $resolvedPath 
  }
}

# ----- Build output object -----
$output = [ordered]@{
  ParsedAt   = (Get-Date).ToString("o")
  FilePath   = $resolvedPath
  LogType    = $logType
  TotalLines = $entries.Count
  Entries    = $entries
}

# ----- Output JSON to terminal -----
Write-Host ""
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "   JSON Output" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

$output | ConvertTo-Json -Depth 10

Write-Host ""
Write-Host "[+] Done. $($entries.Count) entries parsed from '$([System.IO.Path]::GetFileName($resolvedPath))'." -ForegroundColor Green

#endregion


