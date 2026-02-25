<#
.SYNOPSIS
    Scans local drives for file changes within specified time window. Optimized for speed using multithreading.

.DESCRIPTION
    High-performance drive scanner designed to detect file modifications for troubleshooting, 
    malware detection, crash recovery, and change analysis. Supports precise time windows 
    (hours with decimals), file type filtering, size filtering, and directory exclusions.
    
    Use cases:
    - Find recently saved/missing/copied files
    - Detect system changes causing problems  
    - Identify virus/rogue program modifications
    - Locate autosave/temp files after crashes
    - Analyze app installation changes

    Lists of directories to filter out in both the scan and the copy operation can be provided in a .txt file 
    with one directory listed per line. Use trailling '\' for exact match or omit this for part match.

.PARAMETER SingleThreaded
    Y = Run in single thread (debugging). Auto-prompts if debugger detected. Default: Y (debugger) / N (normal)

.PARAMETER ModDefault
    Y = Modifies defaults rather than passing values. Default: N

.PARAMETER CleanTempFiles
    Y = Run windows cleanmgr before scan. Default: N

.PARAMETER HoursToCheck
    Hours to look back for changes. Negative = since X hours ago (-3 = last 3hrs).
    Positive = up to X hours ago (3 = changed before 3hrs ago). 
    Supports decimals (-0.1 = last 6 minutes). Default: -3

.PARAMETER WhichDrive
    A specific drive e.g. C or ALL drives. Default: ALL

.PARAMETER CheckFor
    File types: ALL | IMG (images) | EXT (prompts for extension) | EXE (executables). Default: ALL

.PARAMETER CheckForExt
    Specific extension (no dot) when CheckFor=EXT. Default: EXE

.PARAMETER CheckHidden
    Y = Attempt to scan hidden files. Default: N

.PARAMETER CheckForSizeMin
    Minimum file size (bytes). Default: 0 (all files)

.PARAMETER CheckForSizeMax
    Maximum file size (bytes). -1 = no limit. Default: -1

.PARAMETER FilterApp
    Y = Apply directory exclusion filter during scan. Default: N

.PARAMETER ScanFilterfn
    Text file with one directory path per line to exclude from scan (when FilterApp=Y)

.PARAMETER ShowDirCounts
    Directory roll-up totals. 0=off, otherwise depth level. Default: 4

.PARAMETER ShowHighlights
    Y = List key changed files (EXE/IMG). Default: Y

.PARAMETER CopyHighlights
    Y = Copy highlighted files to Downloads temp folder. Default: N

.PARAMETER HighlightFilter
    Y = Apply exclusion filter to highlighted files. Default: N

.PARAMETER HighlightFilterfn
    Text file with directories to exclude from highlight copy (when HighlightFilter=Y)

.PARAMETER CopyMetaInfo
    Y = Create JSON metadata file for copied highlights. Default: N

.PARAMETER CopyReportErrors
    Y = Log highlight copy errors to results. Default: N

.PARAMETER FilterZeroLenFiles
    Y = Exclude zero-byte files from results. Default: Y

.INPUTS
    Drive(s) and how for back from now to look or hours since now to start looking from, 
    filtering options, if highlighted files should be copied.

.OUTPUTS
    Result file stored in a created directory with name sfc-<date>-<time> in the downloads 
    directory. If copy highlighted files enabled, files also copied into this directory.

.EXAMPLE
    Get-Help scanforchangeshours_fv2.ps1 -Full
    # Show complete help

.EXAMPLE
    scanforchangeshours_fv2.ps1 -ModDefault Y -CheckFor EXE 
    # run with prompting but change one of the defaults

.EXAMPLE
    scanforchangeshours_fv2.ps1 -CleanTempFiles N -HoursToCheck -3 -WhichDrive ALL -CheckFor ALL -CheckHidden Y -CheckForSizeMin 0 -CheckForSizeMax -1 -FilterApp N -ShowDirCounts 0 -ShowHighlights Y -HighlightFilter N -CopyHighlights N -CopyMetaInfo N -CopyReportErrors N -FilterZeroLenFiles Y
    # find all files changed in last 3 hours (no highlited files, no directory roll up counts). Will run without any prompting.

.LINK
    https://github.com/tridashafox/findchangedfiles.git

.NOTES
    Version: 1.1.0
    GitHub: https://github.com/tridashafox/findchangedfiles.git
    Tested: PowerShell 5.1.26100.4652
#>

# TODO
# BUG: fix hang in powershell 7.x
# FMR: use the drive being scanned to filter out patterns not applicible in the buildfilter function
# FMR: move extension lists into function near buildfilters
# FMR: allow a directory to be scanned rather than just a drive
# FMR: full review and code cleanup
# FMR: consider adding result analysis tools
# FMR: add in a built in canary test to ensure finding files and working
# FMR: add functional tests

param (
    [string]$SingleThreaded,       # Y means run process in single thread, useful for debugging. Only prompted for if debugger detected and not specified. Defaults to Y if debugger otherwise N
    [string]$ModDefault,           # Y means the below changes the default rather than passes the value, default is N
    [string]$CleanTempFiles,       # Y if want to run windows cleanmgr before running scan, default is N
    [double]$HoursToCheck,         # Number of hours to look back for changes, default is -3, note this can have a decimal point e.g. -0.5 (last half-hour). If postive looks for changed files before specified hours.
    [string]$WhichDrive,           # Which drive to scan, or all drives, default is ALL
    [string]$CheckFor,             # Which types of files to check for, can be  is ALL, IMG (anything at is an Image), EXT (askes for an CheckForExt), EXE (anything that executes), default is ALL
    [string]$CheckForExt,          # A specific extension to scan for (don't include the '.' before the extension), default EXE. Ignored unless CheckFor is EXT
    [string]$CheckHidden,          # Y if want to try to scan hidden files, default is N
    [int]$CheckForSizeMin,         # Include files above this min size, default is 0 (all files)
    [int]$CheckForSizeMax,         # Include files blow this max size, default is -1 (all files)
    [string]$FilterApp,            # Y means apply filter to the scan to not report on specific directories.
    [string]$ScanFilterfn,         # Name of a file which contains a list of directories which should not be checked for changes if FilterApp is Y
    [int]$ShowDirCounts,           # Shows a roll up total of found items by directory. 0 - don't show, otherwise depth to use for roll up, default is 4
    [string]$ShowHighlights,       # Look for key file types that changed and list them out, default is Y
    [string]$CopyHighlights,       # Copy files found by ShowHighlights to a temp directory in downloads, default is N
    [string]$HighlightFilter,      # Y means apply filter to the highlighted files from specific directories.
    [string]$HighlightFilterfn,    # Name of a file which contains a list of directories from which highlighted files excluded
    [string]$CopyMetaInfo,         # Create a json file with info about for each file found by ShowHighlights, default is N
    [string]$CopyReportErrors,     # Report errors during the ShowHighlights operation into the results file, default is N
    [string]$FilterZeroLenFiles    # Filter out zero length files from the result, default is Y
)

########################################################################
# makes sure no keys pending to be processed
#
function clearpressedkeys() {
    while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }
}

########################################################################
# display prompt before exiting, this never returns
#
function waitbeforeexit() {
    clearpressedkeys
    read-host "Press ENTER to continue"
    exit 1
}

########################################################################
# check if running under debugger, returns string "none" if no debugger
#
function checkfordebugger() {
    $isdebugger = "none"
    if ($env:TERM_PROGRAM -eq 'vscode') { $isdebugger = "Running in VS Code integrated console" } 
    elseif ($PSDebugContext) { $isdebugger = "Running in powershell debugger" } 
    return $isdebugger
}

########################################################################
# reports on on enviroment specifics for debugging
#
function Show-EnvironmentCheck {
    Write-Host "Checking All drives... (fast method v2)"
    Write-Host "`n===== ENVIRONMENT CHECK ====="
    Write-Host "Username:                 $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Host "Admin rights:             $(([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    Write-Host "PowerShell Version:       $($PSVersionTable.PSVersion)"
    Write-Host "PowerShell Edition:       $($PSVersionTable.PSEdition)"
    Write-Host "PowerShell Binary         $(Get-Process -Id $PID | Select-Object -ExpandProperty Path)"
    Write-Host "64-bit Process:           $([Environment]::Is64BitProcess)"
    Write-Host "Process Executable:       $([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)"
    Write-Host "Working Directory:        $(Get-Location)"
    Write-Host "Current Culture:          $([System.Globalization.CultureInfo]::CurrentCulture.Name)"
    Write-Host "Execution Policy:         $(Get-ExecutionPolicy -Scope Process)"
    Write-Host "ErrorActionPreference:    $ErrorActionPreference"
    Write-Host "TEMP:                     $env:TEMP"
    Write-Host "TMP:                      $env:TMP"
    Write-Host "Temp Path (System API):   $([System.IO.Path]::GetTempPath())"
    Write-Host "Debugger present:         $(checkfordebugger)"
    Write-Host "===============================`n"
}

########################################################################
# print out timings (used for debugging)
#
function showscanduration {
    param (
        [pscustomobject]$Result
    )

    if ($Result -is [pscustomobject]) {
        $duration = $Result.EndT - $Result.StartT
        #$middur = $Result.MidT - $Result.StartT
        #Write-Host $middur, $duration, $Result.Path
        $durStr = $duration.TotalSeconds.ToString("N3")
        "Time taken: $($Result.Path) $durStr"
    }
}

########################################################################
# create a place to put the result output file and any highlighted files
#
function createoutputdir {
    $destinationFolder = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    if (Test-Path -Path $destinationFolder -PathType Container) {
        $tempFolderName = "sfc-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff")  # do not change "sfc-"
        $tempFolderPath = Join-Path $destinationFolder $tempFolderName
        $resfldpath = $tempFolderPath
        New-Item -ItemType Directory -Path $resfldpath | Out-Null
        return $resfldpath
    }
}

########################################################################
# remove junk transript log adds at start and end and add to output file
#
function addtranslogtoutput {
    param (
        [Parameter(Mandatory = $true)] [string]$TransLog,
        [Parameter(Mandatory = $true)] [string]$OutputFile
    )

    # Trim last 4 lines of transcript
    (Get-Content $TransLog | Select-Object -SkipLast 4) | Set-Content $TransLog

    # Filter from first [INFO] line onward
    $lines = [System.Collections.Generic.List[string]](Get-Content $TransLog)
    $startIndex = $lines.FindIndex({ param($line) $line -match '\[INFO\]' })
    if ($startIndex -ge 0) {
        $lines.GetRange($startIndex, $lines.Count - $startIndex) | Set-Content $TransLog
    }

    # Merge transcript + output
    $transContent  = Get-Content -Path $TransLog

    # clean out VScode debugger noise which can appear when it tries to get vars for the var/watch window
    if ($IsDebug) {
        $transContent = $transContent | Where-Object { $_ -notmatch "^\(base\)|^>>" }
    }

    $outputContent = Get-Content -Path $OutputFile
    $combined      = $transContent + @("") + $outputContent
    $combined | Set-Content -Path $OutputFile
}

########################################################################
# moves the output result file to the output directory
#
function relocateoutput {
    param (
        [string]$OutputFile,
        [string]$resfldpath,
        [string]$fndirsep = "--"
    )

    # clean up any extra blank lines jfthoi
    (Get-Content $OutputFile | ForEach-Object { $_.Trim() }) -join "`r`n" -replace "(`r?`n){2,}", "`r`n`r`n" | Set-Content $OutputFile

    $originalName = Split-Path -Path $OutputFile -Leaf
    $newFileName = "{0:D8}{1}{2}" -f 0, $fndirsep, $originalName
    $newPath = Join-Path -Path $resfldpath -ChildPath $newFileName
    Move-Item -LiteralPath $OutputFile -Destination $newPath -Force
    Write-Host "Result placed in $newPath."
}

########################################################################
# create a has for a directory path
#
function getpathash {
    param([string]$Path)
    
    # Get relative depth and name
    $parts = $Path -split '[\\/]' | Where-Object {$_}
    $depth = $parts.Count
    $name = $parts[-1].Substring(0, [Math]::Min(8, $parts[-1].Length))
    
    # Simple hash of name + depth
    $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($name)
    $hash = 0
    foreach ($b in $hashBytes) { $hash = ($hash * 31) + $b }

    # Cast to int before formatting
    $suffix = ([int]($hash % 1000000)).ToString('D6')
    return "{0:D2}{1}" -f $depth, $suffix
}

########################################################################
# handle Y/N questions
#
function getYNinput {
    param (
        $ModDefault,    # don't type as string, we need to know if it is $null, if it's typed it will end up ""
        $InitValue,     # don't type as string
        [string]$Name,
        [string]$Prompt,
        [string]$Default = 'N'
    )

    if (!$InitValue -or $ModDefault) {
        if ($ModDefault -and $InitValue) { $Default = $InitValue } else { $Default = $Default.ToUpper().Trim() }
        if ($Default -ne "Y" -and $Default -ne "N") { $Default = "N" }
        $question = $Prompt + " (Y/N): [default " + $Default + "]"
        while ($true) {
            $response = (Read-Host $question).ToUpper().Trim()
            if (-not $response) { return $Default }
            if ($response -eq 'Y' -or $response -eq 'N') { return $response } 
            Write-Host "Invalid option. Enter Y or N" -ForegroundColor Red 
        }
    } elseif ($InitValue -eq 'Y' -or $InitValue -eq 'N') { return $InitValue }

    Write-Host "Invalid option for $Name. Must be Y or N" -ForegroundColor Red 
    waitbeforeexit
}

########################################################################
# handle filename questions
#
function getFNinput {
    param (
        [string]$fnin,
        $ModDefault,
        [string]$prtmsg
    )

    if ($fnin.Length -eq 0 -or $ModDefault) {
        if ($ModDefault -and $fnin.Length -gt 0) { $defval = $fnin.ToLower() } else { $defval = 'none' }
        while ($true) {
            $prtmsg += ": [default $defval]"
            $fnin = (Read-Host $prtmsg).ToLower().Trim()
            if ([string]::IsNullOrEmpty($fnin) -and $defval -eq 'none') { Write-Host "No file provided." -ForegroundColor Red; continue }
            if ([string]::IsNullOrEmpty($fnin)) { $fnin = $defval }
            if (Test-Path -Path $fnin -PathType Leaf) { break } else { Write-Host "File not found." -ForegroundColor Red; continue  }
        }
    }
    return $fnin
}


########################################################################
# Parse results file and display a summary of file counts in directories
# NOTE will fail if any of the formating of the output is changed
#
function getdirfilecounts {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Filename,
        [int]$Depth
    )
    
    $MaxDepth = $Depth + 1

    $drivePattern = '\b([a-zA-Z]):\\'
    $dirCounts = @{}
    $stopProcessing = $false

    Get-Content $Filename | ForEach-Object {
        $line = $_
        
        # Stop processing once "Highlights -" section starts
        if ($line.TrimStart().StartsWith("Highlights -")) {
            $stopProcessing = $true
            return
        }
        
        if ($stopProcessing) {
            return
        }

        # Skip excluded lines
        if ($line.Trim().StartsWith("Time taken:") -or
            $line.ToLower().Contains("highlighted") -or
            $line.Contains("number of modified")) {
            return
        }
        
        # Find drive letter pattern and trim everything before it
        if ($line -match $drivePattern) {
            $fullMatch = $matches[0]
            $drivePos = $line.IndexOf($fullMatch)
            $trimmedPath = $line.Substring($drivePos).Trim()
            
            # Get directory path only (no filename)
            $dirPath = Split-Path $trimmedPath -Parent
            
            # Split directory into levels and take first N levels
            $pathParts = $dirPath -split '\\' | Where-Object { $_ }
            $shortPath = if ($pathParts.Count -le $MaxDepth) { 
                $dirPath 
            } else { 
                ($pathParts[0..($MaxDepth-1)] -join '\') 
            }
            
            if (-not $dirCounts.ContainsKey($shortPath)) {
                $dirCounts[$shortPath] = 0
            }
            $dirCounts[$shortPath]++
        }
    }

    $dirCounts.GetEnumerator() | Sort-Object Name | ForEach-Object {
        $count = $_.Value
        $directory = $_.Name
        $countStr = $count.ToString("D5")  # D6 = 6 digits, right-aligned with spaces
        Write-Output "$countStr  $directory"
    }
}

########################################################################
# wait for jobs to complete with progress dots
#
function watchjobprogress {
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$jobs
    )

    $jobcnt = $jobs.Where({ $_.State -eq 'Running' }).Count
    $oldjobcnt = 0

    # Write does not output to transcript log
    # Transcript logs can't handle Write-Host "." -NoNewline
    # We don't want this in the log anway so use the .net framework Write
    [Console]::Write("Processing scan in $jobcnt parallel jobs:")  

    while ($jobcnt -gt 0) {
        if ($oldjobcnt -ne $jobcnt) {
            [Console]::WriteLine("") 
            [Console]::Write("Jobs remaining $jobcnt.")
            $oldjobcnt = $jobcnt
        }
        [Console]::Write(".")
        $delay = 800 + (Get-Random -Minimum -200 -Maximum 201)
        Start-Sleep -Milliseconds $delay
        $jobcnt = $jobs.Where({ $_.State -eq 'Running' }).Count
    }

    [Console]::WriteLine("done.")
}

########################################################################
# scans a drive for files changed since x hours ago applies filters puts 
# result to two output files, returns a timing result object
# *breakpoints won't work here since called from seperate thread, for workaround see DBGNOTE
#
function doScanfor { 
    param (
        [string]$drive,
        [string]$outfile,
        [string]$hrdir,
        [DateTime]$hago,
        [string]$dofilter,
        [string]$filterpatstr,
        [string]$exttochk,
        [string]$exttochkact,
        [string]$unfall,
        [int]$minSize,   # Minimum file size in bytes
        [int]$maxSize,    # Maximum file size in bytes
        [string]$checkforcehidden,
        [bool]$brootonly
    )

    $startTime = Get-Date
    $drivefull = $drive
    $wildc = ''

    # set up the extensions to look for if looking for images or executables.
    if ( $exttochk -ieq 'IMG' ) { $wildc = "*.BMP", "*.GIF", "*.JPG", "*.JPEG", "*.PNG", "*.TIF", "*.TIFF", "*.ICO" , "*.DDS", "*.MP4", "*.MOV", "*.WebM", "*.AVI", "*.WMV", "*.Webm", "*.Webp", "*.afphoto", "*.psd", "*.pic" } 
    if ( $exttochk -ieq 'EXT' ) { $wildc = "*." + $exttochkact }
    if ( $exttochk -ieq 'EXE' ) { $wildc = "*.BAT", "*.PS1", "*.BIN", "*.CMD", "*.COM", "*.CPL", "*.EXE", "*.GADGET", "*.INF1", "*.INS",`
         "*.INX", "*.ISU", "*.JOB", "*.JSE", "*.LNK", "*.MSC", "*.MSI", "*.MSP", "*.MST", "*.PAF", "*.PIF", "*.PS1", "*.REG", "*.RGS", `
         "*.SCR", "*.SCT", "*.SHB", "*.SHS", "*.U3P", "*.VB", "*.VBE", "*.VBS", "*.VBSCRIPT", "*.WS", "*.WSF", "*.WSH" }

    # filter out the output file from the result
    $filterpatstr += $outfile.Replace("\", "\\")

    # Do the Scan
    # Build dynamic Get-ChildItem parameters
    $gciParams = @{
        Path        = $drivefull
        File        = $true
        ErrorAction = 'SilentlyContinue'
    }

    # Only add the -Force flag if requested, slows performance by x3 in worst cases
    if ($checkforcehidden -eq 'Y') {
        $gciParams['Force'] = $true
    }

    # Only add the -Recurse flag if $brootonly is not true
    if (-not $brootonly) {
        $gciParams['Recurse'] = $true
    }

    # Base filter
    $hx = ($hrdir -eq "after") 
    if ($hx) { $timeFilter = { $_.LastWriteTime -gt $hago -and $_.Length -ge $minSize } }
    else     { $timeFilter = { $_.LastWriteTime -lt $hago -and $_.Length -ge $minSize } }

    # Add size limit if maxSize is specified
    if ($maxSize -ne -1) {
         if ( $hx) { $timeFilter = { $_.LastWriteTime -gt $hago -and $_.Length -ge $minSize -and $_.Length -le $maxSize } }
         else      { $timeFilter = { $_.LastWriteTime -lt $hago -and $_.Length -ge $minSize -and $_.Length -le $maxSize } }
    }

    if ($wildc -ne '') {
        $gciParams['Include'] = $wildc
    }
        
    # Do the scan, and apply filter, filter will just contain output file if not set to 'Y' to include
    Get-ChildItem @gciParams | Where-Object $timeFilter | Format-Table LastWriteTime, Length, FullName -AutoSize | Out-String -Width 2048 | Set-Content -Encoding UTF8 $unfall
    Get-Content $unfall | Select-String -Pattern $filterpatstr -NotMatch | Set-Content -Encoding UTF8 $outfile 

    $midTime = Get-Date

    # clean up output file by only including lines that start with a date so can correcly count number found
    $inputString = Get-Content $outfile -Raw
    $filteredLines = $inputString -split [Environment]::NewLine | Where-Object { $_ -match '^\w\w/\w\w/\w{4}' }

    if ($filteredLines.Count -gt 0) {  # if it's empty then don't tag on the lines and an extra newline, just add the title for the drive
        $filteredString = $filteredLines -join [Environment]::NewLine
        $filteredString = "Drive " + $drivefull + [Environment]::NewLine + $filteredString 
    }
    else { $filteredString = "Drive " + $drivefull}

    $filteredString | Set-Content $outfile

    # Output timing info
    [pscustomobject]@{
        Path = $drivefull
        StartT = $startTime
        MidT = $midTime
        EndT  = Get-Date 
    }
}

########################################################################
# create a filter pattern string to be used to filter out noisy files not of interest
#
function buildfilterpatern { 
    param (
        [string]$ExcludeFilelist,
        [string]$FilterZeroLenfn 
    )

    $textfilterpat = ""
    $patsp = "|" 
    if (-not [string]::IsNullOrEmpty($ExcludeFilelist) -and (Test-Path -Path $ExcludeFilelist -PathType Leaf)) {
        $textfilterpat = (
            Get-Content -Path $ExcludeFilelist | 
                Where-Object   { $_.Trim() -ne ''    } |   # Skip empty lines
                ForEach-Object { $_.Trim()           } |   # Remove leading/trailing spaces
                ForEach-Object { [regex]::Escape($_) }     # Escape special chars
        ) -join $patsp

        if ($textfilterpat -eq $patsp) {  $textfilterpat = ""}
        elseif ($textfilterpat.Length -gt 0 -and $textfilterpat[-1] -ne $patsp) { $textfilterpat +=  $patsp } # add missing end of pat pipe
    }

    if ($textfilterpat.Count -eq 0 -or $textfilterpat.Length -eq 0) { Write-Host "[Warning] Filter file '$ExcludeFilelist' does not exist or contains no entries." -ForegroundColor Yellow}

    return $textfilterpat
}

########################################################################
# add to passed pattern filtering for zero lenght files 
#
function buildfilterpatZfn {
    param ( 
        $Filterpat 
    )

    $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { "$($_.DeviceID)" }
    foreach ($drive in $drives) { $Filterpat += "  0 " + $drive[0]+ ":\\|"}

    return $Filterpat
}

########################################################################
# create a filter string array of directory paths from passed file
#
function buildfilterarray { 
    param (
        [string]$ExcludeFilelist
    )

    $textfilterarr = @()
    if (-not [string]::IsNullOrEmpty($ExcludeFilelist) -and (Test-Path -Path $ExcludeFilelist -PathType Leaf)) {
        $textfilterarr = Get-Content -Path $ExcludeFilelist
    }

    if ($textfilterarr.Count -eq 0) { Write-Host "[Warning] Filter file '$ExcludeFilelist' does not exist or contains no entries." -ForegroundColor Yellow}

    <#
    # For DEBUGGING & - creates a scoped block
    &{
        # dump the filter txt to dowloads dir
        $dwdir = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
        $dboutfn = $dwdir + "\sfc_debug_filter.txt"
        $textfilterpat | Add-Content -Path $dboutfn
    } 
    #>
    
    return $textfilterarr
}

########################################################################
# output a roll up of directory counts
#
function showdircountsinfile {
    param (
        [string] $OutputFile,
        $ShowDirCounts  # 0 - don't show, otherwise the depth to use for rollup of sum
    )

    if ($ShowDirCounts -gt 0 -and (Test-Path $OutputFile)) {
        $TempSumDirCnt = New-TemporaryFile
        $tempcntoutput = getdirfilecounts -Filename $OutputFile -Depth $ShowDirCounts
        if ($tempcntoutput.Count -gt 0) {
            "`nSummary counts of directories:`n" | Out-File -FilePath $TempSumDirCnt -Encoding UTF8
            $tempcntoutput | Sort-Object | Out-File -FilePath $TempSumDirCnt -Append -Encoding UTF8
            "`n" | Out-File -FilePath $TempSumDirCnt -Append -Encoding UTF8
        }
        else { "`nNo files to summarize counts of directories.`n" | Out-File -FilePath $TempSumDirCnt -Encoding UTF8 }

        Get-Content $TempSumDirCnt | Out-File -FilePath $OutputFile -Append -Encoding UTF8
        Remove-Item $TempSumDirCnt
    }
}

########################################################################
# looks for files with specific extenions in unfiltered full list (unfall)  
# and adds results to passed output file (outfile)
#
function findfilestohighlight {
    param (
        [string]$outfile,
        [string]$unfall,
        [string]$copytodw,
        [string]$copyrpterr,
        [string]$resfolder,
        [string]$fnsep,
        [string]$CopyMetaInfo,
        [string]$HighlightFilter,
        [string]$HighlightFilterfn,
        $filterhlpat
        )

    # build up list of files from raw file list of all files
    $filteredfiles = Get-Content -Path $unfall | Where-Object { $ExtsToHilight -contains [System.IO.Path]::GetExtension($_.Trim().Split()[-1]) }
    $filteredfiles = $filteredfiles | Where-Object { $_ -notlike "*   0*" } # remove zero byte files

    # format as a table
    $filteredfiles = $filteredfiles | ForEach-Object {
        $parts = $_.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
        [PSCustomObject]@{
            "Date" = $parts[0]
            "Time" = $parts[1]
            "Length" = $parts[2]
            "FullName" = $parts[3..($parts.Length - 1)] -join ' '
        }
    } | Format-Table -AutoSize -HideTableHeaders | Out-String

    # remove any blank lines
    $lines = $filteredfiles -split [Environment]::NewLine
    $lines = $lines | Where-Object { $_ -ne '' }
    $filteredfiles = $lines -join [Environment]::NewLine

    # print on console number of found files
    $sizeoffnd = $filteredfiles | Measure-Object -Line | Select-Object -ExpandProperty Lines
    $strnfl = "Highlighted # modified or created files "
     if ($HighlightFilter -eq 'Y') { $strnfl += "(no filter) $sizeoffnd" } else { $strnfl += $sizeoffnd }
    Write-Host $strnfl

    # get filelist in good format 
    $filesToCopyraw = $filteredfiles -split [Environment]::NewLine
    $filesToCopyraw = $filesToCopyraw | ForEach-Object { $_.Trim() }

    # Sort by last modified (newest first)
    $filesToCopy = $filesToCopyraw |
        Where-Object { $_.Trim() -ne '' } |
        Sort-Object {
            # Parse date and time from the line: first 2 tokens
            $dateStr = ($_ -split '\s+')[0]
            $timeStr = ($_ -split '\s+')[1]
            # Combine and parse to datetime object
            [datetime]::ParseExact("$dateStr $timeStr", 'dd/MM/yyyy HH:mm:ss', $null)
        } -Descending 

    $filesToCopy = $filesToCopy | ForEach-Object { [string]$_ } ## make sure string array after sort

    # add title and put into output files if there is anything to report.
    if ($filesToCopy.Count -eq 0) {
        $filteredtitle = "No files to highlight found."
        Add-Content -Path $outfile -Value $filteredtitle -Encoding UTF8
    }
    else 
    {
        Add-Content -Path $outfile -Value ""
        if ($HighlightFilter -eq 'Y') { $filtrtxt = "(filtered)" } else { $filtrtxt = ""}
        # Don't change the start of this string it's used to locate the end of the scan when creating for the directory counts
        $filteredtitle += "Highlights - Key file types which changed $filtrtxt (exe,bat,pdf,jpg,png,gif,ico,docx,mp4,tiff,webp,afphoto,psd,pic):"
        Add-Content -Path $outfile -Value $filteredtitle -Encoding UTF8
        Add-Content -Path $outfile -Value ""

        # report on line but also check if filtered out
        $filterdLines = @()
        foreach ($line in $filesToCopy) {
            $filename = ($line -split ' ', 4)[-1]  # Split into 4 parts, take the last part
            $filename = $filename.Trim()
            $shouldSkip = $false
            foreach ($excludeDdg in $filterhlpat) { if ($filename.Length -ge $excludeDdg.Length -and $filename.Substring(0, $excludeDdg.Length) -ieq $excludeDdg) { $shouldSkip = $true; $skippedcnt++; break } }
            if (-not $shouldSkip) { $filterdLines += $line}
        }
        if ($HighlightFilter -eq 'Y') { Write-Host "Highlighted # modified or created files (after filter)" $filterdLines.Count }
        $filterdLines | Add-Content -Path $outfile -Encoding UTF8; 
    }

    if ($copytodw -ieq 'Y') {
        if ($resfolder.Length -gt 0) {
            $tempFolderPath = $resfolder
            $counterstart = 1 # start at 1 - zero is used for the log output
            $counter = $counterstart
            $countercpErr = 0
            $skippedcnt = 0
            foreach ($line in $filterdLines) {
                $filename = ($line -split ' ', 4)[-1]  # Split into 4 parts, take the last part
                $filename = $filename.Trim()

                if ($filename -ne '') {
                    if (Test-Path -LiteralPath $filename) {
                        try {
                            $partname = Get-Item -LiteralPath $filename -Force # -Force needed for files marked as hidden
                            $fullPathStr = $partname.FullName
                            $baseFileName = $partname.BaseName
                            $dirpathonly = $partname.Directory.FullName
                            $pathhash = getpathash -Path $dirpathonly
                        }
                        catch {
                            $countercpErr++
                            $baseFileName = ''
                            if ($copyrpterr -eq 'Y') {
                                $notfoundtocopyerror = $filename + " highlighted file could not be copied due failed to get item. "+ $filename + " Error: $_" 
                                Add-Content -Path $outfile -Value $notfoundtocopyerror -Encoding UTF8
                            }
                        }
                        if ($baseFileName -ne '') {
                            $newFileName = "{0}{2}{1:D8}{2}{3}" -f $pathhash, $counter, $fnsep, $partname.Name
                            $counter++
                            $shouldSkip = $false
                            
                            if (-not $shouldSkip) 
                            {
                                # copy the file
                                try {
                                    $newFileName = Join-Path $tempFolderPath $newFileName

                                    Copy-Item -LiteralPath $filename -Destination $newFileName -Force -ErrorAction SilentlyContinue
                                } 
                                catch [System.UnauthorizedAccessException] {
                                    $countercpErr++
                                    if ($copyrpterr -eq 'Y') {
                                        $notfoundtocopyerror = $filename + " highlighted file could not be copied due to System.UnauthorizedAccessException"
                                        Add-Content -Path $outfile -Value $notfoundtocopyerror -Encoding UTF8
                                    }
                                }
                                catch [System.IO.PathTooLongException] {
                                    $countercpErr++
                                    if ($copyrpterr -eq 'Y') {
                                        $notfoundtocopyerror = "$filename could not be copied due to PathTooLongException (exceeds MAX_PATH)"
                                        Add-Content -Path $outfile -Value $notfoundtocopyerror -Encoding UTF8
                                    }
                                }
                            }

                            # create the meta data file
                            if ($CopyMetaInfo -eq 'Y')
                            {
                                try {
                                    $srcfileInfo = Get-Item $filename
                                    $meta = [ordered]@{  # note the ordered specifier otherwise entries are come out random
                                        originalPath1     = $fullPathStr
                                        originalPath2     = $fullPathStr.Replace("\", "/")
                                        originalname      = Split-Path $srcfileInfo -Leaf
                                        dirpathhash       = $pathhash
                                        filesize          = "{0:N2} KB" -f ($srcfileInfo.Length / 1KB)
                                        lastwritetime     = $srcfileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                                        lastmodifed       = $((New-TimeSpan -Start $srcfileInfo.LastWriteTime).TotalMinutes).ToString("N2") + " mins"
                                        copiedOn          = (Get-Date).ToString("o")
                                    }
                                    $meta | ConvertTo-Json | Set-Content -Path "$newFileName.meta.json" -Encoding UTF8
                                } 
                                catch {
                                    $countercpErr++
                                    if ($copyrpterr -eq 'Y') {
                                        $notfoundtocopyerror = $filename + " highlighted file meta data could not be copied due to $($_.Exception.Message)"
                                        Add-Content -Path $outfile -Value $notfoundtocopyerror -Encoding UTF8
                                    }
                                }
                            }
                        }
                    }
                    else {
                        $countercpErr++
                        if ($copyrpterr -eq 'Y') {
                            $notfoundtocopyerror = $filename + " highlighted file could not be copied due no longer found on system"
                            Add-Content -Path $outfile -Value $notfoundtocopyerror -Encoding UTF8
                        }
                    }
                }
            }

            $nnewline = [Environment]::NewLine # only add a new line once
            if ($counter -gt $counterstart) { 
                $highlitecopyinfotext = $nnewline + $($counter - $counterstart) + " highlighted files were copied to " + $tempFolderPath 
                Add-Content -Path $outfile -Value $highlitecopyinfotext -Encoding UTF8
                $nnewline = ''
            }
            if ($countercpErr -gt 0) { 
                $highlitecopyinfotext =  $nnewline + $countercpErr + " highlighted files could not be copied to " + $tempFolderPath
                Add-Content -Path $outfile -Value $highlitecopyinfotext -Encoding UTF8
            }
            if ($skippedcnt -gt 0) {
                $highlitecopyinfotext =  $nnewline + $skippedcnt + " highlighted files were skipped in copy operation  to " + $tempFolderPath
                Add-Content -Path $outfile -Value $highlitecopyinfotext -Encoding UTF8
            }
        }
    }
}

########################################################################
# Shows counts and summary of output file on console and add the
# results to the accumlative output file 
#
function postprocess {
    param (
        [string]$infile,
        [string]$drivelet,
        [string]$namefilter,
        [string]$outfile
    )

    $lnsnum = 0

    if (Test-Path $infile) {
        # Read all lines as plain text, filter by name pattern
        $filteredLines = Get-Content -Encoding UTF8 $infile |
            Where-Object { $_ -notmatch $namefilter }

        $nonBlankLines = $filteredLines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $cleanedLines = $nonBlankLines | Where-Object { $_ -notmatch '^Drive\s+[A-Z]:\\' }
        $lnsnum = $cleanedLines.Count

        # Output results
        Add-Content -Path $outfile -Value ""           # Clear or separate output
        $cleanedLines | Add-Content -Path $outfile -Encoding UTF8

        $msg = $drivelet + ":\ number of modified or created files"
        Write-Host $msg $lnsnum
    }
}

########################################################################
# do the scan of  drive without threads
#
function Invoke-DriveScan {
    param (
        [Parameter(Mandatory=$true)][string[]]$Drives,
        [string]$hourdirection,
        [datetime]$hoursago,
        $FilterApp,
        $CheckFor,
        $CheckForExt,
        $TempUFAll,
        $CheckForSizeMin,
        $CheckForSizeMax,
        $CheckHidden,
        $ScanFilterfn, 
        [string]$OutputFile,
        $FilterPat
    )

    Write-Host "Scanning Drive(s)" $Drives "..."
    $durres = @()
    foreach ($drive in $Drives) {
        $TempFileX = New-TemporaryFile
        $result = doScanfor -drive $($drive[0] + ":\") -outfile $TempFileX -hrdir $hourdirection -hago $hoursago -dofilter $FilterApp -filterpatstr $FilterPat -exttochk $CheckFor -exttochkact $CheckForExt -unfall $TempUFAll -minSize $CheckForSizeMin -maxSize $CheckForSizeMax -checkforcehidden $CheckHidden -brootonly $false
        $durres += showscanduration -Result $result

        $txtfilterpat = $OutputFile.Replace("\", "\\") + "|" + $TempFileX.FullName.Replace("\", "\\") + "|" + $TempUFAll.FullName.Replace("\", "\\")
        postprocess -drivelet $drive[0] -infile $TempFileX -namefilter $txtfilterpat -outfile $OutputFile

        if (Test-Path $TempFileX) { Remove-Item $TempFileX -Force }
    }
    $durres | ForEach-Object { $_ }
}

########################################################################
# do the scan of a set of drives using threads
# TODO: Hangs in powershell 7.x 
#
function Invoke-DriveScanMT {
    param (
        [Parameter(Mandatory=$true)][string[]]$Drives,
        [string]$hourdirection,
        [datetime]$hoursago,
        $FilterApp,
        $CheckFor,
        $CheckForExt,
        $TempUFAll,
        $CheckForSizeMin,
        $CheckForSizeMax,
        $CheckHidden,
        $ScanFilterfn, 
        [string]$OutputFile,
        $FilterPat
    )

    $jobs = @()
    $TempFilesMap = @{}      # filtered output
    $TempFilesMapUFAll = @{} # unfiltered output used for highlighting, done as two for performance reasons rather than post filtering the unfiltered

    # create jobs for root dir and all root level dirs with recurse for each drive
    foreach ($drive in $Drives) {
        $driveLetter = $drive[0]

        # make each drive have an array of filtered and unfiltered temp files
        $TempFilesMap[$driveLetter] = @()
        $TempFilesMapUFAll[$driveLetter] = @()

        # create a thread for root level only no recurse
        $tempRoot = New-TemporaryFile
        $TempFilesMap[$driveLetter] += $tempRoot  
        $tempRootUFAll = New-TemporaryFile 
        $TempFilesMapUFAll[$driveLetter] += $tempRootUFAll 

        # create drive root level job
        $jobs += Start-Job -ScriptBlock ${function:doScanfor} -ArgumentList (Join-Path $drive "\*"), $tempRoot, $hourdirection, $hoursago, $FilterApp, $FilterPat, `
            $CheckFor, $CheckForExt, $tempRootUFAll, $CheckForSizeMin, $CheckForSizeMax, $CheckHidden, $true

        # one thread for each directory at root level with recurse
        $subDirs = @(Get-ChildItem -Path $(Join-Path $drive "\") -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        foreach ($dir in $subDirs) {
            $tempSub = New-TemporaryFile
            $TempFilesMap[$driveLetter] += $tempSub
            $tempSubUFAll = New-TemporaryFile
            $TempFilesMapUFAll[$driveLetter] += $tempSubUFAll

            # create recurse root level directories job
            $jobs += Start-Job -ScriptBlock ${function:doScanfor} -ArgumentList ($dir + '\'), $tempSub, $hourdirection, $hoursago, $FilterApp, $FilterPat, `
                $CheckFor, $CheckForExt, $tempSubUFAll, $CheckForSizeMin, $CheckForSizeMax, $CheckHidden, $false
        }
    }

    # wait for all jobs to complete - todo make progress not time based but based on number of outstanding jobs
    watchjobprogress -jobs $jobs

    # report on how long they took
    Write-Host "`n`[INFO] Scan timings..." -ForegroundColor Green
    foreach ($job in $jobs) {
        $result = Receive-Job $job
        Write-Host $(showscanduration -Result $result)
    }
    Write-Host ""

    # merge all the filtered temp output files with correct formating and delete the temp files
    # processing each by drive letter complication is useful to provide drive by section with summary 
    $OutputTempFiles = @{}
    $txtfilterpat = $OutputFile.Replace("\", "\\") + "|"
    foreach ($driveLetter in $TempFilesMap.Keys) {
        $combinedFile = New-TemporaryFile
        foreach ($tmp in $TempFilesMap[$driveLetter]) {
            $txtfilterpat += $tmp.FullName.Replace("\", "\\") + "|"
            if (Test-Path $tmp) {
                Get-Content $tmp | Add-Content $combinedFile
                Remove-Item $tmp -Force
            }
        }
        $OutputTempFiles[$driveLetter] = $combinedFile
        $txtfilterpat += $combinedFile.FullName.Replace("\", "\\") + "|"
    }

    foreach ($driveLetter in $TempFilesMapUFAll.Keys) {
        foreach ($tmp in $TempFilesMapUFAll[$driveLetter]) { 
            $txtfilterpat += $tmp.FullName.Replace("\", "\\") + "|" 
            if (Test-Path $tmp) {
                Get-Content $tmp | Add-Content $TempUFAll
                Remove-Item $tmp -Force
            }
        }
    }

    $txtfilterpat += $TempUFAll.FullName.Replace("\", "\\")

    Write-Host "`[INFO] Scan results..." -ForegroundColor Green
    # post process the filtered output files for each drive and combine them in to $OutputFile
    foreach ($driveLetter in $OutputTempFiles.Keys) {
        if (Test-Path $OutputTempFiles[$driveLetter]) {
            postprocess -drivelet $driveLetter -infile $OutputTempFiles[$driveLetter] -namefilter $txtfilterpat -outfile $OutputFile
            Remove-Item $OutputTempFiles[$driveLetter] -Force
        }
    }
}

#################################################
# Main 
#

# FOR DEBUGGING show details of the enviroment if running under a debugger
# POWERSHELL oddies, even though checkfordebugger returns a string, the if might not enforce the string type, causing the
# condition not match the string "none" when "none" is returned. So need the $() around the return from checkfordebugger
$IsDebug = $false
if ($(checkfordebugger) -ne "none") { $IsDebug = $true; }

if ($IsDebug) { Show-EnvironmentCheck }

[console]::bufferwidth = 30000
$dwdir = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
$Drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { "$($_.DeviceID)" }
$OutputFile = $dwdir + "\result.txt"
$ExtsToHilight = @(".exe", ".bat", ".pdf", ".jpg", ".png", ".gif", ".ico", ".docx", ".mp4", ".tif", ".tiff", ".webm", ".webp", ".afphoto", ".psd", ".pic", ".jpeg")
if ($ModDefault -eq "" -or $ModDefault -eq "N") { $ModDefault = $null}
clearpressedkeys

# Options: run in single thread
if ($IsDebug) { 
    $SingleThreaded = getYNinput $ModDefault $SingleThreaded "SingleThreaded" "Run in single thread?" "Y" 
} elseif (-not $PSBoundParameters.ContainsKey('SingleThreaded')) {
    $SingleThreaded = 'N'
}

# Options: Use run cleaner option
$CleanTempFiles = getYNinput $ModDefault $CleanTempFiles "CleanTempFiles" "Use Windows (cleanmgr.exe) to clean temp files before looking for changes?" "N"

# Options: Get hours back to scan, must be negative
<# Note below $HoursToCheck -eq $null rather than !$HoursToCheck, for strings this works as even an empty string is not false. But for numbers zero is false, so need to check for $null
   This is a core issue of untyped language: 

    function launchrocket {
        param ( $cmdinstr )
        if ($cmdinstr) { "count down and launch rocket" }
    }
    
    launchrocket -cmdinstr $a 
    launchrocket -cmdinstr [int]a$ 
    
    For the same value and logic a change of type changes the behavior. 
#>
if ($HoursToCheck -eq 0 -or $ModDefault) {
    if ($ModDefault -and $HoursToCheck -ne 0) { $defval = $HoursToCheck } else { $defval = -3}
    $invvuhr = $true
    while ($invvuhr)
    {
        $invvuhr = $false
        try {  $HoursToCheck = [double](Read-Host "Enter the hours to add to Now to look for changes: [default $defval]" ) }
        catch { $invvuhr = $true; Write-Host "Input must be a number (e.g. 1, 2.5, -3). Try again." -ForegroundColor Yellow }
        if (!$invvuhr -and !$HoursToCheck) { $HoursToCheck = $defval; } 
    }
} 

if ($HoursToCheck -eq 0) { Write-Host "Invalid HoursToCheck. Must not be zero." -ForegroundColor Red; waitbeforeexit}
if ($HoursToCheck -ge 0) { Write-Host "Warning: Positive number entered. Scan will look for files older than specified hours." -ForegroundColor Yellow }

# Options: What drives to scan 
$validDrives = @('ALL') + ($Drives -replace ':')  
if (!$WhichDrive -or $ModDefault) {
    if ($ModDefault -and $WhichDrive) { $defval = $WhichDrive } else { $defval = "ALL" }
    while ($true) {
        $driveStringPrompt = "Which drive? (ALL/" + ((@($Drives) -replace ':') -join '/') + "): [default $defval]"
        $WhichDrive = $(Read-Host $driveStringPrompt).ToUpper()
        if ($WhichDrive -ieq '') { $WhichDrive = $defval }
        if (-not ($validDrives -contains $WhichDrive)) { Write-Host "Invalid drive requested. Valid drives are $validDrives." -ForegroundColor Yellow } else { break }
    }
} elseif (-not ($validDrives -contains $WhichDrive)) { Write-Host "Invalid WhichDrive value. Valid drives are $validDrives." -ForegroundColor Red; waitbeforeexit }

# Options: What file types to look for
$validCftypes = @('ALL', 'IMG', 'EXT', 'EXE')
if (!$CheckFor -or $ModDefault) {
    if ($ModDefault -and $CheckFor) { $defval = $CheckFor } else { $defval = "ALL" }
    while ($true) {
        $CheckFor = $(Read-Host "Check for ALL, any IMaGe type, any EXTension, or any EXEcutable type (ALL/IMG/EXT/EXE)?: [default $defval]").ToUpper()
        if ($CheckFor -ieq '') { $CheckFor = $defval}
        if ($CheckFor -notin $validCftypes) { Write-Host "Invalid option." -ForegroundColor Red } else { break }
    }
} elseif ($CheckFor -notin $validCftypes) { Write-Host "Invalid CheckFor option. Must be one of $validCftypes." -ForegroundColor Red; waitbeforeexit }

if ($CheckFor -eq 'EXT') {
    if (!$CheckForExt -or $ModDefault) {
        if ($ModDefault -and $CheckForExt) { $defval = $CheckForExt } else { $defval = "EXE" }
        $CheckForExt = $(Read-Host "Which extension do you want to checkfor (don't include a '.')?: [default $defval]").ToUpper()
        if ($CheckForExt -ieq '') { $CheckForExt = $defval}
    } 
}

# Options: Scan hidden files - can have x3 slowdown
$CheckHidden = getYNinput $ModDefault $CheckHidden "CheckHidden" "Look for hidden files? (NB: If Y will be slower due to access errors)" 'N'

# Options: Size
# debuger sets uninitialised values to 0, while if run from cmd line it is set to $null, so can't use $null to see if specified.
if (-not $PSBoundParameters.ContainsKey('CheckForSizeMin') -or $ModDefault) { 
    if ($ModDefault -and $CheckForSizeMin) { $defval = $CheckForSizeMin } else { $defval = '0' }
    $CheckForSizeMin = Read-Host "Look only for files that are larger than n bytes?: [default $defval]" 
    if ($CheckForSizeMin -ieq '') { $CheckForSizeMin = $defval }
}
if (-not $PSBoundParameters.ContainsKey('CheckForSizeMax') -or $ModDefault) { 
    if ($ModDefault -and $CheckForSizeMax) { $defval = $CheckForSizeMax } else { $defval = '-1' }
    $CheckForSizeMax = Read-Host "Look only for files that are smaller than n bytes?: [default $defval (not limited)]"
    if ( $CheckForSizeMax -ieq '' ) { $CheckForSizeMax = '-1'}
}

# Options: Apply Filter to directories to scan
$FilterApp = getYNinput $ModDefault $FilterApp "FilterApp" "Apply filter to directories to scan?"
if ($FilterApp -ieq 'Y') { $ScanFilterfn = getFNinput $ScanFilterfn $ModDefault "File containing list of directories to omit from scan?" }

# Options: Show directory counts
if (-not $PSBoundParameters.ContainsKey('ShowDirCounts') -or $ModDefault) { 
    if ($ModDefault -and $ShowDirCounts -ge 0 -and $ShowDirCounts -le 9) { $defval = $ShowDirCounts } else { $defval = '4' }
    while ($true) {
        $ShowDirCounts = Read-Host "Show directory summary counts (0 - don't show, max 9?: [default $defval]"
        if ($ShowDirCounts -eq '') { $ShowDirCounts = $defval; break }
        if ($ShowDirCounts -lt 0 -or $ShowDirCounts -gt 9) { Write-Host "Value must be minimum 0 and maximum 9." -ForegroundColor Red; continue } else {break}
    }
}

# Options: Highlighted files - different default depending on file type requested
$ShowHighlights = getYNinput $ModDefault $ShowHighlights "ShowHighlights" "Highlight key changed file types at end?" 'Y'
if ($ShowHighlights -ieq 'Y') { 
    $HighlightFilter = getYNinput $ModDefault $HighlightFilter "HighlightFilter" "Apply filter to highlighting?" 
    if ($HighlightFilter -ieq 'Y') { $HighlightFilterfn = getFNinput $HighlightFilterfn $ModDefault "File containing directories excluded highlighting?" }

    if ($CheckFor -ieq 'ALL') { $inyndef =  'N' } else { $inyndef =  'Y' }
    $CopyHighlights   = getYNinput $ModDefault $CopyHighlights   "CopyHighlights"   "Copy highlighted files to an output directory?" $inyndef 
    $CopyMetaInfo     = getYNinput $ModDefault $CopyMetaInfo     "CopyMetaInfo"     "Create a [fn].meta.json with path info for each copied highlighted file an output directory?" 'N'
    $CopyReportErrors = getYNinput $ModDefault $CopyReportErrors "CopyReportErrors" "Report errors when copying highlighted files to an output directory?" 'N'
} else { 
    $CopyHighlights = 'N'
    $CopyMetaInfo = 'N' 
    $CopyReportErrors = 'N'
    $HighlightFilter = 'N'
}

#Options: Filter zero length files
$FilterZeroLenFiles = getYNinput $ModDefault $FilterZeroLenFiles "FilterZeroLenFiles" "Filter out zero length files from the result?" 'Y'

# Start a transaction log so it can be included in the output file for later reference
$TransLog = New-TemporaryFile
Start-Transcript -Path $TransLog -Append | Out-Null

# Do Clean
if ( $cleantempfiles -ieq 'Y' ) { 
    Write-Host "`n[INFO] Cleaning temp files with cleanmgr..." -ForegroundColor Green
    Start-Process "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait 
    Write-Host "Cleaning done."
}

# Message to say what the scan will be doing
if ($HoursToCheck -lt 0) { 
    $hoursago = (Get-Date).AddHours($HoursToCheck) 
    $hrdirection = "after";
} else { 
    $hoursago = (Get-Date).AddHours(-$HoursToCheck)
    $hrdirection = "before";
}

$msgsng = if ($SingleThreaded -eq 'Y') {"(single threaded)"} else {""}
$msghid = if ($CheckHidden -eq 'Y') { "including hidden files" } else { "excluding hidden files" }
$maxmsg = if ($CheckForSizeMax -eq '-1') { "no maximum size" } else { "maximum size $CheckForSizeMax bytes" }
$msgflt = if ($FilterApp -eq 'Y') { "filter applied using $ScanFilterfn" } else { "no filter applied" }
$msgdcs = if ($ShowDirCounts -gt 0) {"shown with max depth $ShowDirCounts"} else { "not shown"}
$metaCt = if ($CopyMetaInfo -eq 'Y') { "will be created" } else { "will not be created" }
$msgchi = if ($CopyHighlights -eq 'Y') { "and will be copied to an output directory"} else { "only" }
$msgext = if ($CheckFor -eq 'EXT') { "Extension .$CheckForExt" } else { "" }
$msgflc = if ($HighlightFilter -eq 'Y') { "filter applied using $HighlightFilterFn" } else { "no filter applied" }
$msgzfn = if ($FilterZeroLenFiles -eq 'Y') {"yes"} else {"no"}

Write-Host "`n[INFO] Scanning using values" -ForegroundColor Green
if ($WhichDrive -eq 'ALL') { Write-Host " - Drives: $Drives $msgsng" } else { Write-Host " - Drives: $WhichDrive $msgsng"}
Write-Host " - Look for files modified $hrdirection $hoursago"
Write-Host " - File types: $CheckFor" $msgext
Write-Host " - Hidden files: $msghid"
Write-Host " - File size between: $CheckForSizeMin bytes and $maxmsg"
Write-Host " - Filter scan: $msgflt"
Write-Host " - Directory summary counts: $msgdcs"
Write-Host " - Filtering zero length files: $msgzfn"

if ($ShowHighlights -eq 'Y') {
    Write-Host "`n[INFO] Highlighting enabled..." -ForegroundColor Green
    Write-Host " - Extensions highlighted: $ExtsToHilight"
    Write-Host " - Files modified $hrdirection $hoursago will be reported" $msgchi
    Write-Host " - meta.json files for each highlighted file:" $metaCt
    Write-Host " - Filter highlighted files: $msgflc"
}

Write-Host ""

# full list of files without filtering
$TempUFAll = New-TemporaryFile

# Get drives to scan
if ( $WhichDrive -ne 'ALL') { $drivestoscan = @($WhichDrive + ":") } else { $drivestoscan = $Drives }

# TODO use the drive being scanned to filter out patterns not applicible in the buildfilter function
# Build filter pattern 
if ($FilterApp -eq 'Y')          { $filterpatstr = buildfilterpatern -ExcludeFilelist $ScanFilterfn -FilterZeroLenfn $FilterZeroLenFiles } else { $filterpatstr = "" }
if ($FilterZeroLenFiles -eq 'Y') { $filterpatstr = buildfilterpatZfn -Filterpat $filterpatstr }
if ($HighlightFilter -ieq 'Y')   { $filterhlpat  = buildfilterarray -ExcludeFilelist $HighlightFilterfn } else { $filterhlpat = @() }

# Do the scan
if ($SingleThreaded -eq 'Y') {
    Invoke-DriveScan -Drives $drivestoscan -OutputFile $OutputFile -hourdirection $hrdirection -hoursago $hoursago -FilterApp $FilterApp -CheckFor $CheckFor -CheckForExt $CheckForExt -TempUFAll $TempUFAll -CheckForSizeMin $CheckForSizeMin -CheckForSizeMax $CheckForSizeMax -CheckHidden $CheckHidden -ScanFilterfn $ScanFilterfn -FilterPat $filterpatstr 
} else {
    # Do the scan and get the results with multiple threads to improve time taken
    Invoke-DriveScanMT -Drives $drivestoscan -OutputFile $OutputFile -hourdirection $hrdirection -hoursago $hoursago -FilterApp $FilterApp -CheckFor $CheckFor -CheckForExt $CheckForExt -TempUFAll $TempUFAll -CheckForSizeMin $CheckForSizeMin -CheckForSizeMax $CheckForSizeMax -CheckHidden $CheckHidden -ScanFilterfn $ScanFilterfn -FilterPat $filterpatstr 
}

# add a summary of directory counts to the output
showdircountsinfile -OutputFile $OutputFile -ShowDirCounts $ShowDirCounts

# create a location to store the results and any highlited files
$resfldpath = createoutputdir
if ($copytodw -ieq 'Y' ) { 
    Write-Host "Highlighted files ($($filesToCopy.Count)) will be copied to $resfldpath" 
}

# Highlight key file types which changed and copy them if requested
$fndirsep = "-"
if ( $ShowHighlights -ieq 'Y' ) { 
    findfilestohighlight -outfile $OutputFile -unfall $TempUFAll -copytodw $CopyHighlights -copyrpterr $CopyReportErrors -resfolder $resfldpath -fnsep $fndirsep -CopyMetaInfo $CopyMetaInfo -HighlightFilter $HighlightFilter -HighlightFilterFn $HighlightFilterfn -filterhlpat $filterhlpat
}

if (-not (Test-Path $OutputFile))  { Write-Host "No results found." }

Stop-Transcript | Out-Null

if (Test-Path $TransLog) {
    # Remove junk start transcript / end transcript adds and add the log to the output
    addtranslogtoutput -TransLog $TransLog -OutputFile $OutputFile
    Remove-Item $TransLog -ErrorAction SilentlyContinue
}

# relocate the output results into results directory with any highlited files
if (Test-Path $OutputFile) {
    relocateoutput -OutputFile $OutputFile -resfldpath $resfldpath -fndirsep $fndirsep
}

waitbeforeexit