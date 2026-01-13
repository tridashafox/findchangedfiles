# Checks for changes on all local drives since X hours have passed
# Writen to be as fast as possible using multiple threads
#
# Useful for:
#   Looking for a file that was saved but cannot find
#   Looking for changes that have caused a problem on your system
#   Looking for changes made by a virus or other rouge program
#   Looking for posisble autosave/temp files after program crash to recover them
#   Understanding what changed after an app install
#
# Allows options to specify the number of hours to look back as negative number, 
# Can just look groups of types of foles, for example, images or excutables, etc
# Can filter out some directions which likely not of interest.
# Can just scan one specific drive
# Can highlight changes to key files types (not affected by any filters applied)
# highlighting key files is a sperate processing but uses the same scan output nad hours to look for
#
# It produces a results file that is stored in a directory in users download location
# Note that  this output dir will be included in later scans so delete when not required
#
# After win11H2 update powershell scripts won't run unless you run it in a powershell terminal using command
# powershell -ExecutionPolicy ByPass -File .\scanforchangeshours_fv2.ps1
# or from within VScode
# 
# Only tested in powershell 5.1.26100.4652
# took possibly 40 hours to get right - the joys of powershell, considering if win32 c/c++ would have been better
# vibe coding only 10% helpfully but also a timewaster with bad code and red-herrings, poor logic understanding
# using multiple threading add a lot of complications and restrictions

# TODO
# allow different filter options (None, Light, Full)
# move extension lists into function near buildfilters
# allow a directory to be scanned rather than just a drive
# add functional tests (lol)
# fix hang in powershell 7.x

param (
    [string]$ModDefault,        # Y means the below changes the default rather than passes the value, default is N
    [string]$CleanTempFiles,    # Y if want to run windows cleanmgr before running scan, default is N
    [double]$HoursToCheck,      # Number of hours to look back for changes, default is -3, note this can have a decimal point e.g. -0.5 (last half-hour)
    [string]$WhichDrive,        # Which drive to scan, or all drives, default is ALL
    [string]$CheckFor,          # Which types of files to check for, can be  is ALL, IMG (anything at is an Image), EXT (askes for an CheckForExt), EXE (anything that executes), default is ALL
    [string]$CheckForExt,       # A specific extension to scan for (don't include the '.' before the extension), default PNG. Ignored unless CheckFor is EXT
    [string]$CheckHidden,       # Y if want to try to scan hidden files, default is N
    [int]$CheckForSizeMin,      # Include files above this min size, default is 0 (all files)
    [int]$CheckForSizeMax,      # Include files blow this max size, default is -1 (all files)
    [string]$FilterApp,         # Apply a built in filter to cut down noisey files, default is 'Y' if CheckFor is ALL 
    [string]$ShowHighlights,    # Look for key file types that changed and list them out, default is 'Y'
    [string]$CopyHighlights,    # Copy files found by ShowHighlights to a temp directory in downloads, default is 'N' if CheckFor is ALL
    [string]$CopyMetaInfo,      # Create a json file with info about for each file found by ShowHighlights, default is 'N' if CheckFor is ALL
    [string]$CopyReportErrors   # Report errors during the ShowHighlights operation into the results file, default is 'N'
)

########################################################################
# makes sure no keys pending to be processed
#
function clearpressedkeys() {
    while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }
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
        Write-Host "Time taken:", $duration, $Result.Path
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
# handle Y/N questions
#
function getYNinput {
    param (
        $ModDefault,    # don't typpe as string, we need to know if it is $null, if it's typed it will end up ""
        $InitValue,     # don't typpe as string
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
    exit 1
}

########################################################################
# Parse results file and display a summary of file counts in directories
# NOTE will fail if any of the formating of the output is changed
# Usage examples:
# Get-DirectoryFileCounts -Filename "your_file.txt"
#
function Get-DirectoryFileCounts {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Filename
    )
    
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
            
            # Get parent directory
            $parentDir = Split-Path $trimmedPath -Parent
            if (-not $dirCounts.ContainsKey($parentDir)) {
                $dirCounts[$parentDir] = 0
            }
            $dirCounts[$parentDir]++
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
    $timeFilter = { $_.LastWriteTime -gt $hago -and $_.Length -ge $minSize }

    # Add size limit if maxSize is specified
    if ($maxSize -ne -1) {
        $timeFilter = { $_.LastWriteTime -gt $hago -and $_.Length -ge $minSize -and $_.Length -le $maxSize }
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
        [string]$CopyMetaInfo
        )

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
    Write-Host "Highlighted # modified or created files"  $sizeoffnd 

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
    if ($filesToCopy.Count -gt 0) {
        Add-Content -Path $outfile -Value ""
        $filteredtitle = "Highlights - Key file types which changed (exe,bat,pdf,jpg,png,gif,ico,docx,mp4,tiff,webp,afphoto,psd,pic):"
        Add-Content -Path $outfile -Value $filteredtitle -Encoding UTF8
        Add-Content -Path $outfile -Value ""
        $filesToCopy | Add-Content -Path $outfile -Encoding UTF8
    } else { 
        $filteredtitle = "No files to highlight found."
        Add-Content -Path $outfile -Value $filteredtitle -Encoding UTF8
    }

    if ($copytodw -ieq 'Y') {
        if ($resfolder.Length -gt 0) {
            $tempFolderPath = $resfolder
            # Write-Host "Highlighted files will be copied to $tempFolderPath"

            $counterstart = 1 # start at 1 - zero is used for the log output
            $counter = $counterstart
            $countercpErr = 0
            foreach ($line in $filesToCopy) {
                $filename = ($line -split ' ', 4)[-1]  # Split into 4 parts, take the last part
                $filename = $filename.Trim()

                if ($filename -ne '') {
                    if (Test-Path -LiteralPath $filename) {
                        try {
                            $partname = Get-Item -LiteralPath $filename -Force # -Force needed for files marked as hidden
                            $fullPathStr = $partname.FullName
                            $baseFileName = $partname.BaseName
                            <# 
                            # Old method converts th path into a name c--dir1--dir2--file1.txt
                            $relativePath = $fullPathStr.Substring(3)  # Strip drive letter like C:\
                            $components = $relativePath -split '\\'
                            $safePathName = ($components -join $fnsep)
                            $baseFileName = $fullPathStr[0] + $fnsep + $safePathName
                            #>
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
                            $newFileName = "{0:D8}{1}{2}" -f $counter, $fnsep, $partname.Name
                            $counter++

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

                            # create the meta data file
                            if ($CopyMetaInfo -eq 'Y')
                            {
                                try {
                                    $srcfileInfo = Get-Item $filename
                                    $meta = [ordered]@{  # note the ordered specifier otherwise entries are come out random
                                        originalPath1     = $fullPathStr
                                        originalPath2     = $fullPathStr.Replace("\", "/")
                                        originalname      = Split-Path $srcfileInfo -Leaf
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
# create a filter to be used to filter out noisy files not of interest
#
function buildfilterpatern { 
     # create a filter for common noisy dirs with changes not of interest. Note even with filter highlited files will intentionaly show up
    $patsp = "|" 
    $winddir = $env:WINDIR.Replace("\", "\\") + "\\"
    $sysmdrv = $winddir[0] + ":"
    $homedir = $env:USERPROFILE.Replace("\", "\\")
    $tempRot = $(Split-Path -Path $env:TEMP -Parent).Replace("\", "\\")
    $tempusr = $env:TMP.Replace("\", "\\")
    $prgfles = $env:ProgramFiles.Replace("\", "\\")
    $prgfl86 = ([System.Environment]::GetFolderPath("ProgramFilesX86").Replace("\", "\\")).Replace("(", "\(").Replace(")", "\)")
    $pgmdata = [System.Environment]::GetFolderPath("CommonApplicationData").Replace("\", "\\") 

    # Add others here as required
    $textfilterpat = `
        $winddir + $patsp +`
        $prgfl86 + "\\Steam" + $patsp +`
        $prgfl86 + "\\Google" + $patsp +`
        $prgfl86 + "\\Microsoft\\Edge" + $patsp +`
        $prgfl86 + "\\Epic Games\\" + $patsp +`
        $prgfl86 + "\\Microsoft OneDrive" + $patsp +`
        $prgfles + "\\Microsoft Office" + $patsp +`
        $prgfles + "\\Common Files\\microsoft shared" + $patsp +`
        $prgfles + "\\Adobe" + $patsp +`
        $prgfles + "\\Common Files\\Adobe" + $patsp +`
        $prgfles + "\\Google\\Chrome\\" + $patsp +`
        $prgfles + "\\NVIDIA" + $patsp +`
        $pgmdata + "\\Microsoft\\EdgeUpdate" + $patsp +  
        $pgmdata + "\\Microsoft\\ClickToRun\\" + $patsp +`
        $pgmdata + "\\Mozilla" + $patsp +`
        $pgmdata + "\\NVIDIA Corporation" + $patsp +`
        $pgmdata + "\\regid." + $patsp +`
        $pgmdata + "\\USOPrivate\\UpdateStore" + $patsp +`
        $pgmdata + "\\USOShared\\Logs\\System" + $patsp +`
        $pgmdata + "\\NVIDIA\\" + $patsp +`
        $pgmdata + "\\Microsoft\\Windows Defender\\" + $patsp +`
        $pgmdata + "\\Microsoft\\MapData\\" + $patsp +`
        $pgmdata + "\\Epic\\" + $patsp +`
        $sysmdrv + "\\Users\\All Users\\Microsoft\\EdgeUpdate" + $patsp +`
        $sysmdrv + "\\Users\\All Users\\NVIDIA" + $patsp +`
        $sysmdrv + "\\Users\\All Users\\regid." + $patsp +`
        $sysmdrv + "\\Users\\All Users\\USO" + $patsp +`
        $sysmdrv + "\\Users\\All Users\\USOShared\\Logs\\System\\MoUxCoreWorker" + $patsp +`
        $sysmdrv + "\\Users\\All Users\\Microsoft\\Windows Defender\\" + $patsp +`
        $sysmdrv + "\\Users\\All Users\\Microsoft Visual Studio\\" + $patsp +`
        $sysmdrv + "\\Users\\All Users\\Microsoft\\MapData\\" + $patsp +`
        $sysmdrv + "\\Users\\All Users\\Epic\\" + $patsp +`
        $homedir + "\\.vscode" + $patsp +`
        $homedir + "\\AppData\\Local\\ConnectedDevicesPlatform" + $patsp +`
        $homedir + "\\AppData\\Local\\D3DSCache" + $patsp +`
        $homedir + "\\AppData\\Local\\Google\\Chrome" + $patsp +`
        $homedir + "\\AppData\\Local\\Microsoft" + $patsp +`
        $homedir + "\\AppData\\Local\\Mozilla" + $patsp +`
        $homedir + "\\AppData\\Local\\npm-cache" + $patsp +`
        $homedir + "\\AppData\\Local\\NVIDIA" + $patsp +`
        $homedir + "\\AppData\\Local\\Packages\\Microsoft" + $patsp +`
        $homedir + "\\AppData\\Local\\Packages\\MicrosoftWindows" + $patsp +`
        $homedir + "\\AppData\\Local\\Steam" + $patsp +`
        $tempRot + "\\system\\CreativeCloud" + $patsp +`
        $tempusr + "\\NGL\\NGLClient_" + $patsp +`
        $homedir + "\\AppData\\LocalLow\\Microsoft" + $patsp +`
        $homedir + "\\AppData\\Roaming\\Adobe" + $patsp +`
        $homedir + "\\AppData\\Roaming\\Code" + $patsp +`
        $homedir + "\\AppData\\Roaming\\Mozilla\\" + $patsp +`
        $homedir + "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations" + $patsp +`
        $homedir + "\\AppData\\Local\\Adobe\\OOBE\\" + $patsp +`
        $homedir + "\\AppData\\Roaming\\com.adobe.dunamis\\" + $patsp +`
        $homedir + "\\AppData\\Roaming\\Microsoft\\Spelling\\" + $patsp +`
        $homedir + "\\AppData\\Roaming\\Microsoft\\SystemCertificates\\" + $patsp +`
        $homedir + "\\AppData\\Roaming\\Microsoft\\VisualStudio" + $patsp +`
        $tempusr + "\\VSWebView2Cache\\" + $patsp +`
        $homedir + "\\AppData\\Roaming\\Microsoft\\Windows\\" + $patsp +`
        $homedir + "\\AppData\\Local\\Adobe\\" + $patsp +`
        $homedir + "\\AppData\\Local\\Programs\\Microsoft VS Code\\" + $patsp +`
        $homedir + "\\Saved Games\\" + $patsp

    #  on all drives which need filtering for the same dirs
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { "$($_.DeviceID)" }
    foreach ($drive in $drives) {
        $textfilterpat +=  $drive[0] + ":\\SteamLibrary\\steamapps\\workshop" + $patsp
        $textfilterpat +=  $drive[0] + ":\\SteamLibrary\\steamapps\\common" + $patsp
        $textfilterpat += "  0 " + $drive[0]+ ":\\"+ $patsp # filter out zero lenght files, special case
    }
    
    # For DEBUGGING
    <#
    &{
        # dump the filter txt to dowloads dir
        $dwdir = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
        $dboutfn = $dwdir + "\sfc_debug_filter.txt"
        $textfilterpat | Add-Content -Path $dboutfn
    } #>

    return $textfilterpat
}

########################################################################
# do the scan of single drive without threads
# only used for debugging
#
function Invoke-SingleDriveScan {
    param (
        [Parameter(Mandatory=$true)][string]$WhichDrive,
        [datetime]$hoursago,
        $FilterApp,
        $CheckFor,
        $CheckForExt,
        $TempUFAll,
        $CheckForSizeMin,
        $CheckForSizeMax,
        $CheckHidden,
        [string]$OutputFile
    )

    $TempFileX = New-TemporaryFile
    $temploc = $WhichDrive + ":\"
    $filterpatstr = ''
    if ($FilterApp -eq 'Y') { $filterpatstr = buildfilterpatern }

    $result = doScanfor -drive $temploc -outfile $TempFileX -hago $hoursago -dofilter $FilterApp -filterpatstr $filterpatstr -exttochk $CheckFor -exttochkact $CheckForExt -unfall $TempUFAll -minSize $CheckForSizeMin -maxSize $CheckForSizeMax -checkforcehidden $CheckHidden -brootonly $false
    showscanduration -Result $result

    $txtfilterpat = $OutputFile.Replace("\", "\\") + "|" +`
        $TempFileX.FullName.Replace("\", "\\") + "|" +`
        $TempUFAll.FullName.Replace("\", "\\")

    postprocess -drivelet $WhichDrive -infile $TempFileX -namefilter $txtfilterpat -outfile $OutputFile

    if (Test-Path $TempFileX) {
        Remove-Item $TempFileX -Force
    }
}

########################################################################
# do the scan of a set of drives using threads
# TODO: Hangs in powershell 7.x 
#
function Invoke-DriveScan {
    param (
        [Parameter(Mandatory=$true)][string[]]$Drives,
        [datetime]$hoursago,
        $FilterApp,
        $CheckFor,
        $CheckForExt,
        $TempUFAll,
        $CheckForSizeMin,
        $CheckForSizeMax,
        $CheckHidden,
        [string]$OutputFile
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
        $filterpatstr = ''
        if ($FilterApp -eq 'Y') { $filterpatstr = buildfilterpatern }

        # create drive root level job
        $jobs += Start-Job -ScriptBlock ${function:doScanfor} -ArgumentList (Join-Path $drive "\*"), $tempRoot, $hoursago, $FilterApp, $filterpatstr, `
            $CheckFor, $CheckForExt, $tempRootUFAll, $CheckForSizeMin, $CheckForSizeMax, $CheckHidden, $true

        # one thread for each directory at root level with recurse
        $subDirs = @(Get-ChildItem -Path $(Join-Path $drive "\") -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        foreach ($dir in $subDirs) {
            $tempSub = New-TemporaryFile
            $TempFilesMap[$driveLetter] += $tempSub
            $tempSubUFAll = New-TemporaryFile
            $TempFilesMapUFAll[$driveLetter] += $tempSubUFAll

            # create recurse root level directories job
            $jobs += Start-Job -ScriptBlock ${function:doScanfor} -ArgumentList ($dir + '\'), $tempSub, $hoursago, $FilterApp, $filterpatstr, `
                $CheckFor, $CheckForExt, $tempSubUFAll, $CheckForSizeMin, $CheckForSizeMax, $CheckHidden, $false
        }
    }

    # wait for all jobs to complete - todo make progress not time based but based on number of outstanding jobs
    watchjobprogress -jobs $jobs

    # report on how long they took
    Write-Host "`n`[INFO] Scan timings..." -ForegroundColor Green
    foreach ($job in $jobs) {
        $result = Receive-Job $job
        showscanduration -Result $result
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

[console]::bufferwidth = 30000
$dwdir = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
$Drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { "$($_.DeviceID)" }
$OutputFile = $dwdir + "\result.txt"
$ExtsToHilight = @(".exe", ".bat", ".pdf", ".jpg", ".png", ".gif", ".ico", ".docx", ".mp4", ".tif", ".tiff", ".webm", ".webp", ".afphoto", ".psd", ".pic", ".jpeg")
if ($ModDefault -eq "" -or $ModDefault -eq "N") { $ModDefault = $null}
clearpressedkeys

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
$msgBadHours = "The number of hours to look back must be a negative."
if ($HoursToCheck -ge 0 -or $ModDefault) {
    if ($ModDefault -and $HoursToCheck -lt 0) { $defval = $HoursToCheck } else { $defval = -3}
    while ($true) {
        $HoursToCheck = [double](Read-Host "Enter the hours to add to Now to look for changes: [default $defval]" )
        if (!$HoursToCheck) { $HoursToCheck = $defval } 
        if ($HoursToCheck -ge 0) { Write-Host $msgBadHours -ForegroundColor Red } else { break }
    }
} elseif ($HoursToCheck -ge 0) { Write-Host "Invalid HoursToCheck. $msgBadHours" -ForegroundColor Red; exit 1 }

# Options: What drives to scan 
$validDrives = @('ALL') + ($Drives -replace ':')  
if (!$WhichDrive -or $ModDefault) {
    if ($ModDefault -and $WhichDrive) { $defval = $WhichDrive } else { $defval = "ALL" }
    while ($true) {
        $driveStringPrompt = "Which drive? (ALL/" + ((@($Drives) -replace ':') -join '/') + "): [default $defval]"
        $WhichDrive = $(Read-Host $driveStringPrompt).ToUpper()
        if ($WhichDrive -ieq '') { $WhichDrive = $defval }
        if (-not ($validDrives -contains $WhichDrive)) { Write-Host "Invalid drive requested. Valid drives are $validDrives." -ForegroundColor Red } else { break }
    }
} elseif (-not ($validDrives -contains $WhichDrive)) { Write-Host "Invalid WhichDrive value. Valid drives are $validDrives." -ForegroundColor Red; exit 1 }

# Options: What file types to look for
$validCftypes = @('ALL', 'IMG', 'EXT', 'EXE')
if (!$CheckFor -or $ModDefault) {
    if ($ModDefault -and $CheckFor) { $defval = $CheckFor } else { $defval = "ALL" }
    while ($true) {
        $CheckFor = $(Read-Host "Check for ALL, any IMaGe type, any EXTension, or any EXEcutable type (ALL/IMG/EXT/EXE)?: [default $defval]").ToUpper()
        if ($CheckFor -ieq '') { $CheckFor = $defval}
        if ($CheckFor -notin $validCftypes) { Write-Host "Invalid option." -ForegroundColor Red } else { break }
    }
} elseif ($CheckFor -notin $validCftypes) { Write-Host "Invalid CheckFor option. Must be one of $validCftypes." -ForegroundColor Red; exit 1 }

if ($CheckFor -eq 'EXT') {
    if (!$CheckForExt -or $ModDefault) {
        if ($ModDefault -and $CheckForExt) { $defval = $CheckForExt } else { $defval = "PNG" }
        $CheckForExt = $(Read-Host "Which extension do you want to checkfor (don't include a '.')?: [default $defval]").ToUpper()
        if ($CheckForExt -ieq '') { $CheckForExt = $defval}
    } 
}

# Options: Scan hidden files - can have x3 slowdown
$CheckHidden = getYNinput $ModDefault $CheckHidden "CheckHidden" "Look for hidden files? (NB: If Y will be slower due to access errors)" 'N'
# Options: Size
if ($CheckForSizeMin -eq $null -or $ModDefault) { 
    if ($ModDefault -and $CheckForSizeMin) { $defval = $CheckForSizeMin } else { $defval = '0' }
    $CheckForSizeMin = Read-Host "Look only for files that are larger than n bytes?: [default $defval]" 
    if ($CheckForSizeMin -ieq '') { $CheckForSizeMin = $defval }
}
if ($CheckForSizeMax -eq $null -or $ModDefault) { 
    if ($ModDefault -and $CheckForSizeMax) { $defval = $CheckForSizeMax } else { $defval = '-1' }
    $CheckForSizeMax = Read-Host "Look only for files that are smaller than n bytes?: [default $defval (not limited)]"
    if ( $CheckForSizeMax -ieq '' ) { $CheckForSizeMax = '-1'}
}

# Options: Apply Filter - different default dependng if all drives scan is requested
if ($CheckFor -ne 'ALL') { $inyndef =  'N' } else { $inyndef =  'Y' }
$FilterApp = getYNinput $ModDefault $FilterApp "FilterApp" "Apply filter?" $inyndef 

# Options: Highlighted files - different default depending on file type requested
$ShowHighlights = getYNinput $ModDefault $ShowHighlights "ShowHighlights" "Highlight key changed file types at end?" 'Y'
if ($ShowHighlights -ieq 'Y') { 
    if ($CheckFor -ieq 'ALL') { $inyndef =  'N' } else { $inyndef =  'Y' }
    $CopyHighlights   = getYNinput $ModDefault $CopyHighlights   "CopyHighlights"   "Copy highlighted files to an output directory?" $inyndef 
    $CopyMetaInfo     = getYNinput $ModDefault $CopyMetaInfo     "CopyMetaInfo"     "Create a [fn].meta.json with path info for each copied highlighted file an output directory?" $inyndef 
    $CopyReportErrors = getYNinput $ModDefault $CopyReportErrors "CopyReportErrors" "Report errors when copying highlighted files to an output directory?" 'N'
} else { 
    $CopyHighlights = 'N'
    $CopyMetaInfo = 'N' 
    $CopyReportErrors = 'N'
}

# Start a transaction log so it can be included in the output file for later reference
$TransLog = New-TemporaryFile
Start-Transcript -Path $TransLog -Append | Out-Null

# FOR DEBUGGING show details of the enviroment
# Show-EnvironmentCheck 

# Do Clean
if ( $cleantempfiles -ieq 'Y' ) { 
    Write-Host "`n[INFO] Cleaning temp files with cleanmgr..." -ForegroundColor Green
    Start-Process "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait 
    Write-Host "Cleaning done."
}

# Message to say what the scan will be doing

$hoursago = (Get-Date).AddHours($HoursToCheck)

$msghid = if ($CheckHidden -eq 'Y') { "including hidden files" } else { "excluding hidden files" }
$maxmsg = if ($CheckForSizeMax -eq '-1') { "no maximum size" } else { "maximum size $CheckForSizeMax bytes" }
$msgflt = if ($FilterApp -eq 'Y') { "with filter applied." } else { "with no filter applied." }
$metaCt = if ($CopyMetaInfo -eq 'Y') { "will be created." } else { "will not be created." }
$msgchi = if ($CopyHighlights -eq 'Y') { "and will be copied to an output directory."} else { "only." }
$msgext = if ($CheckFor -eq 'EXT') { "Extension .$CheckForExt" } else { "" }

Write-Host "`n[INFO] Scanning using values..." -ForegroundColor Green
if ($WhichDrive -eq 'ALL') { Write-Host " - Drives: $Drives" } else { Write-Host " - Drives:" $WhichDrive}
Write-Host " - Look for files modified after: $hoursago"
Write-Host " - File types: $CheckFor" $msgext
Write-Host " - Hidden files: $msghid"
Write-Host " - File size between: $CheckForSizeMin bytes and $maxmsg"
Write-Host " - Filter: $msgflt"

if ($ShowHighlights -eq 'Y') {
    Write-Host "`n[INFO] Highlighting enabled..." -ForegroundColor Green
    Write-Host " - Extensions highlighted: $ExtsToHilight"
    Write-Host " - Files modified after $hoursago will be reported" $msgchi
    Write-Host " - meta.json files for each highlighted file:" $metaCt
}

Write-Host ""

# full list of files without filtering
$TempUFAll = New-TemporaryFile

# Get drives to scan
if ( $WhichDrive -ne 'ALL') { $drivestoscan = @($WhichDrive + ":") } else { $drivestoscan = $Drives }

# DBGNOTE: use this instead of Invoke-DriveScan to scan of just one drive (assumes ALL drives not specified). It does not run in seperarte tread, used to debug doScanFor so break points can be used
#Invoke-SingleDriveScan -WhichDrive $WhichDrive -OutputFile $OutputFile -hoursago $hoursago -FilterApp $FilterApp -CheckFor $CheckFor -CheckForExt $CheckForExt -TempUFAll $TempUFAll -CheckForSizeMin $CheckForSizeMin -CheckForSizeMax $CheckForSizeMax -CheckHidden $CheckHidden

# Do the scan and get the results with multiple threads to improve time taken
Invoke-DriveScan -Drives $drivestoscan -OutputFile $OutputFile -hoursago $hoursago -FilterApp $FilterApp -CheckFor $CheckFor -CheckForExt $CheckForExt -TempUFAll $TempUFAll -CheckForSizeMin $CheckForSizeMin -CheckForSizeMax $CheckForSizeMax -CheckHidden $CheckHidden

# add a summary of directory counts to the output
if (Test-Path $OutputFile) {
    $TempSumDirCnt = New-TemporaryFile
    "`nSummary counts of directories:`n" | Out-File -FilePath $TempSumDirCnt -Encoding UTF8
    Get-DirectoryFileCounts -Filename $OutputFile | Out-File -FilePath $TempSumDirCnt -Append -Encoding UTF8
    "`n" | Out-File -FilePath $TempSumDirCnt -Append -Encoding UTF8
    Get-Content $TempSumDirCnt | Out-File -FilePath $OutputFile -Append -Encoding UTF8
    Remove-Item $TempSumDirCnt
}

# create a location to store the results and any highlited files
$resfldpath = createoutputdir
if ($copytodw -ieq 'Y' ) { 
    Write-Host "Highlighted files ($($filesToCopy.Count)) will be copied to $resfldpath" 
}

# Highlight key file types which changed and copy them if requested
$fndirsep = "--"
if ( $ShowHighlights -ieq 'Y' ) { 
    findfilestohighlight -outfile $OutputFile -unfall $TempUFAll -copytodw $CopyHighlights -copyrpterr $CopyReportErrors -resfolder $resfldpath -fnsep $fndirsep -CopyMetaInfo $CopyMetaInfo
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

clearpressedkeys
read-host "Press ENTER to continue"