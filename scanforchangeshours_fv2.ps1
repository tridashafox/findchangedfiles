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
# allow for shorter than hour time period
# fix hang in powershell 7

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
        [string]$exttochk,
        [string]$unfall,
        [int]$minSize,   # Minimum file size in bytes
        [int]$maxSize,    # Maximum file size in bytes
        [string]$checkforcehidden,
        [bool]$brootonly
    )

    $startTime = Get-Date
    $drivefull = $drive
    $textfilterpat = ''
    $wildc = ''

    # set up the extensions to look for if looking for images or executables.
    if ( $exttochk -ieq 'IMG' ) { $wildc = "*.BMP", "*.GIF", "*.JPG", "*.JPEG", "*.PNG", "*.TIF", "*.TIFF", "*.ICO" , "*.DDS", "*.MP4", "*.MOV", "*.WebM", "*.AVI", "*.WMV", "*.Webp", "*.afphoto", "*.psd", "*.pic" } 
    if ( $exttochk -ieq 'PNG' ) { $wildc = "*.PNG" }
    if ( $exttochk -ieq 'EXE' ) { $wildc = "*.BAT", "*.PS1", "*.BIN", "*.CMD", "*.COM", "*.CPL", "*.EXE", "*.GADGET", "*.INF1", "*.INS",`
         "*.INX", "*.ISU", "*.JOB", "*.JSE", "*.LNK", "*.MSC", "*.MSI", "*.MSP", "*.MST", "*.PAF", "*.PIF", "*.PS1", "*.REG", "*.RGS", `
         "*.SCR", "*.SCT", "*.SHB", "*.SHS", "*.U3P", "*.VB", "*.VBE", "*.VBS", "*.VBSCRIPT", "*.WS", "*.WSF", "*.WSH" }

    # create a filter for common noisy dirs with changes not of interest. Note even with filter highlited files will intentionaly show up
    if ($dofilter -ieq 'Y' ) {
        & { # should be a function but can't be because this is kicked off as a job in a seperate thread and it cannot functions outside the thread
            # Used in a filter so any dirs need to have \ escaped to \\ also other special characters e.g. \(\)
            $patsp = "|" 
            $winddir = $env:WINDIR.Replace("\", "\\") + "\\"
            $sysmdrv = $winddir[0] + ":"
            $homedir = $env:USERPROFILE.Replace("\", "\\")
            $tempRot = $(Split-Path -Path $env:TEMP -Parent).Replace("\", "\\")
            $tempusr = $env:TMP.Replace("\", "\\")
            $prgfles = $env:ProgramFiles.Replace("\", "\\")
            $prgfl86 = ([System.Environment]::GetFolderPath("ProgramFilesX86").Replace("\", "\\") + "\\").Replace("(", "\(").Replace(")", "\)")
            $pgmdata = [System.Environment]::GetFolderPath("CommonApplicationData").Replace("\", "\\") 

            # Add others here as required
            $textfilterpat += `
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
        }
    }

    # filter out the output file from the result
    $textfilterpat += $outfile.Replace("\", "\\")

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
    Get-Content $unfall | Select-String -Pattern $textfilterpat -NotMatch | Set-Content -Encoding UTF8 $outfile 


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
        $filteredtitle = "Highlights - Key file types which changed (exe,bat,pdf,jpg,png,docx,mp4,tiff,webp,afphoto,psd,pic):"
        Add-Content -Path $outfile -Value $filteredtitle -Encoding UTF8
        $filesToCopy | Add-Content -Path $outfile -Encoding UTF8
    } else { 
        $filteredtitle = "No files to highlight found."
        Add-Content -Path $outfile -Value $filteredtitle -Encoding UTF8
    }

    if ($copytodw -ieq 'Y') {
        if ($resfolder.Length -gt 0) {
            $tempFolderPath = $resfolder
            Write-Host "Highlighted files will be copied to $tempFolderPath"

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
                            $fullPath = $partname.FullName
                            $baseFileName = $partname.BaseName
                            <# 
                            # Old method converts th path into a name c--dir1--dir2--file1.txt
                            $relativePath = $fullPath.Substring(3)  # Strip drive letter like C:\
                            $components = $relativePath -split '\\'
                            $safePathName = ($components -join $fnsep)
                            $baseFileName = $fullPath[0] + $fnsep + $safePathName
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
                                    $meta = @{
                                        originalPath  = $fullPath
                                        lastwritetime = $srcfileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                                        copiedOn      = (Get-Date).ToString("o")
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
        [string]$Prompt,
        [string]$Default = 'N'
    )

    $question = $Prompt + " (Y/N): [default " + $Default + "]"
    $response = (Read-Host $question).ToUpper().Trim()
    if (-not $response) { return $Default }

    if ($response -eq 'Y' -or $response -eq 'N') { return $response } 
    return $Default
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
# do the scan of single drive without threads
# only used for debugging
#
function Invoke-SingleDriveScan {
    param (
        [Parameter(Mandatory=$true)][string]$WhichDrive,
        [datetime]$hoursago,
        $FilterApp,
        $CheckFor,
        $TempUFAll,
        $CheckForSizeMin,
        $CheckForSizeMax,
        $CheckHidden,
        [string]$OutputFile
    )

    $TempFileX = New-TemporaryFile
    $temploc = $WhichDrive + ":\"

    $result = doScanfor -drive $temploc -outfile $TempFileX -hago $hoursago -dofilter $FilterApp -exttochk $CheckFor -unfall $TempUFAll -minSize $CheckForSizeMin -maxSize $CheckForSizeMax -checkforcehidden $CheckHidden -brootonly $false
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

        # create drive root level job
        $jobs += Start-Job -ScriptBlock ${function:doScanfor} -ArgumentList (Join-Path $drive "\*"), $tempRoot, $hoursago, $FilterApp, $CheckFor, $tempRootUFAll, $CheckForSizeMin, $CheckForSizeMax, $CheckHidden, $true

        # one thread for each directory at root level with recurse
        $subDirs = @(Get-ChildItem -Path $(Join-Path $drive "\") -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        foreach ($dir in $subDirs) {
            $tempSub = New-TemporaryFile
            $TempFilesMap[$driveLetter] += $tempSub
            $tempSubUFAll = New-TemporaryFile
            $TempFilesMapUFAll[$driveLetter] += $tempSubUFAll

            # create recurse root level directories job
            $jobs += Start-Job -ScriptBlock ${function:doScanfor} -ArgumentList ($dir + '\'), $tempSub, $hoursago, $FilterApp, $CheckFor, $tempSubUFAll, $CheckForSizeMin, $CheckForSizeMax, $CheckHidden, $false
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

# FOR DEBUGGING show details of the enviroment
# Show-EnvironmentCheck 

$hourstocheck = $null
$FilterApp = $null
$WhichDrive = $null
$dwdir = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
$Drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { "$($_.DeviceID)" }
$OutputFile = $dwdir + "\result.txt"
$ExtsToHilight = @(".exe", ".bat", ".pdf", ".jpg", ".png", ".docx", ".mp4", ".tif", ".tiff", ".webp", ".afphoto", ".psd", ".pic", ".jpeg")

"Results of Scan for modified files:" | Set-Content -Path $OutputFile -Force
[console]::bufferwidth = 30000

clearpressedkeys

# Use cleaner option
$cleantempfiles = getYNinput "Use Windows (cleanmgr.exe) to clean temp before looking for changes?" 'N'

while ($true) {
    $hourstocheck = Read-Host "Enter the hours to add to Now to look for changes: [default -3]" 
    if (!$hourstocheck) { $hourstocheck = -3 }
    if ([Int] $hourstocheck -ge 0) { Write-Host "The number of hours to look back must be a negative number." -ForegroundColor Red }
    else { break }
}

# Options: What drives to scan 
$driveStringPrompt = "Which drive? (ALL/" + ((@($Drives) -replace ':') -join '/') + "): [default ALL]"
$WhichDrive = $(Read-Host $driveStringPrompt).ToUpper()
if (!$WhichDrive) { $WhichDrive = 'ALL' }

$validDrives = @('ALL') + ($Drives -replace ':')  
if (-not ($validDrives -contains $WhichDrive)) { $WhichDrive = 'ALL'}

# Options: What file types to look for
$CheckFor = $(Read-Host "Check for ALL, any IMaGe type, just PNG, or any EXEcutable type (ALL/IMG/PNG/EXE)?: [default IMG]").ToUpper()
if ($CheckFor -ieq '') { $CheckFor = 'IMG' }
if ($CheckFor -notin @('ALL', 'IMG', 'PNG', 'EXE')) { $CheckFor = 'IMG' }

# Options: Scan hidden files - can have x3 slowdown
$CheckHidden = getYNinput "Look for hidden files? (NB: If Y will be slower due to access errors)" 'Y'

# Options: Size
$CheckForSizeMin = Read-Host "Look only for files that are larger than n bytes?: [default 0]"
if ( $CheckForSizeMin -ieq '' ) { $CheckForSizeMin = '0' }
$CheckForSizeMax = Read-Host "Look only for files that are smaller than n bytes?: [default -1 (not limited)]"
if ( $CheckForSizeMax -ieq '' ) { $CheckForSizeMax = '-1'}

# Options: Apply Filter - different default dependng if all drives scan is requested
if ($CheckFor -ne 'ALL') { 
    $FilterApp = getYNinput "Apply filter? (NB: Default N due to ALL not specified)" 'N'
}
else { 
    $FilterApp = getYNinput "Apply filter?" 'Y' 
}

# Options: Highlighted files - different default depending on file type requested
$ShowHighlights = getYNinput "Highlight key changed file types at end?" 'Y'
$CopyHighlights = 'N'
if ($ShowHighlights -ieq 'Y') { 
    $chiprmt = "Copy highlighted files to an output directory?"
    if ($CheckFor -ieq 'IMG' -or $CheckFor -ieq 'PNG') 
         { $CopyHighlights = getYNinput $chiprmt 'Y' }
    else { $CopyHighlights = getYNinput $chiprmt 'N' }
}

$CopyMetaInfo = 'N'
if ($CopyHighlights -ieq 'Y') { 
    $cmiprmt = "Create a [fn].meta.json with path info for each copied highlighted file an output directory?"
    if ($CheckFor -ieq 'IMG' -or $CheckFor -ieq 'PNG') 
         { $CopyMetaInfo = getYNinput $cmiprmt 'N' }
    else { $CopyMetaInfo = getYNinput $cmiprmt 'Y' }
}

$CopyReportErrors = 'N'
if ($CopyHighlights -ieq 'Y') { 
    $CopyReportErrors = getYNinput "Report errors when copying highlighted files to an output directory?" 'N'
}

# Do Clean
if ( $cleantempfiles -ieq 'Y' ) { 
    Write-Host "Cleaning temp files with cleanmgr..." -ForegroundColor Green
    Start-Process "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait 
}

# Message to say what the scan will be doing
$hoursago = (Get-Date).AddHours($hourstocheck)

$msghid = if ($CheckHidden -eq 'Y') { "including hidden files" } else { "excluding hidden files" }
$maxmsg = if ($CheckForSizeMax -eq '-1') { "no maximum size" } else { "maximum size $CheckForSizeMax bytes" }
$msgflt = if ($FilterApp -eq 'Y') { "with filter applied." } else { "with no filter applied." }
$metaCt = if ($CopyMetaInfo -eq 'Y') { "created." } else { "not created." }
$msgchi = if ($CopyHighlights -eq 'Y') { "and will be copied to an output directory."} else { "only." }

$TransLog = New-TemporaryFile
Start-Transcript -Path $TransLog -Append | Out-Null

Write-Host "`n[INFO] Scanning using values..." -ForegroundColor Green
if ($WhichDrive -eq 'ALL') { Write-Host " - Drives: $Drives" } else { Write-Host " - Drives:" $WhichDrive}
Write-Host " - File types: $CheckFor"
Write-Host " - Hidden files: $msghid"
Write-Host " - Time modified after: $hoursago"
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
#Invoke-SingleDriveScan -WhichDrive $WhichDrive -OutputFile $OutputFile -hoursago $hoursago -FilterApp $FilterApp -CheckFor $CheckFor -TempUFAll $TempUFAll -CheckForSizeMin $CheckForSizeMin -CheckForSizeMax $CheckForSizeMax -CheckHidden $CheckHidden

# Do the scan and get the results with multiple threads to improve time taken
Invoke-DriveScan -Drives $drivestoscan -OutputFile $OutputFile -hoursago $hoursago -FilterApp $FilterApp -CheckFor $CheckFor -TempUFAll $TempUFAll -CheckForSizeMin $CheckForSizeMin -CheckForSizeMax $CheckForSizeMax -CheckHidden $CheckHidden

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

Stop-Transcript | Out-Null
# remove junk start transcript / end transcript adds - todo consider not using transcript 
&{
    (Get-Content $TransLog | Select-Object -SkipLast 4) | Set-Content $TransLog
    $lines = [System.Collections.Generic.List[string]] (Get-Content $TransLog)
    $startIndex = $lines.FindIndex({ param($line) $line -match '\[INFO\]' })
    if ($startIndex -ge 0) { $lines.GetRange($startIndex, $lines.Count - $startIndex) | Set-Content $TransLog }

    # add transcript to output
    $transContent  = Get-Content -Path $TransLog
    $outputContent = Get-Content -Path $OutputFile
    # Combine: trans first, then output
    $combined = $transContent + @("") + $outputContent

    # Overwrite the output file with combined content
    $combined | Set-Content -Path $OutputFile
    if (test-path $TransLog) { Remove-Item $TransLog }
}

if (test-path $TempUFAll) { Remove-Item $TempUFAll }


# relocate the output results into results directory with any highlited files
if (Test-Path $OutputFile) {
    relocateoutput -OutputFile $OutputFile -resfldpath $resfldpath -fndirsep $fndirsep
} else { Write-Host "No results found."}

clearpressedkeys
read-host "Press ENTER to continue"