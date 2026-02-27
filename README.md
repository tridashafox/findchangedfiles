# scanforchangeshours_fv2

**PowerShell scripts to search for files changed on all, or a single, local drive within the last X hours using multiple threads.**

## Purpose

Useful when diagnosing system changes or locating lost files.  
Scenarios include:

- You just saved a file and can't find it.
- You did an install and can't find the package location.
- You are seeing a fault on your system but have not changed anything.
- Checking if a virus or unknown application installed a file.
- Understanding which files are being writting to verbosely (Adoble I'm looking at you)

The script can search for different file types and provides these functions:

### Core Functions

1. **List Changed Files**

   List all files changed on all (or specified) drives in the last X hours. Writes results to a file in the output directory.

3. **Highlight & Copy Important Files**
    
   For "highlighted" file types (pre-defined), copies changed files to an output directory for inspection.

   - Output directory: created in your Downloads folder, begins with `sfc-`
   - Optionally: for every copied file, generates a `[filename].meta.json` file with the original location.
     
4. **Filters**
   
   Filters can applied to exclude directories from both List Changed Files and Highlight & Copy Important Files operations.

   - Directories to exclude are specified in a .txt file with each directory, e.g. C:\WINDOWS\ on a seperate line

5. **Directory Count Summary**
   
   A total of changed files is rolled up for a directory path with a specified depth.
  
<!-- ## Example script run -->

<!-- ![My diagram](example1.png) -->
<!--     --snip-- -->

## Usage Notes

The script will ask for all the options, or they can be passed as switches on the command line. They are:

| Parameter          | Type   | Description                                                                                                                                                    | Default |
| ------------------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| SingleThreaded     | string | Y means run process in single thread, useful for debugging. Only prompted for if debugger detected and not specified. Defaults to Y if debugger otherwise N    | N       |
| ModDefault         | string | Y means the below changes the default rather than passes the value.                                                                                            | N       |
| CleanTempFiles     | string | Y to run Windows cleanmgr before running scan.                                                                                                                 | N       |
| HoursToCheck       | double | Number of hours to look back for changes (e.g. -3 means last 3 hours, -0.5 means last half-hour). If positive, looks for changed files before specified hours. | -3      |
| WhichDrive         | string | Drive to scan, or ‘ALL’ for all drives.                                                                                                                        | ALL     |
| CheckFor           | string | Which types of files to check: ALL, IMG (images), EXT (specific extension), EXE (executables).                                                                 | ALL     |
| CheckForExt        | string | Specific extension to scan for (without the .). Used when CheckFor = EXT.                                                                                      | EXE     |
| CheckHidden        | string | Y to include hidden files in the scan.                                                                                                                         | N       |
| CheckForSizeMin    | int    | Include files above this minimum size (in bytes).                                                                                                              | 0       |
| CheckForSizeMax    | int    | Include files below this maximum size (in bytes). Use -1 for no limit.                                                                                         | -1      |
| FilterApp          | string | Y to apply a filter that excludes certain directories from scan results.                                                                                       | N       |
| ScanFilterfn       | string | File name containing a list of directories to exclude during scanning (used when FilterApp = Y).                                                               | —       |
| ShowDirCounts      | int    | Shows a roll up total of found files by directory. 0 - don't show, otherwise depth to use for roll up.                                                         | 4       |
| ShowHighlights     | string | Y to list key file types that changed.                                                                                                                         | Y       |
| CopyHighlights     | string | Y to copy highlighted files to a temporary directory in Downloads.                                                                                             | N       |
| HighlightFilter    | string | Y to apply a filter excluding certain directories from highlighted files.                                                                                      | N       |
| HighlightFilterfn  | string | File name with list of directories to exclude from highlighted results.                                                                                        | —       |
| CopyMetaInfo       | string | Y to create a JSON file with metadata for each highlighted file.                                                                                               | N       |
| CopyReportErrors   | string | Y to log errors during ShowHighlights into the results file.                                                                                                   | N       |
| FilterZeroLenFiles | string | Y to filter out zero length files.                                                                                                                             | Y       |
| WaitOnExit         | string | Y Wait for enter to be pressed before ending. Not prompted for.                                                                                                | Y       |

`File groups` are sets of extensions not an actual extensions
| Parameter | Extensions  |
|-----------|-------------|
| `ALL`     | all extensions |
| `IMG`     | BMP, GIF, JPG, JPEG, PNG, TIF, TIFF, ICO, DDS, MP4, MOV, WEBM, AVI, WMV, WEBP, AFPHOTO, PSD, PIC |
| `EXE`     | BAT, PS1, BIN, CMD, COM, CPL, EXE, GADGET, INF1, INS, INX, ISU, JOB, JSE, LNK, MSC, MSI, MSP, MST, PAF, PIF, PS1, REG, RGS, SCR, SCT, SHB, SHS, U3P, VB, VBE, VBS, VBSCRIPT, WS, WSF, WSH |
| `EXT`     | A single extension to look for as defined in `CheckForExt`. Do not include the `'.'` prefix when specifing  `CheckForExt`. |

### Example 1 - find all files changed in last 3 hours (no highlited files, no directory roll up counts). Will run without promptin.

`powershell -File "scanforchangeshours_fv2.ps1" -CleanTempFiles N -HoursToCheck -3 -WhichDrive ALL -CheckFor ALL -CheckHidden Y -CheckForSizeMin 0 -CheckForSizeMax -1 -FilterApp N -ShowDirCounts 0 -ShowHighlights Y -HighlightFilter N -CopyHighlights N -CopyMetaInfo N -CopyReportErrors N -FilterZeroLenFiles Y`

### Example 2 - run with prompting but change one of the defaults

`powershell -File "scanforchangeshours_fv2.ps1" -ModDefault Y -CheckFor EXE `

### Notes
- **Processing Hidden Files:** Script can be up to 3x slower when including hidden files, especially if not running as admin (access denied errors).
- **Result Folders:** If you run the script multiple times without deleting previous results, the output may be scanned again. This is intentional.
- **PowerShell Version:** Only works reliably with **PowerShell 5.1**, due to threading issues in 7.x.  
  Check your version with:
  ```powershell
  Write-Host $($PSVersionTable.PSVersion)
  ```
- See the top of the scanforchangeshours_fv2.ps1 for more notes.
- This project does not have dedicated support. Any issues are unlikely to be fixed in a timely fashion

## Update History

- **2025-08-05:** Initial version
- **2026-02-24:** Updates to how filtering works, directory summary counts added

## License

> Licensed under: As specified in git repo - CC0-1.0 license
> This software is provided 'as-is', without any expressed or implied warranty. In no event will the author be held liable for any damages arising from the use of this software. This holds true overtop of any statements in the license.
