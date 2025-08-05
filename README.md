Certainly! Here’s your document formatted in **Markdown** using code and info sections as appropriate for a PowerShell project readme or documentation file (e.g. `README.md`):

# scanforchangeshours_fv2

**PowerShell scripts to search for files changed on all, or a single, local drive within the last X hours using multiple threads.**

## Purpose

Useful when diagnosing system changes or locating lost files.  
Scenarios include:

- You just saved a file and can't find it.
- You did an install and can't find the package location.
- You are seeing a fault on your system but have not changed anything.
- Checking if a virus or unknown application installed a file.

The script can search for different file types and provides these functions:

### Core Functions

1. **List Changed Files**  
   List all files changed on all (or specified) drives in the last X hours. Writes results to a file in the output directory.

2. **Highlight & Copy Important Files**  
   For "highlighted" file types (pre-defined), copies changed files to an output directory for inspection.

   - Output directory: created in your Downloads folder, begins with `sfc-`
   - Optionally: for every copied file, generates a `[filename].meta.json` file with the original location.
  
## Example of start of script

![My diagram](example1.png)

## Usage Notes

> After Win11 H2 update, PowerShell scripts may not run by default.  
> You must open a PowerShell terminal to run scripts with bypassed execution policy, or use a batch file or Visual Studio Code.

#### Examples

**From PowerShell terminal:**  
```powershell
powershell -ExecutionPolicy ByPass -File .\scanforchangeshours_fv2.ps1
```
**From Batch File (`runfindfile.bat`):**  
```batch
powershell -ExecutionPolicy ByPass -File .\scanforchangeshours_fv2.ps1
```
**From Visual Studio Code:**  
Run the script directly within VS Code.

### Additional Notes

- **Processing Hidden Files:** Script can be up to 3x slower when including hidden files, especially if not running as admin (access denied errors).
- **Result Folders:** If you run the script multiple times without deleting previous results, the output may be scanned again. This is intentional—to avoid missing new or changed result files.
- **PowerShell Version:** Only works reliably with **PowerShell 5.1**, due to threading issues in 7.x.  
  Check your version with:
  ```powershell
  Write-Host $($PSVersionTable.PSVersion)
  ```
- See the top of the scanforchangeshours_fv2.ps1  for more notes.

### Update History

- **2025-08-05:** Initial version

## License

> Licensed under: **CC BY-NC-SA 4.0**  
> This software is provided 'as-is', without any express or implied warranty. In no event will the author be held liable for any damages arising from the use of this software.
