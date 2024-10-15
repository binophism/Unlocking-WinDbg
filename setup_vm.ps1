function Show-LastException {
    Write-Host "Exception occurred"
    $errorMsg = $_.Exception.Message
    Write-Host $errorMsg
}


function Add-ToPath {
    param (
        [string]$name,
        [string]$pathToAdd
    )
    $currentPath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($currentPath -like "*$pathToAdd*") {
        Write-Host "$name already in PATH"
        return
    }

    Write-Host "Adding $name to PATH..."
    $newPath = "$currentPath;$pathToAdd"
    [System.Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
}

function Install-7zip {
    $zipPath = "C:\Program Files\7-Zip"
    if (Test-Path $zipPath) {
        Write-Host "7-Zip already installed"
        return
    }

    Write-Host "Installing 7-Zip..."
    try {
        Invoke-WebRequest -Uri "https://www.7-zip.org/a/7z2408-x64.exe" -OutFile "$env:USERPROFILE\Downloads\7z2408-x64.exe"
        Start-Process -FilePath "$env:USERPROFILE\Downloads\7z2408-x64.exe" -ArgumentList "/S" -Wait
    } catch {
        Show-LastException
    }
}


function Install-Notepadpp {
    $nppPath = "C:\Program Files\Notepad++"
    if (Test-Path $nppPath) {
        Write-Host "Notepad++ already installed"
        return
    }

    Write-Host "Installing Notepad++..."
    try {
        Invoke-WebRequest -Uri "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7/npp.8.7.Installer.x64.exe" -OutFile "$env:USERPROFILE\Downloads\npp.8.7.Installer.x64.exe"
        Start-Process -FilePath "$env:USERPROFILE\Downloads\npp.8.7.Installer.x64.exe" -ArgumentList "/S" -Wait
    } catch {
        Show-LastException
    }
}



function Install-Sysinternals {
    $sysinternalsPath = "$env:USERPROFILE\Desktop\Tools\SysinternalsSuite"
    if (Test-Path $sysinternalsPath) {
        Write-Host "Sysinternals tools already installed"
        return
    }

    Write-Host "Installing Sysinternals tools..."
    try {
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "$env:USERPROFILE\Downloads\SysinternalsSuite.zip"
        Expand-Archive -Path "$env:USERPROFILE\Downloads\SysinternalsSuite.zip" -DestinationPath $sysinternalsPath
    } catch {
        Show-LastException
    }
}

function Setup-WindowsDefender {
    $exclusion = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
    if ($exclusion -contains "$env:USERPROFILE\Downloads") {
        Write-Host "Windows Defender already setup"
        return
    }

    Write-Host "Setting up Windows Defender..."
    try {
        Add-MpPreference -ExclusionPath "$env:USERPROFILE\Desktop"
        Add-MpPreference -ExclusionPath "$env:USERPROFILE\Downloads"
    } catch {
        Show-LastException
    }
}


function Disable-AutoUpdate {

    try {
        Stop-Service -Name wuauserv -Force
        Write-Host "Stopping Windows Update service..."
        Set-Service -Name wuauserv -StartupType Disabled
        Write-Host "Disabling Windows Update service startup..."
        $service = Get-Service -Name wuauserv
        if ($service.Status -eq 'Stopped' -and $service.StartType -eq 'Disabled') {
            Write-Host "Windows Update service has been successfully disabled."
        } else {
            Write-Host "Failed to disable Windows Update service."
        }
    } catch {
        Write-Host "An error occurred while disabling Windows Update service."
        Show-LastException
    }
}



function Install-ProcessHacker {
    $phPath = "C:\Program Files\Process Hacker 2"
    if (Test-Path $phPath) {
        Write-Host "Process Hacker already installed"
        return
    }

    Write-Host "Installing systeminformer..."
    try {
        Invoke-WebRequest -UserAgent "Wget" -Uri "https://sourceforge.net/projects/systeminformer/files/latest/download" -OutFile "$env:USERPROFILE\Downloads\systeminformer-3.0.7660-release-setup.exe"
        Start-Process -FilePath "$env:USERPROFILE\Downloads\systeminformer-3.0.7660-release-setup.exe" -ArgumentList "/SILENT" -Wait
    } catch {
        Show-LastException
    }
}


function Install-Ghidra {
    $ghidraPath = "$env:USERPROFILE\Desktop\Tools\ghidra_11.2_PUBLIC"
    if (Test-Path $ghidraPath) {
        Write-Host "Ghidra already installed"
        return
    }

    Write-Host "Installing Ghidra..."
    try {
        Invoke-WebRequest -Uri "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20240926.zip" -OutFile "$env:USERPROFILE\Downloads\ghidra_11.2_PUBLIC.zip"
        Expand-Archive -Path "$env:USERPROFILE\Downloads\ghidra_11.2_PUBLIC.zip" -DestinationPath "$env:USERPROFILE\Desktop\Tools\"
    } catch {
        Show-LastException
    }
}

function Setup-Symbols {
    if (-not [System.Environment]::GetEnvironmentVariable("_NT_SYMBOL_PATH", "Machine")) {
        Write-Host "Setting up symbols..."
        Start-Process "setx" -ArgumentList "/M", "_NT_SYMBOL_PATH", "SRV*c:\symbols*http://msdl.microsoft.com/download/symbols" -Wait
        Write-Host "Symbols setup complete, restart might be needed."
    } else {
        Write-Host "Symbols are already set."
    }
}

function Replace-TaskManager-With-ProcExp {

    $procexpPath = "$env:USERPROFILE\Desktop\Tools\SysinternalsSuite\procexp64.exe"
    if (-Not (Test-Path $procexpPath)) {
        Write-Host "Error: Process Explorer not found at the specified path: $procexpPath"
        Show-LastException
    }

    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" -Name Debugger -Value $procexpPath
        Write-Host "Task Manager has been replaced with Process Explorer."
    } catch {
        Write-Host "Failed to replace Task Manager with Process Explorer."
        Show-LastException
    }
}

function Install-VisualStudio {
    if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community") {
        Write-Host "Visual Studio already installed"
    } else {
        Write-Host "Installing Visual Studio..."
        try {
            Invoke-WebRequest -Uri "https://download.visualstudio.microsoft.com/download/pr/5c555b0d-fffd-45a2-9929-4a5bb59479a4/7a92444b6df4ad128e5eaf1e787fa6fe0fe8e86ba039e37b98b8be6bcc0ea878/vs_Community.exe" -OutFile "$env:USERPROFILE\Downloads\vs_Community.exe"
            Start-Process -FilePath "$env:USERPROFILE\Downloads\vs_Community.exe" -ArgumentList "--wait", "--passive", "--add", "Microsoft.VisualStudio.Workload.NativeDesktop;includeRecommended" -Wait
            Write-Host "Visual Studio installed successfully"
        } catch {
            Write-Host "Visual Studio installation failed"
            Show-LastException
        }
    }
}

function Install-Git {
    if (Test-Path "C:\Program Files\Git") {
        Write-Host "Git already installed"
    } else {
        Write-Host "Installing Git..."
        try {
            Invoke-WebRequest -Uri "https://github.com/git-for-windows/git/releases/download/v2.47.0.windows.1/Git-2.47.0-64-bit.exe" -OutFile "$env:USERPROFILE\Downloads\Git-2.47.0-64-bit.exe"
            Start-Process -FilePath "$env:USERPROFILE\Downloads\Git-2.47.0-64-bit.exe" -ArgumentList "/SILENT" -Wait
            Write-Host "Git installed successfully"
        } catch {
            Write-Host "Git installation failed"
            Show-LastException
        }
    }
}

function Add-GitToPath {
    Add-ToPath -name "Git" -path "C:\Program Files\Git\bin\"
}

function Check-WinDbg {
    if (-not (Test-Path "$env:USERPROFILE\AppData\Local\Microsoft\WindowsApps\WinDbgX.exe")) {
        Write-Host "WinDbg Preview is not installed. Please install it manually from the Microsoft Store."
    }
}
function Install-WinMerge {
    if (Test-Path "C:\Program Files (x86)\WinMerge") {
        Write-Host "WinMerge already installed"
    } else {
        Write-Host "Installing WinMerge..."
        try {
            Invoke-WebRequest -Uri "https://github.com/WinMerge/winmerge/releases/download/v2.16.42.1/WinMerge-2.16.42.1-Setup.exe" -OutFile "$env:USERPROFILE\Downloads\WinMerge-2.16.42.1-Setup.exe"
            Start-Process -FilePath "$env:USERPROFILE\Downloads\WinMerge-2.16.42.1-Setup.exe" -ArgumentList "/SILENT" -Wait
            Write-Host "WinMerge installed successfully"
        } catch {
            Write-Host "WinMerge installation failed"
            Show-LastException
        }
    }
}
$RETSYNC_INSTALL_DIR = "$env:USERPROFILE\Desktop\tools\ret-sync"
$sync_dll = "$env:USERPROFILE\Desktop\Tools\ret-sync\ext_windbg\sync\x64\Release\sync.dll"
$windbg_preview_path = "$env:USERPROFILE\AppData\Local\Microsoft\WindowsApps\sync.dll"
function Install-RetSync {
    if (Test-Path $windbg_preview_path) {
        Write-Host "ret-sync already installed"
        return
    }

    if (!(Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "Git not installed or not in PATH. You may have to restart PowerShell too. Then restart this script."
        exit 1
    }

    if (!(Test-Path $RETSYNC_INSTALL_DIR)) {
        try {
            Start-Process git -ArgumentList @("clone", "https://github.com/bootleg/ret-sync", $RETSYNC_INSTALL_DIR) -NoNewWindow -Wait

		} catch {
					Write-Host "ret-sync clone failed"
					exit 1
				}
			
	}
	$choice = Read-Host "Have you compiled retsync(ext_windbg)?(y/n): "
	if($choice -eq 'y')
		{
			if (!(Test-Path $sync_dll))
			{
				Write-Host "Could not build ret-sync"
				exit 1
			}
			Copy-Item -Path $sync_dll -Destination $windbg_preview_path
			Write-Host "Launch WinDbg on target"
			Write-Host "Load extension (.load command): .load sync"
		}
        
}
function Install-RetSync-ida{
        if (Test-Path "$env:USERPROFILE\AppData\Roaming\Hex-Rays\IDA Pro\plugins\SyncPlugin.py")
        {
			Write-Host "ida ret-sync already installed"
			return
        }
		try
		{
			$sourceFile = "$env:USERPROFILE\Desktop\Tools\ret-sync\ext_ida\SyncPlugin.py"
			$sourceFolder = "$env:USERPROFILE\Desktop\Tools\ret-sync\ext_ida\retsync"
			$destinationPath = "$env:USERPROFILE\AppData\Roaming\Hex-Rays\IDA Pro\plugins"
			if (!(Test-Path -Path $destinationPath))
			{
				New-Item -Path $destinationPath -ItemType Directory
			}
			Copy-Item -Path $sourceFile -Destination $destinationPath
			Copy-Item -Path $sourceFolder -Destination $destinationPath -Recurse
		}catch
		{
			Show-LastException
		}

}
function Setup-VM {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Host "This script must be run as administrator!"
        exit 1
    }
    Write-Host "Possible targets:"
    Write-Host "1. Target/Debuggee VM"
    Write-Host "2. Development/Debugger VM"
    $choice = Read-Host "What VM are you installing? [1/2]"

    if ($choice -eq '1') {
        Disable-AutoUpdate
        Install-7zip
        Install-Notepadpp
        Install-ProcessHacker
        Setup-WindowsDefender
        Install-Sysinternals
    } elseif ($choice -eq '2') {
        Setup-Symbols
        Disable-AutoUpdate
        Setup-WindowsDefender
        Install-7Zip
        Install-NotepadPP
        Install-Sysinternals
        Replace-TaskManager-With-ProcExp
        Install-VisualStudio
        Install-Git
        Add-GitToPath
        Install-Ghidra
        Check-WinDbg
        Install-RetSync
        Install-RetSync-ida
    } else {
        Write-Host "Invalid choice"
        exit 1
    }

    Write-Host "All done, you are good to go!"
}

Setup-VM
