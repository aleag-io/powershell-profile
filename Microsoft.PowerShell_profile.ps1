
New-Alias -Name subli -Value "C:\Program Files\Sublime Text 3\sublime_text.exe" -ErrorAction SilentlyContinue
New-Alias -Name np -value "C:\Windows\System32\notepad.exe" -ErrorAction SilentlyContinue
New-Alias -Name grep -value "Select-String" -ErrorAction SilentlyContinue

# Set-Location based on if it is the home computer or the work computer. 

$oneDrivePath = $env:userprofile + "\OneDrive\WindowsPowerShell"
if((test-path x:) -eq $true){
	$oneDrivePath = $oneDrivePath.Replace("C", "X")
	cd $oneDrivePath
}else
{
	cd ($env:userprofile + "\OneDrive\WindowsPowerShell")
}

Import-Module posh-git
Import-Module oh-my-posh
Set-Theme Paradox

#set-location $env:USERPROFILE\OneDrive\WindowsPowerShell

## $shell.BackgroundColor = “Gray"




 #clear-host

# $Guy = $env:Username.ToUpper()
#Write-Verbose "You are now entering PowerShell as $Guy" -Verbose




#Set-Location D:\Documents\xxxxxx\PERSONNEL\powerscripts
$Shell=$Host.UI.RawUI
$size=$Shell.BufferSize
#$size.width=180
$size.height=9999
$Shell.BufferSize=$size
$size=$Shell.WindowSize
$size.width=120
$size.height=30
#$Shell.WindowSize=$size

 
#$Shell.BackgroundColor="Black"
#$Shell.ForegroundColor="White"
#$Shell.CursorSize=10
 
function Get-Time {return $(Get-Date | ForEach {$_.ToLongTimeString()})}
function prompt
{
    Write-Host "[" -noNewLine
    Write-Host $(Get-Time) -ForegroundColor DarkYellow -noNewLine
    Write-Host "] " -noNewLine
    Write-Host $($(Get-Location).Path.replace($home,"~")) -ForegroundColor DarkGreen -noNewLine
    Write-Host $(if ($nestedpromptlevel -ge 1) { '>>' }) -noNewLine
    return "> "
}
 
function ll
{
    param ($dir = ".", $all = $false)
 
    $origFg = $Host.UI.RawUI.ForegroundColor
    if ( $all ) { $toList = ls -force $dir }
    else { $toList = ls $dir }
 
    foreach ($Item in $toList)
    {
        Switch ($Item.Extension)
        {
            ".exe" {$Host.UI.RawUI.ForegroundColor="DarkYellow"}
            ".hta" {$Host.UI.RawUI.ForegroundColor="DarkYellow"}
            ".cmd" {$Host.UI.RawUI.ForegroundColor="DarkRed"}
            ".ps1" {$Host.UI.RawUI.ForegroundColor="DarkGreen"}
            ".html" {$Host.UI.RawUI.ForegroundColor="Cyan"}
            ".htm" {$Host.UI.RawUI.ForegroundColor="Cyan"}
            ".7z" {$Host.UI.RawUI.ForegroundColor="Magenta"}
            ".zip" {$Host.UI.RawUI.ForegroundColor="Magenta"}
            ".gz" {$Host.UI.RawUI.ForegroundColor="Magenta"}
            ".rar" {$Host.UI.RawUI.ForegroundColor="Magenta"}
            Default {$Host.UI.RawUI.ForegroundColor=$origFg}
        }
        if ($item.Mode.StartsWith("d")) {$Host.UI.RawUI.ForegroundColor="Gray"}
        $item
    }
    $Host.UI.RawUI.ForegroundColor = $origFg
}
 
function Edit-HostsFile {
    Start-Process -FilePath notepad -ArgumentList "$env:windir\system32\drivers\etc\hosts"
}
 
function rdp ($rdpHost) {
    Start-Process -FilePath mstsc -ArgumentList "/admin /w:1024 /h:768 /v:$rdpHost"
}
 
function tail ($file) {
Get-Content $file -Wait
}
 
function whoami {
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}
 
function Reload-Profile {
    @(
        $Profile.AllUsersAllHosts,
        $Profile.AllUsersCurrentHost,
        $Profile.CurrentUserAllHosts,
        $Profile.CurrentUserCurrentHost
    ) | % {
        if(Test-Path $_) {
            Write-Verbose "Running $_"
            . $_
        }
    }    
}

function uptime {
    #Get-CimInstance -ClassName win32_operatingsystem | select csname, lastbootuptime
    $now = Get-Date
    $lastBootUpTime = (Get-CimInstance -ClassName win32_operatingsystem).LastBootUpTime
    $uptime = $now - $lastBootUpTime
    $d =$uptime.days
	$h =$uptime.hours
	$m =$uptime.Minutes
	$s = $uptime.Seconds

    Write-Host "$d Days $h Hours $m Minutes $s Seconds'n"
}
 
function Check-SessionArch {
    if ([System.IntPtr]::Size -eq 8) { return "x64" }
    else { return "x86" }
}
 
function Test-Port {
[cmdletbinding()]
param(
[parameter(mandatory=$true)]
[string]$Target,
[parameter(mandatory=$true)]
[int32]$Port,
[int32]$Timeout=2000
)
$outputobj=New-Object -TypeName PSobject
$outputobj | Add-Member -MemberType NoteProperty -Name TargetHostName -Value $Target
if(Test-Connection -ComputerName $Target -Count 2) {$outputobj | Add-Member -MemberType NoteProperty -Name TargetHostStatus -Value "ONLINE"}
else
{$outputobj | Add-Member -MemberType NoteProperty -Name TargetHostStatus -Value "OFFLINE"}            
$outputobj | Add-Member -MemberType NoteProperty -Name PortNumber -Value $Port
$Socket=New-Object System.Net.Sockets.TCPClient
$Connection=$Socket.BeginConnect($Target,$Port,$null,$null)
$Connection.AsyncWaitHandle.WaitOne($timeout,$false) | Out-Null
if($Socket.Connected -eq $true) {$outputobj | Add-Member -MemberType NoteProperty -Name ConnectionStatus -Value "Success"}
else
{$outputobj | Add-Member -MemberType NoteProperty -Name ConnectionStatus -Value "Failed"}            
$Socket.Close | Out-Null
$outputobj | Select TargetHostName, TargetHostStatus, PortNumber, Connectionstatus | Format-Table -AutoSize
}
 
#Set-Alias powergui "C:\Program Files\PowerGUI\ScriptEditor.exe"
 
$MaximumHistoryCount=1024
$IPAddress=@(Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.DefaultIpGateway})[0].IPAddress[0]
$PSVersion=$host | Select-Object -ExpandProperty Version
$PSVersion=$PSVersion -replace '^.+@\s'
$SessionArch=Check-SessionArch
#$Shell.WindowTitle="AGPS $pwd ($SessionArch)"
 
#Clear-Host
 
Write-Host "`r`nsssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ssssssssss" -nonewline; Write-Host "`t`t`t`t`t`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ssss sssss`tHi Anoop!" -nonewline; Write-Host "`t`t`t`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "sss   ssss" -nonewline; Write-Host "`t`t`t`t`t`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ss     sss`tComputerName`t`t" -nonewline
Write-Host $($env:COMPUTERNAME) -nonewline; Write-Host "`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ssssssssss`tIP Address`t`t" -nonewline
Write-Host $IPAddress -nonewline; Write-Host "`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "         s`tUserName`t`t" -nonewline
Write-Host $env:UserDomain\$env:UserName -nonewline; Write-Host "`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ssssssssss`tPowerShell Version`t" -nonewline
Write-Host $PSVersion -nonewline; Write-Host "`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ssssssssss`tPowerShell Session`t" -nonewline
Write-Host $SessionArch -nonewline; Write-Host "`t`t`ts" -ForegroundColor Yellow
Write-Host "s" -ForegroundColor Yellow -nonewline; Write-Host "ssssssssss" -nonewline; Write-Host "`t`t`t`t`t`t`ts" -ForegroundColor Yellow
Write-Host "sssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss`n" -ForegroundColor Yellow

## Transcript
## Delete Transcripts older than 30 days

Write-Verbose ("[{0}] Initialize Transcript" -f (Get-Date).ToString()) -Verbose
If ($host.Name -eq "ConsoleHost") {
    $transcripts = (Join-Path $oneDrivePath "\Transcripts")
    If (-Not (Test-Path $transcripts)) {
        New-Item -path $transcripts -Type Directory | out-null
    }
    $global:TRANSCRIPT = ("{0}\PSLOG-{1}-{2:yyyy-MM-dd-hh-ss}.txt" -f $transcripts,$env:computername,(Get-Date))
    Start-Transcript -Path $transcript -Append | out-null
    Get-ChildItem $transcripts | Where {
        $_.LastWriteTime -lt (Get-Date).AddDays(-30)
    } | Remove-Item -Force -ea 0
}

$LogicalDisk = @()
Get-WmiObject Win32_LogicalDisk -filter "DriveType='3'" | % {
    $LogicalDisk += @($_ | Select @{n="Name";e={$_.Caption}},
    @{n="Volume Label";e={$_.VolumeName}},
    @{n="Size (Tb)";e={"{0:N2}" -f ($_.Size/1TB)}},
    @{n="Used (Tb)";e={"{0:N2}" -f (($_.Size/1TB) - ($_.FreeSpace/1TB))}},
    @{n="Free (Tb)";e={"{0:N2}" -f ($_.FreeSpace/1TB)}},
    @{n="Free (%)";e={if($_.Size) {"{0:N2}" -f (($_.FreeSpace/1TB) / ($_.Size/1TB) * 100 )} else {"NAN"} }})
  }
$LogicalDisk | Format-Table -AutoSize | Out-String




# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}
