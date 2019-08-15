<#
.SYNOPSIS
  Script to update the size of VMware App Volumes Writable Volumes.  Can also be used to view sizes of volumes.
	
.OUTPUTS
  Log file stored in %temp%\expand-wv.log>

.NOTES
  Version:        1.0
  Author:         Chris Halstead - chalstead@vmware.com
  Creation Date:  4/8/2019
  Purpose/Change: Initial script development
  **This script and the App Volumes API is not supported by VMware**
  New sizes won't be reflected until a user logs in and attaches the Writable Volume	
  
#>


#----------------------------------------------------------[Declarations]----------------------------------------------------------
#Log File Info
$sLogPath = $env:TEMP 
$sDomain = $env:USERDOMAIN
$sUser = $env:USERNAME
$sComputer = $env:COMPUTERNAME
$sLogName = "Horizon.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName
$sLogTitle = "Starting Script as $sdomain\$sUser from $scomputer***************"
Add-Content $sLogFile -Value $sLogTitle
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


#-----------------------------------------------------------[Functions]------------------------------------------------------------
Function Write-Log {
    [CmdletBinding()]
    Param(
    
    [Parameter(Mandatory=$True)]
    [System.Object]
    $Message

    )
    $Stamp = (Get-Date).toString("MM/dd/yyyy HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    Add-Content $sLogFile -Value $Line
   
    }

Function SearchForDevices {

if ([string]::IsNullOrEmpty($wsoserver))
  {
    $script:WSOServer = Read-Host -Prompt 'Enter the Workspace ONE UEM Server Name'
    
  }
 if ([string]::IsNullOrEmpty($header))
  {
    $Username = Read-Host -Prompt 'Enter the Username'
    $Password = Read-Host -Prompt 'Enter the Password' -AsSecureString
    $apikey = Read-Host -Prompt 'Enter the API Key'

    #Convert the Password
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    #Base64 Encode AW Username and Password
    $combined = $Username + ":" + $UnsecurePassword
    $encoding = [System.Text.Encoding]::ASCII.GetBytes($combined)
    $cred = [Convert]::ToBase64String($encoding)

    $script:header = @{
    "Authorization"  = "Basic $cred";
    "aw-tenant-code" = $apikey;
    "Accept"		 = "application/json;version=2";
    "Content-Type"   = "application/json";}
  }

$user = Read-Host -Prompt 'Enter a user name to show devices'

try {
    
  $sresult = Invoke-RestMethod -Method Get -Uri "https://$wsoserver/api/mdm/devices/search?user=$user" -ContentType "application/json" -Header $header

}

catch {
  Write-Host "An error occurred when logging on $_"
  break
}


foreach ($id in $sresult.devices.uuid) {

  try {
    
    $device = Invoke-RestMethod -Method Get -Uri "https://$wsoserver/API/mdm/devices/$id" -ContentType "application/json" -Header $header
    $device | format-table -Property @{Name = 'Username'; Expression = {$_.enrollmentinfo.username}},FriendlyName,@{Name = 'OS'; Expression = {$_.platforminfo.osversion}},DataEncrypted,@{Name = 'Enrollment Status'; Expression = {$_.enrollmentinfo.enrollmentstatus}}

  }
  catch {
    
    Write-Host "An error occurred when getting device $_"
    break

  }
  
}

} 

Function SearchForGroups {

  if ([string]::IsNullOrEmpty($wsoserver))
    {
      $script:WSOServer = Read-Host -Prompt 'Enter the Workspace ONE UEM Server Name'
      
    }
   if ([string]::IsNullOrEmpty($header))
    {
      $Username = Read-Host -Prompt 'Enter the Username'
      $Password = Read-Host -Prompt 'Enter the Password' -AsSecureString
      $apikey = Read-Host -Prompt 'Enter the API Key'
  
      #Convert the Password
      $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
      $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
  
      #Base64 Encode AW Username and Password
      $combined = $Username + ":" + $UnsecurePassword
      $encoding = [System.Text.Encoding]::ASCII.GetBytes($combined)
      $cred = [Convert]::ToBase64String($encoding)
  
      $script:header = @{
      "Authorization"  = "Basic $cred";
      "aw-tenant-code" = $apikey;
      "Accept"		 = "application/json";
      "Content-Type"   = "application/json";}
    }
  
  $group = Read-Host -Prompt 'Enter a group name'
  
  try {
      
    $sresult = Invoke-RestMethod -Method Get -Uri "https://$wsoserver/API/system/groups/search?name=$group" -Body $Credentials -ContentType "application/json" -Header $header
  
  }
  
  catch {
    Write-Host "An error occurred when logging on $_"
    break
  }
  
if ($sresult.total -eq 0) {

  Write-Host "No Results"
  break

}

  #Logged In
  $sresult.LocationGroups | Format-table -AutoSize 
  
  } 
  
  

function Show-Menu
  {
    param (
          [string]$Title = 'VMware Workspace ONE UEM API Menu'
          )
       Clear-Host
       Write-Host "================ $Title ================"
       Write-Host "Press '1' to show devices by username"
       Write-Host "Press '2' to show groups by name"
       Write-Host "Press '3' for AppStack Details"
       Write-Host "Press '4' for a List of Applications in an AppStack"
       Write-Host "Press 'Q' to quit."
         }

do

 {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    
    '1' {  

         SearchForDevices
    } 
    
    '2' {
   
         SearchForGroups

    }
    
    '3' {
       
         AppStackDetails
      
    }
'4' {
       
    AppStackApps
     
    }

'5' {
       
    Writables
 
}
'6' {
  
 AppStackApps

}

'7' {
  
Activity_Log
 
 }

 '8' {
  
  Get_Online

}

    }
    pause
 }
 until ($selection -eq 'q')


Write-Log -Message "Finishing Script******************************************************"
Write-Host "Finished"