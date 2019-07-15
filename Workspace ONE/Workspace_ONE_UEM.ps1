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

Function LogintoWSO {

#Get Values from User
$script:WSOServer = Read-Host -Prompt 'Enter the Workspace ONE UEM Server Name'
$Username = Read-Host -Prompt 'Enter the Username'
$Password = Read-Host -Prompt 'Enter the Password' -AsSecureString
$apikey = Read-Host -Prompt 'Enter the API Key'
$og = Read-Host -Prompt 'Enter the Organization Group Name'

#Convert the Password
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

$URL = $AirwatchServer + "/api"

#Base64 Encode AW Username and Password
$combined = $Username + ":" + $UnsecurePassword
$encoding = [System.Text.Encoding]::ASCII.GetBytes($combined)
$cred = [Convert]::ToBase64String($encoding)


$header = @{
    "Authorization"  = "Basic $cred";
    "aw-tenant-code" = $apikey;
    "Accept"		 = "application/json";
    "Content-Type"   = "application/json";}

$Credentials = '{"username":"' + $username + '","password":"' + $unsecurepassword + '","domain":"' + $domain + '"}'

#Login to AppVolumes
try {
    
  $sresult = Invoke-RestMethod -Method Post -Uri "https://$appvolserver/cv_api/sessions" -Body $Credentials -ContentType "application/json" -SessionVariable avsession  

}

catch {
  Write-Host "An error occurred when logging on $_"
  break
}

#Logged In
$sresult | Format-List
write-host "Successfully Logged In"

#Save the AV session state to a varable - contains cookies with session information
$script:AVSession = $avsession

  } 


function Show-Menu
  {
    param (
          [string]$Title = 'VMware Workspace ONE UEM API Menu'
          )
       Clear-Host
       Write-Host "================ $Title ================"
       Write-Host "Press '1' to Login to Workspace ONE UEM"
       Write-Host "======AppStack Operations======"
       Write-Host "Press '2' for a List of AppStacks"
       Write-Host "Press '3' for AppStack Details"
       Write-Host "Press '4' for a List of Applications in an AppStack"
       write-host "======Writable Volume Operations======"
       Write-Host "Press '5' for Writable Volumes"
       Write-Host "Press '6' for a List of Applications in an AppStack"
       Write-Host "======System Information======"
       Write-Host "Press '7' for the Activity Log"
       Write-Host "Press '8' for Online Entities"
       Write-Host "Press 'Q' to quit."
         }

do

 {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    
    '1' {  

         LogintoWSO
    } 
    
    '2' {
   
         ListAppStacks

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