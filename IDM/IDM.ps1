<#
.SYNOPSIS
  Script to update the size of VMware App Volumes Writable Volumes.  Can also be used to view sizes of volumes.
	
.INPUTS
  Parameters Below

.OUTPUTS
  Log file stored in %temp%\expand-wv.log>

.NOTES
  Version:        1.0
  Author:         Chris Halstead - chalstead@vmware.com
  Creation Date:  4/8/2019
  Purpose/Change: Initial script development
  **This script and the App Volumes API is not supported by VMware**
  New sizes won't be reflected until a user logs in and attaches the Writable Volume	
  
.EXAMPLE
 .\Expand-WV.ps1 
        -AppVolumesServerFQDN "avmanager.company.com"
        -AppVolumesDomain "mydomain" 
        -AppVolumesUser "Username" 
        -AppVolumesPassword "SecurePassword" 
        -New_Size_In_MB "40960" 
        -Update_WV_Size "yes" 

    .PARAMETER AppVolumesServerFQDN
    The FQDN of the App Volumes Manager where you want to view / change the Writable Volumes

    .PARAMETER AppVolumesDomain
    Active Directory Domain of the user with Administrative access

    .PARAMETER AppVolumesUser
    Active Directoty User with administrative access

    .PARAMETER AppVolumesPassword
    The password that is used by the user specified in the username parameter

    .PARAMETER New_Size_In_MB
    New size for the writable volumes in Megabytes. Take gigabytes and mutltiply by 1024.

    .PARAMETER Update_WV_Size
    Enter yes to update the sizes.  Type anything else for a list of writable volumes.
#>

[CmdletBinding()]
    Param(

        [Parameter(Mandatory=$True)]
        [string]$IDMClientID,
           
        [Parameter(Mandatory=$True)]
        [string]$IDMSharedSecret,

        [Parameter(Mandatory=$True)]
        [string]$IDMServer

)

#----------------------------------------------------------[Declarations]----------------------------------------------------------
#Log File Info
$sLogPath = $env:TEMP 
$sDomain = $env:USERDOMAIN
$sUser = $env:USERNAME
$sComputer = $env:COMPUTERNAME
$sLogName = "expand-wv.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName
$sLogTitle = "Starting Script as $sdomain\$sUser from $scomputer***************"
Add-Content $sLogFile -Value $sLogTitle
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$pair = "${IDMclientID}:${IDMSharedSecret}"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"


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

Function LogintoIDM {
#Connect to App Volumes Manager
Write-Host "Getting Token From: $idmserver"
$headers = @{ Authorization = $basicAuthValue }
try {
    
    $sresult = Invoke-RestMethod -Method Post -Uri "https://$idmserver/SAAS/API/1.0/oauth2/token?grant_type=client_credentials" -Headers $headers -SessionVariable IDMSession
}

catch {
  Write-Host "An error occurred when logging on $_"
  Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
  Write-Log -Message "Finishing Script*************************************"
  exit 
}

$global:IDMToken = $sresult.access_token

write-Log -Message "Logging on to AppVolumes Manager: $sresult"

  } 

      Function GetApps {
        #Connect to App Volumes Manager
        Write-Host "Getting IDM Users: $idmserver"
        $bearerAuthValue = "Bearer $IDMToken"
        $headers = @{ Authorization = $bearerAuthValue }  

        try{$scimusers = Invoke-RestMethod -Method Get -Uri "https://aw-techzone.vmwareidentity.com/SAAS/jersey/manager/api/scim/Users" -Headers $headers -ContentType "application/json"
        }
        
        catch {
          Write-Host "An error occurred when getting apps $_"
          Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
          Write-Log -Message "Finishing Script*************************************"
          exit 
        }

        $json = $scimusers.resources.Username

        foreach ($item in $json)
        {
          
          Write-Host $item

        }
        
        write-Log -Message "Logging on to AppVolumes Manager: $sresult"
        
          } 



#-----------------------------------------------------------[Execution]------------------------------------------------------------

LogintoIDM
GetApps


Write-Log -Message "Finishing Script******************************************************"
Write-Host "Finished"