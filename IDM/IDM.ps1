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

$script:idmserver = Read-Host -Prompt 'Enter the IDM Server Name'
$IDMclientID = Read-Host -Prompt 'Enter the oAuth2 Client ID'
$IDMSharedSecret = Read-Host -Prompt 'Enter the Shared Secret' 

$pair = "${IDMclientID}:${IDMSharedSecret}"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"

Write-Host "Getting Token From: $idmserver"
$headers = @{ Authorization = $basicAuthValue }
try {
    
    $sresult = Invoke-RestMethod -Method Post -Uri "https://$idmserver/SAAS/API/1.0/oauth2/token?grant_type=client_credentials" -Headers $headers 
}

catch {
  Write-Host "An error occurred when logging on $_"
  Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
  Write-Log -Message "Finishing Script*************************************"
  exit 
}

#write the returned oAuth2 token to a Global Variable
$script:IDMToken = $sresult.access_token

Write-Host "Successfully Logged In"

  } 

  Function GetUsers {

    if ([string]::IsNullOrEmpty($IDMToken))
    {
       write-host "You are not logged into Horizon"
        break   
       
    }


     Write-Host "Getting IDM Users on: $idmserver"
     $bearerAuthValue = "Bearer $IDMToken"
     $headers = @{ Authorization = $bearerAuthValue }  

       try{$scimusers = Invoke-RestMethod -Method Get -Uri "https://$idmserver/SAAS/jersey/manager/api/scim/Users" -Headers $headers -ContentType "application/json"
        }
        
        catch {
          Write-Host "An error occurred when getting apps $_"
          Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
          Write-Log -Message "Finishing Script*************************************"
          exit 
        }

        $scimusers.Resources | Format-Table -autosize -Property active,username,name,emails
           
          } 
  
 Function GetGroups {
    #Connect to App Volumes Manager
    Write-Host "Getting IDM Groups on: $idmserver"
    $bearerAuthValue = "Bearer $IDMToken"
    $headers = @{ Authorization = $bearerAuthValue }  
    
    try{
      
      $scimgroups = Invoke-RestMethod -Method Get -Uri "https://$idmserver/SAAS/jersey/manager/api/scim/Groups" -Headers $headers -ContentType "application/json"
       }
            
            catch {
              Write-Host "An error occurred when getting apps $_"
              Write-Log -Message "Error when getting groups: $_"
              Write-Log -Message "Finishing Script*************************************"
              exit 
                  }
    
            $json = $scimgroups.resources
    
            foreach ($item in $json)
            {
              
              Write-Host $item.displayname $item.ID
    
            }
            
                      
         }          

Function CreateUser {
         
Write-Host "Getting IDM Groups on: $idmserver"
$bearerAuthValue = "Bearer $IDMToken"
$headers = @{ Authorization = $bearerAuthValue }  

$firstname = Read-Host -Prompt 'Input the users first name'
$lastname = Read-Host -Prompt 'Input the users last name'
$username = read-host -Prompt 'Input the User Name'
$emailaddress = Read-Host -Prompt 'Input the users email address'

$UserJson = '{"urn:scim:schemas:extension:workspace:1.0":{"domain":"System Domain"},"urn:scim:schemas:extension:enterprise:1.0":{},"schemas":["urn:scim:schemas:extension:workspace:mfa:1.0","urn:scim:schemas:extension:workspace:1.0","urn:scim:schemas:extension:enterprise:1.0","urn:scim:schemas:core:1.0"],"name":{"givenName":' + ${firstname} + ',"familyName":' + ${lastname} + ',"userName":"manualuser","emails":[{"value":"chrisdhalstead@gmail.com"}]}' | ConvertTo-Json
 
$UserJson = $UserJson.Trim()


  try{
     
    $smimcreate = Invoke-RestMethod -Method Post -Uri "https://$idmserver/SAAS/jersey/manager/api/scim/Users" -Headers $headers -Body $UserJson -ContentType "application/json;charset=UTF-8"
             }
                  
              catch {
                Write-Host "An error occurred when getting apps $_"
                Write-Log -Message "Error when getting groups: $_"
                Write-Log -Message "Finishing Script*************************************"
                 exit 
                    }
          
                  $json = $scimgroups.resources
          
                  foreach ($item in $json)
                  {
                    
                    Write-Host $item.displayname $item.ID
          
                  }
                  
                            
               }


function Show-Menu
  {
    param (
          [string]$Title = 'IDM API Menu'
          )
       Clear-Host
       Write-Host "================ $Title ================"
             
       Write-Host "1: Press '1' to Login to IDM"
       Write-Host "2: Press '2' for a list of IDM User."
       Write-Host "3: Press '3' to create a local user"
       Write-Host "Q: Press 'Q' to quit."
         }

#-----------------------------------------------------------[Execution]------------------------------------------------------------
do
 {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    
    '1' {  

         LogintoIDM
    } 
    
    '2' {
   
         GetUsers

    } '3' {
       
        CreateUser
      
    }
    }
    pause
 }
 until ($selection -eq 'q')


Write-Log -Message "Finishing Script******************************************************"
Write-Host "Finished"