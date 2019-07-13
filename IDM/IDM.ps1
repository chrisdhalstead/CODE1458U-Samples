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
#Connect to IDM

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

  Write-Host "An error occurred when logging on to IDM $_"
  break 
}

#write the returned oAuth2 token to a Global Variable
$script:IDMToken = $sresult.access_token

Write-Host "Successfully Logged In"

  } 

  Function GetUsers {

    if ([string]::IsNullOrEmpty($IDMToken))
    {
       write-host "You are not logged into IDM"
        break   
       
    }


     Write-Host "Getting IDM Users on: $idmserver"
     $bearerAuthValue = "Bearer $IDMToken"
     $headers = @{ Authorization = $bearerAuthValue }  
     $allusers
   
 
$istartat = 1     
 
do {
 
  try{$scimusers = Invoke-RestMethod -Method Get -Uri "https://$idmserver/SAAS/jersey/manager/api/scim/Users?startIndex=$istartat" -Headers $headers -ContentType "application/json"
        }
                catch {
          Write-Host "An error occurred when getting users $_"
          break 
        }

      $allusers = $scimusers.totalresults
      $stotal = $stotal += $scimusers.itemsPerPage
      write-host "Found $allusers users (returning $istartat to $stotal)"
      $istartat += $scimusers.itemsPerPage
      
      $scimusers.Resources | Format-Table -autosize -Property active,username,name,emails
  
} until ($allusers -eq $stotal)

           
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
              Write-Host "An error occurred when getting IDM Groups $_"
              
              break 
                  }
    
                  $scimusers.Resources | Format-Table -autosize -Property active,username,name,emails
                                  
         }          

Function CreateUser {
         
Write-Host "Getting IDM Groups on: $idmserver"
$bearerAuthValue = "Bearer $IDMToken"
$headers = @{ Authorization = $bearerAuthValue }  

$firstname = Read-Host -Prompt 'Input the users first name'
$lastname = Read-Host -Prompt 'Input the users last name'
$username = read-host -Prompt 'Input the User Name'
$emailaddress = Read-Host -Prompt 'Input the users email address'

$UserJson = '{"urn:scim:schemas:extension:workspace:1.0":{"domain":"System Domain"},"urn:scim:schemas:extension:enterprise:1.0":{},"schemas":["urn:scim:schemas:extension:workspace:mfa:1.0","urn:scim:schemas:extension:workspace:1.0","urn:scim:schemas:extension:enterprise:1.0","urn:scim:schemas:core:1.0"],"name":{"givenName":"VMworld","familyName":"Demo"},"userName":"vmdemo","emails":[{"value":"chalstead@vmware.com"}]}'

  try{
     
    $scimcreate = Invoke-RestMethod -Method Post -Uri "https://$idmserver/SAAS/jersey/manager/api/scim/Users" -Headers $headers -Body $UserJson -ContentType "application/json;charset=UTF-8"
             }
  
                           catch {
                Write-Host "An error occurred when creating a user $_"
             
                 break
                 
                    }
          
                $scimcreate.Resources | Format-Table -autosize -Property active,username,name,emails
                  
                            
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