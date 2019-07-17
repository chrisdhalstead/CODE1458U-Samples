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

Function LogintoAppVolumes {

#Get Values from User
$script:AppVolServer = Read-Host -Prompt 'Enter the App Volumes Manager Name'
$Username = Read-Host -Prompt 'Enter the Username'
$Password = Read-Host -Prompt 'Enter the Password' -AsSecureString
$domain = Read-Host -Prompt 'Enter the Domain'

#Convert the Password
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

#Construct JSON to pass to login endpoint
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

Function ListAppStacks {
    
    if ([string]::IsNullOrEmpty($AVSession))
    {
       write-host "You are not logged into App Volumes"
        break   
       
    }

   
    try {
        
        $sresult = Invoke-RestMethod -Method Get -Uri "https://$appvolserver/cv_api/appstacks" -ContentType "application/json" -WebSession $avSession 
    }
    
    catch {
      Write-Host "An error occurred when logging on $_"
      Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
      Write-Log -Message "Finishing Script*************************************"
     break 
    }
    
write-host "List of AppStacks on: "$appvolserver
$sresult | Format-Table -autosize -Property Id,Name,Status,created_at_human
    
      } 
Function AppStackDetails {
   
        if ([string]::IsNullOrEmpty($AVSession))
        {
           write-host "You are not logged into App Volumes"
            break   
           
        }

        $asid = Read-Host -Prompt 'Enter the AppStack ID for More Details'
           
        try {
            
            $sresult = Invoke-RestMethod -Method Get -Uri "https://$appvolserver/cv_api/appstacks/$asid" -ContentType "application/json" -WebSession $AVSession
        }
        
        catch {
          Write-Host "An error occurred when logging on $_"
          Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
          Write-Log -Message "Finishing Script*************************************"
         break 
        }
        
        
      $sresult.AppStack | Format-Table -AutoSize -Property Name,Status,Size_mb,Assigments_Total
       
          } 

Function AppStackApps {
   
  if ([string]::IsNullOrEmpty($AVSession))
      {
        write-host "You are not logged into App Volumes"
        break   
               
      }
    
      $asid = Read-Host -Prompt 'Enter the AppStack ID for the list of Applications'
               
            try {
                
                $sresult = Invoke-RestMethod -Method Get -Uri "https://$appvolserver/cv_api/appstacks/$asid/applications" -ContentType "application/json" -WebSession $AVSession
            }
            
            catch {
              Write-Host "An error occurred when logging on $_"
              break 
            }
            
            
          $sresult.applications | Format-Table -AutoSize -Property Name,version,publisher

           
              } 

Function Writables {
   
  if ([string]::IsNullOrEmpty($AVSession))
        {
          write-host "You are not logged into App Volumes"
          break   
                             
        }
                  
                            
    try {                    
      $sresult = Invoke-RestMethod -Method Get -Uri "https://$appvolserver/cv_api/writables" -ContentType "application/json" -WebSession $AVSession
        }
                          
        catch {
              Write-Host "An error occurred when logging on $_"
              break 
              }
                     
    $sresult.datastores.writable_volumes | Format-Table -AutoSize -Property Name,Owner_Name,Total_MB,Percent_Available
             
                         
} 

Function Activity_Log {
   
  if ([string]::IsNullOrEmpty($AVSession))
        {
          write-host "You are not logged into App Volumes"
          break   
                             
        }
                  
                            
    try {                    
      $sresult = Invoke-RestMethod -Method Get -Uri "https://$appvolserver/cv_api/system_messages" -ContentType "application/json" -WebSession $AVSession
        }
                          
        catch {
              Write-Host "An error occurred when logging on $_"
              break 
              }
                     
    $sresult.allmessages.system_messages | Format-list -Property Message,Event_time_human
             
                         
} 

Function Get_Online {
   
  if ([string]::IsNullOrEmpty($AVSession))
        {
          write-host "You are not logged into App Volumes"
          break   
                             
        }
                  
                            
    try {                    
      $sresult = Invoke-RestMethod -Method Get -Uri "https://$appvolserver/cv_api/online_entities" -ContentType "application/json" -WebSession $AVSession
        }
                          
        catch {
              Write-Host "An error occurred when logging on $_"
              break 
              }
                     
    $sresult.online.records | Format-Table -AutoSize -Property agent_status,entity_name,entity_type,duration_words,details
             
                         
} 

function Show-Menu
  {
    param (
          [string]$Title = 'VMware App Volumes API Menu'
          )
       Clear-Host
       Write-Host "================ $Title ================"
       Write-Host "Press '1' to Login to App Volumes"
       Write-Host "Press '2' for a List of AppStacks"
       Write-Host "Press '3' for AppStack Details"
       Write-Host "Press '4' for a List of Applications in an AppStack"
       Write-Host "Press '5' for Writable Volumes"
       Write-Host "Press '6' to Increase Writable Volume Size"
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

         LogintoAppVolumes
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