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

Function LogintoHorizon {

$script:HorizonServer = Read-Host -Prompt 'Enter the Horizon Server Name'
$Username = Read-Host -Prompt 'Enter the Username'
$Password = Read-Host -Prompt 'Enter the Password' -AsSecureString
$domain = read-host -Prompt 'Enter the Horizon Domain'

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

$Credentials = '{"name":' + $username + ',"passwd":' + $UnsecurePassword +',"domain":' + $domain +'}' 

try {
    
    $sresult = Invoke-WebRequest -Method Post -Uri "https://$HorizonServer/view-vlsi/rest/v1/login" -Body $Credentials -ContentType "application/json" -SessionVariable session
}

catch {
  Write-Host "An error occurred when logging on $_"
  Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
  Write-Log -Message "Finishing Script*************************************"
  break
}

write-host "Successfully Logged In"

#write the returned oAuth2 token to a Global Variable
$script:HorizonCSRF = $sresult.headers.CSRFToken
$script:HorizonSession = $session


  } 

Function GetSessions {
    
    if ([string]::IsNullOrEmpty($HorizonCSRF))
    {
       write-host "You are not logged into Horizon"
        break   
       
    }
 
    $headers = @{CSRFToken = $HorizonCSRF}

    $SESSIONJSON = '{"queryEntityType":"SessionLocalSummaryView","sortDescending":false,"startingOffset":0}'
   
    try {
        
        $sresult = Invoke-RestMethod -Method Post -Uri "https://$horizonserver/view-vlsi/rest/v1/queryservice/create" -Headers $headers -body $SESSIONJSON -ContentType "application/json" -WebSession $HorizonSession 
    }
    
    catch {
      Write-Host "An error occurred when logging on $_"
      Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
      Write-Log -Message "Finishing Script*************************************"
     break 
    }
    
  if ($sresult.results.Count -eq 0)
   {
    write-host "No Sessions"
    break   
       
    }
  
$query = $sresult.id
     
$killsession
write-host "Results will be logged to: "$sLogPath"\"$sLogName
write-host "There are" $sresult.results.Count "total sessions"

$sresult.Results | Format-table -AutoSize -Property @{Name = 'Username'; Expression = {$_.namesdata.username}},@{Name = 'Desktop Name'; Expression = {$_.namesdata.desktopname}},@{Name = 'Machine or RDS Server'; Expression = {$_.namesdata.machineorrdsservername}}`
,@{Name = 'Client Name'; Expression = {$_.namesdata.clientname}},@{Name = 'Client Type'; Expression = {$_.namesdata.clienttype}},@{Name = 'Client Version'; Expression = {$_.namesdata.clientversion}},@{Name = 'Client IP'; Expression = {$_.namesdata.clientaddress}}`
,@{Name = 'Session Type'; Expression = {$_.sessiondata.sessiontype}},@{Name = 'Session State'; Expression = {$_.sessiondata.sessionstate}},@{Name = 'Location'; Expression = {$_.namesdata.securitygatewaylocation}}

#Clean Up
  try {
            
          $killsession = Invoke-RestMethod -Method Get -Uri "https://$horizonserver/view-vlsi/rest/v1/queryservice/delete?id=$query" -Headers $headers -ContentType "application/json" -WebSession $HorizonSession
  
    }
    
    catch {

      Write-Host "An error occurred when logging on $_"
      Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
      Write-Log -Message "Finishing Script*************************************"
     break 
    }
 
    
      } 
Function GetMachines {
    
        if ([string]::IsNullOrEmpty($HorizonCSRF))
        {
           write-host "You are not logged into Horizon"
            break   
           
        }
     
        $headers = @{CSRFToken = $HorizonCSRF}
    
        $JSON = '{"queryEntityType":"MachineNamesView","sortDescending":false,"startingOffset":0,"filter":{"type":"Equals","memberName":"base.type","value":"MANAGED_VIRTUAL_MACHINE"}}'

       
        try {
            
            $sresult = Invoke-RestMethod -Method Post -Uri "https://$horizonserver/view-vlsi/rest/v1/queryservice/create" -Headers $headers -body $JSON -ContentType "application/json" -WebSession $HorizonSession 
        }
        
        catch {
          Write-Host "An error occurred when logging on $_"
          Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
          Write-Log -Message "Finishing Script*************************************"
         break 
        }
        
      if ($sresult.results.Count -eq 0)
       {
        write-host "No Sessions"
        break   
           
        }
      
    $query = $sresult.id
         
    $killsession
    write-host "Results will be logged to: "$sLogPath"\"$sLogName
    write-host "There are" $sresult.results.Count "desktops"

  $script:dtlookup = @{}

  foreach ($item in $sresult.Results) {

    $dtlookup.add($item.base.name,$item.id)
  
}
    
    $sresult.Results | Format-table -AutoSize -Property @{Name = 'Machine'; Expression = {$_.base.name}},@{Name = 'Pool'; Expression = {$_.base.desktopname}},@{Name = 'OS'; Expression = {$_.base.operatingsystem}}`
    ,@{Name = 'Achitecture'; Expression = {$_.base.operatingsystemarchitecture}},@{Name = 'Agent Version'; Expression = {$_.base.agentversion}},@{Name = 'Status'; Expression = {$_.base.basicstate}}
    #Clean Up
      try {
                
              $killsession = Invoke-RestMethod -Method Get -Uri "https://$horizonserver/view-vlsi/rest/v1/queryservice/delete?id=$query" -Headers $headers -ContentType "application/json" -WebSession $HorizonSession
      
        }
        
        catch {
    
          Write-Host "An error occurred when logging on $_"
          Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
          Write-Log -Message "Finishing Script*************************************"
         break 
        }
     
        
          } 
Function GetApplications {

   
        if ([string]::IsNullOrEmpty($HorizonCSRF))
        {
           write-host "You are not logged into Horizon"
            break   
           
        }
    
        $headers = @{CSRFToken = $HorizonCSRF}
    
        $SESSIONJSON = '{"queryEntityType":"ApplicationInfo","sortDescending":false,"startingOffset":0}'
       
        try {
            
            $sresult = Invoke-RestMethod -Method Post -Uri "https://$horizonserver/view-vlsi/rest/v1/queryservice/create" -Headers $headers -body $SESSIONJSON -ContentType "application/json" -WebSession $HorizonSession
        }
        
        catch {
          Write-Host "An error occurred when logging on $_"
          Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
          Write-Log -Message "Finishing Script*************************************"
         break 
        }
        
        $query = $sresult.id
        write-host "There are" $sresult.results.Count "total applications"

        $sresult.Results.data | Format-Table -autosize       
      
    
        try {
            
            $sresult = Invoke-RestMethod -Method Get -Uri "https://$horizonserver/view-vlsi/rest/v1/queryservice/delete?id=$query" -Headers $headers -ContentType "application/json" -WebSession $HorizonSession
        }
        
        catch {
          Write-Host "An error occurred when logging on $_"
          Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
          Write-Log -Message "Finishing Script*************************************"
         break 
        }
     
      
       
          } 


function DTActions{

  {
    param (
          [string]$Title = 'VMware Horizon Desktop Actions'
          )
       Clear-Host
       Write-Host "================ $Title ================"
             
       Write-Host "Press '1' to Reboot a Machine"
       Write-Host "Press '2' for a List of Sessions"
       Write-Host "Press '3' for a List of Applications"
       Write-Host "Press '4' for a List of Machines"
       Write-Host "Press '5' for Desktop Actions"
       Write-Host "Press '6' for Recent Events"
       Write-Host "Press '7' for Licensing Usage"
       Write-Host "Press 'Q' to quit."
         }

do
 {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    
    '1' {  

        RebootMachine
    } 
    
    '2' {
   
         GetSessions

    }
    
    '3' {
       
         GetApplications
      
    }

    '4' {
       
     GetMachines
   
 }

 '5' {
       
  DTActions

}
'6' {

GetEvents

}

 '7' {
       
GetLicenseUsage
     
   }
  
    }
    pause
 }
 
 until ($selection -eq 'q')






}





Function GetLicenseUsage {

   
            if ([string]::IsNullOrEmpty($HorizonCSRF))
            {
               write-host "You are not logged into Horizon"
                break   
               
            }
        
            $headers = @{CSRFToken = $HorizonCSRF}
        
               
            try {
                
                $sresult = Invoke-RestMethod -Method Get -Uri "https://$horizonserver/view-vlsi/rest/v1/UsageStatistics/GetLicensingCounters" -Headers $headers -ContentType "application/json" -WebSession $HorizonSession
            }
            
            catch {
              Write-Host "An error occurred when logging on $_"
              Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
              Write-Log -Message "Finishing Script*************************************"
             break 
            }
      
            write-host "Current Usage:"
            $sresult.currentUsage | Format-list 
            write-Host "Highest Usage:"
            $sresult.highestUsage | Format-list 
                
         
            
          
           
              } 
Function GetEvents {

   
  if ([string]::IsNullOrEmpty($HorizonCSRF))
        {
            write-host "You are not logged into Horizon"
            break   
               
        }
        
  $headers = @{CSRFToken = $HorizonCSRF}
        
  $SESSIONJSON = '{"queryEntityType":"EventSummaryView","sortDescending":true,"startingOffset":0,"sortBy":"data.time","limit":50,"maxPageSize":50}'
           
            try {
                
                $sresult = Invoke-RestMethod -Method Post -Uri "https://$horizonserver/view-vlsi/rest/v1/queryservice/create" -Headers $headers -body $SESSIONJSON -ContentType "application/json" -WebSession $HorizonSession
            }
            
            catch {
              Write-Host "An error occurred when logging on $_"
              Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
              Write-Log -Message "Finishing Script*************************************"
             break 
            }
            
            $query = $sresult.id
            write-host "There are" $sresult.results.Count "events shown"
    
            $sresult.Results.data | Format-list -Property EventType,severity,message
          
        
            try {
                
                $sresult = Invoke-RestMethod -Method Get -Uri "https://$horizonserver/view-vlsi/rest/v1/queryservice/delete?id=$query" -Headers $headers -ContentType "application/json" -WebSession $HorizonSession
            }
            
            catch {
              Write-Host "An error occurred when logging on $_"
              Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
              Write-Log -Message "Finishing Script*************************************"
             break 
            }
         
          
           
              } 
 
function Show-Menu
  {
    param (
          [string]$Title = 'VMware Horizon API Menu'
          )
       Clear-Host
       Write-Host "================ $Title ================"
             
       Write-Host "Press '1' to Login to Horizon"
       Write-Host "Press '2' for a List of Sessions"
       Write-Host "Press '3' for a List of Applications"
       Write-Host "Press '4' for a List of Machines"
       Write-Host "Press '5' for Recent Events"
       Write-Host "Press '6' for Licensing Usage"
       Write-Host "Press 'Q' to quit."
         }

do
 {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    
    '1' {  

         LogintoHorizon
    } 
    
    '2' {
   
         GetSessions

    }
    
    '3' {
       
         GetApplications
      
    }

    '4' {
       
     GetMachines
   
 }
    '5' {
       
        GetEvents
     
   }
   '6' {
       
    GetLicenseUsage
 
}

    }
    pause
 }
 
 until ($selection -eq 'q')


Write-Log -Message "Finishing Script******************************************************"
Write-Host "Finished"