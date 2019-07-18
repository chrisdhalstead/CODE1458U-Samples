<#
.SYNOPSIS
Samples Scripts Using the VMware Horzon REST API
	
.NOTES
  Version:        1.0
  Author:         Chris Halstead - chalstead@vmware.com
  Creation Date:  7/18/2019
  Purpose/Change: Initial script development
  **This script and the VMware Horizon REST API is not supported by VMware**
 
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

#Capture Login Information
$script:HorizonServer = Read-Host -Prompt 'Enter the Horizon Server Name'
$Username = Read-Host -Prompt 'Enter the Username'
$Password = Read-Host -Prompt 'Enter the Password' -AsSecureString
$domain = read-host -Prompt 'Enter the Horizon Domain'

#Convert Password for JSON
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)


try {
    
$script:hvServer = Connect-HVServer -Server $horizonserver -User $username -Password $UnsecurePassword -Domain $domain
$script:hvServices = $hvServer.ExtensionData

}

catch {
  Write-Host "An error occurred when logging on $_"
  Write-Log -Message "Error when logging on to AppVolumes Manager: $_"
  Write-Log -Message "Finishing Script*************************************"
  break
}

write-host "Successfully Logged In"

$script:HorizonCSRF = $sresult.headers.CSRFToken
$script:HorizonSession = $session

} 

Function GetSessions {
    
    if ([string]::IsNullOrEmpty($hvServer))
    {
       write-host "You are not logged into Horizon"
        break   
       
    }
 
      
    try {

      $query = New-Object "Vmware.Hv.QueryDefinition"

      $query.queryEntityType = 'SessionLocalSummaryView'
      
      $qSrv = New-Object "Vmware.Hv.QueryServiceService"
      
      $sresult = $qSRv.QueryService_Query($hvServices,$query)
      
   
         

    }

    
    catch {
      Write-Host "An error occurred when getting sessions $_"
     break 
    }
    
  if ($sresult.results.count -eq 0)
   {
    write-host "No Sessions"
    break   
       
    }
  
write-host "Results will be logged to: "$sLogPath"\"$sLogName
write-host "There are" $sresult.results.Count "total sessions"

$sresult.Results | Format-table -AutoSize -Property @{Name = 'Username'; Expression = {$_.namesdata.username}},@{Name = 'Desktop Name'; Expression = {$_.namesdata.desktopname}},@{Name = 'Machine or RDS Server'; Expression = {$_.namesdata.machineorrdsservername}}`
,@{Name = 'Client Name'; Expression = {$_.namesdata.clientname}},@{Name = 'Client Type'; Expression = {$_.namesdata.clienttype}},@{Name = 'Client Version'; Expression = {$_.namesdata.clientversion}},@{Name = 'Client IP'; Expression = {$_.namesdata.clientaddress}}`
,@{Name = 'Session Type'; Expression = {$_.sessiondata.sessiontype}},@{Name = 'Session State'; Expression = {$_.sessiondata.sessionstate}},@{Name = 'Location'; Expression = {$_.namesdata.securitygatewaylocation}}

 
    
      } 

      
Function RebootDT {
    
        if ([string]::IsNullOrEmpty($HorizonCSRF))
        {
           write-host "You are not logged into Horizon"
            break   
           
        }

$thedesktop = Read-Host -Prompt 'Enter the Desktop Name'

$dtencoded = $dtlookup[$thedesktop]

    Write-host "Would you like to reboot $thedesktop? (Default is No)" -ForegroundColor Yellow 
    $Readhost = Read-Host " ( y / n ) " 
    Switch ($ReadHost) 
     { 
       Y {Write-host "Rebooting $thedesktop. This may take a few minutes.";Continue} 
       N {Write-Host "Doing Nothing"; break} 
       Default {Write-Host "Default, Do Nothing"; break} 
     } 
     
    $headers = @{CSRFToken = $HorizonCSRF}
    $sresult

    $JSON = '["' + $dtencoded +  '"]'        
       
      try {
            
            $sresult = Invoke-RestMethod -Method Post -Uri "https://$horizonserver/view-vlsi/rest/v1/Machine/RestartMachines" -Headers $headers -body $JSON -ContentType "application/json" -WebSession $HorizonSession 
        }
        
        catch {
          Write-Host "An error occurred when logging on $_"
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
          Write-Host "An error occurred when getting sessions $_"
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
    
          Write-Host "An error occurred when deleting query $_"
      
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
                 break 
        }
           
       
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
       Write-Host "Press '5' to Reboot a Desktop"
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
       
  RebootDT

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


Write-Log -Message "Finishing Script******************************************************"
Write-Host "Finished"