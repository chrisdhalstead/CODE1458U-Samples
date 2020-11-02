
<#
.SYNOPSIS
Samples Scripts Using the VMware Horizon API via PowerCLI
	
.NOTES
  Version:        1.0
  Author:         Chris Halstead - chalstead@vmware.com
  Creation Date:  7/18/2019
  Purpose/Change: Initial script development
 #>

#----------------------------------------------------------[Declarations]----------------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
#-----------------------------------------------------------[Functions]------------------------------------------------------------
Function LogintoHorizon {

#Capture Login Information

#Import-Module VMware.VimAutomation.HorizonView

$script:HorizonServer = Read-Host -Prompt 'Enter the Horizon Server Name'
$Username = Read-Host -Prompt 'Enter the Username'
$Password = Read-Host -Prompt 'Enter the Password' -AsSecureString
$domain = read-host -Prompt 'Enter the Horizon Domain'

#Convert Password
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

try {
    
    $script:hvServer = Connect-HVServer -Server $horizonserver -User $username -Password $UnsecurePassword -Domain $domain
    $script:hvServices = $hvServer.ExtensionData

    }

catch {
  Write-Host "An error occurred when logging on $_"
  break
}

write-host "Successfully Logged In"

} 

Function GetSSInfo {

   
        if ([string]::IsNullOrEmpty($hvserver))
        {
           write-host "You are not logged into Horizon"
            break   
           
        }
    
                
        try {
           
           
          $ss = $hvservices.SecurityServer.SecurityServer_List()

          $ss | Format-table -AutoSize -Property @{Name = 'Security Server Name'; Expression = {$_.general.name}},@{Name = 'Server Address'; Expression = {$_.general.ServerAddress}},@{Name = 'PCoIP Secure GW'; Expression = {$_.general.PCoipsecuregatewayinstalled}}`

         

       

$Main                            = New-Object system.Windows.Forms.Form
$Main.ClientSize                 = New-Object System.Drawing.Point(400,400)
$Main.text                       = "Horizon Security Servers"
$Main.TopMost                    = $true

$ComboBox1                       = New-Object system.Windows.Forms.ComboBox
$ComboBox1.text                  = "SecurityServers"
$ComboBox1.width                 = 234
$ComboBox1.height                = 20
$ComboBox1.location              = New-Object System.Drawing.Point(125,13)
$ComboBox1.Font                  = New-Object System.Drawing.Font('Tahoma',10)
$ComboBox1.items

$lblsecurityservers              = New-Object system.Windows.Forms.Label
$lblsecurityservers.text         = "Security Servers: "
$lblsecurityservers.AutoSize     = $true
$lblsecurityservers.width        = 25
$lblsecurityservers.height       = 10
$lblsecurityservers.location     = New-Object System.Drawing.Point(11,15)
$lblsecurityservers.Font         = New-Object System.Drawing.Font('Tahoma',10)

$btnSave                         = New-Object system.Windows.Forms.Button
$btnSave.text                    = "Save Settings"
$btnSave.width                   = 109
$btnSave.height                  = 30
$btnSave.location                = New-Object System.Drawing.Point(280,361)
$btnSave.Font                    = New-Object System.Drawing.Font('Tahoma',10)

$Main.controls.AddRange(@($ComboBox1,$lblsecurityservers,$btnSave))

$btnSave.Add_Click({  })
$ComboBox1.Add_SelectedValueChanged({  })

[void]$main.ShowDialog()
#Sets the starting position of the form at run time.
$CenterScreen = [System.Windows.Forms.FormStartPosition]::CenterScreen
$main.StartPosition = $CenterScreen
                   
          }

                catch {
          Write-Host "An error occurred when logging on $_"
          break 
        }
        
            $ss    
       
          } 
     
Function SetCSPairingPW {

  try {
  $ConnectionServerId = $script:hvServices.connectionserver.ConnectionServer_List()[0].Id
  $SSPassword = Read-Host -Prompt 'Specify Security Server Pairing Password' -AsSecureString
  #Convert Password
  $BSTRss = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SSPassword)
  $SSUnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRss)
  $Bytes = [System.Text.Encoding]::UTF8.GetBytes($SSUnsecurePassword)
  $SecureString = New-Object VMware.Hv.SecureString
  $SecureString.Utf8String = $Bytes
  $PairingData = New-Object VMware.Hv.ConnectionServerSecurityServerPairingData
  $PairingData.PairingPassword = $SecureString
  $PairingData.TimeoutMinutes = 30
  $UpdateData = New-Object VMware.Hv.MapEntry
  $UpdateData.key = 'securityServerPairing'
  $UpdateData.Value = $PairingData
  $script:hvServices.connectionserver.ConnectionServer_Update($ConnectionServerId,$updatedata)

  }

  catch {
    Write-Host "An error occurred when setting the Security Server Pairing Password: $_"
    break 
  }

 write-host "Successfully set the pairing password - it is good for 30 minutes"


}

Function GetSSHealth {

   
  if ([string]::IsNullOrEmpty($hvserver))
    {
        write-host "You are not logged into Horizon"
        break   
               
    }
        
                    
    try {
                           
      $ss = $hvservices.SecurityServerHealth.SecurityServerHealth_List()
               
        }
           
            catch {
              Write-Host "An error occurred when logging on $_"
              break 
            }
            
                $ss    
           
              }         
 
function Show-Menu
  {
    param (
          [string]$Title = 'VMware Horizon API Menu'
          )
       Clear-Host
       Write-Host "================ $Title ================"
             
       Write-Host "Press '1' to Login to Horizon"
       Write-Host "Press '2' to specify Security Server pairing password"
       Write-Host "Press '7' for Security Server Info"
       Write-Host "Press '8' for Usage Info"
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
   
         SetCSPairingPW

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
       
        GetDtPools
     
   }
   '7' {
       
    GetSSInfo
 
}
'8' {
       
  GetUsage

}

    }
    pause
 }
 
 until ($selection -eq 'q')


