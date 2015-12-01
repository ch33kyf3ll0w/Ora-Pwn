# Ora-Pwn
An Oracle attack tool written in PowerShell and using the .NET OracleClient Namespace. Can be used to bruteforce SIDs, user credentials, and to execute queries.


## Current Functions:
    Invoke-SIDGuess             -   Checks to see if provided SIDs are valid.
    Invoke-CredentialGuess      -   Checks to see if provided Username and Password is valid.
    Invoke-QueryExec            -   Executes and returns output for provided querys
    Invoke-UNCInject-DS         -   Leverages ctxsys.context to inject a UNC filepath

## Future Additions:
    Functions:
    Invoke-QueryExec            -   Executes and returns output for provided querys
    Invoke-UNCInject-DS         -   Leverages ctxsys.context to inject a UNC filepath
    
    General:
    Improved Error handling
    Spooling functionality
