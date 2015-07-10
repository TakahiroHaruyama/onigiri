# onigiri
onigiri - remote malware triage script

Check [my blog](http://takahiroharuyama.github.io/blog/2015/07/03/remote-malware-triage-automation/) about the purpose.

## Preparation

#### Install Python
* You need both of Python x86 (for volatility) / x64 (for F-Response COM DLLs) if installed F-Response binaries are 64-bit
  * Set the x86 python path to *g_x86_python_path* or specify -p option

#### Install the following Python packages
* [Win32 Extensions (win32com)](http://starship.python.net/~skippy/win32/Downloads.html)
* [Requests](http://docs.python-requests.org/en/latest/)
* [python-registry](https://github.com/williballenthin/python-registry)
* [colorama](https://pypi.python.org/pypi/colorama)

#### Install Volatility Framework and openioc_scan
* [Volatility Installation](https://github.com/volatilityfoundation/volatility/wiki/Installation)
  * Set the vol.py/plugins paths to *g_vol_path* and *g_vol_plugins_path* or specify -o and -l options
* [openioc_scan](http://takahiroharuyama.github.io/blog/2014/08/15/fast-malware-triage-using-openioc-scan-volatility-plugin/)

#### Download FTK Imager CLI version
* [FTK Imager CLI version](http://accessdata.com/product-download)
  * Set the path to *g_ftk_path* or specify -t option

#### Open TCP ports
* examiner: tcp/5681
* victim: tcp/3260-3261 (Consultant), tcp/445 (Consultant+Covert, Enterprise)

#### Configure F-Response
* Set examinerIP/username/password for iSCSI authentication and enable PhysicalMemory/FlexdiskAPI
* Save fresponse.ini on F-Response Consultant Connector (consultant and Consultant+Covert only)

## Usage

1. Run F-Response License Manager Monitor on the examiner machine then start it
* Run R-Response agent program on the victim machine then start it using GUI tools (consultant and Consultant+Covert only)
* Run this script and check the result
  * Type -h for help
    * Specify the folder path including fresponse.ini (consultant and Consultant+Covert only)
    * Specify credentials of domain admin or local built-in Administrator account (Enterprise only)

## Trouble Shooting

#### COM Errors

If any errors about win32com, try following:

* Check the COM DLL (e.g., FCCCTRLx64.dll, FEMCCTRLx64.dll) architecture. You need x64 python and win32com for x64 DLL.
* Check the COM API CLSIDs in registry (e.g., search FCCCTRL or FEMCCTRL). If not found, register COM Dlls using regsvr32 command. You need x86 regsvr32 (under C:\Windows\SysWOW64) if your COM DLL is 32-bit version.


    regsvr32 "C:\Program Files\F-Response\FEMCCTRLx64.dll"

#### Memory Acquisition Failure of Win8.1 x64 machines

I checked physical memory acquisition through F-Response didn't work on some conditions:
- The target OS is Win8.1 x64
- The RAM size is big (e.g., 8GB or 16GB)

Specifically, process data structures (\_EPROCESS) become null. I sent the report to F-Response and I'm waiting for the reply.

If you have [DumpIt commercial version](http://www.moonsols.com/windows-memory-toolkit/), you can use it combined with [PsExec](https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx) for secure memory acquisition (specify -a option and more). 

## What's "Onigiri"?

[Onigiri](https://en.wikipedia.org/wiki/Onigiri) is a Japanese soul food, made with plain rice, wrapped in nori (seaweed), sometimes filled with pickled ume (umeboshi), kombu, tarako, or any other salty or sour ingredient as a natural preservative. Onigiri makes rice portable and easy to eat as well as preserving it. I named this tool after its convenience, inspired by [Noriben](https://github.com/Rurik/Noriben).

## License
GNU GPLv2
