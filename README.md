# GoICMPScanWarner

### Description
This command line tool is sniffing on the given network interface to detect if another computer on the network is scanning you. When this is true the tool will execute the given custom command. After the program has finished you will find a `logFile.log` file in your current working directory. This file contains the MAC adresses and IP adresses of the computer you got scanned from. (the file needs to be opened with `sudo`)

### Usage
You need to provide a `-i` flag for the network interface and a `-cmd` flag for the custom command.
##### Example:
`sudo ./go_icmp_scan_warner -i "en0" -cmd "say 'Warning: You got scanned!'"`