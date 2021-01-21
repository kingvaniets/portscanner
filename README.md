# portscanner
Tool that will help you scan ports

To identify those scans with Wiresharks apply following filters:

StealthScan:
ip.dst==192.168.3.70 and ((tcp.flags.syn == 1) || (tcp.flags.push == 0) || (tcp.flags.reset == 0))

ConnectScan:
ip.dst==192.168.3.70 and ((tcp.flags.syn == 1) || (tcp.flags.push == 0) || (tcp.flags.reset == 0))

XMASScan:
ip.dst==192.168.3.70 and ((tcp.flags.syn == 1) || (tcp.flags.push == 1) || (tcp.flags.reset == 1))
