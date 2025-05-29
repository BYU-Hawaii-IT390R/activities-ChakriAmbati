# Windows Admin Toolkit – IT390R

## Added Tasks

### --task win-procs
Lists processes using more than X MB RAM (default: 100 MB).  
You can adjust using the `--ram` flag.  
AI citation: Copilot snippet (filtered tasklist by RAM)

### --task win-firewall
Shows inbound firewall rules that allow all remote IPs (e.g., 0.0.0.0/0).  
AI citation: ChatGPT snippet (netsh firewall rule parser)

---

## Example Runs

```powershell
python analyze_windows.py --task win-procs --ram 150
python analyze_windows.py --task win-firewall
