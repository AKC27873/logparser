# logparser
Logparser to parse log files and output them into readable JSON format.
---------------------------------------------------------

### **Requirements**
* Python 3.8 or newer

---------------------------------------------------------

### Quick Start Commands

```bash 
python logparser.py

python logparser.py -i /var/log/syslog

python logparser.py -i /var/log/syslog -o /tmp/syslog

python logparser.py --help
```

**Supported Log Formats**
The parser inspects the filename and automatically picks the right parser.

**JSON Output**
Results are printed to the terminal and saved to the output file. The top-level
structure looks like this:

```json
{
  "file_path": "/var/log/syslog",
  "log_type": "syslog",
  "parsed_at": "2024-06-01T12:00:00Z",
  "total_lines": 3,
  "entries": [
    {
      "line_number": 1,
      "timestamp": "Jun  1 12:00:00",
      "level": "INFO",
      "hostname": "myhost",
      "process": "systemd",
      "pid": "1",
      "message": "Started Daily apt download activities.",
      "raw": "Jun  1 12:00:00 myhost systemd[1]: Started Daily apt download activities."
    }
  ]
}
```


