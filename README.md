# Pcap downloader to extract server TLS configs

Input files: `input-data/*.json` in the form of `(ip, hostname, port)` to which we
will establish TLS connections. Note that our script does not check for
certificate validity (which is the whole point).

Prerequisites:

```
source env/bin/activate
pip install -r requirements.txt
python get_pcaps.py [input_folder] [output_pcap_folder]
```

