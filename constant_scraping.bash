#!/bin/bash

while [ 1 ]
do
    git pull
    md5=$(md5sum input-data/extra_snis.csv | cut -d ' ' -f 1)
    python3 get_pcaps.py input-data/extra_snis.csv output-pcap-continuous/$md5
    sleep 10
done