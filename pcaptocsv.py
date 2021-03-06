#!/usr/bin/python3

import argparse
import os

def run_tshark(in_pcap, out_csv_gz):
    command = "tshark -r " + in_pcap + " -T fields -e ip.src -e ip.dst -e ip.id -e ip.checksum -e data.data | " + \
              "awk 'BEGIN {OFS=\",\"; print \"src\",\"dst\",\"attack\" } {print $1,$2,$3,$4,substr($5,50,1) }' | " + \
              "gzip > " + out_csv_gz
    os.system(command)

def main():


    parser = argparse.ArgumentParser(description="Processes a PCAP file generated and outputs a CSV.GZ file containing " + 
                                                 "src, dst and attack flag.")
    parser.add_argument("-i", "--in_pcap", help="PCAP file to process")
    parser.add_argument("-o", "--out_csv_gz", help="CSV.GZ file to save results to")
    args = parser.parse_args()

    assert os.path.isfile(args.in_pcap)
    assert not os.path.isfile(args.out_csv_gz) 
        
    run_tshark(args.in_pcap, args.out_csv_gz) 
        
if __name__ == '__main__':
    main()
