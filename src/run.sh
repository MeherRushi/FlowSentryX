#!/bin/bash

while getopts "t:p:b:" flag; do
 case $flag in
   h) # Handle the -h flag 
   # Show usage of script
   ;;
   t) # Handle the -t flag
   # Set variable BLOCK_TIME
   times="$OPTARG"
   ;;
   p) # Handle the -p flag
   # Set variable PACKETS_THRESHOLD
   packets="$OPTARG"
   ;;
   b) # Handle the -b flag with an argument
   bytes="$OPTARG"
   # Set variable BYTES_THRESHOLD
   ;;
   \?)
   # Handle invalid options
   ;;
 esac
done

# Default variable values
BLOCK_TIME=10               # time in minutes
PACKETS_THRESHOLD=1000000   # packets allowed per second
BYTES_THRESHOLD=125000000   # bytes allowed per second

# Function to display script usage
usage() {
 echo "Usage: $0 [OPTIONS]"
 echo "Options:"
 echo " -h, --help      Display this help message"
 echo " -t, --time      Set Block Time"
 echo " -p, --packet    Set Packets Threshold"
 echo " -b, --bytes     Set Bytes Threshold"
}

has_argument() {
    [[ ("$1" == *=* && -n ${1#*=}) || ( ! -z "$2" && "$2" != -*)  ]];
}

extract_argument() {
  echo "${2:-${1#*=}}"
}

# Function to handle options and arguments
handle_options() {
  while [ $# -gt 0 ]; do
    case $1 in
      -h | --help)
        usage
        exit 0
        ;;
      -t | --time)
        if ! has_argument $@; then
          BLOCK_TIME= $times
          echo "$BLOCK_TIME"
          usage
          exit 1
        fi        ;;
      -p | --packet)
        if ! has_argument $@; then
          PACKETS_THRESHOLD= $packets
          usage
          exit 1
        fi        ;;
      -b | --bytes)
        if ! has_argument $@; then
          BYTES_THRESHOLD= $bytes
          usage
          exit 1
        fi        ;;

        # output_file=$(extract_argument $@)
        # shift
        # ;;
      *)
        echo "Invalid option: $1" >&2
        usage
        exit 1
        ;;
    esac
    shift
  done
}

make

# Main script execution
handle_options "$@"