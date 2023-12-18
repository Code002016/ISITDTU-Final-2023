#!/bin/bash

generate_flag() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32 | base64
}

operation="$1"
host="$2"
echo $operation
case "$operation" in
    "check")
        python3 checker.py check "$host" 
        ;;
    "put")
        flag=$(generate_flag)
        python3 checker.py put "$host" 0 "$flag" 
		echo "$flag"
        ;;
    "get")
        flag_id="$3"
        flag="$4"
        python3 checker.py get "$host" "$flag_id" "$flag" 
        ;;
    *)
        echo "Invalid operation. Choose 'check', 'put', or 'get'." 
        ;;
esac
