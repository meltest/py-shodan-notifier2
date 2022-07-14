#!/bin/bash

CMDNAME=`basename $0`
TIMESTAMP=`TZ=UTC-9 date "+%Y%m%d%H%M%S"`
TZ=UTC

ADDRESS=""
PORT=""
STATUS=""

while getopts ha:p:s: OPT
do
    case $OPT in
        "a" )
            ADDRESS='.value.ip=="'$OPTARG'"'
            ;;
        "p" )
            PORT=".value.port==$OPTARG"
            ;;
        "s" )
            STATUS='.value.status=="'$OPTARG'"'
            ;;
        "h" ) echo "Usage: $CMDNAME [-a ipaddress] [-p port] json_file" 1>&2
                exit 1 ;;
        * ) echo "Usage: $CMDNAME [-a ipaddress] [-p port] json_file" 1>&2
                exit 1 ;;
    esac
done

options=($ADDRESS $PORT $STATUS)
is_first=1
query=""

for option in ${options[@]}
do
    if [[ ! -z $option  && $is_first -eq 1 ]]; then
        query+="${option}"
        is_first=0
    elif [[ ! -z $option && $is_first -eq 0 ]]; then
        query+=" and ${option}"
    fi
done

shift `expr $OPTIND - 1`

if [[ -z $query  ]]; then
    echo "cat $1 | jq -c '._default | to_entries | map(.key, .value)' | perl -pe 's/},{/}\n{/g'"
    cat $1 | jq -c '._default | to_entries | map(.key, .value)' | perl -pe 's/},{/}\n{/g'
else
    echo "cat $1 | jq -c '._default | to_entries | map(select(${query})) | map(.key, .value)' | perl -pe 's/},/}\n{/g'"
    cat $1 | jq -c "._default | to_entries | map(select(${query})) | map(.key, .value)" | perl -pe 's/},/}\n{/g'
fi
