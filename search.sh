#!/bin/bash

CMDNAME=`basename $0`
TIMESTAMP=`TZ=UTC-9 date "+%Y%m%d%H%M%S"`

while getopts sha:p:r: OPT
do
        case $OPT in
                "a" ) AVALUE="$OPTARG"; AGGRESSION="-a $AVALUE"; AFLAG="${AVALUE}_" ;;
                "p" ) PVALUE="$OPTARG"; PROXY="-p $PVALUE" ;;
                "h" ) echo "Usage: $CMDNAME [-a ipaddress] [-p port] json_file" 1>&2
                        exit 1 ;;
                * ) echo "Usage: $CMDNAME [-a ipaddress] [-p port] json_file" 1>&2
                        exit 1 ;;
        esac
done

TZ=UTC

shift `expr $OPTIND - 1`

if [[ -z $AVALUE && -z $PVALUE ]]; then
  cat $1 | jq -c '._default | to_entries | map(.key, .value)' | perl -pe 's/},{/}\n{/g'
elif [[ ! -z $AVALUE && -z $PVALUE ]]; then
  cat $1 | jq -c '._default | to_entries | map(select(.value.ip == "'$AVALUE'")) | map(.key, .value)' | perl -pe 's/},/}\n{/g'
elif [[ -z $AVALUE && ! -z $PVALUE ]]; then
  cat $1 | jq -c '._default | to_entries | map(select(.value.port == '$PVALUE')) | map(.key, .value)' | perl -pe 's/},/}\n{/g'
elif [[ ! -z $AVALUE && ! -z $PVALUE ]]; then
  cat $1 | jq -c '._default | to_entries | map(select(.value.ip == "'$AVALUE'" and .value.port == '$PVALUE')) | map(.key, .value)' | perl -pe 's/},/}\n{/g'
else
  cat $1 | jq -c '._default | to_entries | map(.key, .value)' | perl -pe 's/},{/}\n{/g'
fi
