#!/usr/bin/env bash
set -e

ES_URL=http://10.81.12.36:9200
INDEX=ids-snort-*

curl -s "$ES_URL/_cat/indices/$INDEX?v"
echo
curl -s "$ES_URL/$INDEX/_search?size=5&sort=@timestamp:desc"
