#!/usr/bin/env bash
set -e

ES_URL=${ES_URL:-http://127.0.0.1:9200}
INDEX=${INDEX:-ids-snort-*}

curl -s "$ES_URL/_cat/indices/$INDEX?v"
echo
curl -s "$ES_URL/$INDEX/_search?size=5&sort=@timestamp:desc"
