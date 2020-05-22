#!/bin/bash
ESHOST="DOCKER_ELASTIC_IP:9200"
curl "$ESHOST/_cat/shards" 2>/dev/null |awk '{print $1}'|sort -u|while read index; do
        echo "";echo -n "Optimizing index: $index - "; curl -XPOST DOCKER_ELASTIC_IP:9200/$index/_forcemerge?max_num_segments=1 2>/dev/null
done