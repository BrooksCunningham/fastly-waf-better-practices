#!/bin/bash
echo 'Where is robots.txt in URL format. For example "https://www.fastly.com/robots.txt"'
read ROBOTS_TXT

# ROBOTS_DISALLOW=`curl -s https://www.fastly.com/robots.txt | grep -i disallow | awk '{print $2}'`
ROBOTS_DISALLOW=`curl -s ${ROBOTS_TXT} | grep -i disallow | awk '{print $2}'`

TF_ARRAY="ROBOTS_DISALLOW_LIST = ["

for i in $ROBOTS_DISALLOW
do
    TF_ARRAY+="\"$i\","
done

TF_ARRAY+="]"

echo
echo $TF_ARRAY
echo 'writing to ./main.auto.tfvars'
echo $TF_ARRAY > ./main.auto.tfvars
echo
