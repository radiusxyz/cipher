#!/bin/sh --
SHELL_PATH=`pwd -P`

x=`cat ./script/data/encryption_info.json | jq .x`
t=`cat ./script/data/encryption_info.json | jq .t`
original_text=`cat ./script/data/encryption_info.json | jq .original_text`

echo "x: $x"
echo "t (the number of iterration): $t"
echo "original_text: $original_text"

vdf-cli encrypt "{\"x\": $x, \"t\": $t, \"original_text\": $original_text}" -t wesolowski > ./script/data/decryption_info.json