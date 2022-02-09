#!/bin/sh --
SHELL_PATH=`pwd -P`

x=`cat ./script/data/decryption_info.json | jq .x`
t=`cat ./script/data/decryption_info.json | jq .t`
message_length=`cat ./script/data/decryption_info.json | jq .message_length`
nonce=`cat ./script/data/decryption_info.json | jq .nonce`
cipher_text=`cat ./script/data/decryption_info.json | jq .cipher_text`

echo "x: $x"
echo "t (the number of iterration): $t"
echo "message_length: $message_length"
echo "nonce: $nonce"
echo "cipher_text: $cipher_text"

vdf-cli decrypt "{\"x\": $x, \"t\": $t, \"message_length\": $message_length, \"nonce\": $nonce, \"cipher_text\": $cipher_text}" -t wesolowski