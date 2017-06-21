#!/bin/bash

echo "#### ShellCheck"
shellcheck chute/cmd.sh
echo "Returned: $?"

echo "#### php lint"
php -l chute/index.php
echo "Returned: $?"

echo "#### php mess detector"
phpmd chute/index.php text cleancode,codesize,design,naming,unusedcode
echo "Returned: $?"

echo "#### pylint"
pylint chute/captive.py
echo "Returned: $?"
