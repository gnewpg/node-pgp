cd "$(dirname "$0")"

[ ! -e ../node_modules/nodeunit ] && npm install nodeunit
../node_modules/nodeunit/bin/nodeunit *.js
