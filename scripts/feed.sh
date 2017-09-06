#!/bin/bash

_term() {
  for pid in ${pids[@]}; do
    kill -INT $pid
  done
}

trap _term SIGINT

couch_addr="http://127.0.0.1:5984"
curl -s $couch_addr/_all_dbs | jq -r '.[]' | \
  xargs -I % python -c "import urllib; print urllib.quote('''%''', safe='')" | \
  xargs -I % curl -X DELETE ${couch_addr}/%

killall cozy-registry-v3

reg1=("bank" "drive" "health" "photos")
reg2=("drive" "homebook" "bank" "collect")
reg3=("bank" "collect" "drive" "onboarding" "photos" "settings")

pids=()
cozy-registry-v3 --port 8081 --couchdb-prefix reg1 serve &
pids+=($!)
cozy-registry-v3 --port 8082 --couchdb-prefix reg2 serve &
pids+=($!)
cozy-registry-v3 --port 8083 --couchdb-prefix reg3 serve &
pids+=($!)

sleep 1

cozy-registry-v3 add-editor cozy --couchdb-prefix reg1
cozy-registry-v3 add-editor cozy --couchdb-prefix reg2
cozy-registry-v3 add-editor cozy --couchdb-prefix reg3

for name in "${reg1[@]}"; do
  curl \
    -X POST http://localhost:8081/registry/${name} \
    -H 'Content-Type:application/json' \
    -H "Authorization: Token $(cozy-registry-v3 gen-token cozy --couchdb-prefix reg1)" \
    -d '{"editor":"cozy", "description":{"en":"The drive application"}, "repository": "https://github.com/cozy/cozy-drive", "tags": ["reg1", "foo", "bar", "baz"], "type": "webapp", "category": "bar"}'
done

for name in "${reg2[@]}"; do
  curl \
    -X POST http://localhost:8082/registry/${name} \
    -H 'Content-Type:application/json' \
    -H "Authorization: Token $(cozy-registry-v3 gen-token cozy --couchdb-prefix reg2)" \
    -d '{"editor":"cozy", "description":{"en":"The drive application"}, "repository": "https://github.com/cozy/cozy-drive", "tags": ["reg2", "foo", "bar", "baz"], "type": "webapp", "category": "bar"}'
done

for name in "${reg3[@]}"; do
  curl \
    -X POST http://localhost:8083/registry/${name} \
    -H 'Content-Type:application/json' \
    -H "Authorization: Token $(cozy-registry-v3 gen-token cozy --couchdb-prefix reg3)" \
    -d '{"editor":"cozy", "description":{"en":"The drive application"}, "repository": "https://github.com/cozy/cozy-drive", "tags": ["reg3", "foo", "bar", "baz"], "type": "webapp", "category": "bar"}'
done

cat
