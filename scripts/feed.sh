#!/bin/bash

_term() {
  for pid in ${pids[@]}; do
    kill -INT $pid
  done
}

trap _term SIGINT

couch_addr="http://127.0.0.1:5984"
curl -s $couch_addr/_all_dbs | jq -r '.[]' | grep "registry-" | \
  xargs -I % python -c "import urllib; print urllib.quote('''%''', safe='')" | \
  xargs -I % curl -X DELETE ${couch_addr}/%

reg1=("bank" "drive" "health" "photos" "collect")
reg2=("drive" "homebook" "bank" "collect")
reg3=("bank" "collect" "drive" "onboarding" "photos" "settings")

pids=()
cozy-apps-registry --port 8081 --couchdb-prefix reg1 serve &
pids+=($!)
cozy-apps-registry --port 8082 --couchdb-prefix reg2 serve &
pids+=($!)
cozy-apps-registry --port 8083 --couchdb-prefix reg3 serve &
pids+=($!)

sleep 1

cozy-apps-registry add-editor cozy --couchdb-prefix reg1
cozy-apps-registry add-editor cozy --couchdb-prefix reg2
cozy-apps-registry add-editor cozy --couchdb-prefix reg3

for name in "${reg1[@]}"; do
  curl \
    --silent --fail \
    -X POST http://localhost:8081/registry \
    -H 'Content-Type:application/json' \
    -H "Authorization: Token $(cozy-apps-registry gen-token cozy --couchdb-prefix reg1)" \
    -d "{\"slug\": \"${name}\", \"editor\":\"cozy\", \"type\": \"webapp\"}" \
    > /dev/null
done

for name in "${reg2[@]}"; do
  curl \
    --silent --fail \
    -X POST http://localhost:8082/registry \
    -H 'Content-Type:application/json' \
    -H "Authorization: Token $(cozy-apps-registry gen-token cozy --couchdb-prefix reg2)" \
    -d "{\"slug\": \"${name}\", \"editor\":\"cozy\", \"type\": \"webapp\"}" \
    > /dev/null
done

for name in "${reg3[@]}"; do
  curl \
    --silent --fail \
    -X POST http://localhost:8083/registry \
    -H 'Content-Type:application/json' \
    -H "Authorization: Token $(cozy-apps-registry gen-token cozy --couchdb-prefix reg3)" \
    -d "{\"slug\": \"${name}\", \"editor\":\"cozy\", \"type\": \"webapp\"}" \
    > /dev/null
done

echo "Ready !"
cat
