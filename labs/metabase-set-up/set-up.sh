#!/bin/sh
# Start Metabase, finish its setup with an admin account nobody is told the password of,
# and stop it, so that the image starts set up.
set -eu
/app/run_metabase.sh > /tmp/metabase.log 2>&1 &
base=http://127.0.0.1:3000
tries=0
until curl -sf "$base/api/health" > /dev/null; do
  tries=$((tries + 1))
  if [ "$tries" -ge 150 ]; then tail -20 /tmp/metabase.log; exit 1; fi
  sleep 2
done
token=$(curl -sf "$base/api/session/properties" | grep -o '"setup-token":"[^"]*"' | cut -d '"' -f 4)
password="Lab1-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
curl -sf -o /dev/null -H 'Content-Type: application/json' "$base/api/setup" -d "{
  \"token\": \"$token\",
  \"user\": {\"email\": \"lab@example.com\", \"password\": \"$password\",
             \"first_name\": \"Lab\", \"last_name\": \"Admin\", \"site_name\": \"lab\"},
  \"prefs\": {\"site_name\": \"lab\", \"site_locale\": \"en\", \"allow_tracking\": \"false\"}}"
curl -sf "$base/api/session/properties" | grep -q '"has-user-setup":true'
kill $(pidof java)
while pidof java > /dev/null; do sleep 1; done
rm -f /tmp/metabase.log
