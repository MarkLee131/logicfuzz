#!/bin/bash

set -x

bootstrap_empty_db() {
  echo "Warning: $BASE/$DATA_DIR/fuzz_introspector_db not found."
  echo "         Creating an empty placeholder DB so the web app can boot."
  echo "         To see real data, mount /experiment/data-dir/fuzz_introspector_db."
  mkdir -p db/db-projects
  cat <<'EOF' > db/db-timestamps.json
[]
EOF
  cat <<'EOF' > db/all-project-timestamps.json
[]
EOF
  cat <<'EOF' > db/all-project-current.json
[]
EOF
  cat <<'EOF' > db/build-status.json
{}
EOF
  cat <<'EOF' > db/projects-not-in-oss-fuzz.json
[]
EOF
  cat <<'EOF' > db/all-header-files.json
[]
EOF
  cat <<'EOF' > db/full-oss-fuzz-project-count.json
{}
EOF
}

BASE=$PWD
DATA_DIR="data-dir"

PROJECTS_TO_ANALYSE=""
for d in $DATA_DIR/oss-fuzz2/projects/*; do
  PROJECTS_TO_ANALYSE="${PROJECTS_TO_ANALYSE}$(basename $d),"
done

echo "${PROJECTS_TO_ANALYSE}"

# Create a minor clone of OSS-Fuzz where we will populate it with data
# for Fuzz Introspector webapp
git clone --depth=1 https://github.com/gejingquan/oss-fuzz

cd oss-fuzz
rsync -avu "$BASE/$DATA_DIR/oss-fuzz2/" .

############ Start a Fuzz Introspector server
cd $BASE
git clone --depth=1 https://github.com/ossf/fuzz-introspector
cd fuzz-introspector/tools/web-fuzzing-introspection
${PYTHON} -m pip install -r requirements.txt
#python3 -m virtualenv .venv
#.venv/bin/python3 -m pip install -r requirements.txt

# Copy the database we have created already
cd app/static/assets
rm -rf ./db
if [ -d "$BASE/$DATA_DIR/fuzz_introspector_db" ]; then
  cp -rf $BASE/$DATA_DIR/fuzz_introspector_db db
else
  bootstrap_empty_db
fi
cd ../../
# Launch the server
FUZZ_INTROSPECTOR_SHUTDOWN=1 FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=$BASE/$DATA_DIR/oss-fuzz2 ${PYTHON} main.py >>/dev/null &

# Wait until the server has launched
SECONDS=5
while true
do
  # Checking if exists
  MSG=$(curl -v --silent 127.0.0.1:8080 2>&1 | grep "Fuzzing" | wc -l)
  if [[ $MSG > 0 ]]; then
    echo "Found it"
    break
  fi
  echo "- Waiting for webapp to load. Sleeping ${SECONDS} seconds."
  sleep ${SECONDS}
done
echo "Local version of introspector is up and running"
exit 0
