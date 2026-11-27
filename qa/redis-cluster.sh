#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
root="$(mktemp -d)"
ports=(17380 17381 17382 17383 17384 17385)
case "$OTP_CLUSTER_ENGINE" in
  redis) image=redis:8; server=redis-server; cli=redis-cli; bus=(--cluster-bus-port-protected-mode no) ;;
  valkey) image=valkey/valkey:8; server=valkey-server; cli=valkey-cli; bus=() ;;
  *) exit 2 ;;
esac
cleanup() {
  for port in "${ports[@]}"; do docker rm -f "otp-cluster-$port" >/dev/null 2>&1 || :; done
  rm -rf "$root"
}
trap cleanup EXIT
run() { local port="$1"; shift; docker exec "otp-cluster-$port" "$cli" -p "$port" --raw "$@"; }
wait_for() {
  local attempts="$1"; shift
  for ((i=0; i<attempts; i++)); do
    if "$@"; then return 0; fi
    sleep 1
  done
  return 1
}
ping_node() { run "$1" ping 2>/dev/null | grep -qx PONG; }
healthy() { run "$1" cluster info 2>/dev/null | tr -d '\r' | grep -qx 'cluster_state:ok'; }
unavailable() { run "$1" cluster info 2>/dev/null | tr -d '\r' | grep -qx 'cluster_state:fail'; }
promoted() { run "$1" role 2>/dev/null | sed -n '1p' | grep -qx master && healthy "$1"; }
seed_list() { local p; local seeds=(); for p in "$@"; do seeds+=("127.0.0.1:$p"); done; (IFS=,; echo "${seeds[*]}"); }
for port in "${ports[@]}"; do
  docker run -d --name "otp-cluster-$port" --network host "$image" "$server" --bind 127.0.0.1 --port "$port" \
    --cluster-enabled yes "${bus[@]}" --cluster-config-file nodes.conf --cluster-node-timeout 2000 \
    --cluster-require-full-coverage yes --cluster-allow-reads-when-down no \
    --cluster-announce-ip 127.0.0.1 --cluster-announce-port "$port" --cluster-announce-bus-port "$((port + 10000))" \
    --appendonly yes --appendfsync always --repl-diskless-sync-delay 0 >/dev/null
done
addresses=()
for port in "${ports[@]}"; do
  wait_for 60 ping_node "$port"
  addresses+=("127.0.0.1:$port")
done
run 17380 --cluster create "${addresses[@]}" --cluster-replicas 1 --cluster-yes
for port in "${ports[@]}"; do wait_for 60 healthy "$port"; done
export OTP_CLUSTER_SEEDS="$(seed_list "${ports[@]}")"
timeout 60s php qa/redis-cluster.php seed "$OTP_CLUSTER_FACTOR" > "$root/proof"
run 17380 cluster nodes > "$root/nodes"
primary=''
key=''
while read -r id endpoint flags owner rest; do
  [[ "$flags" == *master* ]] || continue
  port="${endpoint#*:}"; port="${port%%@*}"
  found="$(run "$port" --scan --pattern 'otp-cluster:*:d:*')"
  [[ -n "$found" ]] || continue
  [[ -z "$primary" && "$found" != *$'\n'* ]]
  primary="$port"; primary_id="$id"; key="$found"
done < "$root/nodes"
[[ -n "$primary" && -n "$key" ]]
replica_endpoint="$(awk -v id="$primary_id" '$4==id && $3~/slave/{print $2;exit}' "$root/nodes")"
[[ -n "$replica_endpoint" ]]
replica="${replica_endpoint#*:}"; replica="${replica%%@*}"
native_digest() { run "$1" get "$key" | sha256sum | cut -d' ' -f1; }
[[ "$(run "$primary" exists "$key")" == 1 ]]
before="$(native_digest "$primary")"
offset="$(run "$primary" info replication | tr -d '\r' | sed -n 's/^master_repl_offset://p')"
[[ "$offset" =~ ^[0-9]+$ ]]
replicated() {
  local replica_offset
  replica_offset="$(run "$replica" info replication | tr -d '\r' | sed -n 's/^slave_repl_offset://p')"
  [[ "$replica_offset" =~ ^[0-9]+$ ]] && (( replica_offset >= offset )) &&
    run "$replica" info replication | tr -d '\r' | grep -qx 'master_link_status:up'
}
wait_for 60 replicated
echo "Native replay record identified; replica caught up."
if [[ "$OTP_CLUSTER_FAULT" == promotion ]]; then
  docker stop -t 1 "otp-cluster-$primary" >/dev/null
  wait_for 90 promoted "$replica"
  [[ "$(run "$replica" exists "$key")" == 1 && "$(native_digest "$replica")" == "$before" ]]
  survivors=()
  for port in "${ports[@]}"; do [[ "$port" == "$primary" ]] || survivors+=("$port"); done
  export OTP_CLUSTER_SEEDS="$(seed_list "${survivors[@]}")"
else
  stopped=(); survivors=()
  for port in "${ports[@]}"; do
    case "$OTP_CLUSTER_FAULT" in
      minority) if [[ "$port" == "$primary" || "$port" == "$replica" ]]; then survivors+=("$port"); else stopped+=("$port"); fi ;;
      shard-loss) if [[ "$port" == "$primary" || "$port" == "$replica" ]]; then stopped+=("$port"); else survivors+=("$port"); fi ;;
      *) exit 2 ;;
    esac
  done
  for port in "${stopped[@]}"; do docker kill "otp-cluster-$port" >/dev/null; done
  for port in "${stopped[@]}"; do
    [[ "$(docker inspect -f '{{.State.Running}}' "otp-cluster-$port")" == false ]]
  done
  for port in "${survivors[@]}"; do wait_for 60 unavailable "$port"; done
  native="$(run "${survivors[0]}" set otp-outage-control rejected 2>&1 || :)"
  grep -q CLUSTERDOWN <<< "$native"
  export OTP_CLUSTER_SEEDS="$(seed_list "${survivors[@]}")"
  timeout 60s php qa/redis-cluster.php offline "$OTP_CLUSTER_FACTOR" < "$root/proof"
  for port in "${stopped[@]}"; do docker start "otp-cluster-$port" >/dev/null; done
  for port in "${ports[@]}"; do wait_for 90 healthy "$port"; done
  export OTP_CLUSTER_SEEDS="$(seed_list "${ports[@]}")"
  [[ "$(run 17380 -c exists otp-outage-control)" == 0 ]]
  [[ "$(run 17380 -c exists "$key")" == 1 ]]
  [[ "$(run 17380 -c get "$key" | sha256sum | cut -d' ' -f1)" == "$before" ]]
fi
timeout 90s php qa/redis-cluster.php recover "$OTP_CLUSTER_FACTOR" < "$root/proof"
echo "Verified $OTP_CLUSTER_ENGINE / $OTP_CLUSTER_FAULT / $OTP_CLUSTER_FACTOR: native state and one-winner recovery."
