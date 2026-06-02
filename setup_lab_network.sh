#!/bin/bash
# Creates two isolated network namespaces connected by a veth pair.
# Server and client get different IPs — real ICMP flows between them.
#
# Usage:
#   sudo bash setup_lab_network.sh setup   [--server-ip IP] [--client-ip IP]
#   sudo bash setup_lab_network.sh teardown

SERVER_IP="${SERVER_IP:-10.99.0.2}"
CLIENT_IP="${CLIENT_IP:-10.99.0.1}"

# Parse flags
while [[ $# -gt 0 ]]; do
  case $1 in
    --server-ip) SERVER_IP="$2"; shift 2 ;;
    --client-ip) CLIENT_IP="$2"; shift 2 ;;
    setup|teardown) CMD="$1"; shift ;;
    *) shift ;;
  esac
done

NS_SERVER="nps_server"
NS_CLIENT="nps_client"
VETH_S="veth_srv"
VETH_C="veth_cli"

teardown() {
  ip netns del "$NS_SERVER" 2>/dev/null
  ip netns del "$NS_CLIENT" 2>/dev/null
  echo "Torn down."
}

setup() {
  # Clean previous
  ip netns del "$NS_SERVER" 2>/dev/null
  ip netns del "$NS_CLIENT" 2>/dev/null

  # Create namespaces
  ip netns add "$NS_SERVER"
  ip netns add "$NS_CLIENT"

  # Create veth pair
  ip link add "$VETH_S" type veth peer name "$VETH_C"

  # Move each end into its namespace
  ip link set "$VETH_S" netns "$NS_SERVER"
  ip link set "$VETH_C" netns "$NS_CLIENT"

  # Assign IPs and bring up
  ip netns exec "$NS_SERVER" ip addr add "${SERVER_IP}/24" dev "$VETH_S"
  ip netns exec "$NS_SERVER" ip link set "$VETH_S" up
  ip netns exec "$NS_SERVER" ip link set lo up

  ip netns exec "$NS_CLIENT" ip addr add "${CLIENT_IP}/24" dev "$VETH_C"
  ip netns exec "$NS_CLIENT" ip link set "$VETH_C" up
  ip netns exec "$NS_CLIENT" ip link set lo up

  # Verify connectivity
  ip netns exec "$NS_CLIENT" ping -c1 -W1 "$SERVER_IP" >/dev/null 2>&1 \
    && echo "Ping OK: $CLIENT_IP -> $SERVER_IP" \
    || echo "WARNING: ping failed — check kernel support for veth"

  echo ""
  echo "======================================================="
  echo "  Lab network ready"
  echo "  Server IP : $SERVER_IP  (namespace: $NS_SERVER)"
  echo "  Client IP : $CLIENT_IP  (namespace: $NS_CLIENT)"
  echo "======================================================="
  echo ""
  echo "Run the SERVER in one terminal:"
  echo ""
  echo "  sudo ip netns exec $NS_SERVER \\"
  echo "    .venv/bin/python -m nps_lab_el.cli.sniffer_daemon \\"
  echo "    --config config/examples/lab_linux.yaml \\"
  echo "    --iface $VETH_S --verbose"
  echo ""
  echo "Run the KNOCKER in another terminal:"
  echo ""
  echo "  sudo ip netns exec $NS_CLIENT \\"
  echo "    .venv/bin/python -m nps_lab_el.cli.knock_client \\"
  echo "    --config config/examples/lab_linux.yaml \\"
  echo "    --target $SERVER_IP"
  echo ""
  echo "Teardown when done:"
  echo "  sudo bash setup_lab_network.sh teardown"
}

if [[ $EUID -ne 0 ]]; then
  echo "Must run as root: sudo bash $0 $CMD"
  exit 1
fi

case "$CMD" in
  setup)    setup ;;
  teardown) teardown ;;
  *) echo "Usage: sudo bash $0 setup|teardown [--server-ip IP] [--client-ip IP]"; exit 1 ;;
esac
