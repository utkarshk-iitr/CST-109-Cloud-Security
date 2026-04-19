#!/usr/bin/env bash
set -e

IFACE=${IFACE:-lo}
DURATION=${DURATION:-180}
OUT_DIR=${OUT_DIR:-./output}
PCAP_FILE=${PCAP_FILE:-$OUT_DIR/capture.pcapng}

mkdir -p "$OUT_DIR"

sudo tshark -i "$IFACE" -a "duration:$DURATION" -w "$PCAP_FILE"

SESSION_FILE="$OUT_DIR/sessions.txt"
HANDSHAKE_FILE="$OUT_DIR/tcp_handshake.txt"
DNS_FILE="$OUT_DIR/dns_queries.txt"
PLAINTEXT_FILE="$OUT_DIR/plaintext_vs_tls.txt"

sudo tshark -r "$PCAP_FILE" -Y "ip" -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e _ws.col.Protocol 2>/dev/null | awk 'NF>=5 {print $1":"$2" -> "$3":"$4" ["$5"]"}' | sort -u | head -n 20 > "$SESSION_FILE"

STREAM_ID=$(sudo tshark -r "$PCAP_FILE" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e tcp.stream | head -n 1 || true)
if [ -n "$STREAM_ID" ]; then
  sudo tshark -r "$PCAP_FILE" -Y "tcp.stream==$STREAM_ID && (tcp.flags.syn==1 || tcp.flags.ack==1)" -T fields -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags | head -n 10 > "$HANDSHAKE_FILE"
else
  echo "No TCP handshake found" > "$HANDSHAKE_FILE"
fi

sudo tshark -r "$PCAP_FILE" -Y "dns" -T fields -e frame.number -e ip.src -e ip.dst -e dns.qry.name -e dns.a | awk 'NF>0' | head -n 40 > "$DNS_FILE"

HTTP_COUNT=$(sudo tshark -r "$PCAP_FILE" -Y "http" | wc -l)
TLS_COUNT=$(sudo tshark -r "$PCAP_FILE" -Y "tls || ssl" | wc -l)
{
  echo "HTTP_FRAMES=$HTTP_COUNT"
  echo "TLS_FRAMES=$TLS_COUNT"
  echo "HTTP_SAMPLE"
  sudo tshark -r "$PCAP_FILE" -Y "http.request" -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | head -n 10
  echo "TLS_SAMPLE"
  sudo tshark -r "$PCAP_FILE" -Y "tls.handshake.type==1" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name | head -n 10
} > "$PLAINTEXT_FILE"

printf "Capture: %s\n" "$PCAP_FILE"
printf "Sessions: %s\n" "$SESSION_FILE"
printf "Handshake: %s\n" "$HANDSHAKE_FILE"
printf "DNS: %s\n" "$DNS_FILE"
printf "Plaintext/TLS: %s\n" "$PLAINTEXT_FILE"
