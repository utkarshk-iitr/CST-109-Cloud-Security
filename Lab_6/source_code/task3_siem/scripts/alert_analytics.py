import argparse
import json
import re
from collections import Counter

ALERT_RE = re.compile(
    r"\[\d+:\d+:\d+\]\s+(?P<msg>.*?)\s+\[\*\*\].*?\{(?P<proto>\w+)\}\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)"
)


def run(path):
    msg_count = Counter()
    src_count = Counter()
    proto_count = Counter()

    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            match = ALERT_RE.search(line)
            if not match:
                continue
            data = match.groupdict()
            msg_count[data["msg"]] += 1
            src_count[data["src_ip"]] += 1
            proto_count[data["proto"]] += 1

    output = {
        "threat_type_frequency": dict(msg_count),
        "source_ip_frequency": dict(src_count),
        "protocol_frequency": dict(proto_count),
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--alert-file", default="/var/log/snort/alert")
    args = parser.parse_args()
    run(args.alert_file)
