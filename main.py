import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

SUSPICIOUS_PORTS = {22, 23, 3389, 5900}


def read_packets(file_path: Path):
    with file_path.open("r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return list(reader)


def analyze_packets(packets):
    src_counter = Counter()
    port_counter = Counter()
    bytes_by_src = defaultdict(int)
    suspicious_events = []

    for packet in packets:
        src_ip = packet["src_ip"]
        dst_port = int(packet["dst_port"])
        bytes_sent = int(packet["bytes"])

        src_counter[src_ip] += 1
        port_counter[dst_port] += 1
        bytes_by_src[src_ip] += bytes_sent

        if dst_port in SUSPICIOUS_PORTS and packet["flag"].upper() == "FAILED":
            suspicious_events.append(
                f"Repeated failed access on sensitive port {dst_port} from {src_ip}"
            )

        if bytes_sent > 1000000:
            suspicious_events.append(
                f"Large transfer ({bytes_sent} bytes) from {src_ip} to {packet['dst_ip']}"
            )

    noisy_sources = [ip for ip, count in src_counter.items() if count >= 10]
    return src_counter, port_counter, bytes_by_src, noisy_sources, suspicious_events


def main() -> None:
    parser = argparse.ArgumentParser(description="Network Traffic Log Analysis")
    parser.add_argument("--input", default="sample_data/packets.csv", help="Path to packet log CSV")
    args = parser.parse_args()

    file_path = Path(args.input)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")

    packets = read_packets(file_path)
    src_counter, port_counter, bytes_by_src, noisy_sources, suspicious_events = analyze_packets(packets)

    print("Network Traffic Analysis Report")
    print("=" * 32)
    print(f"Total packets analyzed: {len(packets)}")

    print("\nTop talkers (source IP):")
    for ip, count in src_counter.most_common(5):
        print(f"- {ip}: {count} packets, {bytes_by_src[ip]} bytes")

    print("\nMost targeted ports:")
    for port, count in port_counter.most_common(5):
        print(f"- Port {port}: {count} hits")

    if noisy_sources:
        print("\nPotential scanning/noisy sources:")
        for ip in noisy_sources:
            print(f"- {ip}")

    print("\nSuspicious events:")
    if suspicious_events:
        for event in suspicious_events:
            print(f"- {event}")
    else:
        print("- No suspicious events detected.")


if __name__ == "__main__":
    main()
