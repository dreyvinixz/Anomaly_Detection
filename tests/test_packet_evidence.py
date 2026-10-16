"""Synthetic protocol evidence checks; no real PCAP download needed."""

import unittest
from anomaly_detection.packet_evidence import Evidence, phenotype, FIELDS


def packet(protocol="6", dst="172.16.114.207", syn="1", ack="0", port="80"):
    bits = (0x02 if syn == "1" else 0) | (0x10 if ack == "1" else 0)
    return ["921000000.500", "60", "198.51.100.2", dst, protocol,
            port if protocol == "6" else "", "53" if protocol == "17" else "",
            hex(bits) if protocol == "6" else ""]


class PacketEvidenceTests(unittest.TestCase):
    def test_metadata_field_count(self):
        self.assertEqual(len(packet()), len(FIELDS))

    def test_syn_counts_and_target_port_diversity(self):
        evidence = Evidence()
        for port in ("22", "80", "443"):
            evidence.add(packet(port=port))
        evidence.add(packet(syn="1", ack="1"))
        result = evidence.row("thursday", 15_350_000)
        self.assertEqual(result["packets"], 4)
        self.assertEqual(result["tcp_packets"], 4)
        self.assertEqual(result["syn_no_ack_packets"], 3)
        self.assertEqual(result["syn_ack_packets"], 1)
        self.assertEqual(result["top_syn_dst_ip"], "172.16.114.207")
        self.assertEqual(result["top_syn_dst_distinct_ports"], 3)

    def test_unknown_addresses_not_assigned_to_marx(self):
        evidence = Evidence()
        for _ in range(40):
            evidence.add(packet(dst="153.37.134.17"))
        result = evidence.row("wednesday", 15_350_000)
        self.assertEqual(result["top_syn_dst_ip"], "153.37.134.17")
        self.assertNotIn("marx", str(result).lower())
        self.assertEqual(phenotype(result), "tcp_syn_heavy")

    def test_udp_and_icmp_phenotypes(self):
        e = Evidence()
        for _ in range(6):
            e.add(packet(protocol="17"))
        self.assertEqual(phenotype(e.row("monday", 15_350_000)), "udp_dominated")


if __name__ == "__main__":
    unittest.main()
