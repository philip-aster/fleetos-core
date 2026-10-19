//! CORE-WI-6: wire-surface lock for NodeStatusReport.
//!
//! Pins field numbers (1 = node_svid, 2 = observed_at_unix) via golden
//! bytes — the same discipline as fleetos-ebpf-common's layout tests.

use fleetos_core::proto::state::NodeStatusReport;
use prost::Message;

fn read_varint(buf: &[u8], mut pos: usize) -> (u64, usize) {
    let mut value: u64 = 0;
    let mut shift = 0;
    loop {
        let byte = buf[pos];
        value |= ((byte & 0x7F) as u64) << shift;
        pos += 1;
        if byte & 0x80 == 0 {
            return (value, pos);
        }
        shift += 7;
    }
}

#[test]
fn node_status_report_field_numbers_are_frozen() {
    let report = NodeStatusReport {
        node_svid: "spiffe://fleet.example.internal/ns/system/node/agent-1".to_owned(),
        observed_at_unix: 1_700_000_000,
    };
    let mut buf = Vec::new();
    report.encode(&mut buf).unwrap();

    // Field 1 (node_svid): tag = (1 << 3) | 2 = 0x0A, length-delimited.
    assert_eq!(buf[0], 0x0A, "node_svid must remain field 1");
    let (len, next) = read_varint(&buf, 1);
    assert_eq!(len as usize, report.node_svid.len());
    // Field 2 (observed_at_unix): tag = (2 << 3) | 0 = 0x10, varint.
    // Field 2's tag sits after the string's content bytes.
    assert_eq!(
        buf[next + len as usize],
        0x10,
        "observed_at_unix must remain field 2"
    );
}

#[test]
fn node_status_report_round_trip() {
    let report = NodeStatusReport {
        node_svid: "spiffe://fleet.example.internal/ns/system/node/agent-1".to_owned(),
        observed_at_unix: 1_700_000_000,
    };
    let mut buf = Vec::new();
    report.encode(&mut buf).unwrap();
    let decoded = NodeStatusReport::decode(buf.as_slice()).unwrap();
    assert_eq!(decoded, report);
}
