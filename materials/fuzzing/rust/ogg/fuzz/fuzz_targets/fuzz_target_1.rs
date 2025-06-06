#![no_main]

use ogg::{PacketReader, PacketWriter};
use ogg::writing::PacketWriteEndInfo;
use std::fs::File;
use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

fn harness(data: &[u8]) {
    let mut data = data.to_vec();
    let mut pck_rdr = PacketReader::new(Cursor::new(data));

    pck_rdr.delete_unread_packets();

    let output = Vec::new();

    let mut pck_wtr = PacketWriter::new(Cursor::new(output));

    if let Ok(r) = pck_rdr.read_packet() {
        if let Ok(r) = pck_rdr.read_packet() {
            match r {
                Some(pck) => {
                    let inf = if pck.last_in_stream() {
                        PacketWriteEndInfo::EndStream
                    } else if pck.last_in_page() {
                        PacketWriteEndInfo::EndPage
                    } else {
                        PacketWriteEndInfo::NormalPacket
                    };
                    let stream_serial = pck.stream_serial();
                    let absgp_page = pck.absgp_page();
                    let _ = pck_wtr.write_packet(pck.data, stream_serial, inf, absgp_page);
                }
                // End of stream
                None => return,
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    harness(data);
});
