use std::collections::HashMap;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct TcpFlowKey {
    src: String,
    dst: String,
    sport: u16,
    dport: u16,
}

impl TcpFlowKey {
    pub fn new(src: String, dst: String, sport: u16, dport: u16) -> Self {
        Self { src, dst, sport, dport }
    }
}

pub struct TcpJoiner {
    next_seq: u32,
    buffer: Vec<u8>,
}

impl TcpJoiner {
    pub fn new(seq: u32) -> Self {
        Self {
            next_seq: seq,
            buffer: Vec::new(),
        }
    }

    pub fn push(&mut self, seq: u32, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.is_empty() {
            return None;
        }

        if seq == self.next_seq {
            self.buffer.extend_from_slice(payload);
            self.next_seq += payload.len() as u32;
            return Some(std::mem::take(&mut self.buffer));
        }

        // sequence mismatch → reset
        self.buffer.clear();
        self.buffer.extend_from_slice(payload);
        self.next_seq = seq + payload.len() as u32;

        None
    }
}

#[derive(Default)]
pub struct TcpReassembler {
    flows: HashMap<TcpFlowKey, TcpJoiner>,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(
        &mut self,
        key: TcpFlowKey,
        seq: u32,
        payload: &[u8],
    ) -> Option<Vec<u8>> {

        let stream = self
            .flows
            .entry(key)
            .or_insert_with(|| TcpJoiner::new(seq));

        stream.push(seq, payload)
    }
}