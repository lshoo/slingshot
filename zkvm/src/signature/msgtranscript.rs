use merlin::Transcript;
use std::ops::Deref;

pub struct MsgTranscript {
    transcript: Transcript,
}

impl MsgTranscript {
    pub fn new(label: &[u8], msg: &Vec<u8>) -> MsgTranscript {
        let mut t = Transcript::new(label);
        t.commit_bytes(b"message", msg);
        MsgTranscript {
            transcript: t,
        }
    }
}

impl Deref for MsgTranscript {
    type Target = Transcript;

    fn deref(&self) -> &Transcript {
        &self.transcript
    }
}
