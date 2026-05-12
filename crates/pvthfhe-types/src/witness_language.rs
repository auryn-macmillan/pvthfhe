pub use crate::ProtocolBytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessSchemaVersion {
    V1,
}

impl WitnessSchemaVersion {
    fn to_u16(&self) -> u16 {
        match self {
            Self::V1 => 0x0001,
        }
    }

    fn from_u16(v: u16) -> Result<Self, SchemaError> {
        match v {
            0x0001 => Ok(Self::V1),
            _ => Err(SchemaError::UnsupportedVersion(v)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum R3Relation {
    ShareWellFormedness = 0,
    PartialDecryption = 1,
}

impl R3Relation {
    fn to_u32(&self) -> u32 {
        *self as u32
    }

    fn from_u32(v: u32) -> Result<Self, SchemaError> {
        match v {
            0 => Ok(Self::ShareWellFormedness),
            1 => Ok(Self::PartialDecryption),
            _ => Err(SchemaError::InvalidRelationId(v)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BfvParameters {
    pub q_log2: u64,
    pub degree: usize,
    pub error_bound: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessStatement {
    pub version: WitnessSchemaVersion,
    pub relation: R3Relation,
    pub session_id: ProtocolBytes,
    pub participant_id: u16,
    pub params: BfvParameters,
    pub public_key: ProtocolBytes,
    pub ciphertext: ProtocolBytes,
    pub commitment: ProtocolBytes,
    pub dkg_root: ProtocolBytes,
}

impl WitnessStatement {
    pub fn to_statement_bytes(&self) -> Result<Vec<u8>, SchemaError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_u16().to_be_bytes());
        out.extend_from_slice(&self.relation.to_u32().to_be_bytes());
        encode_len_prefixed(&mut out, self.session_id.as_slice())?;
        out.extend_from_slice(&self.participant_id.to_be_bytes());
        out.extend_from_slice(&self.params.q_log2.to_be_bytes());
        out.extend_from_slice(
            &u64::try_from(self.params.degree)
                .map_err(|_| SchemaError::Encoding("degree out of u64 range"))?
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.params.error_bound.to_be_bytes());
        encode_len_prefixed(&mut out, self.public_key.as_slice())?;
        encode_len_prefixed(&mut out, self.ciphertext.as_slice())?;
        encode_len_prefixed(&mut out, self.commitment.as_slice())?;
        encode_len_prefixed(&mut out, self.dkg_root.as_slice())?;
        Ok(out)
    }

    pub fn from_statement_bytes(bytes: &[u8]) -> Result<Self, SchemaError> {
        let mut cur = Cursor::new(bytes);
        let version_raw = cur.read_u16()?;
        let version = WitnessSchemaVersion::from_u16(version_raw)?;
        if !matches!(version, WitnessSchemaVersion::V1) {
            return Err(SchemaError::UnsupportedVersion(version_raw));
        }
        let relation_raw = cur.read_u32()?;
        let relation = R3Relation::from_u32(relation_raw)?;
        let session_id = ProtocolBytes::from(cur.read_len_prefixed_bytes()?);
        let participant_id = cur.read_u16()?;
        let q_log2 = cur.read_u64()?;
        let degree = usize::try_from(cur.read_u64()?)
            .map_err(|_| SchemaError::InvalidFormat("degree out of usize range"))?;
        let error_bound = cur.read_u64()?;
        let params = BfvParameters {
            q_log2,
            degree,
            error_bound,
        };
        let public_key = ProtocolBytes::from(cur.read_len_prefixed_bytes()?);
        let ciphertext = ProtocolBytes::from(cur.read_len_prefixed_bytes()?);
        let commitment = ProtocolBytes::from(cur.read_len_prefixed_bytes()?);
        let dkg_root = ProtocolBytes::from(cur.read_len_prefixed_bytes()?);
        cur.finish()?;
        Ok(Self {
            version,
            relation,
            session_id,
            participant_id,
            params,
            public_key,
            ciphertext,
            commitment,
            dkg_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessSecret {
    pub secret_share: crate::ShareSecret,
    pub randomness: crate::EncRandomness,
    pub noise: crate::NoisePoly,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WitnessCommitment {
    pub commitment_bytes: ProtocolBytes,
    pub hash_binding: ProtocolBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    UnsupportedVersion(u16),
    InvalidRelationId(u32),
    InvalidFormat(&'static str),
    Encoding(&'static str),
    Truncated,
    TrailingBytes,
}

impl core::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported schema version: {v}"),
            Self::InvalidRelationId(v) => write!(f, "invalid relation id: {v}"),
            Self::InvalidFormat(msg) => write!(f, "invalid statement format: {msg}"),
            Self::Encoding(msg) => write!(f, "encoding error: {msg}"),
            Self::Truncated => write!(f, "truncated statement bytes"),
            Self::TrailingBytes => write!(f, "trailing bytes after statement"),
        }
    }
}

impl std::error::Error for SchemaError {}

fn encode_len_prefixed(out: &mut Vec<u8>, data: &[u8]) -> Result<(), SchemaError> {
    let len = u32::try_from(data.len())
        .map_err(|_| SchemaError::Encoding("field too large for u32 length prefix"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], SchemaError> {
        let end = self.offset.checked_add(len).ok_or(SchemaError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(SchemaError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn read_u16(&mut self) -> Result<u16, SchemaError> {
        let b: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| SchemaError::Truncated)?;
        Ok(u16::from_be_bytes(b))
    }

    fn read_u32(&mut self) -> Result<u32, SchemaError> {
        let b: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| SchemaError::Truncated)?;
        Ok(u32::from_be_bytes(b))
    }

    fn read_u64(&mut self) -> Result<u64, SchemaError> {
        let b: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| SchemaError::Truncated)?;
        Ok(u64::from_be_bytes(b))
    }

    fn read_len_prefixed_bytes(&mut self) -> Result<Vec<u8>, SchemaError> {
        let len = usize::try_from(self.read_u32()?)
            .map_err(|_| SchemaError::InvalidFormat("length overflows usize"))?;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn finish(self) -> Result<(), SchemaError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SchemaError::TrailingBytes)
        }
    }
}
