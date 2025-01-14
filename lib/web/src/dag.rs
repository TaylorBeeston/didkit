use anyhow::Result;
use libipld::{cbor::DagCborCodec, codec::Codec, Cid, Ipld};
use multihash::{Code, MultihashDigest};
use serde::Serialize;
use serde_wasm_bindgen::{from_value, Serializer};
use wasm_bindgen::JsValue;

const ENC_BLOCK_SIZE: usize = 24;

/// Pads a byte array with zeros to reach a multiple of the block size
fn pad(bytes: &[u8], block_size: Option<usize>) -> Vec<u8> {
    let block_size = block_size.unwrap_or(ENC_BLOCK_SIZE);
    let pad_len = (block_size - (bytes.len() % block_size)) % block_size;
    let mut padded = Vec::with_capacity(bytes.len() + pad_len);
    padded.extend_from_slice(bytes);
    padded.extend(std::iter::repeat(0).take(pad_len));
    padded
}

/// Encodes a value using DAG-CBOR and creates a CID with identity multihash
fn encode_identity_cid(value: &JsValue) -> Result<Cid> {
    let ipld: Ipld = from_value(value.clone()).unwrap();

    // Encode to DAG-CBOR
    let bytes = DagCborCodec.encode(&ipld)?;

    // Create identity multihash
    let mh = Code::Identity.digest(&bytes);

    // Create CID (dag-cbor with identity multihash)
    Ok(Cid::new_v1(DagCborCodec.into(), mh))
}

/// Decodes a CID with identity multihash back to the original value
fn decode_identity_cid(cid: &Cid) -> Result<JsValue> {
    if cid.codec() != u64::from(DagCborCodec) {
        anyhow::bail!("CID codec must be dag-cbor");
    }

    if cid.hash().code() != u64::from(Code::Identity) {
        anyhow::bail!("CID must use identity multihash");
    }

    let bytes = cid.hash().digest();
    let ipld: Ipld = DagCborCodec.decode(bytes)?;

    let serializer = Serializer::json_compatible();

    Ok(ipld.serialize(&serializer).unwrap())
}

/// Prepares cleartext for encryption by encoding it as a CID and padding
pub async fn prepare_cleartext(cleartext: &JsValue, block_size: Option<usize>) -> Result<Vec<u8>> {
    let cid = encode_identity_cid(cleartext)?;
    Ok(pad(&cid.to_bytes(), block_size))
}

/// Decodes padded cleartext bytes back to the original value
pub fn decode_cleartext(bytes: &[u8]) -> Result<JsValue> {
    let cid = Cid::read_bytes(bytes)?;
    decode_identity_cid(&cid)
}
