#![allow(dead_code)]
use bytes::Bytes;
use thiserror::Error;

type VarInt = u64;

#[derive(Error, Debug)]
pub enum FrameError {
    #[error("Buffer too short")]
    BufferTooShort,
    #[error("Invalid frame type")]
    InvalidFrameType,
    #[error("Invalid variable length integer decoding")]
    InvalidVarInt,
    #[error("Invalid connection id length")]
    InvalidConnectionIdLength,
}

enum StreamDirection {
    BiDirectional,
    UniDirectional,
}
pub enum Frame {
    Padding,
    Ping,
    HandshakeDone,
    MaxData(VarInt),
    DataBlocked(VarInt),
    RetireConnectionId(VarInt),
    ResetStream(VarInt, VarInt, VarInt),
    StopSending(VarInt, VarInt),
    MaxStreamData(VarInt, VarInt),
    MaxStreams(StreamDirection, VarInt),
    StreamDataBlocked(VarInt, VarInt),
    StreamsBlocked(StreamDirection, VarInt),
    PathChallenge(u8, u8, u8, u8, u8, u8, u8, u8),
    PathResponse(u8, u8, u8, u8, u8, u8, u8, u8),
    NewToken(VarInt, Bytes),
    Crypto(VarInt, VarInt, Bytes),
    NewConnectionId(VarInt, VarInt, u8, VarInt, u128),
    ConnectionClose(VarInt, Option<VarInt>, VarInt, Bytes),
}
