use thiserror::Error;

type VarInt = u64;

#[derive(Error, Debug, PartialEq)]
pub enum FrameValidationError {
    #[error("MAX_STREAMS value decreased (current={current}, new={new})")]
    MaxStreamsDecreased { current: VarInt, new: VarInt },
    #[error("MAX_STREAM_DATA value decreased (current={current}, new={new})")]
    MaxStreamDataDecreased { current: VarInt, new: VarInt },
    #[error("Final size changed (current={current}, new={new})")]
    FinalSizeChanged { current: VarInt, new: VarInt },
    #[error(
        "Final size below received data (final_size={final_size}, observed_end={observed_end})"
    )]
    FinalSizeBelowReceived {
        final_size: VarInt,
        observed_end: VarInt,
    },
    #[error("MAX_STREAMS above limit (value={value}, limit={limit})")]
    MaxStreamsAboveLimit { value: VarInt, limit: VarInt },
    #[error("MAX_STREAM_DATA above limit (value={value}, limit={limit})")]
    MaxStreamDataAboveLimit { value: VarInt, limit: VarInt },
    #[error("STREAMS_BLOCKED above limit (value={value}, limit={limit})")]
    StreamsBlockedAboveLimit { value: VarInt, limit: VarInt },
    #[error("STREAM_DATA_BLOCKED above limit (value={value}, limit={limit})")]
    StreamDataBlockedAboveLimit { value: VarInt, limit: VarInt },
}

pub fn validate_max_streams_monotonic(
    current: Option<VarInt>,
    new: VarInt,
) -> Result<(), FrameValidationError> {
    if let Some(current_value) = current
        && new < current_value
    {
        return Err(FrameValidationError::MaxStreamsDecreased {
            current: current_value,
            new,
        });
    }
    Ok(())
}

pub fn validate_max_stream_data_monotonic(
    current: Option<VarInt>,
    new: VarInt,
) -> Result<(), FrameValidationError> {
    if let Some(current_value) = current
        && new < current_value
    {
        return Err(FrameValidationError::MaxStreamDataDecreased {
            current: current_value,
            new,
        });
    }
    Ok(())
}

pub fn validate_final_size(
    current: Option<VarInt>,
    new: VarInt,
    observed_end: Option<VarInt>,
) -> Result<(), FrameValidationError> {
    if let Some(current_value) = current
        && new != current_value
    {
        return Err(FrameValidationError::FinalSizeChanged {
            current: current_value,
            new,
        });
    }
    if let Some(observed) = observed_end
        && new < observed
    {
        return Err(FrameValidationError::FinalSizeBelowReceived {
            final_size: new,
            observed_end: observed,
        });
    }
    Ok(())
}

pub fn validate_max_streams_upper_bound(
    value: VarInt,
    limit: VarInt,
) -> Result<(), FrameValidationError> {
    if value > limit {
        return Err(FrameValidationError::MaxStreamsAboveLimit { value, limit });
    }
    Ok(())
}

pub fn validate_max_stream_data_upper_bound(
    value: VarInt,
    limit: VarInt,
) -> Result<(), FrameValidationError> {
    if value > limit {
        return Err(FrameValidationError::MaxStreamDataAboveLimit { value, limit });
    }
    Ok(())
}

pub fn validate_streams_blocked(value: VarInt, limit: VarInt) -> Result<(), FrameValidationError> {
    if value > limit {
        return Err(FrameValidationError::StreamsBlockedAboveLimit { value, limit });
    }
    Ok(())
}

pub fn validate_stream_data_blocked(
    value: VarInt,
    limit: VarInt,
) -> Result<(), FrameValidationError> {
    if value > limit {
        return Err(FrameValidationError::StreamDataBlockedAboveLimit { value, limit });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_max_streams_monotonic_ok() {
        assert_eq!(validate_max_streams_monotonic(Some(10), 10), Ok(()));
        assert_eq!(validate_max_streams_monotonic(Some(10), 12), Ok(()));
    }

    #[test]
    fn test_validate_max_streams_monotonic_decreased() {
        assert_eq!(
            validate_max_streams_monotonic(Some(10), 9),
            Err(FrameValidationError::MaxStreamsDecreased {
                current: 10,
                new: 9
            })
        );
    }

    #[test]
    fn test_validate_max_stream_data_monotonic_decreased() {
        assert_eq!(
            validate_max_stream_data_monotonic(Some(5), 4),
            Err(FrameValidationError::MaxStreamDataDecreased { current: 5, new: 4 })
        );
    }

    #[test]
    fn test_validate_final_size_changed() {
        assert_eq!(
            validate_final_size(Some(10), 12, None),
            Err(FrameValidationError::FinalSizeChanged {
                current: 10,
                new: 12
            })
        );
    }

    #[test]
    fn test_validate_final_size_below_received() {
        assert_eq!(
            validate_final_size(None, 5, Some(6)),
            Err(FrameValidationError::FinalSizeBelowReceived {
                final_size: 5,
                observed_end: 6
            })
        );
    }

    #[test]
    fn test_validate_max_streams_upper_bound() {
        assert_eq!(validate_max_streams_upper_bound(10, 10), Ok(()));
        assert_eq!(
            validate_max_streams_upper_bound(11, 10),
            Err(FrameValidationError::MaxStreamsAboveLimit {
                value: 11,
                limit: 10
            })
        );
    }

    #[test]
    fn test_validate_streams_blocked_upper_bound() {
        assert_eq!(
            validate_streams_blocked(5, 4),
            Err(FrameValidationError::StreamsBlockedAboveLimit { value: 5, limit: 4 })
        );
    }

    #[test]
    fn test_validate_stream_data_blocked_upper_bound() {
        assert_eq!(
            validate_stream_data_blocked(9, 8),
            Err(FrameValidationError::StreamDataBlockedAboveLimit { value: 9, limit: 8 })
        );
    }
}
