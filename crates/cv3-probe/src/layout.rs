//! The interface the sensor must present before any protocol work is attempted.
//!
//! Interface 0 is vendor-specific (class `0xfe`) and carries exactly three endpoints: bulk OUT
//! `0x01` for commands, bulk IN `0x81` for reply bodies, and interrupt IN `0x85` for the
//! asynchronous announcement and finger events. Validating this before sending a byte keeps a
//! wrong device, or a firmware that changed its descriptor, from being driven with the wrong
//! pipe.

use core::fmt;

/// Transfer type of an endpoint, from `bmAttributes` bits 0–1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
}

impl fmt::Display for TransferType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Control => "control",
            Self::Isochronous => "isochronous",
            Self::Bulk => "bulk",
            Self::Interrupt => "interrupt",
        };
        f.write_str(name)
    }
}

/// One endpoint as the descriptor reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointDescriptor {
    /// `bEndpointAddress`, direction bit included.
    pub address: u8,
    pub transfer: TransferType,
}

/// One alternate setting of an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDescriptor {
    /// `bInterfaceNumber`.
    pub number: u8,
    /// `bInterfaceClass`; the sensor's is `0xfe` (vendor specific).
    pub class: u8,
    pub endpoints: Vec<EndpointDescriptor>,
}

/// The three pipes the protocol uses, once the descriptor has been accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointLayout {
    pub out: u8,
    pub input: u8,
    pub interrupt: u8,
}

impl EndpointLayout {
    pub const SENSOR: Self = Self {
        out: 0x01,
        input: 0x81,
        interrupt: 0x85,
    };
}

/// Why a descriptor is not the sensor's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    WrongInterface {
        got: u8,
        want: u8,
    },
    WrongClass {
        got: u8,
        want: u8,
    },
    MissingEndpoint {
        address: u8,
        transfer: TransferType,
    },
    WrongTransferType {
        address: u8,
        got: TransferType,
    },
    UnexpectedEndpoint {
        address: u8,
    },
    /// The same expected endpoint appears more than once.
    ///
    /// Kept separate from [`Self::UnexpectedEndpoint`]: `0x01` *is* expected, so calling its
    /// second listing "unexpected" would hide that the descriptor names the command pipe twice.
    DuplicateEndpoint {
        address: u8,
    },
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongInterface { got, want } => {
                write!(f, "interface {got} is not the sensor's interface {want}")
            }
            Self::WrongClass { got, want } => {
                write!(f, "interface class {got:#04x} is not {want:#04x}")
            }
            Self::MissingEndpoint { address, transfer } => {
                write!(f, "missing {transfer} endpoint {address:#04x}")
            }
            Self::WrongTransferType { address, got } => {
                write!(
                    f,
                    "endpoint {address:#04x} is {got}, not the type the protocol needs"
                )
            }
            Self::UnexpectedEndpoint { address } => {
                write!(f, "unexpected endpoint {address:#04x}")
            }
            Self::DuplicateEndpoint { address } => {
                write!(f, "endpoint {address:#04x} is listed more than once")
            }
        }
    }
}

impl std::error::Error for LayoutError {}

/// Interface number the protocol uses.
pub const SENSOR_INTERFACE: u8 = 0;
/// Interface class of the sensor's command interface.
pub const SENSOR_CLASS: u8 = 0xfe;

/// Checks that `descriptor` is the sensor's interface and returns the pipes to open.
///
/// The layout is exact: a missing, mistyped or additional endpoint is an error, because a
/// descriptor that differs from the audited one means the protocol assumptions no longer hold.
pub fn validate(descriptor: &InterfaceDescriptor) -> Result<EndpointLayout, LayoutError> {
    if descriptor.number != SENSOR_INTERFACE {
        return Err(LayoutError::WrongInterface {
            got: descriptor.number,
            want: SENSOR_INTERFACE,
        });
    }
    if descriptor.class != SENSOR_CLASS {
        return Err(LayoutError::WrongClass {
            got: descriptor.class,
            want: SENSOR_CLASS,
        });
    }

    let expected = [
        (EndpointLayout::SENSOR.out, TransferType::Bulk),
        (EndpointLayout::SENSOR.input, TransferType::Bulk),
        (EndpointLayout::SENSOR.interrupt, TransferType::Interrupt),
    ];
    for (address, transfer) in expected {
        let endpoint = descriptor
            .endpoints
            .iter()
            .find(|endpoint| endpoint.address == address)
            .ok_or(LayoutError::MissingEndpoint { address, transfer })?;
        if endpoint.transfer != transfer {
            return Err(LayoutError::WrongTransferType {
                address,
                got: endpoint.transfer,
            });
        }
    }

    // Every endpoint must account for exactly one expected pipe, in any order. Matching by pair
    // rather than position is what makes an extra endpoint before the expected ones an error.
    let mut seen = [false; 3];
    for endpoint in &descriptor.endpoints {
        let expected_index = expected.iter().position(|&(address, transfer)| {
            endpoint.address == address && endpoint.transfer == transfer
        });
        match expected_index {
            Some(index) if !seen[index] => seen[index] = true,
            Some(_) => {
                return Err(LayoutError::DuplicateEndpoint {
                    address: endpoint.address,
                });
            }
            None => {
                return Err(LayoutError::UnexpectedEndpoint {
                    address: endpoint.address,
                });
            }
        }
    }

    Ok(EndpointLayout::SENSOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sensor() -> InterfaceDescriptor {
        InterfaceDescriptor {
            number: 0,
            class: 0xfe,
            endpoints: vec![
                EndpointDescriptor {
                    address: 0x01,
                    transfer: TransferType::Bulk,
                },
                EndpointDescriptor {
                    address: 0x81,
                    transfer: TransferType::Bulk,
                },
                EndpointDescriptor {
                    address: 0x85,
                    transfer: TransferType::Interrupt,
                },
            ],
        }
    }

    #[test]
    fn accepts_the_sensor_descriptor_and_returns_its_three_pipes() {
        let layout = validate(&sensor()).expect("the real descriptor is accepted");

        assert_eq!(
            layout,
            EndpointLayout {
                out: 0x01,
                input: 0x81,
                interrupt: 0x85,
            }
        );
    }

    #[test]
    fn rejects_an_interface_other_than_zero() {
        let mut descriptor = sensor();
        descriptor.number = 1;

        assert_eq!(
            validate(&descriptor),
            Err(LayoutError::WrongInterface { got: 1, want: 0 })
        );
    }

    #[test]
    fn rejects_a_non_vendor_interface_class() {
        let mut descriptor = sensor();
        descriptor.class = 0x03;

        assert_eq!(
            validate(&descriptor),
            Err(LayoutError::WrongClass {
                got: 0x03,
                want: 0xfe
            })
        );
    }

    #[test]
    fn rejects_a_descriptor_without_the_command_endpoint() {
        let mut descriptor = sensor();
        descriptor.endpoints.retain(|ep| ep.address != 0x01);

        assert_eq!(
            validate(&descriptor),
            Err(LayoutError::MissingEndpoint {
                address: 0x01,
                transfer: TransferType::Bulk,
            })
        );
    }

    #[test]
    fn rejects_a_reply_endpoint_of_the_wrong_transfer_type() {
        let mut descriptor = sensor();
        descriptor.endpoints[1].transfer = TransferType::Interrupt;

        assert_eq!(
            validate(&descriptor),
            Err(LayoutError::WrongTransferType {
                address: 0x81,
                got: TransferType::Interrupt,
            })
        );
    }

    #[test]
    fn rejects_a_fourth_endpoint() {
        let mut descriptor = sensor();
        descriptor.endpoints.push(EndpointDescriptor {
            address: 0x02,
            transfer: TransferType::Bulk,
        });

        assert_eq!(
            validate(&descriptor),
            Err(LayoutError::UnexpectedEndpoint { address: 0x02 })
        );
    }

    #[test]
    fn rejects_an_extra_endpoint_before_the_expected_ones() {
        let mut descriptor = sensor();
        descriptor.endpoints.insert(
            0,
            EndpointDescriptor {
                address: 0x02,
                transfer: TransferType::Bulk,
            },
        );

        assert_eq!(
            validate(&descriptor),
            Err(LayoutError::UnexpectedEndpoint { address: 0x02 })
        );
    }

    #[test]
    fn rejects_an_endpoint_listed_twice() {
        let mut descriptor = sensor();
        descriptor.endpoints.insert(
            1,
            EndpointDescriptor {
                address: 0x01,
                transfer: TransferType::Bulk,
            },
        );

        assert_eq!(
            validate(&descriptor),
            Err(LayoutError::DuplicateEndpoint { address: 0x01 })
        );
    }
}
