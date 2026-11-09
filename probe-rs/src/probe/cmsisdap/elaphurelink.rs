//! CMSIS-DAP over the elaphureLink wireless DAP proxy.
//!
//! elaphureLink exposes a CMSIS-DAP probe over TCP. This is the framing used by
//! OpenOCD's `cmsis-dap backend elaphurelink` (`cmsis_dap_elaphurelink.c`):
//!
//! * Connect to `host:3240` (`dap.local` by default).
//! * Send a 12 byte handshake in network byte order: `0x8a656c70`,
//!   `0x00000000` (handshake command), `0x00010000` (proxy version). Expect the
//!   same identifier and command back, plus the device's DAP version.
//! * Send `88 02 00 00` to enter the vendor command scope; the proxy answers
//!   with a vendor frame whose status byte must be 0.
//! * Every CMSIS-DAP command is sent as `88 01 <len:u16 BE> <payload>` and every
//!   reply arrives as `88 <status> <len:u16 BE> <payload>`. The payload is the
//!   raw CMSIS-DAP command/response, without a HID report id.
//!
//! Like a TCP CMSIS-DAP probe, a network probe has no USB identity, so it is
//! selected with a placeholder VID:PID and its address as the serial number,
//! for example `--probe 0000:0002:dap.local`.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Placeholder vendor id that routes a selector to the elaphureLink transport.
pub(crate) const ELAPHURELINK_VID: u16 = 0x0000;

/// Placeholder product id that routes a selector to the elaphureLink transport.
/// `0x0001` is already used by the generic CMSIS-DAP TCP backend.
pub(crate) const ELAPHURELINK_PID: u16 = 0x0002;

/// Port used by elaphureLink proxies and OpenOCD's backend.
const DEFAULT_PORT: u16 = 3240;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// A Wi-Fi round trip is slower than a USB timeout; OpenOCD uses the same floor.
const MIN_READ_TIMEOUT: Duration = Duration::from_millis(150);

const LINK_IDENTIFIER: u32 = 0x8a65_6c70;
const COMMAND_HANDSHAKE: u32 = 0x0000_0000;
const PROXY_VERSION: u32 = 0x0001_0000;

const VENDOR_PREFIX: u8 = 0x88;
const VENDOR_PASSTHROUGH: u8 = 0x01;
const VENDOR_SCOPE_ENTER: u8 = 0x02;
const HEADER_LEN: usize = 4;
/// OpenOCD sizes elaphureLink packets for an Ethernet MTU.
const MAX_PAYLOAD: usize = 1500 - HEADER_LEN;

/// A connection to an elaphureLink proxy.
pub struct ElaphureLinkDevice {
    stream: TcpStream,
    address: String,
    /// Bytes received but not yet returned as one complete vendor frame.
    pending: Vec<u8>,
}

impl ElaphureLinkDevice {
    /// Connect to `address`, given as `host`, `host:port` or `[ipv6]:port`,
    /// and complete the elaphureLink handshake.
    pub fn connect(address: &str) -> io::Result<Self> {
        let mut last_error = io::Error::new(ErrorKind::NotFound, "address resolved to nothing");
        for socket_address in resolve(address)? {
            match TcpStream::connect_timeout(&socket_address, CONNECT_TIMEOUT) {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    let mut device = Self {
                        stream,
                        address: address.to_string(),
                        pending: Vec::new(),
                    };
                    let result = device.handshake();
                    // Command reads set their own timeouts; leave none in between.
                    device.stream.set_read_timeout(None)?;
                    device.stream.set_write_timeout(None)?;
                    result?;
                    return Ok(device);
                }
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    /// The address the device was opened with.
    pub fn address(&self) -> &str {
        &self.address
    }

    fn handshake(&mut self) -> io::Result<()> {
        self.stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        self.stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

        let mut request = Vec::with_capacity(12);
        request.extend_from_slice(&LINK_IDENTIFIER.to_be_bytes());
        request.extend_from_slice(&COMMAND_HANDSHAKE.to_be_bytes());
        request.extend_from_slice(&PROXY_VERSION.to_be_bytes());
        self.stream.write_all(&request)?;

        let mut reply = [0u8; 12];
        self.stream.read_exact(&mut reply).map_err(timed_out)?;
        let identifier = u32::from_be_bytes(reply[0..4].try_into().unwrap());
        let command = u32::from_be_bytes(reply[4..8].try_into().unwrap());
        let version = u32::from_be_bytes(reply[8..12].try_into().unwrap());
        if identifier != LINK_IDENTIFIER || command != COMMAND_HANDSHAKE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid elaphureLink handshake response",
            ));
        }
        if (version >> 16) & 0xffff < 1 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unsupported elaphureLink proxy version (major version < 1)",
            ));
        }

        // Enter vendor scope before any passthrough command is accepted.
        self.stream
            .write_all(&[VENDOR_PREFIX, VENDOR_SCOPE_ENTER, 0, 0])?;
        let mut discard = [0u8; MAX_PAYLOAD];
        let (status, _) = self.read_frame(&mut discard, HANDSHAKE_TIMEOUT)?;
        if status != 0 {
            return Err(io::Error::other(format!(
                "elaphureLink vendor scope was rejected (status {status:#04x})"
            )));
        }
        Ok(())
    }

    /// Send one CMSIS-DAP command.
    pub fn write(&mut self, payload: &[u8]) -> io::Result<usize> {
        if payload.len() > MAX_PAYLOAD {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "elaphureLink packet longer than the 1496 byte MTU",
            ));
        }
        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
        frame.extend_from_slice(&[VENDOR_PREFIX, VENDOR_PASSTHROUGH]);
        // OpenOCD writes this length with htons(), i.e. big endian.
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        self.stream.write_all(&frame)?;
        Ok(payload.len())
    }

    /// Receive one CMSIS-DAP response into `buf`, returning its length.
    ///
    /// Fails with [`ErrorKind::TimedOut`] if no complete frame arrives within
    /// `timeout`. Bytes of a partial frame are kept for the next call, so a
    /// late reply is delivered intact rather than corrupting the next command.
    pub fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let (status, length) = self.read_frame(buf, timeout)?;
        if status != 0 {
            // OpenOCD ignores the status on ordinary replies; surface it in the
            // log but still hand the payload to the command layer.
            tracing::warn!("elaphureLink vendor frame reported status {status:#04x}");
        }
        Ok(length)
    }

    /// Read exactly one vendor frame, returning `(status, payload length)`.
    fn read_frame(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<(u8, usize)> {
        let deadline = Instant::now() + timeout.max(MIN_READ_TIMEOUT);
        loop {
            if let Some(frame) = self.take_frame(buf)? {
                return Ok(frame);
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ErrorKind::TimedOut.into());
            }
            self.stream.set_read_timeout(Some(remaining))?;

            let mut chunk = [0u8; 2048];
            match self.stream.read(&mut chunk).map_err(timed_out)? {
                0 => return Err(ErrorKind::ConnectionAborted.into()),
                n => self.pending.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Move one complete frame from `pending` to `buf`, if there is one.
    fn take_frame(&mut self, buf: &mut [u8]) -> io::Result<Option<(u8, usize)>> {
        if self.pending.len() < HEADER_LEN {
            return Ok(None);
        }
        let (status, length) = {
            let header = &self.pending[..HEADER_LEN];
            if header[0] != VENDOR_PREFIX {
                self.pending.clear();
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid elaphureLink vendor frame prefix",
                ));
            }
            (
                header[1],
                u16::from_be_bytes([header[2], header[3]]) as usize,
            )
        };
        if self.pending.len() < HEADER_LEN + length {
            return Ok(None);
        }
        if length > buf.len() {
            self.pending.drain(..HEADER_LEN + length);
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "elaphureLink response longer than the packet size",
            ));
        }
        buf[..length].copy_from_slice(&self.pending[HEADER_LEN..HEADER_LEN + length]);
        self.pending.drain(..HEADER_LEN + length);
        Ok(Some((status, length)))
    }
}

/// A socket read timeout is `WouldBlock` on Unix and `TimedOut` on Windows;
/// report both as `TimedOut`.
fn timed_out(error: io::Error) -> io::Error {
    match error.kind() {
        ErrorKind::WouldBlock => ErrorKind::TimedOut.into(),
        _ => error,
    }
}

/// Resolve `host`, `host:port` or `[ipv6]:port`, defaulting the port to `port`.
fn resolve(address: &str) -> io::Result<Vec<SocketAddr>> {
    if let Ok(addresses) = address.to_socket_addrs() {
        return Ok(addresses.collect());
    }
    let host = address.trim_start_matches('[').trim_end_matches(']');
    Ok((host, DEFAULT_PORT).to_socket_addrs()?.collect())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::TcpListener;
    use std::thread::{self, JoinHandle};

    fn frame(status: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![VENDOR_PREFIX, status];
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    /// Complete the handshake on the server side, then hand the stream to `serve`.
    fn server(
        serve: impl FnOnce(&mut TcpStream) + Send + 'static,
    ) -> (ElaphureLinkDevice, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            let mut stream = listener.accept().unwrap().0;
            let mut request = [0u8; 12];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(
                u32::from_be_bytes(request[0..4].try_into().unwrap()),
                LINK_IDENTIFIER
            );
            assert_eq!(
                u32::from_be_bytes(request[4..8].try_into().unwrap()),
                COMMAND_HANDSHAKE
            );
            assert_eq!(
                u32::from_be_bytes(request[8..12].try_into().unwrap()),
                PROXY_VERSION
            );
            let mut response = LINK_IDENTIFIER.to_be_bytes().to_vec();
            response.extend_from_slice(&COMMAND_HANDSHAKE.to_be_bytes());
            response.extend_from_slice(&0x0002_0000u32.to_be_bytes());
            stream.write_all(&response).unwrap();

            let mut scope = [0u8; 4];
            stream.read_exact(&mut scope).unwrap();
            assert_eq!(scope, [VENDOR_PREFIX, VENDOR_SCOPE_ENTER, 0, 0]);
            stream.write_all(&frame(0, &[])).unwrap();
            serve(&mut stream);
        });
        (ElaphureLinkDevice::connect(&address).unwrap(), handle)
    }

    #[test]
    fn commands_are_wrapped_with_big_endian_length() {
        let (mut device, handle) = server(|stream| {
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header, [VENDOR_PREFIX, VENDOR_PASSTHROUGH, 0, 3]);
            let mut payload = [0u8; 3];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(payload, [0x05, 0x00, 0x01]);
            stream.write_all(&frame(0, &[0x05, 0x01, 0x00])).unwrap();
        });
        device.write(&[0x05, 0x00, 0x01]).unwrap();
        let mut buf = [0u8; 64];
        let n = device.read(&mut buf, Duration::from_secs(1)).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf[..n], [0x05, 0x01, 0x00]);
        handle.join().unwrap();
    }

    #[test]
    fn responses_are_reassembled_across_segments() {
        let (mut device, handle) = server(|stream| {
            let reply = frame(0, &[0x00, 0x02, 0x00, 0x04]);
            stream.write_all(&reply[..5]).unwrap();
            thread::sleep(Duration::from_millis(20));
            stream.write_all(&reply[5..]).unwrap();
            let mut frames = frame(0, &[0x05, 0x01]);
            frames.extend(frame(0, &[0x06, 0x00]));
            stream.write_all(&frames).unwrap();
        });
        let mut buf = [0u8; 64];
        let timeout = Duration::from_secs(1);
        assert_eq!(device.read(&mut buf, timeout).unwrap(), 4);
        assert_eq!(buf[..4], [0x00, 0x02, 0x00, 0x04]);
        assert_eq!(device.read(&mut buf, timeout).unwrap(), 2);
        assert_eq!(buf[..2], [0x05, 0x01]);
        assert_eq!(device.read(&mut buf, timeout).unwrap(), 2);
        assert_eq!(buf[..2], [0x06, 0x00]);
        handle.join().unwrap();
    }

    #[test]
    fn late_reply_is_kept_intact_after_a_timeout() {
        let (mut device, handle) = server(|stream| {
            let reply = frame(0, &[0x00, 0x02]);
            stream.write_all(&reply[..5]).unwrap();
            thread::sleep(MIN_READ_TIMEOUT * 2);
            stream.write_all(&reply[5..]).unwrap();
        });
        let mut buf = [0u8; 64];
        assert_eq!(
            device.read(&mut buf, Duration::ZERO).unwrap_err().kind(),
            ErrorKind::TimedOut
        );
        assert_eq!(device.read(&mut buf, Duration::from_secs(1)).unwrap(), 2);
        assert_eq!(buf[..2], [0x00, 0x02]);
        handle.join().unwrap();
    }

    #[test]
    fn bad_prefix_is_rejected() {
        let (mut device, handle) = server(|stream| {
            let mut reply = frame(0, &[0x00]);
            reply[0] = b'X';
            stream.write_all(&reply).unwrap();
        });
        let mut buf = [0u8; 64];
        assert_eq!(
            device.read(&mut buf, Duration::from_secs(1)).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        handle.join().unwrap();
    }

    #[test]
    fn oversized_command_is_rejected_before_sending() {
        let (mut device, handle) = server(|_| {});
        let error = device.write(&vec![0u8; MAX_PAYLOAD + 1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        handle.join().unwrap();
    }

    /// Exercise the whole open path: selector -> factory -> handshake ->
    /// DAP_Info commands through the vendor passthrough framing.
    #[test]
    fn factory_opens_a_network_cmsis_dap_probe() {
        use crate::probe::{
            DebugProbeSelector, ProbeFactory,
            cmsisdap::CmsisDapFactory,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            let mut stream = listener.accept().unwrap().0;
            // Never block forever: once the probe is opened the client stops
            // sending commands and the test joins this thread.
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0u8; 12];
            stream.read_exact(&mut request).unwrap();
            let mut response = LINK_IDENTIFIER.to_be_bytes().to_vec();
            response.extend_from_slice(&COMMAND_HANDSHAKE.to_be_bytes());
            response.extend_from_slice(&0x0001_0000u32.to_be_bytes());
            stream.write_all(&response).unwrap();

            let mut scope = [0u8; 4];
            stream.read_exact(&mut scope).unwrap();
            assert_eq!(scope, [VENDOR_PREFIX, VENDOR_SCOPE_ENTER, 0, 0]);
            stream.write_all(&frame(0, &[])).unwrap();

            // Answer the DAP_Info / DAP_HostStatus commands new_from_device
            // sends while opening a probe.
            for _ in 0..32 {
                let mut header = [0u8; 4];
                if stream.read_exact(&mut header).is_err() {
                    break;
                }
                let length = u16::from_be_bytes([header[2], header[3]]) as usize;
                let mut payload = vec![0u8; length];
                if stream.read_exact(&mut payload).is_err() {
                    break;
                }
                let reply: Vec<u8> = match (payload.first(), payload.get(1)) {
                    (Some(0x00), Some(0xFF)) => vec![0x00, 0x02, 0x00, 0x02], // packet size 512
                    (Some(0x00), Some(0xFE)) => vec![0x00, 0x01, 0x01],       // packet count
                    (Some(0x00), Some(0xF0)) => vec![0x00, 0x01, 0x01],       // SWD capability
                    (Some(0x00), Some(0xFD)) => vec![0x00, 0x04, 0, 0, 0, 0],
                    (Some(0x00), Some(_)) => vec![0x00, 0x00],
                    (Some(0x01), _) => vec![0x01, 0x00], // DAP_HostStatus
                    _ => vec![0x00],
                };
                stream.write_all(&frame(0, &reply)).unwrap();
            }
        });

        let selector = DebugProbeSelector {
            vendor_id: ELAPHURELINK_VID,
            product_id: ELAPHURELINK_PID,
            serial_number: Some(address),
            interface: None,
            usb_location: None,
        };
        let result = CmsisDapFactory.open(&selector);
        let opened = result.is_ok();
        if let Err(error) = &result {
            eprintln!("network probe did not open: {error:?}");
        }
        // Closing the probe closes the socket, which lets the server thread
        // leave its read loop.
        drop(result);
        assert!(opened, "network probe did not open");
        handle.join().unwrap();
    }
}
