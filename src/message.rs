// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, NlasIterator, ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::{AmneziaWireguardAttribute, AmneziaWireguardCmd};

const WG_FAMILY_NAME: &str = "amneziawg";
const WG_FAMILY_VERSION: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmneziaWireguardMessage {
    pub cmd: AmneziaWireguardCmd,
    pub attributes: Vec<AmneziaWireguardAttribute>,
}

impl GenlFamily for AmneziaWireguardMessage {
    fn family_name() -> &'static str {
        WG_FAMILY_NAME
    }

    fn version(&self) -> u8 {
        WG_FAMILY_VERSION
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl Emitable for AmneziaWireguardMessage {
    fn emit(&self, buffer: &mut [u8]) {
        self.attributes.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }
}

impl ParseableParametrized<[u8], GenlHeader> for AmneziaWireguardMessage {
    fn parse_with_param(buf: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        let mut attributes = Vec::new();
        for nla in NlasIterator::new(buf) {
            let nla = &nla.context("failed to parse amneziawg netlink attributes")?;
            attributes.push(AmneziaWireguardAttribute::parse_for_family_version(
                nla,
                Some(header.version),
            )?);
        }
        Ok(Self {
            cmd: header.cmd.into(),
            attributes,
        })
    }
}
