use super::{NicInput, Node, PortNumber};
use anyhow::{bail, Context as AnyhowContext};
use async_graphql::{types::ID, InputObject, Result};
use review_database::IndexedMapUpdate;
use std::net::IpAddr;

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct NodeInput {
    pub name: String,
    pub customer_id: ID,
    pub description: String,
    pub hostname: String,
    pub nics: Vec<NicInput>,
    pub disk_usage_limit: Option<f32>,
    pub allow_access_from: Option<Vec<String>>,

    pub review_id: Option<ID>,

    pub ssh_port: PortNumber,
    pub dns_server_ip: Option<String>,
    pub dns_server_port: Option<PortNumber>,
    pub syslog_server_ip: Option<String>,
    pub syslog_server_port: Option<PortNumber>,

    pub review: bool,
    pub review_nics: Option<Vec<String>>,
    pub review_port: Option<PortNumber>,
    pub review_web_port: Option<PortNumber>,
    pub ntp_server_ip: Option<String>,
    pub ntp_server_port: Option<PortNumber>,

    pub piglet: bool,

    pub giganto: bool,
    pub giganto_ingestion_nics: Option<Vec<String>>,
    pub giganto_ingestion_port: Option<PortNumber>,
    pub giganto_publish_nics: Option<Vec<String>>,
    pub giganto_publish_port: Option<PortNumber>,
    pub giganto_graphql_nics: Option<Vec<String>>,
    pub giganto_graphql_port: Option<PortNumber>,

    pub reconverge: bool,

    pub hog: bool,
}

impl IndexedMapUpdate for NodeInput {
    type Entry = Node;

    fn key(&self) -> Option<&[u8]> {
        Some(self.name.as_bytes())
    }

    #[allow(clippy::too_many_lines)]
    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.name.clear();
        value.name.push_str(&self.name);
        value.customer_id = self
            .customer_id
            .as_str()
            .parse::<u32>()
            .context("invalid customer ID")?;
        value.description.clear();
        value.description.push_str(&self.description);
        value.hostname.clear();
        value.hostname.push_str(&self.hostname);
        value.nics.clear();
        for n in &self.nics {
            value
                .nics
                .push(n.try_into().context("invalid IP address: nic")?);
        }
        let original_count = value.nics.len();
        value.nics.sort_by(|a, b| a.name.cmp(&b.name));
        value.nics.dedup_by(|a, b| a.name == b.name);
        if value.nics.len() != original_count {
            bail!("duplicate network interface name");
        }
        value.disk_usage_limit = self.disk_usage_limit;
        if let Some(allow_access_from) = self.allow_access_from.as_ref() {
            let mut allow = Vec::<IpAddr>::with_capacity(allow_access_from.len());
            for ip in allow_access_from {
                allow.push(ip.parse::<IpAddr>().context("invalid IP address: access")?);
            }
            allow.sort_unstable();
            allow.dedup();
            value.allow_access_from = Some(allow);
        } else {
            value.allow_access_from = None;
        }

        // review server
        value.review_id = if let Some(id) = self.review_id.as_ref() {
            Some(id.parse::<u32>().context("invalid review ID")?)
        } else {
            None
        };

        // communication
        value.ssh_port = self.ssh_port;
        value.dns_server_ip = if let Some(ip) = self.dns_server_ip.as_deref() {
            Some(
                ip.parse::<IpAddr>()
                    .context("invalid IP address: dns server")?,
            )
        } else {
            None
        };
        value.dns_server_port = self.dns_server_port;
        value.syslog_server_ip = if let Some(ip) = self.syslog_server_ip.as_deref() {
            Some(
                ip.parse::<IpAddr>()
                    .context("invalid IP address: syslog server")?,
            )
        } else {
            None
        };
        value.syslog_server_port = self.syslog_server_port;

        // review
        value.review = self.review;
        value.review_nics = self.review_nics.clone();
        value.review_port = self.review_port;
        value.review_web_port = self.review_web_port;
        value.ntp_server_ip = if let Some(ip) = self.ntp_server_ip.as_deref() {
            Some(
                ip.parse::<IpAddr>()
                    .context("invalid IP address: ntp server")?,
            )
        } else {
            None
        };
        value.ntp_server_port = self.ntp_server_port;

        // piglet
        value.piglet = self.piglet;

        // giganto
        value.giganto = self.giganto;
        value.giganto_ingestion_nics = self.giganto_ingestion_nics.clone();
        value.giganto_ingestion_port = self.giganto_ingestion_port;
        value.giganto_publish_nics = self.giganto_publish_nics.clone();
        value.giganto_publish_port = self.giganto_publish_port;
        value.giganto_graphql_nics = self.giganto_graphql_nics.clone();
        value.giganto_graphql_port = self.giganto_graphql_port;

        // reconverge
        value.reconverge = self.reconverge;

        // hog
        value.hog = self.hog;

        Ok(value)
    }

    #[allow(clippy::too_many_lines)]
    fn verify(&self, value: &Self::Entry) -> bool {
        if self.name != value.name {
            return false;
        }
        if self
            .customer_id
            .as_str()
            .parse::<u32>()
            .map_or(true, |id| id != value.customer_id)
        {
            return false;
        }
        if self.description != value.description {
            return false;
        }
        if self.hostname != value.hostname {
            return false;
        }
        if self.nics.len() != value.nics.len() {
            return false;
        }
        if !self
            .nics
            .iter()
            .zip(value.nics.iter())
            .all(|(lhs, rhs)| lhs == rhs)
        {
            return false;
        }
        if self.disk_usage_limit != value.disk_usage_limit {
            return false;
        }
        if let (Some(v), Some(value_allow_access_from)) =
            (self.allow_access_from.as_ref(), &value.allow_access_from)
        {
            if v.len() != value_allow_access_from.len() {
                return false;
            }
            if !v
                .iter()
                .zip(value_allow_access_from.iter())
                .all(|(lhs, rhs)| lhs.parse::<IpAddr>().map_or(true, |lhs| lhs == *rhs))
            {
                return false;
            }
        } else if self.allow_access_from.is_some() || value.allow_access_from.is_some() {
            return false;
        }

        // review server
        let same_review_id = match (self.review_id.as_ref(), value.review_id.as_ref()) {
            (Some(self_id), Some(value_id)) => self_id
                .parse::<u32>()
                .map_or(false, |self_id| self_id == *value_id),
            (None, None) => true,
            _ => false,
        };
        if !same_review_id {
            return false;
        }

        // communication
        if self.ssh_port != value.ssh_port {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) =
            (self.dns_server_ip.as_deref(), value.dns_server_ip)
        {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.dns_server_ip.is_some() || value.dns_server_ip.is_some() {
            return false;
        }
        if self.dns_server_port != value.dns_server_port {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) =
            (self.syslog_server_ip.as_deref(), value.syslog_server_ip)
        {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.syslog_server_ip.is_some() || value.syslog_server_ip.is_some() {
            return false;
        }
        if self.syslog_server_port != value.syslog_server_port {
            return false;
        }

        // review
        if self.review != value.review {
            return false;
        }
        if !nics_eq(self.review_nics.as_ref(), value.review_nics.as_ref()) {
            return false;
        }
        if self.review_port != value.review_port {
            return false;
        }
        if self.review_web_port != value.review_web_port {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) =
            (self.ntp_server_ip.as_deref(), value.ntp_server_ip)
        {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.ntp_server_ip.is_some() || value.ntp_server_ip.is_some() {
            return false;
        }
        if self.ntp_server_port != value.ntp_server_port {
            return false;
        }

        // piglet
        if self.piglet != value.piglet {
            return false;
        }

        // giganto
        if self.giganto != value.giganto {
            return false;
        }
        if !nics_eq(
            self.giganto_ingestion_nics.as_ref(),
            value.giganto_ingestion_nics.as_ref(),
        ) {
            return false;
        }
        if self.giganto_ingestion_port != value.giganto_ingestion_port {
            return false;
        }
        if !nics_eq(
            self.giganto_publish_nics.as_ref(),
            value.giganto_publish_nics.as_ref(),
        ) {
            return false;
        }
        if self.giganto_publish_port != value.giganto_publish_port {
            return false;
        }
        if !nics_eq(
            self.giganto_graphql_nics.as_ref(),
            value.giganto_graphql_nics.as_ref(),
        ) {
            return false;
        }
        if self.giganto_graphql_port != value.giganto_graphql_port {
            return false;
        }

        // reconverge
        if self.reconverge != value.reconverge {
            return false;
        }

        // hog
        if self.hog != value.hog {
            return false;
        }

        true
    }
}

fn nics_eq(lhs: Option<&Vec<String>>, rhs: Option<&Vec<String>>) -> bool {
    match (lhs, rhs) {
        (None, None) => true,
        (Some(l), Some(r)) => {
            let (mut l, mut r) = (l.clone(), r.clone());
            l.sort_unstable();
            r.sort_unstable();
            l == r
        }
        _ => false,
    }
}
