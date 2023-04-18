use super::{Role, RoleGuard};
use async_graphql::{Context, Object, Result, SimpleObject};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

#[derive(Default)]
pub(super) struct IpLocationQuery;

#[Object]
impl IpLocationQuery {
    /// The location of an IP address.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn ip_location(&self, ctx: &Context<'_>, address: String) -> Result<Option<IpLocation>> {
        let Ok(addr) = address.parse::<IpAddr>() else {
            return Err("invalid IP address".into());
        };
        let Ok(mutex) = ctx.data::<Arc<Mutex<ip2location::DB>>>() else {
            return Err("IP location database unavailable".into());
        };
        let record = {
            if let Ok(mut locator) = mutex.lock() {
                locator.ip_lookup(addr).ok()
            } else {
                None
            }
        };

        Ok(record.map(std::convert::TryInto::try_into).transpose()?)
    }
}

#[derive(SimpleObject)]
struct IpLocation {
    latitude: Option<f32>,
    longitude: Option<f32>,
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    domain: Option<String>,
    zip_code: Option<String>,
    time_zone: Option<String>,
    net_speed: Option<String>,
    idd_code: Option<String>,
    area_code: Option<String>,
    weather_station_code: Option<String>,
    weather_station_name: Option<String>,
    mcc: Option<String>,
    mnc: Option<String>,
    mobile_brand: Option<String>,
    elevation: Option<String>,
    usage_type: Option<String>,
}

impl TryFrom<ip2location::Record> for IpLocation {
    type Error = &'static str;
    fn try_from(record: ip2location::Record) -> Result<Self, Self::Error> {
        use ip2location::Record;
        match record {
            Record::LocationDb(record) => Ok(Self {
                latitude: record.latitude,
                longitude: record.longitude,
                country: record.country.map(|c| c.short_name),
                region: record.region,
                city: record.city,
                isp: record.isp,
                domain: record.domain,
                zip_code: record.zip_code,
                time_zone: record.time_zone,
                net_speed: record.net_speed,
                idd_code: record.idd_code,
                area_code: record.area_code,
                weather_station_code: record.weather_station_code,
                weather_station_name: record.weather_station_name,
                mcc: record.mcc,
                mnc: record.mnc,
                mobile_brand: record.mobile_brand,
                elevation: record.elevation,
                usage_type: record.usage_type,
            }),
            Record::ProxyDb(_) => Err("Failed to create IpLocation from ProxyDb record"),
        }
    }
}
