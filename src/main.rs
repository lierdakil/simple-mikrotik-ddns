use std::{
    collections::HashMap,
    fmt::Display,
    hash::Hash,
    net::{IpAddr, Ipv4Addr},
};

use anyhow::Result;
use clap::Parser;
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use hickory_server::{
    authority::MessageResponseBuilder,
    proto::{
        op::{Header, MessageType, OpCode, ResponseCode},
        rr::{rdata::PTR, LowerName, Name, RData, Record, RecordType},
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};
use log::{debug, error, info};
use serde::Deserializer;
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct Info {
    address: Ipv4Addr,
    host_name: Option<String>,
    #[serde(deserialize_with = "serde_boolean")]
    dynamic: bool,
    active_mac_address: CaseInsensitiveString,
    #[serde(with = "humantime_serde")]
    expires_after: Duration,
}

fn serde_boolean<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    use serde::de;
    use serde_json::Value;
    Ok(match serde::de::Deserialize::deserialize(deserializer)? {
        Value::Bool(b) => b,
        Value::String(s) if s == "true" => true,
        Value::String(s) if s == "false" => false,
        _ => return Err(de::Error::custom("Wrong type, expected boolean")),
    })
}

#[derive(serde::Deserialize)]
struct Handler {
    my_zone: SerName,
    username: String,
    password: String,
    hostname: String,
    #[serde(default)]
    allow_wildcard: bool,
    #[serde(default = "static_timeout_default")]
    static_timeout: u32,
    #[serde(default)]
    static_records: HashMap<SerName, Ipv4Addr>,
    #[serde(default)]
    name_overrides: HashMap<CaseInsensitiveString, String>,
}

const fn static_timeout_default() -> u32 {
    3600 * 24
}

#[derive(serde::Deserialize, Debug)]
#[serde(transparent)]
struct CaseInsensitiveString(String);

impl Hash for CaseInsensitiveString {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_lowercase().hash(state)
    }
}

impl PartialEq for CaseInsensitiveString {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_lowercase().eq(&other.0.to_lowercase())
    }
}

impl Eq for CaseInsensitiveString {}

#[derive(serde::Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
struct SerName(#[serde(deserialize_with = "serde_name")] Name);

impl Display for SerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl SerName {
    pub fn name(&self) -> &Name {
        &self.0
    }
}

fn serde_name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Name, D::Error> {
    use serde::de;
    use serde_json::Value;
    Ok(match serde::de::Deserialize::deserialize(deserializer)? {
        Value::String(s) => Name::from_str_relaxed(s).map_err(de::Error::custom)?,
        _ => return Err(de::Error::custom("Wrong type, expected string")),
    })
}

impl Handler {
    async fn do_handle_request(
        &self,
        request: &Request,
        response_handler: &mut impl ResponseHandler,
    ) -> Result<ResponseInfo> {
        anyhow::ensure!(
            matches!(request.op_code(), OpCode::Query),
            "only query requests are allowed"
        );

        anyhow::ensure!(
            matches!(request.message_type(), MessageType::Query),
            "only query requests are allowed"
        );

        let info = request.request_info()?;

        let name = info.query.name();

        anyhow::ensure!(
            LowerName::new(self.my_zone.name()).zone_of(name)
                || LowerName::new(&Name::from_ascii("in-addr.arpa.").unwrap()).zone_of(name),
            "only {} zone or PTR queries are supported, got {name}",
            self.my_zone,
        );

        let query_type = info.query.query_type();

        if !matches!(query_type, RecordType::A | RecordType::PTR) {
            // only A requests are supported
            return Self::empty_response(response_handler, request).await;
        }

        info!("Got request for {}", name);

        enum Check<L, R> {
            Name(L),
            Addr(R),
        }

        let check = match query_type {
            RecordType::A => Check::Name(|host_name: &Name| {
                if self.allow_wildcard {
                    LowerName::new(host_name).zone_of(name)
                } else {
                    &LowerName::new(host_name) == name
                }
            }),
            RecordType::PTR => Check::Addr({
                let req = name.parse_arpa_name()?;
                move |ip: Ipv4Addr| req.addr() == IpAddr::V4(ip)
            }),
            _ => {
                // unsupported request
                return Self::empty_response(response_handler, request).await;
            }
        };

        for (name, ip) in self.static_records.iter() {
            let host_name = name.name().clone().append_domain(self.my_zone.name())?;
            debug!("Trying static name {host_name} with address {ip}");
            match check {
                Check::Name(check_name) => {
                    if check_name(&host_name) {
                        debug!("Matched on {host_name}!");
                        return Self::send_response(
                            response_handler,
                            request,
                            RData::A((*ip).into()),
                            self.static_timeout,
                        )
                        .await;
                    }
                }
                Check::Addr(check_addr) => {
                    if check_addr(*ip) {
                        debug!("Matched on {ip}!");
                        return Self::send_response(
                            response_handler,
                            request,
                            RData::PTR(PTR(host_name)),
                            self.static_timeout,
                        )
                        .await;
                    }
                }
            }
        }

        let client = reqwest::Client::new();
        let fields = serde_aux::serde_introspection::serde_introspect::<Info>().join(",");
        let resp: Vec<Info> = client
            .post(format!(
                "http://{}/rest/ip/dhcp-server/lease/print",
                self.hostname
            ))
            .basic_auth(&self.username, Some(&self.password))
            .json(&HashMap::from([
                (".query", ["status=bound"]),
                (".proplist", [&fields]),
            ]))
            .send()
            .await?
            .json()
            .await?;

        debug!("Got addresses from mikrotik: {resp:?}");

        for r in resp {
            debug!("Trying {r:?}...");
            let Some(host_name) = self
                .name_overrides
                .get(&r.active_mac_address)
                .or(r.host_name.as_ref())
            else {
                debug!("No host name found, skipping");
                continue;
            };
            if let Ok(host_name) = Name::from_str_relaxed(host_name) {
                let host_name = host_name.append_domain(self.my_zone.name())?;
                debug!("Constructed FQDN {host_name}");
                let timeout = if r.dynamic {
                    r.expires_after.as_secs().try_into().unwrap_or(u32::MAX)
                } else {
                    self.static_timeout
                };
                match check {
                    Check::Name(check_name) => {
                        if check_name(&host_name) {
                            debug!("Matched query for {host_name}!");
                            return Self::send_response(
                                response_handler,
                                request,
                                RData::A(r.address.into()),
                                timeout,
                            )
                            .await;
                        }
                    }
                    Check::Addr(check_addr) => {
                        if check_addr(r.address) {
                            debug!("Matched query for {}!", r.address);
                            return Self::send_response(
                                response_handler,
                                request,
                                RData::PTR(PTR(host_name)),
                                timeout,
                            )
                            .await;
                        }
                    }
                }
            }
        }

        Self::empty_response(response_handler, request).await
    }

    async fn send_response(
        response_handler: &mut impl ResponseHandler,
        request: &Request,
        response: RData,
        timeout: u32,
    ) -> Result<ResponseInfo> {
        let builder = MessageResponseBuilder::from_message_request(request);

        let info = request.request_info()?;

        let mut header = Header::response_from_request(request.header());

        header.set_authoritative(true);

        info!("Sending response {} with timeout {}", response, &timeout);

        let records = vec![Record::from_rdata(
            info.query.name().into(),
            timeout,
            response,
        )];

        let response = builder.build(header, records.iter(), &[], &[], &[]);

        debug!("Sending response {:?}", &response);

        Ok(response_handler.send_response(response).await?)
    }

    async fn empty_response(
        response_handler: &mut impl ResponseHandler,
        request: &Request,
    ) -> Result<ResponseInfo> {
        let response = MessageResponseBuilder::from_message_request(request)
            .build_no_records(Header::response_from_request(request.header()));

        Ok(response_handler.send_response(response).await?)
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        match self.do_handle_request(request, &mut response_handle).await {
            Ok(info) => info,
            Err(error) => {
                error!("Error in request handler: {error}");
                let msg = MessageResponseBuilder::from_message_request(request)
                    .error_msg(request.header(), ResponseCode::ServFail);
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                response_handle.send_response(msg).await.unwrap()
            }
        }
    }
}

#[derive(clap::Parser)]
struct Args {
    #[arg(short, long, default_value = "/etc/simple-mikrotik-ddns/config.toml")]
    config: std::path::PathBuf,
    #[arg(short, long, default_value = "127.0.0.1:53")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let args = Args::parse();

    let handler: Handler = Figment::new()
        .merge(Toml::file(args.config))
        .admerge(Env::prefixed("SIMPLE_MIKROTIK_DDNS_"))
        .extract()?;

    let mut server = ServerFuture::new(handler);

    server.register_socket(UdpSocket::bind(args.listen).await?);

    server.block_until_done().await?;

    Ok(())
}
