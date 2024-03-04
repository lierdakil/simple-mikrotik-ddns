use std::{collections::HashMap, net::Ipv4Addr};

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
        rr::{LowerName, Name, RData, Record, RecordType},
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};
use log::{debug, error, info};
use serde::Deserializer;
use tokio::net::UdpSocket;

#[derive(serde::Deserialize, Debug)]
struct Info {
    address: Ipv4Addr,
    #[serde(rename = "host-name")]
    host_name: String,
    #[serde(deserialize_with = "serde_boolean")]
    dynamic: bool,
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
    #[serde(deserialize_with = "serde_name")]
    my_zone: Name,
    username: String,
    password: String,
    hostname: String,
    #[serde(default)]
    allow_wildcard: bool,
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

        let name = request.query().name();

        anyhow::ensure!(
            LowerName::new(&self.my_zone).zone_of(name),
            "only {} zone is supported, got {name}",
            self.my_zone,
        );

        anyhow::ensure!(
            request.query().query_type() == RecordType::A,
            "only A requests are supported"
        );

        info!("Got request for {}", name);

        let builder = MessageResponseBuilder::from_message_request(request);

        let mut header = Header::response_from_request(request.header());

        header.set_authoritative(true);

        let client = reqwest::Client::new();
        let resp: Vec<Info> = client
            .post(format!(
                "http://{}/rest/ip/dhcp-server/lease/print",
                self.hostname
            ))
            .basic_auth(&self.username, Some(&self.password))
            .json(&HashMap::from([
                (".query", ["status=bound"]),
                (".proplist", ["address,host-name,dynamic"]),
            ]))
            .send()
            .await?
            .json()
            .await?;

        debug!("Got addresses from mikrotik: {resp:?}");

        for r in resp {
            debug!("Trying {r:?}...");
            if let Ok(host_name) = Name::from_str_relaxed(r.host_name) {
                let host_name = host_name.append_domain(&self.my_zone)?;
                debug!("Constructed FDQN {host_name}");
                fn check_name(
                    allow_wildcard: bool,
                    host_name: &Name,
                    req_name: &LowerName,
                ) -> bool {
                    if allow_wildcard {
                        LowerName::new(host_name).zone_of(req_name)
                    } else {
                        &LowerName::new(host_name) == req_name
                    }
                }
                if check_name(self.allow_wildcard, &host_name, request.query().name()) {
                    debug!("Matched query!");
                    let timeout = if r.dynamic { 60 } else { 3600 * 24 };

                    info!("Sending response {} with timeout {}", &r.address, &timeout);

                    let records = vec![Record::from_rdata(
                        request.query().name().into(),
                        timeout,
                        RData::A(r.address.into()),
                    )];

                    let response = builder.build(header, records.iter(), &[], &[], &[]);

                    debug!("Sending response {:?}", &response);

                    return Ok(response_handler.send_response(response).await?);
                }
            }
        }

        let response = builder.build(header, &[], &[], &[], &[]);

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
