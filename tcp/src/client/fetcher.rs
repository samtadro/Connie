
use std::io::Result;
use std::process::exit;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use common_lib::log::error;
use lib_db::{
    media::fetch::Smedia, 
    types::SqlitePool
};
use lib_db::sqlite::{
        sqlite_host::SqliteHost,
        sqlite_user::SqliteUser
};

use common_lib::{
    log::debug,
    public_ip,
};
use common_lib::tokio::{
        io::{
            AsyncReadExt,
            AsyncWriteExt
        },
        net::TcpStream
};

use tokio_rustls::rustls::pki_types::ServerName;

use crate::common::request::SERVER_WILL_NOT_ALLOW_NOTLS;
use crate::common::util::core::raw_rvfs;
use crate::common::{
    handshakes,
    request::FETCH,
    util::client::rvfs,
};
use crate::{
    server::req_format::Chead,
    client::connector::get_tlstream,
};


pub async fn get_files(
    u: &SqliteUser,
    server: &SqliteHost,
    jwt: String,
    custom_port: Option<u16>,
    custom_ip: Option<IpAddr>,
    pool: &SqlitePool,
    pub_files: bool,
    notls: bool,
) -> Result<(Vec<Smedia>, Option<Vec<Smedia>>)> {
    let port = if custom_port.is_some() {
        debug!("using custom port");
        custom_port.unwrap()
    } else {
        debug!("using server default port: {}",server.port);
        server.port
    };

    let server_pub_ip: IpAddr = server.pub_ip.parse().unwrap();
    let server_pri_ip: IpAddr = server.pri_ip.parse().unwrap();

    let bind_me_pub_ip = public_ip::addr().await;
    let me_pub_ip = if bind_me_pub_ip.is_some() {
        bind_me_pub_ip.unwrap()
    } else {
        IpAddr::from_str("0.0.0.0").unwrap()
    };
    debug!("current public ip: {:?}", me_pub_ip);

    let ip: IpAddr;
    let addr = if custom_ip.is_some() {
        debug!("using custom ip");
        ip = custom_ip.unwrap();
        SocketAddr::new(ip, port)

    } else if me_pub_ip != server_pub_ip {
        debug!("using public ip: {}", &server.pub_ip);
        ip = server_pub_ip;
        SocketAddr::new(ip, port)
        
    } else {
        debug!("using private ip: {}", &server.pri_ip);
        ip = server_pri_ip;
        SocketAddr::new(ip, port)
        
    };

    let mut stream = TcpStream::connect(&addr).await?;
    let server_name = ServerName::from(ip);

    if notls {
        stream.write_u8(1).await?;
        let server_will_allow_no_tls = stream.read_u8().await?;
        if server_will_allow_no_tls == SERVER_WILL_NOT_ALLOW_NOTLS {
            error!(
                "SERVER will not allow notls connections with status: {}",
                SERVER_WILL_NOT_ALLOW_NOTLS 
            );
            exit(SERVER_WILL_NOT_ALLOW_NOTLS as  i32);
        };
        let res = notls_fetcher_helper(
            &mut stream,
            u,
            server, jwt,
            pub_files,
            pool
        ).await?;
        return Ok(res);
    };
    
    //write connection status 
    stream.write_u8(0).await?;

    let mut stream = get_tlstream(stream, server_name).await?;
    debug!("tls connected");
    // get request ready before handshake
    let head = Chead {
        jwt,
        cpid: u.cpid.clone()
    };
    // handshake 
    let is_who_server = handshakes::client(
        &mut stream,
        &server,
        pool
    ).await?;
    if is_who_server != 0 {
        exit(1);
    };
    debug!("handshake done");

    // serializeing request 
    let request = head.sz().unwrap();
    // writing request header
    stream.write_u8(FETCH).await?;
    stream.write_all(&request).await?;

    debug!("sent {}",request.len());
    stream.flush().await?;
    let items = stream.read_u16().await.unwrap();
    let mut media_from_server: Vec<Smedia> = vec![];

    for _i in 0..items {
        
        let buf = rvfs(&mut stream).await?;
        let media: Smedia = Smedia::dz(buf).unwrap();
        let sqlitem = Smedia {
            name: media.name,
            type_: media.type_,
            checksum: media.checksum,
            size: media.size,
        };

        media_from_server.push(sqlitem);
    }

    let public_files: Option<Vec<Smedia>> = if pub_files {
        stream.write_u8(1).await?;
        stream.flush().await?;
        let items = stream.read_u16().await.unwrap();
        let mut public_files: Vec<Smedia> = vec![];

        for _i in 0..items {
            
            let buf = rvfs(&mut stream).await?;
            let media: Smedia = Smedia::dz(buf).unwrap();
            let sqlitem = Smedia {
                name: media.name,
                type_: media.type_,
                checksum: media.checksum,
                size: media.size,
            };

            public_files.push(sqlitem);
        };
        Some(public_files)
    }else {
        stream.write_u8(0).await?;
        stream.flush().await?;
        None
    };

    

    
    Ok((media_from_server, public_files))
}



// first vec is user files second vec is public files
async fn notls_fetcher_helper(
    stream: &mut TcpStream,
    u: &SqliteUser,
    server: &SqliteHost,
    jwt: String,
    pub_files: bool,
    pool: &SqlitePool,
) -> Result<(Vec<Smedia>, Option<Vec<Smedia>>)> {

    let head = Chead {
        jwt,
        cpid: u.cpid.clone()
    };
    // handshake 
    let is_who_server = handshakes::raw_client_handshake(
        stream,
        &server,
        pool
    ).await?;
    if is_who_server != 0 {
        exit(1);
    };
    debug!("handshake done");

    // serializeing request 
    let request = head.sz().unwrap();
    // writing request header
    stream.write_u8(FETCH).await?;
    stream.write_all(&request).await?;

    stream.flush().await?;
    let items = stream.read_u16().await.unwrap();
    let mut media_from_server: Vec<Smedia> = vec![];

    for _i in 0..items {
        
        let buf = raw_rvfs(stream).await?;
        let media: Smedia = Smedia::dz(buf).unwrap();
        let sqlitem = Smedia {
            name: media.name,
            type_: media.type_,
            checksum: media.checksum,
            size: media.size,
        };

        media_from_server.push(sqlitem);
    }

    let public_files: Option<Vec<Smedia>> = if pub_files {
        stream.write_u8(1).await?;
        stream.flush().await?;
        let items = stream.read_u16().await.unwrap();
        let mut public_files: Vec<Smedia> = vec![];

        for _i in 0..items {
            
            let buf = raw_rvfs(stream).await?;
            let media: Smedia = Smedia::dz(buf).unwrap();
            let sqlitem = Smedia {
                name: media.name,
                type_: media.type_,
                checksum: media.checksum,
                size: media.size,
            };

            public_files.push(sqlitem);
        };
        Some(public_files)
    }else {
        stream.write_u8(0).await?;
        stream.flush().await?;
        None
    };

    
    Ok((media_from_server, public_files))
}
