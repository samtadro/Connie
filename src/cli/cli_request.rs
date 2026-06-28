
use std::io::{
    stdin,
    Write,
    stdout,
};
use std::net::IpAddr;
use std::time;
use std::{
    path::PathBuf,
    process::exit,
};

use common_lib::log::warn;
use common_lib::{
    public_ip,
    display_size,
    path::SQLITEDB_PATH,
    log::{debug, error, info},
};

use lib_db::hash_passwords;
use lib_db::sqlite::sqlite_host::SqliteHost;
use lib_db::sqlite::sqlite_user::SqliteUser;
use lib_db::sqlite::sqlite_jwt::check_jwt_status;
use lib_db::{
    types::SqlitePool,
    media::fetch::Smedia,
    jwt::get_current_timestamp,
};

use lib_db::sqlite::{
    self,
    sqlite_host::fetch_server,
    sqlite_jwt::delete_expd_jwt,
    sqlite_user::fetch_sqlite_user_with_server_cpid,
};
use lib_db::sqlite::sqlite_media::{
    SqliteMedia,
    sqlite_delete_media,
    sqlite_media_exists,
    fetch_all_media_from_host,
    fetch_all_media_from_host_smedia,
    fetch_all_public_files_from_host,
};

use tcp::client::client::client_login_process;
use tcp::types::DELETE;
use tcp::{
    client::{
        fetcher,
        client::client_process,
    },
    types::{GET, POST, RQM},
};

use crate::{get_pass, Commands};











async fn pub_file_checker(
    db_files: Vec<Smedia>,
    server_pub_files: Vec<Smedia>,
    host: String,
    pool: &SqlitePool
) {
    let start = time::Instant::now();
    let mut deleted = 0;
    let mut added = 0;
    // deleteing local sqlite media that is deleted from the server
    for df in db_files {
        if !server_pub_files.contains(&df) {
            sqlite_delete_media(
                &host,
                &host,
                &df.checksum,
                pool
            ).await;
            deleted+=1;
        };
    }
    // adding new fils from server
    for sf in server_pub_files {
        if !sqlite_media_exists(&host, &host, &sf.checksum, pool).await {
            let media = SqliteMedia {
                name: sf.name,
                checksum: sf.checksum,
                cpid: host.clone(),
                host: host.clone(),
                size: sf.size,
                type_: sf.type_,
                date: get_current_timestamp() as i64,
                path: "./".to_string()
            };
            SqliteMedia::add_media(media, pool).await.unwrap();
            added+=1;
        };
    }
    let end = start.elapsed();
    
    if 0 != added {info!("PUBFILECHECKER: added {added} files from server")};
    if 0 != deleted {info!("PUBFILECHECKER: deleted {deleted} files server")};
    info!("PUBFILECHECKER: finished in {}ms", end.as_millis());
}



async fn file_checker(
    db_files: Vec<Smedia>,
    server_files: Vec<Smedia>,
    host: String,
    cpid: String,
    pool: &SqlitePool
) {
    let start = time::Instant::now();
    let mut deleted = 0;
    let mut added = 0;
    // deleteing local sqlite media that is deleted from the server
    for df in db_files {
        if !server_files.contains(&df) {
            sqlite_delete_media(
                &host,
                &cpid,
                &df.checksum,
                pool
            ).await;
            deleted+=1;
        };
    }
    // adding new fils from server
    for sf in server_files {
        if !sqlite_media_exists(&host, &cpid, &sf.checksum, pool).await {
            let media = SqliteMedia {
                name: sf.name,
                checksum: sf.checksum,
                cpid: cpid.clone(),
                host: host.clone(),
                size: sf.size,
                type_: sf.type_,
                date: get_current_timestamp() as i64,
                path: "./".to_string()
            };
            SqliteMedia::add_media(media, pool).await.unwrap();
            added+=1;
        };
    }
    let end = start.elapsed();
    
    if 0 != added {info!("FILECHECKER: added {added} files from server")};
    if 0 != deleted {info!("FILECHECKER: deleted {deleted} files server")};
    info!("FILECHECKER: finished in {}ms", end.as_millis());
}

#[allow(unused_assignments)]
pub async fn handle_cli_request(command: Commands) {
    match command {

        Commands::REQUEST { 
            db,
            Ip: ip,
            get,
            all,
            host,
            user,
            Port: port,
            post,
            login,
            no_tls,
            Delete,
            Domain,
            pub_files,
            server_name,
            fetch_files, 
            create_checksum: checksum,
        } => {
            let mut command_vec: Vec<bool> = vec![];
            if get.is_some() {
                command_vec.push(true);
            };
            if post.is_some() {
                if pub_files.is_some() {
                    warn!("pub files flag only works with get and fetch")
                }
                command_vec.push(true);
            };
            if fetch_files.is_some() {
                command_vec.push(true);
            };
            if Delete.is_some() {
                if pub_files.is_some() {
                    warn!("pub files flag only works with get and fetch")
                }
                command_vec.push(true);
            };
            if login.is_some() {
                if pub_files.is_some() {
                    warn!("pub files flag only works with get and fetch")
                }
                command_vec.push(true);
            }

            if command_vec.len() > 1usize {
                error!(
                    "you can't enter more than one request \n
                    (post/get/delete/fetch/login);"
                );
                exit(1);
            };
            if command_vec.is_empty() {
                error!("you need to enter a request");
                exit(1);
            };

            let no_tls = if no_tls.is_none(){
                false
            } else {
                warn!(
                "the --no-tls flag tells the program to not encrypt the data and it will be faster
                to be safe that the files didn't get changed while being unencrypted on public networks make sure you use the <-c true> 
                which will checksum on the local machine before sending it "
                );
                no_tls.unwrap()}
            ;
            let db_path = if db.is_none() {
                debug!("using default sqliteDB ");
                SQLITEDB_PATH.to_string()
            } else {
                let bind = db.unwrap();
                let stred = bind.to_str().unwrap();
                let path = stred.to_string();
                debug!("using db path: {}",&path);
                path
            };
            let _pool = sqlite::get_sqlite_conn(&db_path.to_string())
                .await
                .unwrap();
            let pool = &_pool;
            delete_expd_jwt(pool).await;
            
            let server = if host.is_some() && server_name.is_some() {
                let server_name = server_name.unwrap();
                let server = fetch_server(&server_name, host, pool).await;
                server
            } else if let Some(name) = server_name {
                let server = fetch_server(&name, None, pool).await;
                server
            }else {
                error!("you need to enter a user - server_name if
                you have more than 1 server with the same name it's
                better to enter the host too");
                exit(1)

            };
            let checksum = checksum.unwrap();


            let pub_files = if pub_files.is_some() {
                pub_files.unwrap()
            }else {false};

            
            let usr = fetch_sqlite_user_with_server_cpid(
                &user,
                &server.cpid,
                pool
            ).await.expect("could not fetch user");

            if fetch_files.is_some(){

                fetch_proc(usr, server, ip, port, no_tls, post, pub_files, _pool).await;

            } else if post.is_some() { 

                post_proc(usr, server, ip, port, no_tls, post, checksum, _pool).await;

            } else if get.is_some() {

                get_proc(usr, server, ip, port, no_tls, get, checksum, pub_files, _pool).await;

            } else if Delete.is_some() && Delete.unwrap() {
                
                delete_proc(usr, server, ip, port, no_tls, _pool).await;
            
            }else if login.is_some() && login.unwrap() {

               login_proc(usr, server, port, ip, no_tls, pool).await;
            }
            else {
                error!("you did not enter a command to execute")
            }
        }

        _=> {}

    }
}





async fn fetch_proc(
    usr: SqliteUser,
    server: SqliteHost,
    ip: Option<IpAddr>,
    port: Option<u16>,
    no_tls: bool,
    post: Option<PathBuf>,
    pub_files: bool,
    _pool: SqlitePool,
) {
    let pool = &_pool;
    let status = check_jwt_status(
        &usr.cpid,
        &server.cpid,
        pool
    ).await;
    if !status {
        error!("you have no available token please login first");
        exit(1)
    };
    debug!("fetching files");
    let jwt = sqlite::sqlite_jwt::get_jwt(
        &server.cpid,
        &usr.cpid,
        pool
    ).await.unwrap();
    if jwt.is_none() {
        error!("a jwt was not found");

    }

    let jwt = jwt.unwrap();
    let _me_pub_ip = public_ip::addr().await;
    let host_cpid = server.cpid.clone();
    let user_cpid = usr.cpid.clone();
    
    let (server_media, server_pub_files) = fetcher::get_files(
        &usr,
        &server,
        jwt,
        port,
        ip,
        pool,
        pub_files,
        no_tls,
    ).await.unwrap();

    if server_media.len() == 0usize {
        info!("you don't have any files on that server");
        exit(0)
    };
    let should_be_files = server_media.len() as u64;

    let db_media = fetch_all_media_from_host_smedia(
        &host_cpid,
        &user_cpid,
        pool
    ).await.unwrap();
    if pub_files {
        
        let db_pub_files = fetch_all_public_files_from_host(
            &host_cpid,
            pool
        ).await.unwrap();
        if server_pub_files.is_some() {
            pub_file_checker(
                db_pub_files,
                server_pub_files.unwrap(),
                host_cpid.clone(),
                pool
            ).await;
        } 

    };

    file_checker(
        db_media,
        server_media,
        host_cpid,
        user_cpid,
        pool
    ).await;
    info!("done");
    
}




async fn post_proc(

    usr: SqliteUser,
    server: SqliteHost,
    ip: Option<IpAddr>,
    port: Option<u16>,
    no_tls: bool,
    post: Option<PathBuf>,
    checksum: bool,
    _pool: SqlitePool,
) {
    let pool = &_pool;
    let status = check_jwt_status(
        &usr.cpid,
        &server.cpid,
        pool
    ).await;
    if !status {
        error!("you have no available token please login first");
        exit(1)
    };
    debug!("creating a checksum: {checksum}");
    let request: RQM = RQM::create(
        post.unwrap(),
        POST.to_string(),
        usr.cpid.clone(),
        checksum
    ).await.unwrap();

    let request = Some(request);
    let res = client_process(
        _pool,
        usr,
        server,
        port,
        ip,
        None,
        request,
        no_tls,
    ).await.unwrap();

    println!("done {}", res);
    info!("STATUS: {res}");


}

async fn get_proc(
    usr: SqliteUser,
    server: SqliteHost,
    ip: Option<IpAddr>,
    port: Option<u16>,
    no_tls: bool,
    get: Option<PathBuf>,
    checksum: bool,
    pub_files: bool,
    _pool: SqlitePool,
) {
    let pool = &_pool;
    let status = check_jwt_status(
        &usr.cpid,
        &server.cpid,
        pool
    ).await;
    if !status {
        error!("you have no available token please login first");
        exit(1)
    };
    let _media_vec = if pub_files {
        info!("fetching public files");
        fetch_all_media_from_host(
        &server.cpid,
        &server.cpid,
        pool
    ).await} 
    else {
        fetch_all_media_from_host(
        &server.cpid,
        &usr.cpid,
        pool
    ).await};
    if _media_vec.is_err() {
        let e = _media_vec.err().unwrap();
        error!("database error: {}",e.to_string());
        info!("you don't have any files in said host");
        exit(0)
        
    };
    let mv = _media_vec.unwrap();
    let mut i = 0;

    for m in &mv {
        i+=1;
        println!("{i}(name: {}\n type: {}\nsize: {} checksum: {}\n)",
            m.name,
            m.type_,
            display_size(m.size as u64),
            m.checksum
        );
    };

    print!("enter the index of media you want: ");
    stdout().flush().unwrap();
    let mut buf =  String::new();
    let size = stdin().read_line(&mut buf).unwrap();

    let index = buf.trim_ascii_end();
    println!("you chose {index}");

    let user_index:u32 = index.parse().unwrap();
    let index = user_index - 1;
    let m: SqliteMedia = mv[index as usize ].clone();
    let getp = get.unwrap();
    let path = if getp == PathBuf::from("./") {
        format!("./{}", &m.name)
    } else {
        let path: String;
        if getp.is_dir() {
            let string_path = getp.to_str().unwrap();
            if string_path.ends_with("/") {
                path = format!("{string_path}{}",m.name);
            }else {
                path = format!("{string_path}/{}",m.name);
            };
        } else {
            path = getp.to_str().unwrap().to_string();
        };
        path


    };

    let request = RQM {
        cpid: m.cpid,
        name: m.name,
        size: m.size,
        type_: m.type_,
        header: GET.to_string(),
        chcksum: m.checksum,
        path: Some(path),
    };

    let request = Some(request);
    let res = client_process(
        _pool.clone(),
        usr.clone(),
        server.clone(),
        port,
        ip,
        Some(checksum),
        request.clone(),
        no_tls,

    ).await.unwrap();

    info!("STATUS: {res}");
}


async fn delete_proc(
    usr: SqliteUser,
    server: SqliteHost,
    ip: Option<IpAddr>,
    port: Option<u16>,
    no_tls: bool,
    _pool: SqlitePool,
) {
    let pool = &_pool;
    let status = check_jwt_status(
        &usr.cpid,
        &server.cpid,
        pool
    ).await;
    if !status {
        error!("you have no available token please login first");
        exit(1)
    };
    let _media_vec = fetch_all_media_from_host(
        &server.cpid,
        &usr.cpid,
        pool
    ).await;
    if _media_vec.is_err() {
        let e = _media_vec.err().unwrap();
        error!("database error: {}",e.to_string());
        info!("you don't have any files in said host");
        exit(0)
        
    };
    let mv = _media_vec.unwrap();
    let mut i = 0;
    
    for m in &mv {
        i+=1;
        println!("{i}(name: {}\n type: {}\nsize: {:.4}MB checksum: {}\n)",
            m.name,
            m.type_,
            (m.size as f64 / 1000 as f64) / 1000 as f64,
            m.checksum
        );
    };
    warn!("you are doing a delete request");
    print!("enter the index of media you want: ");
    stdout().flush().unwrap();
    let mut buf =  String::new();
    let size = stdin().read_line(&mut buf).unwrap();

    let index = buf.trim_ascii_end();
    println!("you chose {index}");

    let user_index:u32 = index.parse().unwrap();
    let index = user_index - 1;
    let m: SqliteMedia = mv[index as usize ].clone();
    let request = RQM {
        size: m.size,
        cpid: m.cpid,
        name: m.name,
        type_: m.type_,
        header: DELETE.to_string(),
        chcksum: m.checksum,
        path: Some(m.path),
    };
    let request = Some(request);
    let res = client_process(
        _pool,
        usr,
        server,
        port,
        ip,
        Some(false),
        request,
        no_tls,
    ).await.unwrap();
}


async fn login_proc(
    usr: SqliteUser,
    server: SqliteHost,
    port: Option<u16>,
    ip: Option<IpAddr>,
    no_tls: bool,
    pool: &SqlitePool
) {

    let mut passwd = String::new();
    let pass = get_pass(&mut passwd, &usr.name);
    let passwd = hash_passwords(passwd);
    let res = client_login_process(
        pool,
        usr,
        server,
        port,
        ip,
        passwd,
        no_tls
    ).await.unwrap();
    info!("STATUS: {res}");

}
