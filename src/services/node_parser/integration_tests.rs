//! Opt-in integration tests use only local, disposable proxy servers.
//! Run: MIAO_TEST_SING_BOX=/absolute/path/to/sing-box cargo test local_proxy_round_trips -- --ignored
use super::*;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn core(binary: &str, config: JsonValue) -> tokio::process::Child {
    let mut child = tokio::process::Command::new(binary)
        .args(["run", "-c", "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(config.to_string().as_bytes())
        .await
        .unwrap();
    child
}

async fn ready(child: &mut tokio::process::Child, port: u16) {
    for _ in 0..100 {
        assert!(
            child.try_wait().unwrap().is_none(),
            "test core exited before becoming ready"
        );
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("test core did not listen in time");
}

#[tokio::test]
#[ignore = "requires MIAO_TEST_SING_BOX and openssl; starts loopback-only proxy servers"]
async fn local_proxy_round_trips() {
    let binary = std::env::var("MIAO_TEST_SING_BOX").unwrap();
    let directory =
        std::env::temp_dir().join(format!("miao-core-roundtrip-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let cert = directory.join("cert.pem");
    let key = directory.join("key.pem");
    assert!(std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
    let pair = std::process::Command::new(&binary)
        .args(["generate", "reality-keypair"])
        .output()
        .unwrap();
    assert!(pair.status.success());
    let pair = String::from_utf8(pair.stdout).unwrap();
    let extract_key = |name: &str| {
        pair.lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .trim()
            .to_string()
    };
    let private_key = extract_key("PrivateKey:");
    let public_key = extract_key("PublicKey:");
    // Keep ports distinct even when the OS immediately reuses an ephemeral port.
    let sockets: Vec<_> = (0..5)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<_> = sockets
        .iter()
        .map(|s| s.local_addr().unwrap().port())
        .collect();
    let (socks, https, hy2, tuic, vless) = (ports[0], ports[1], ports[2], ports[3], ports[4]);
    let uuid = "123e4567-e89b-12d3-a456-426614174000";
    let tls = json!({"enabled":true,"certificate_path":cert,"key_path":key,"curve_preferences":["X25519"]});
    let server_config = json!({
        "log":{"disabled":true},
        "inbounds":[
            {"type":"socks","listen":"127.0.0.1","listen_port":socks,"users":[{"username":"user","password":"p@ss"}]},
            {"type":"http","listen":"127.0.0.1","listen_port":https,"users":[{"username":"user","password":"p@ss"}],"tls":tls},
            {"type":"hysteria2","listen":"127.0.0.1","listen_port":hy2,"users":[{"name":"test","password":"p@ss"}],"tls":tls},
            {"type":"tuic","listen":"127.0.0.1","listen_port":tuic,"users":[{"uuid":uuid,"password":"p@ss"}],"tls":tls},
            {"type":"vless","listen":"127.0.0.1","listen_port":vless,"users":[{"uuid":uuid}],"tls":{"enabled":true,"server_name":"localhost","reality":{"enabled":true,"private_key":private_key,"short_id":[""],"handshake":{"server":"127.0.0.1","server_port":https}}}}
        ],
        "outbounds":[{"type":"direct","tag":"direct"}]
    });
    drop(sockets);
    let mut server = core(&binary, server_config).await;
    ready(&mut server, socks).await;
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        axum::serve(
            target,
            axum::Router::new().route("/", axum::routing::get(|| async { "miao roundtrip" })),
        )
        .await
        .unwrap();
    });
    let uris = [
        format!("socks5://user:p%40ss@127.0.0.1:{socks}#socks"),
        format!("https://user:p%40ss@127.0.0.1:{https}?sni=localhost&insecure=1#https"),
        format!("hy2://p%40ss@127.0.0.1:{hy2}?sni=localhost&insecure=1#hy2"),
        format!("tuic://{uuid}:p%40ss@127.0.0.1:{tuic}?sni=localhost&allow_insecure=1&congestion_control=bbr#tuic"),
        format!("vless://{uuid}@127.0.0.1:{vless}?type=tcp&security=reality&pbk={public_key}&sni=localhost&fp=chrome#vless"),
    ];
    for uri in uris {
        let parsed = parse_uri_subscription_with_options(&uri, true).unwrap();
        assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
        let (name, outbound) = parsed.nodes.into_iter().next().unwrap();
        let port = free_port();
        let mut client_core = core(
            &binary,
            json!({
                "log":{"disabled":true},
                "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":port}],
                "outbounds":[outbound],"route":{"final":name}
            }),
        )
        .await;
        ready(&mut client_core, port).await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).unwrap())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        let response = client
            .get(format!("http://127.0.0.1:{target_port}/"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("{name} roundtrip failed: {e}"));
        assert_eq!(response.text().await.unwrap(), "miao roundtrip", "{name}");
        client_core.kill().await.unwrap();
        client_core.wait().await.unwrap();
    }
    server.kill().await.unwrap();
    server.wait().await.unwrap();
    target_task.abort();
}
