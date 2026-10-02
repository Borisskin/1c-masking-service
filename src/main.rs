use std::{
    env, fs,
    io::IsTerminal,
    path::{Path, PathBuf},
    sync::Arc,
};

use onec_masking_service::{
    auth::{AuthStore, LocalAuthProvider},
    human_app,
    internal_api::AxumListener,
    internal_app,
    local_ipc::{self, Access, Endpoint, Listener, Peer},
    manager_client::ManagerClient,
    AppState, SqliteStorage,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

/// Значения по умолчанию зависят от ОС: в Windows путей Unix нет, а база данных не имеет
/// умолчания вовсе (`MASKING_DATABASE_PATH` обязателен).
#[cfg(unix)]
mod defaults {
    pub const DATABASE: Option<&str> = Some("/var/lib/1c-masking/service.sqlite3");
    pub const SOCKET: &str = "/run/1c-masking/service.sock";
    pub const CONTROL: &str = "/run/1c-masking/control.sock";
}
#[cfg(windows)]
mod defaults {
    pub const DATABASE: Option<&str> = None;
    pub const SOCKET: &str = r"\\.\pipe\1c-masking-service";
    pub const CONTROL: &str = r"\\.\pipe\1c-masking-control";
}

/// Читает адрес канала из окружения (или умолчания) и проверяет его правилами текущей ОС.
/// Значение в сообщение об ошибке не попадает.
fn endpoint_from_env(name: &str, default: Option<&str>) -> Result<Endpoint, String> {
    let value = match env::var(name) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => default
            .ok_or_else(|| format!("{name} is required"))?
            .to_owned(),
        Err(_) => return Err(format!("{name} is not valid unicode")),
    };
    Endpoint::parse(Path::new(&value)).map_err(|error| format!("{name}: {error}"))
}

/// Читает необязательную переменную; не-Unicode значение — ошибка (без вывода значения).
fn optional_env(name: &str) -> Result<Option<String>, String> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(format!("{name} is not valid unicode")),
    }
}

/// Собирает ожидаемого менеджера из значений окружения. Параметр чужой ОС — ошибка запуска,
/// а не молчаливое игнорирование; значения параметров в сообщения не попадают.
fn manager_peer(uid: Option<&str>, sid: Option<&str>, exe: Option<&str>) -> Result<Peer, String> {
    #[cfg(unix)]
    {
        for (name, value) in [("MASKING_MANAGER_SID", sid), ("MASKING_MANAGER_EXE", exe)] {
            if value.is_some() {
                return Err(format!("{name} is not supported on this OS"));
            }
        }
        match uid {
            // Менеджер по умолчанию работает под той же учётной записью, что и служба.
            None => Peer::current_process().map_err(|_| "cannot determine current user".to_owned()),
            Some(uid) => {
                let uid = uid
                    .parse::<u32>()
                    .map_err(|_| "MASKING_MANAGER_UID must be a numeric uid".to_owned())?;
                Peer::from_config(Some(uid), None, None).map_err(|error| error.to_string())
            }
        }
    }
    #[cfg(windows)]
    {
        if uid.is_some() {
            return Err("MASKING_MANAGER_UID is not supported on this OS".to_owned());
        }
        Peer::from_config(None, sid, exe.map(Path::new)).map_err(|error| {
            let field = match error {
                local_ipc::ConfigError::Unsupported { field }
                | local_ipc::ConfigError::Missing { field }
                | local_ipc::ConfigError::Invalid { field } => field,
            };
            format!("MASKING_MANAGER_{}: {error}", field.to_uppercase())
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args()
        .skip(1)
        .eq(["admin", "bootstrap"].map(str::to_owned))
    {
        return bootstrap_client().await;
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .without_time()
        .compact()
        .init();
    std::panic::set_hook(Box::new(|info| {
        if let Some(location) = info.location() {
            eprintln!(
                "MASKING_SERVICE_PANIC at {}:{}",
                location.file(),
                location.line()
            );
        } else {
            eprintln!("MASKING_SERVICE_PANIC");
        }
    }));

    // Адреса и идентичность менеджера разбираются сразу: ошибка конфигурации — до любых
    // побочных действий (создание каталогов, открытие базы).
    let database_path = match env::var("MASKING_DATABASE_PATH") {
        Ok(value) => PathBuf::from(value),
        Err(_) => PathBuf::from(defaults::DATABASE.ok_or("MASKING_DATABASE_PATH is required")?),
    };
    let socket_endpoint = endpoint_from_env("MASKING_SOCKET_PATH", Some(defaults::SOCKET))?;
    let control_endpoint =
        endpoint_from_env("MASKING_CONTROL_SOCKET_PATH", Some(defaults::CONTROL))?;
    //++agent TASK-222 [05.10.2026]
    // Pull-модель: metadata/dictionary сервис загружает сам, вызывая internal
    // tools через канал менеджера. Переменная обязательна — без неё durable
    // intents некому выполнять, enabled-базы остались бы not-ready навсегда.
    let manager_endpoint = endpoint_from_env("MASKING_MANAGER_SOCKET_PATH", None)?;
    //++agent TASK-222
    let manager_peer = manager_peer(
        optional_env("MASKING_MANAGER_UID")?.as_deref(),
        optional_env("MASKING_MANAGER_SID")?.as_deref(),
        optional_env("MASKING_MANAGER_EXE")?.as_deref(),
    )?;
    let human_bind = env::var("MASKING_HUMAN_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
    let expected_origin = env::var("MASKING_EXPECTED_ORIGIN")
        .map_err(|_| "MASKING_EXPECTED_ORIGIN is required for the human listener")?;
    if expected_origin.is_empty() {
        return Err("MASKING_EXPECTED_ORIGIN must not be empty".into());
    }
    prepare_parent(&database_path)?;
    let storage = Arc::new(SqliteStorage::open(&database_path)?);
    set_private_file_mode(&database_path)?;
    let state = AppState::new(storage.clone(), expected_origin);
    let auth_store: Arc<dyn AuthStore> = storage.clone();
    let control_auth = Arc::new(LocalAuthProvider::new(auth_store)?);
    control_auth.initialize()?;
    let listener = Listener::bind(
        &socket_endpoint,
        Access {
            unix_mode: Some(0o660),
            allow: Some(manager_peer.clone()),
        },
    )?;
    let control_listener = Listener::bind(
        &control_endpoint,
        Access {
            unix_mode: Some(0o600),
            allow: None,
        },
    )?;
    let human_listener = TcpListener::bind(&human_bind).await?;
    tokio::spawn(serve_control(control_listener, control_auth));
    let maintenance = state.masking.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let _ = maintenance.maintenance_tick().await;
        }
    });
    //++agent TASK-222 [05.10.2026]
    // Pull worker: короткий тик дрейнит durable v2_refresh_intents — startup
    // intents ставятся конструктором сервиса, Admin-мутации дополняют очередь.
    // Сбой одного pull не останавливает цикл (transient intent переживает тик).
    let pull_service = state.masking.clone();
    let manager_client = ManagerClient::new(manager_endpoint, manager_peer);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(bounded_env(
            "MASKING_PULL_INTERVAL_SECONDS",
            10,
            1,
            300,
        )));
        loop {
            interval.tick().await;
            let _ = pull_service.refresh_due_intents(&manager_client, 10).await;
        }
    });
    //++agent TASK-222
    tracing::info!(event = "service_started");
    let internal = axum::serve(
        AxumListener(listener),
        internal_app(state.clone()).into_make_service_with_connect_info::<local_ipc::PeerInfo>(),
    );
    let human = axum::serve(human_listener, human_app(state)?);
    tokio::try_join!(internal, human)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct BootstrapRequest {
    password: String,
}

#[derive(Serialize, Deserialize)]
struct BootstrapResponse {
    success: bool,
}

async fn bootstrap_client() -> Result<(), Box<dyn std::error::Error>> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err("bootstrap requires an interactive TTY".into());
    }
    let first = rpassword::prompt_password("Новый пароль Admin: ")?;
    let second = rpassword::prompt_password("Повторите пароль: ")?;
    if first != second || first.len() < 12 || first.len() > 1024 {
        return Err("password confirmation or length is invalid".into());
    }
    let endpoint = endpoint_from_env("MASKING_CONTROL_SOCKET_PATH", Some(defaults::CONTROL))?;
    // Клиент и сервер — один и тот же masking-service.exe: в Windows сервер обязан быть им.
    #[cfg(windows)]
    let server = Some(Peer::current_process()?);
    #[cfg(not(windows))]
    let server: Option<Peer> = None;
    let mut stream = local_ipc::connect(&endpoint, server.as_ref()).await?;
    let mut request = serde_json::to_vec(&BootstrapRequest { password: first })?;
    request.push(b'\n');
    stream.write_all(&request).await?;
    stream.flush().await?;
    request.fill(0);
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).await?;
    let response: BootstrapResponse = serde_json::from_str(&response)?;
    if !response.success {
        return Err("bootstrap was rejected".into());
    }
    eprintln!("Пароль Admin установлен.");
    Ok(())
}

async fn serve_control(mut listener: Listener, auth: Arc<LocalAuthProvider>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            // Временная ошибка приёма: пауза, чтобы не крутиться вхолостую.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        };
        if !peer.authorized {
            continue;
        }
        let auth = auth.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(stream);
            let mut line = String::new();
            let success = match BufReader::new(reader).take(2049).read_line(&mut line).await {
                Ok(size) if size <= 2048 => serde_json::from_str::<BootstrapRequest>(&line)
                    .ok()
                    .filter(|request| (12..=1024).contains(&request.password.len()))
                    .is_some_and(|request| {
                        auth.bootstrap_admin_password(&request.password).is_ok()
                    }),
                _ => false,
            };
            line.clear();
            let response = serde_json::to_vec(&BootstrapResponse { success })
                .unwrap_or_else(|_| b"{\"success\":false}".to_vec());
            let _ = writer.write_all(&response).await;
            let _ = writer.write_all(b"\n").await;
            let _ = writer.flush().await;
        });
    }
}

//++agent TASK-222 [05.10.2026]
fn bounded_env(name: &str, default: u64, minimum: u64, maximum: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .unwrap_or(default)
}
//++agent TASK-222

fn prepare_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn set_private_file_mode(_path: &Path) -> std::io::Result<()> {
    // Права каталога данных в Windows пока не меняются: вопрос отложен. Файл наследует ACL
    // каталога, поэтому оператор выбирает каталог, недоступный другим учётным записям.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn foreign_os_manager_parameters_are_startup_errors() {
        for (sid, exe, name) in [
            (Some("S-1-5-18"), None, "MASKING_MANAGER_SID"),
            (None, Some("/bin/x"), "MASKING_MANAGER_EXE"),
        ] {
            let error = manager_peer(None, sid, exe).unwrap_err();
            assert!(error.contains(name));
            assert!(!error.contains("S-1-5-18") && !error.contains("/bin/x"));
        }
        assert!(manager_peer(Some("1000"), None, None).is_ok());
        assert!(manager_peer(None, None, None).is_ok());
        let error = manager_peer(Some("secret-value"), None, None).unwrap_err();
        assert!(error.contains("MASKING_MANAGER_UID") && !error.contains("secret-value"));
    }

    #[cfg(windows)]
    #[test]
    fn foreign_os_manager_parameters_are_startup_errors() {
        let error = manager_peer(Some("1000"), None, Some(r"C:\x.exe")).unwrap_err();
        assert!(error.contains("MASKING_MANAGER_UID") && !error.contains("1000"));
        let error = manager_peer(None, None, None).unwrap_err();
        assert!(error.contains("MASKING_MANAGER_EXE"));
    }
}
