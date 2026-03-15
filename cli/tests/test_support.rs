use std::{env, future::Future, path::PathBuf, sync::LazyLock};

use tempfile::tempdir;
use tiny_http::Server;
use tokio::sync::Mutex;

static ENV_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

struct EnvGuard {
    previous: Option<std::ffi::OsString>,
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => env::set_var("AGENTPREY_HOME", value),
            None => env::remove_var("AGENTPREY_HOME"),
        }
    }
}

pub async fn with_temp_agentprey_home<F, Fut, T>(run: F) -> T
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: Future<Output = T>,
{
    let _lock = ENV_MUTEX.lock().await;
    let temp = tempdir().expect("tempdir should be created");
    let agentprey_home = temp.path().join("agentprey-home");
    std::fs::create_dir_all(&agentprey_home).expect("agentprey home should be created");

    let previous = env::var_os("AGENTPREY_HOME");
    env::set_var("AGENTPREY_HOME", &agentprey_home);
    let _guard = EnvGuard { previous };

    run(agentprey_home).await
}

#[allow(dead_code)]
pub fn try_bind_test_server(context: &str) -> Option<Server> {
    match Server::http("127.0.0.1:0") {
        Ok(server) => Some(server),
        Err(error) if error.to_string().contains("Operation not permitted") => {
            eprintln!(
                "skipping {context}: local test server bind not permitted in this environment"
            );
            None
        }
        Err(error) => panic!("{context}: {error}"),
    }
}
