use std::{env, future::Future, path::PathBuf, sync::LazyLock};

use tempfile::tempdir;
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
