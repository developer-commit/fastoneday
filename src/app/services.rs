use std::sync::{Arc, Mutex};

use crate::{
    acquire::Engine,
    config::Settings,
    net::Http,
    sources::msrc::MsrcClient,
    store::{Cache, History, Workspace},
};

/// Long-lived collaborators shared by all use cases.
pub struct Services {
    pub settings: Settings,
    pub http: Arc<Http>,
    pub msrc: MsrcClient,
    pub engine: Engine,
    pub cache: Cache,
    pub workspace: Workspace,
    pub history: Mutex<History>,
}

impl Services {
    pub fn new(settings: Settings) -> Arc<Self> {
        let http = Arc::new(Http::new(&settings.user_agent, settings.request_timeout));
        let cache = Cache::new(settings.cache_dir());
        cache.clear_spill();
        Arc::new(Self {
            msrc: MsrcClient::new(http.clone()),
            engine: Engine::new(http.clone(), cache.clone()),
            workspace: Workspace::new(settings.cases_dir()),
            history: Mutex::new(History::load(settings.history_file())),
            cache,
            http,
            settings,
        })
    }
}
