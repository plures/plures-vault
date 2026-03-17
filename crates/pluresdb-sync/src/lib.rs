use tokio::sync::broadcast;

pub struct GunRelayServer;

impl GunRelayServer {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Clone, Debug)]
pub enum SyncEvent {
    NodeUpsert { id: String },
    PeerConnected { peer_id: String },
    PeerDisconnected { peer_id: String },
}

pub struct SyncBroadcaster {
    tx: broadcast::Sender<SyncEvent>,
}

impl SyncBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SyncEvent> {
        self.tx.subscribe()
    }

    pub fn send(&self, event: SyncEvent) {
        let _ = self.tx.send(event);
    }
}
