pub type NodeData = serde_json::Value;

#[derive(Clone, Debug)]
pub struct Record {
    pub id: String,
    pub data: NodeData,
}
