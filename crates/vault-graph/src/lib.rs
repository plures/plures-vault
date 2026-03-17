use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum GraphError {
    #[error("Node not found: {0}")]
    NodeNotFound(Uuid),
    #[error("Edge not found: {0} -> {1}")]
    EdgeNotFound(Uuid, Uuid),
    #[error("Duplicate edge: {0} -> {1}")]
    DuplicateEdge(Uuid, Uuid),
    #[error("Cycle detected: adding {0} -> {1} would create a cycle")]
    CycleDetected(Uuid, Uuid),
    #[error("Self-reference not allowed")]
    SelfReference,
}

// ---------------------------------------------------------------------------
// Node types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecretNodeKind {
    Credential,
    Group,
    Tag,
    Environment,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretNode {
    pub id: Uuid,
    pub kind: SecretNodeKind,
    pub label: String,
    pub metadata: serde_json::Map<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Edge / relationship types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RelationshipType {
    DependsOn,
    GroupMember,
    TaggedWith,
    DerivedFrom,
    SharedWith,
    Supersedes,
    BundledWith,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEdge {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: RelationshipType,
    pub metadata: serde_json::Map<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Serialization helper
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct GraphData {
    nodes: Vec<SecretNode>,
    edges: Vec<SecretEdge>,
}

// ---------------------------------------------------------------------------
// SecretGraph
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SecretGraph {
    nodes: HashMap<Uuid, SecretNode>,
    edges: Vec<SecretEdge>,
}

impl Default for SecretGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
        }
    }

    // -- Node operations ----------------------------------------------------

    pub fn add_node(&mut self, kind: SecretNodeKind, label: impl Into<String>) -> SecretNode {
        let now = Utc::now();
        let node = SecretNode {
            id: Uuid::new_v4(),
            kind,
            label: label.into(),
            metadata: serde_json::Map::new(),
            created_at: now,
            updated_at: now,
        };
        self.nodes.insert(node.id, node.clone());
        node
    }

    pub fn add_node_with_id(
        &mut self,
        id: Uuid,
        kind: SecretNodeKind,
        label: impl Into<String>,
    ) -> SecretNode {
        let now = Utc::now();
        let node = SecretNode {
            id,
            kind,
            label: label.into(),
            metadata: serde_json::Map::new(),
            created_at: now,
            updated_at: now,
        };
        self.nodes.insert(node.id, node.clone());
        node
    }

    pub fn get_node(&self, id: &Uuid) -> Option<&SecretNode> {
        self.nodes.get(id)
    }

    pub fn remove_node(&mut self, id: &Uuid) -> Result<SecretNode, GraphError> {
        let node = self
            .nodes
            .remove(id)
            .ok_or(GraphError::NodeNotFound(*id))?;
        self.edges.retain(|e| e.source != *id && e.target != *id);
        Ok(node)
    }

    pub fn list_nodes(&self) -> Vec<&SecretNode> {
        self.nodes.values().collect()
    }

    pub fn find_nodes_by_kind(&self, kind: &SecretNodeKind) -> Vec<&SecretNode> {
        self.nodes.values().filter(|n| &n.kind == kind).collect()
    }

    pub fn find_nodes_by_label(&self, label: &str) -> Vec<&SecretNode> {
        let lower = label.to_lowercase();
        self.nodes
            .values()
            .filter(|n| n.label.to_lowercase().contains(&lower))
            .collect()
    }

    // -- Edge operations ----------------------------------------------------

    pub fn add_edge(
        &mut self,
        source: Uuid,
        target: Uuid,
        relationship: RelationshipType,
    ) -> Result<&SecretEdge, GraphError> {
        if source == target {
            return Err(GraphError::SelfReference);
        }
        if !self.nodes.contains_key(&source) {
            return Err(GraphError::NodeNotFound(source));
        }
        if !self.nodes.contains_key(&target) {
            return Err(GraphError::NodeNotFound(target));
        }

        // Check for duplicate (same source, target, AND relationship type)
        if self
            .edges
            .iter()
            .any(|e| e.source == source && e.target == target && e.relationship == relationship)
        {
            return Err(GraphError::DuplicateEdge(source, target));
        }

        // For DependsOn edges, check for cycles
        if relationship == RelationshipType::DependsOn && self.would_create_cycle(source, target) {
            return Err(GraphError::CycleDetected(source, target));
        }

        let edge = SecretEdge {
            source,
            target,
            relationship,
            metadata: serde_json::Map::new(),
            created_at: Utc::now(),
        };
        self.edges.push(edge);
        Ok(self.edges.last().unwrap())
    }

    pub fn remove_edge(
        &mut self,
        source: &Uuid,
        target: &Uuid,
        relationship: &RelationshipType,
    ) -> Result<(), GraphError> {
        let idx = self
            .edges
            .iter()
            .position(|e| {
                &e.source == source && &e.target == target && &e.relationship == relationship
            })
            .ok_or(GraphError::EdgeNotFound(*source, *target))?;
        self.edges.remove(idx);
        Ok(())
    }

    pub fn get_edges_from(&self, source: &Uuid) -> Vec<&SecretEdge> {
        self.edges.iter().filter(|e| &e.source == source).collect()
    }

    pub fn get_edges_to(&self, target: &Uuid) -> Vec<&SecretEdge> {
        self.edges.iter().filter(|e| &e.target == target).collect()
    }

    pub fn get_edges_between(&self, a: &Uuid, b: &Uuid) -> Vec<&SecretEdge> {
        self.edges
            .iter()
            .filter(|e| {
                (e.source == *a && e.target == *b) || (e.source == *b && e.target == *a)
            })
            .collect()
    }

    // -- Graph queries ------------------------------------------------------

    pub fn related_nodes(&self, id: &Uuid) -> Vec<&SecretNode> {
        let mut related_ids: HashSet<Uuid> = HashSet::new();
        for edge in &self.edges {
            if edge.source == *id {
                related_ids.insert(edge.target);
            } else if edge.target == *id {
                related_ids.insert(edge.source);
            }
        }
        related_ids
            .iter()
            .filter_map(|rid| self.nodes.get(rid))
            .collect()
    }

    /// Nodes that depend on this node (DependsOn edges pointing TO this node).
    pub fn dependents(&self, id: &Uuid) -> Vec<&SecretNode> {
        self.edges
            .iter()
            .filter(|e| e.target == *id && e.relationship == RelationshipType::DependsOn)
            .filter_map(|e| self.nodes.get(&e.source))
            .collect()
    }

    /// Nodes this node depends on (DependsOn edges FROM this node).
    pub fn dependencies(&self, id: &Uuid) -> Vec<&SecretNode> {
        self.edges
            .iter()
            .filter(|e| e.source == *id && e.relationship == RelationshipType::DependsOn)
            .filter_map(|e| self.nodes.get(&e.target))
            .collect()
    }

    /// Impact analysis – all transitive dependents via BFS.
    pub fn rotation_impact(&self, id: &Uuid) -> Vec<&SecretNode> {
        let mut visited: HashSet<Uuid> = HashSet::new();
        let mut queue: VecDeque<Uuid> = VecDeque::new();

        // Seed with direct dependents
        for edge in &self.edges {
            if edge.target == *id
                && edge.relationship == RelationshipType::DependsOn
                && visited.insert(edge.source)
            {
                queue.push_back(edge.source);
            }
        }

        while let Some(current) = queue.pop_front() {
            for edge in &self.edges {
                if edge.target == current
                    && edge.relationship == RelationshipType::DependsOn
                    && visited.insert(edge.source)
                {
                    queue.push_back(edge.source);
                }
            }
        }

        visited
            .iter()
            .filter_map(|nid| self.nodes.get(nid))
            .collect()
    }

    // -- Group / tag operations ---------------------------------------------

    pub fn group_members(&self, group_id: &Uuid) -> Vec<&SecretNode> {
        self.edges
            .iter()
            .filter(|e| e.target == *group_id && e.relationship == RelationshipType::GroupMember)
            .filter_map(|e| self.nodes.get(&e.source))
            .collect()
    }

    pub fn node_groups(&self, node_id: &Uuid) -> Vec<&SecretNode> {
        self.edges
            .iter()
            .filter(|e| e.source == *node_id && e.relationship == RelationshipType::GroupMember)
            .filter_map(|e| self.nodes.get(&e.target))
            .collect()
    }

    pub fn node_tags(&self, node_id: &Uuid) -> Vec<&SecretNode> {
        self.edges
            .iter()
            .filter(|e| e.source == *node_id && e.relationship == RelationshipType::TaggedWith)
            .filter_map(|e| self.nodes.get(&e.target))
            .collect()
    }

    // -- Serialization ------------------------------------------------------

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let data = GraphData {
            nodes: self.nodes.values().cloned().collect(),
            edges: self.edges.clone(),
        };
        serde_json::to_string_pretty(&data)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let data: GraphData = serde_json::from_str(json)?;
        let nodes = data.nodes.into_iter().map(|n| (n.id, n)).collect();
        Ok(Self {
            nodes,
            edges: data.edges,
        })
    }

    // -- Statistics ---------------------------------------------------------

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    // -- Internal helpers ---------------------------------------------------

    /// BFS from `target` following DependsOn edges (target→...) to see if
    /// `source` is reachable, which would indicate a cycle.
    fn would_create_cycle(&self, source: Uuid, target: Uuid) -> bool {
        let mut visited: HashSet<Uuid> = HashSet::new();
        let mut queue: VecDeque<Uuid> = VecDeque::new();
        queue.push_back(target);
        visited.insert(target);

        while let Some(current) = queue.pop_front() {
            if current == source {
                return true;
            }
            for edge in &self.edges {
                if edge.source == current
                    && edge.relationship == RelationshipType::DependsOn
                    && visited.insert(edge.target)
                {
                    queue.push_back(edge.target);
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers ------------------------------------------------------------

    fn sample_graph() -> (SecretGraph, Uuid, Uuid, Uuid) {
        let mut g = SecretGraph::new();
        let db = g.add_node(SecretNodeKind::Credential, "DB password");
        let app = g.add_node(SecretNodeKind::Credential, "App secret");
        let api = g.add_node(SecretNodeKind::Credential, "API key");
        // app DependsOn db, api DependsOn app
        g.add_edge(app.id, db.id, RelationshipType::DependsOn)
            .unwrap();
        g.add_edge(api.id, app.id, RelationshipType::DependsOn)
            .unwrap();
        (g, db.id, app.id, api.id)
    }

    // == 1. Node CRUD ======================================================

    #[test]
    fn test_add_and_get_node() {
        let mut g = SecretGraph::new();
        let node = g.add_node(SecretNodeKind::Credential, "my secret");
        assert_eq!(g.get_node(&node.id).unwrap().label, "my secret");
    }

    #[test]
    fn test_add_node_with_id() {
        let mut g = SecretGraph::new();
        let id = Uuid::new_v4();
        let node = g.add_node_with_id(id, SecretNodeKind::Service, "GitHub");
        assert_eq!(node.id, id);
        assert_eq!(g.get_node(&id).unwrap().kind, SecretNodeKind::Service);
    }

    #[test]
    fn test_remove_node() {
        let mut g = SecretGraph::new();
        let node = g.add_node(SecretNodeKind::Tag, "critical");
        let id = node.id;
        let removed = g.remove_node(&id).unwrap();
        assert_eq!(removed.label, "critical");
        assert!(g.get_node(&id).is_none());
    }

    #[test]
    fn test_remove_nonexistent_node() {
        let mut g = SecretGraph::new();
        let id = Uuid::new_v4();
        assert!(matches!(g.remove_node(&id), Err(GraphError::NodeNotFound(_))));
    }

    #[test]
    fn test_list_nodes() {
        let mut g = SecretGraph::new();
        g.add_node(SecretNodeKind::Credential, "a");
        g.add_node(SecretNodeKind::Group, "b");
        assert_eq!(g.list_nodes().len(), 2);
    }

    #[test]
    fn test_find_nodes_by_kind() {
        let mut g = SecretGraph::new();
        g.add_node(SecretNodeKind::Credential, "c1");
        g.add_node(SecretNodeKind::Credential, "c2");
        g.add_node(SecretNodeKind::Tag, "t1");
        assert_eq!(g.find_nodes_by_kind(&SecretNodeKind::Credential).len(), 2);
        assert_eq!(g.find_nodes_by_kind(&SecretNodeKind::Tag).len(), 1);
        assert_eq!(
            g.find_nodes_by_kind(&SecretNodeKind::Environment).len(),
            0
        );
    }

    #[test]
    fn test_find_nodes_by_label_case_insensitive() {
        let mut g = SecretGraph::new();
        g.add_node(SecretNodeKind::Credential, "Production DB");
        g.add_node(SecretNodeKind::Credential, "staging db");
        let results = g.find_nodes_by_label("db");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_nodes_by_label_substring() {
        let mut g = SecretGraph::new();
        g.add_node(SecretNodeKind::Credential, "my-secret-key");
        g.add_node(SecretNodeKind::Credential, "other");
        let results = g.find_nodes_by_label("secret");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "my-secret-key");
    }

    // == 2. Edge CRUD ======================================================

    #[test]
    fn test_add_and_get_edge() {
        let mut g = SecretGraph::new();
        let a = g.add_node(SecretNodeKind::Credential, "a");
        let b = g.add_node(SecretNodeKind::Credential, "b");
        g.add_edge(a.id, b.id, RelationshipType::DependsOn).unwrap();
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn test_remove_edge() {
        let mut g = SecretGraph::new();
        let a = g.add_node(SecretNodeKind::Credential, "a");
        let b = g.add_node(SecretNodeKind::Credential, "b");
        g.add_edge(a.id, b.id, RelationshipType::DependsOn).unwrap();
        g.remove_edge(&a.id, &b.id, &RelationshipType::DependsOn)
            .unwrap();
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_edge() {
        let mut g = SecretGraph::new();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert!(matches!(
            g.remove_edge(&a, &b, &RelationshipType::DependsOn),
            Err(GraphError::EdgeNotFound(_, _))
        ));
    }

    #[test]
    fn test_get_edges_from() {
        let (g, db_id, app_id, _) = sample_graph();
        let from_app = g.get_edges_from(&app_id);
        assert_eq!(from_app.len(), 1);
        assert_eq!(from_app[0].target, db_id);
    }

    #[test]
    fn test_get_edges_to() {
        let (g, db_id, app_id, _) = sample_graph();
        let to_db = g.get_edges_to(&db_id);
        assert_eq!(to_db.len(), 1);
        assert_eq!(to_db[0].source, app_id);
    }

    #[test]
    fn test_get_edges_between() {
        let mut g = SecretGraph::new();
        let a = g.add_node(SecretNodeKind::Credential, "a");
        let b = g.add_node(SecretNodeKind::Credential, "b");
        let c = g.add_node(SecretNodeKind::Credential, "c");
        g.add_edge(a.id, b.id, RelationshipType::DependsOn).unwrap();
        g.add_edge(b.id, a.id, RelationshipType::BundledWith)
            .unwrap();
        g.add_edge(a.id, c.id, RelationshipType::DependsOn).unwrap();
        let between = g.get_edges_between(&a.id, &b.id);
        assert_eq!(between.len(), 2);
    }

    #[test]
    fn test_multiple_relationship_types_same_pair() {
        let mut g = SecretGraph::new();
        let a = g.add_node(SecretNodeKind::Credential, "a");
        let b = g.add_node(SecretNodeKind::Credential, "b");
        g.add_edge(a.id, b.id, RelationshipType::DependsOn).unwrap();
        g.add_edge(a.id, b.id, RelationshipType::BundledWith)
            .unwrap();
        assert_eq!(g.edge_count(), 2);
    }

    // == 3. Validation =====================================================

    #[test]
    fn test_self_reference() {
        let mut g = SecretGraph::new();
        let a = g.add_node(SecretNodeKind::Credential, "a");
        assert!(matches!(
            g.add_edge(a.id, a.id, RelationshipType::DependsOn),
            Err(GraphError::SelfReference)
        ));
    }

    #[test]
    fn test_duplicate_edge() {
        let mut g = SecretGraph::new();
        let a = g.add_node(SecretNodeKind::Credential, "a");
        let b = g.add_node(SecretNodeKind::Credential, "b");
        g.add_edge(a.id, b.id, RelationshipType::DependsOn).unwrap();
        assert!(matches!(
            g.add_edge(a.id, b.id, RelationshipType::DependsOn),
            Err(GraphError::DuplicateEdge(_, _))
        ));
    }

    #[test]
    fn test_node_not_found_source() {
        let mut g = SecretGraph::new();
        let b = g.add_node(SecretNodeKind::Credential, "b");
        let fake = Uuid::new_v4();
        assert!(matches!(
            g.add_edge(fake, b.id, RelationshipType::DependsOn),
            Err(GraphError::NodeNotFound(_))
        ));
    }

    #[test]
    fn test_node_not_found_target() {
        let mut g = SecretGraph::new();
        let a = g.add_node(SecretNodeKind::Credential, "a");
        let fake = Uuid::new_v4();
        assert!(matches!(
            g.add_edge(a.id, fake, RelationshipType::DependsOn),
            Err(GraphError::NodeNotFound(_))
        ));
    }

    #[test]
    fn test_cycle_detection_direct() {
        let mut g = SecretGraph::new();
        let a = g.add_node(SecretNodeKind::Credential, "a");
        let b = g.add_node(SecretNodeKind::Credential, "b");
        g.add_edge(a.id, b.id, RelationshipType::DependsOn).unwrap();
        assert!(matches!(
            g.add_edge(b.id, a.id, RelationshipType::DependsOn),
            Err(GraphError::CycleDetected(_, _))
        ));
    }

    #[test]
    fn test_cycle_detection_transitive() {
        let mut g = SecretGraph::new();
        let a = g.add_node(SecretNodeKind::Credential, "a");
        let b = g.add_node(SecretNodeKind::Credential, "b");
        let c = g.add_node(SecretNodeKind::Credential, "c");
        g.add_edge(a.id, b.id, RelationshipType::DependsOn).unwrap();
        g.add_edge(b.id, c.id, RelationshipType::DependsOn).unwrap();
        assert!(matches!(
            g.add_edge(c.id, a.id, RelationshipType::DependsOn),
            Err(GraphError::CycleDetected(_, _))
        ));
    }

    #[test]
    fn test_no_cycle_for_non_depends_on() {
        let mut g = SecretGraph::new();
        let a = g.add_node(SecretNodeKind::Credential, "a");
        let b = g.add_node(SecretNodeKind::Credential, "b");
        g.add_edge(a.id, b.id, RelationshipType::BundledWith)
            .unwrap();
        // Reverse edge with non-DependsOn should be fine
        g.add_edge(b.id, a.id, RelationshipType::BundledWith)
            .unwrap();
        assert_eq!(g.edge_count(), 2);
    }

    // == 4. Graph queries ===================================================

    #[test]
    fn test_related_nodes() {
        let (g, db_id, app_id, api_id) = sample_graph();
        let related = g.related_nodes(&app_id);
        let ids: HashSet<Uuid> = related.iter().map(|n| n.id).collect();
        assert!(ids.contains(&db_id));
        assert!(ids.contains(&api_id));
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_dependents() {
        let (g, db_id, app_id, _) = sample_graph();
        let deps = g.dependents(&db_id);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].id, app_id);
    }

    #[test]
    fn test_dependencies() {
        let (g, db_id, _, api_id) = sample_graph();
        let deps = g.dependencies(&api_id);
        assert_eq!(deps.len(), 1);
        // api depends on app, not directly on db
        assert_ne!(deps[0].id, db_id);
    }

    #[test]
    fn test_rotation_impact_chain() {
        // db <- app <- api  (app DependsOn db, api DependsOn app)
        let (g, db_id, app_id, api_id) = sample_graph();
        let impact = g.rotation_impact(&db_id);
        let ids: HashSet<Uuid> = impact.iter().map(|n| n.id).collect();
        // Rotating db affects both app and api transitively
        assert!(ids.contains(&app_id));
        assert!(ids.contains(&api_id));
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_rotation_impact_no_dependents() {
        let (g, _, _, api_id) = sample_graph();
        let impact = g.rotation_impact(&api_id);
        assert!(impact.is_empty());
    }

    #[test]
    fn test_rotation_impact_fan_out() {
        let mut g = SecretGraph::new();
        let root = g.add_node(SecretNodeKind::Credential, "root");
        let c1 = g.add_node(SecretNodeKind::Credential, "child1");
        let c2 = g.add_node(SecretNodeKind::Credential, "child2");
        let c3 = g.add_node(SecretNodeKind::Credential, "child3");
        g.add_edge(c1.id, root.id, RelationshipType::DependsOn)
            .unwrap();
        g.add_edge(c2.id, root.id, RelationshipType::DependsOn)
            .unwrap();
        g.add_edge(c3.id, c1.id, RelationshipType::DependsOn)
            .unwrap();
        let impact = g.rotation_impact(&root.id);
        let ids: HashSet<Uuid> = impact.iter().map(|n| n.id).collect();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&c1.id));
        assert!(ids.contains(&c2.id));
        assert!(ids.contains(&c3.id));
    }

    // == 5. Group operations ================================================

    #[test]
    fn test_group_members() {
        let mut g = SecretGraph::new();
        let grp = g.add_node(SecretNodeKind::Group, "Work");
        let c1 = g.add_node(SecretNodeKind::Credential, "c1");
        let c2 = g.add_node(SecretNodeKind::Credential, "c2");
        g.add_edge(c1.id, grp.id, RelationshipType::GroupMember)
            .unwrap();
        g.add_edge(c2.id, grp.id, RelationshipType::GroupMember)
            .unwrap();
        let members = g.group_members(&grp.id);
        assert_eq!(members.len(), 2);
    }

    #[test]
    fn test_node_groups() {
        let mut g = SecretGraph::new();
        let g1 = g.add_node(SecretNodeKind::Group, "Work");
        let g2 = g.add_node(SecretNodeKind::Group, "Personal");
        let cred = g.add_node(SecretNodeKind::Credential, "shared");
        g.add_edge(cred.id, g1.id, RelationshipType::GroupMember)
            .unwrap();
        g.add_edge(cred.id, g2.id, RelationshipType::GroupMember)
            .unwrap();
        let groups = g.node_groups(&cred.id);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn test_node_tags() {
        let mut g = SecretGraph::new();
        let tag = g.add_node(SecretNodeKind::Tag, "critical");
        let cred = g.add_node(SecretNodeKind::Credential, "db-pass");
        g.add_edge(cred.id, tag.id, RelationshipType::TaggedWith)
            .unwrap();
        let tags = g.node_tags(&cred.id);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].label, "critical");
    }

    // == 6. Serialization ===================================================

    #[test]
    fn test_json_round_trip() {
        let (g, _, _, _) = sample_graph();
        let json = g.to_json().unwrap();
        let g2 = SecretGraph::from_json(&json).unwrap();
        assert_eq!(g2.node_count(), g.node_count());
        assert_eq!(g2.edge_count(), g.edge_count());
    }

    #[test]
    fn test_empty_graph_serialization() {
        let g = SecretGraph::new();
        let json = g.to_json().unwrap();
        let g2 = SecretGraph::from_json(&json).unwrap();
        assert_eq!(g2.node_count(), 0);
        assert_eq!(g2.edge_count(), 0);
    }

    // == 7. Edge cases ======================================================

    #[test]
    fn test_empty_graph_queries() {
        let g = SecretGraph::new();
        let fake = Uuid::new_v4();
        assert!(g.related_nodes(&fake).is_empty());
        assert!(g.dependents(&fake).is_empty());
        assert!(g.dependencies(&fake).is_empty());
        assert!(g.rotation_impact(&fake).is_empty());
        assert!(g.group_members(&fake).is_empty());
        assert!(g.node_groups(&fake).is_empty());
        assert!(g.node_tags(&fake).is_empty());
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn test_remove_node_removes_edges() {
        let mut g = SecretGraph::new();
        let a = g.add_node(SecretNodeKind::Credential, "a");
        let b = g.add_node(SecretNodeKind::Credential, "b");
        let c = g.add_node(SecretNodeKind::Credential, "c");
        g.add_edge(a.id, b.id, RelationshipType::DependsOn).unwrap();
        g.add_edge(c.id, b.id, RelationshipType::BundledWith)
            .unwrap();
        assert_eq!(g.edge_count(), 2);
        g.remove_node(&b.id).unwrap();
        assert_eq!(g.edge_count(), 0);
        assert_eq!(g.node_count(), 2);
    }

    #[test]
    fn test_default_trait() {
        let g = SecretGraph::default();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn test_node_count_and_edge_count() {
        let (g, _, _, _) = sample_graph();
        assert_eq!(g.node_count(), 3);
        assert_eq!(g.edge_count(), 2);
    }
}
