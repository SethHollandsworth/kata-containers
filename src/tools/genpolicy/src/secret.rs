// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Allow K8s YAML field names.
#![allow(non_snake_case)]

use crate::obj_meta;
use crate::pod;
use crate::policy;
use crate::registry;
use crate::yaml;

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// See Reference / Kubernetes API / Config and Storage Resources / Secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secret {
    apiVersion: String,
    kind: String,
    pub metadata: obj_meta::ObjectMeta,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    immutable: Option<bool>,
    // TODO: additional fields.

    #[serde(skip)]
    doc_mapping: serde_yaml::Value,
}

impl Secret {
    pub fn get_value(&self, value_from: &pod::EnvVarSource) -> Option<String> {
        if let Some(key_ref) = &value_from.secretKeyRef {
            if let Some(name) = &key_ref.name {
                if let Some(my_name) = &self.metadata.name {
                    if my_name.eq(name) {
                        if let Some(data) = &self.data {
                            if let Some(value) = data.get(&key_ref.key) {
                                let value_bytes = general_purpose::STANDARD.decode(&value).unwrap();
                                let value_string = std::str::from_utf8(&value_bytes).unwrap();
                                return Some(value_string.to_string());
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

pub fn get_value(value_from: &pod::EnvVarSource, secrets: &Vec<Secret>) -> Option<String> {
    for secret in secrets {
        if let Some(value) = secret.get_value(value_from) {
            return Some(value);
        }
    }

    None
}

#[async_trait]
impl yaml::K8sResource for Secret {
    async fn init(
        &mut self,
        _use_cache: bool,
        doc_mapping: &serde_yaml::Value,
        _silent_unsupported_fields: bool,
    ) -> anyhow::Result<()> {
        self.doc_mapping = doc_mapping.clone();
        Ok(())
    }

    fn get_metadata_name(&self) -> String {
        panic!("Unsupported");
    }

    fn get_host_name(&self) -> String {
        panic!("Unsupported");
    }

    fn get_sandbox_name(&self) -> Option<String> {
        panic!("Unsupported");
    }

    fn get_namespace(&self) -> String {
        panic!("Unsupported");
    }

    fn get_container_mounts_and_storages(
        &self,
        _policy_mounts: &mut Vec<oci::Mount>,
        _storages: &mut Vec<policy::SerializedStorage>,
        _container: &pod::Container,
        _agent_policy: &policy::AgentPolicy,
    ) {
        panic!("Unsupported");
    }

    fn generate_policy(&self, _agent_policy: &policy::AgentPolicy) -> String {
        "".to_string()
    }

    fn serialize(&mut self, _policy: &str) -> String {
        serde_yaml::to_string(&self.doc_mapping).unwrap()
    }

    fn get_containers(&self) -> (&Vec<registry::Container>, &Vec<pod::Container>) {
        panic!("Unsupported");
    }
}