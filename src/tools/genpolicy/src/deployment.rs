// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Allow K8s YAML field names.
#![allow(non_snake_case)]

use crate::config_map;
use crate::infra;
use crate::obj_meta;
use crate::pod;
use crate::pod_template;
use crate::policy;
use crate::registry;
use crate::utils;
use crate::yaml;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

/// Reference / Kubernetes API / Workload Resources / Deployment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    apiVersion: String,
    kind: String,
    pub metadata: obj_meta::ObjectMeta,
    pub spec: DeploymentSpec,

    #[serde(skip)]
    registry_containers: Vec<registry::Container>,
}

/// Reference / Kubernetes API / Workload Resources / Deployment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    replicas: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    selector: Option<yaml::LabelSelector>,

    #[serde(skip_serializing_if = "Option::is_none")]
    strategy: Option<DeploymentStrategy>,

    pub template: pod_template::PodTemplateSpec,
    // TODO: additional fields.
}

/// Reference / Kubernetes API / Workload Resources / Deployment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentStrategy {
    #[serde(skip_serializing_if = "Option::is_none")]
    r#type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    rollingUpdate: Option<RollingUpdateDeployment>,
}

/// Reference / Kubernetes API / Workload Resources / Deployment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollingUpdateDeployment {
    #[serde(skip_serializing_if = "Option::is_none")]
    maxSurge: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    maxUnavailable: Option<i32>,
}

#[async_trait]
impl yaml::K8sObject for Deployment {
    async fn initialize(&mut self, use_cached_files: bool) -> Result<()> {
        yaml::init_k8s_object(
            &mut self.spec.template.spec.containers,
            &mut self.registry_containers,
            use_cached_files).await
    }

    fn requires_policy(&self) -> bool {
        true
    }

    fn get_metadata_name(&self) -> Result<String> {
        self.metadata.get_name()
    }

    fn get_host_name(&self) -> Result<String> {
        // Deployment pod names have variable lengths for some reason.
        Ok("^".to_string() + &self.get_metadata_name()? + "-[a-z0-9]*-[a-z0-9]{5}$")
    }

    fn get_sandbox_name(&self) -> Result<Option<String>> {
        Ok(None)
    }

    fn get_namespace(&self) -> Result<String> {
        self.metadata.get_namespace()
    }

    fn get_container_mounts_and_storages(
        &self,
        _policy_mounts: &mut Vec<oci::Mount>,
        _storages: &mut Vec<policy::SerializedStorage>,
        _container: &pod::Container,
        _infra_policy: &infra::InfraPolicy,
    ) -> Result<()> {
        Ok(())
    }

    fn generate_policy(
        &mut self,
        rules: &str,
        infra_policy: &infra::InfraPolicy,
        config_maps: &Vec<config_map::ConfigMap>,
        in_out_files: &utils::InOutFiles,
    ) -> Result<()> {
        let mut policy_containers = Vec::new();

        for i in 0..self.spec.template.spec.containers.len() {
            policy_containers.push(policy::get_container_policy(
                self,
                infra_policy,
                config_maps,
                &self.spec.template.spec.containers[i],
                i == 0,
                &self.registry_containers[i],
            )?);
        }

        let policy_data = policy::PolicyData {
            containers: policy_containers,
        };

        let json_data = serde_json::to_string_pretty(&policy_data)
            .map_err(|e| anyhow!(e))
            .unwrap();

        let policy = rules.to_string() + "\npolicy_data := " + &json_data;
        if let Some(file_name) = &in_out_files.output_policy_file {
            policy::export_decoded_policy(&policy, &file_name)?;
        }

        let encoded_policy = general_purpose::STANDARD.encode(policy.as_bytes());
        self.spec
            .template
            .metadata
            .add_policy_annotation(&encoded_policy);

        // Remove the pause container before serializing.
        self.spec.template.spec.containers.remove(0);
        Ok(())
    }

    fn serialize(&mut self) -> Result<String> {
        Ok(serde_yaml::to_string(&self)?)
    }
}
