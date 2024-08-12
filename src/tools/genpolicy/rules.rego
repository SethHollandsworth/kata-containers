package play

import rego.v1

# Welcome to the Rego playground! Rego (pronounced "ray-go") is OPA's policy language.
#
# Try it out:
#
#   1. Click Evaluate. Note: 'hello' is 'true'
#   2. Change "world" to "hello" in the INPUT panel. Click Evaluate. Note: 'hello' is 'false'
#   3. Change "world" to "hello" on line 25 in the editor. Click Evaluate. Note: 'hello' is 'true'
#
# Features:
#
#         Examples  browse a collection of example policies
#         Coverage  view the policy statements that were executed
#         Evaluate  execute the policy with INPUT and DATA
#          Publish  share your playground and experiment with local deployment
#            INPUT  edit the JSON value your policy sees under the 'input' global variable
#    (resize) DATA  edit the JSON value your policy sees under the 'data' global variable
#           OUTPUT  view the result of policy execution

# default allow_envs := false
#
# allow_envs if {
# 	i_envs := input.config.envs
# 	p_envs := policy_data.allow_envs
#
# 	every i_env in i_envs {
# 		allow_env(i_env, p_envs)
# 	}
# }
#
# allow_env(i_env, p_envs) if {
# 	some p_env in p_envs
# 	p_env == i_env
# }
#
# policy_data := {"allow_envs": [
# 	{
# 		"key": "KUBERNETES_PORT_443_TCP_PORT",
# 		"value": "443",
# 	},
# 	{
# 		"key": "KUBERNETES_PORT_443_TCP_ADDR",
# 		"value": "10.96.0.1",
# 	},
# 	{
# 		"key": "KUBERNETES_SERVICE_HOST",
# 		"value": "11.96.0.1",
# 	},
# 	{
# 		"key": "KUBERNETES_SERVICE_PORT",
# 		"value": "443",
# 	},
# 	{
# 		"key": "KUBERNETES_SERVICE_PORT_HTTPS",
# 		"value": "443",
# 	},
# 	{
# 		"key": "KUBERNETES_PORT",
# 		"value": "tcp://10.96.0.1:443",
# 	},
# 	{
# 		"key": "KUBERNETES_PORT_443_TCP",
# 		"value": "tcp://10.96.0.1:443",
# 	},
# 	{
# 		"key": "KUBERNETES_PORT_443_TCP_PROTO",
# 		"value": "tcp",
# 	},
# ]}

# Copyright (c) 2023 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# package agent_policy

# import future.keywords.in
# import future.keywords.every

import input

# Default values, returned by OPA when rules cannot be evaluated to true.
default AddARPNeighborsRequest := false
default AddSwapRequest := false
default CloseStdinRequest := false
default CopyFileRequest := false
default CreateContainerRequest := false
default CreateSandboxRequest := false
default DestroySandboxRequest := true
default ExecProcessRequest := false
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := false
default ListRoutesRequest := false
default MemHotplugByProbeRequest := false
default OnlineCPUMemRequest := true
default PauseContainerRequest := false
default ReadStreamRequest := false
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := false
default ResumeContainerRequest := false
default SetGuestDateTimeRequest := false
default SetPolicyRequest := false
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := false
default StatsContainerRequest := true
default StopTracingRequest := false
default TtyWinResizeRequest := true
default UpdateContainerRequest := false
default UpdateEphemeralMountsRequest := false
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := false

# AllowRequestsFailingPolicy := true configures the Agent to *allow any
# requests causing a policy failure*. This is an unsecure configuration
# but is useful for allowing unsecure pods to start, then connect to
# them and inspect OPA logs for the root cause of a failure.
default AllowRequestsFailingPolicy := false

CreateContainerRequest if {
    i_config := input.config
#     i_storages := input.storages

    ##  print("CreateContainerRequest: i_config.Hooks =", i_config.Hooks)
    # is_null(i_config.Hooks)

   #  print("CreateContainerRequest: i_config.Linux.Seccomp =", i_config.Linux.Seccomp)
    is_null(i_config.Linux.Seccomp)

    some p_container in policy_data.containers
   #  print("======== CreateContainerRequest: trying next policy container")

    p_pidns := p_container.sandbox_pidns
    i_pidns := input.sandbox_pidns
#    #  print("CreateContainerRequest: p_pidns =", p_pidns, "i_pidns =", i_pidns)
    p_pidns == i_pidns

    p_config := p_container.config

   #  print("CreateContainerRequest: p Version =", p_config.Version, "i Version =", i_config.Version)
    # p_config.Version == i_config.Version

   #  print("CreateContainerRequest: p Readonly =", p_config.Root.Readonly, "i Readonly =", i_config.Root.Readonly)
    # p_config.Root.Readonly == i_config.Root.Readonly

    allow_process(p_config, i_config)

    allow_label(p_config, i_config)

    # p_storages := p_container.storages
    # allow_by_anno(p_config, i_config, p_storages, i_storages)
    i_linux := i_config.linux
    p_linux := p_config.linux

    allow_linux(p_linux, i_linux)

   #  print("CreateContainerRequest: true")

   p_sandbox := p_container.sandboxConfig
   i_sandbox := input.sandboxConfig
   allow_sandbox(p_config, i_config)
}

# Reject unexpected labels.
allow_label(_, i_config) if {
   #  print("allow_label 1: start")

    not i_config.labels

   #  print("allow_label 1: true")
}
allow_label(p_oci, i_config) if {
   #  print("allow_label 2: p labels =", p_oci.labels)
   #  print("allow_label 2: i labels =", i_config.labels)

    i_keys := object.keys(i_config.labels)
   #  print("allow_label 2: i keys =", i_keys)

    every i_key in i_keys {
        allow_label_key(i_key, p_oci)
    }

   #  print("allow_label 2: true")
}

allow_label_key(i_key, _) if {
   #  print("allow_label_key 1: i key =", i_key)

    startswith(i_key, "io.kubernetes.")

   #  print("allow_label_key 1: true")
}
allow_label_key(i_key, p_oci) if {
   #  print("allow_label_key 2: i key =", i_key)

    some p_key, _ in p_oci.labels
    p_key == i_key

   #  print("allow_label_key 2: true")
}

# SETH: This io.kubernetes.cri.sandbox-name annotation is not present in the CRI spec.

# Get the value of the "io.kubernetes.cri.sandbox-name" annotation and
# correlate it with other annotations and process fields.
# allow_by_anno(p_oci, i_oci, p_storages, i_storages) {
#    #  print("allow_by_anno 1: start")

#     s_name := "io.kubernetes.cri.sandbox-name"

#     not p_oci.Annotations[s_name]

#     i_s_name := i_oci.Annotations[s_name]
#    #  print("allow_by_anno 1: i_s_name =", i_s_name)

#     allow_by_sandbox_name(p_oci, i_oci, p_storages, i_storages, i_s_name)

#    #  print("allow_by_anno 1: true")
# }
# allow_by_anno(p_oci, i_oci, p_storages, i_storages) {
#    #  print("allow_by_anno 2: start")

#     s_name := "io.kubernetes.cri.sandbox-name"

#     p_s_name := p_oci.Annotations[s_name]
#     i_s_name := i_oci.Annotations[s_name]
#    #  print("allow_by_anno 2: i_s_name =", i_s_name, "p_s_name =", p_s_name)

#     allow_sandbox_name(p_s_name, i_s_name)
#     allow_by_sandbox_name(p_oci, i_oci, p_storages, i_storages, i_s_name)

#    #  print("allow_by_anno 2: true")
# }

# allow_by_sandbox_name(p_oci, i_oci, p_storages, i_storages, s_name) {
#    #  print("allow_by_sandbox_name: start")

#     s_namespace := "io.kubernetes.cri.sandbox-namespace"

#     p_namespace := p_oci.Annotations[s_namespace]
#     i_namespace := i_oci.Annotations[s_namespace]
#    #  print("allow_by_sandbox_name: p_namespace =", p_namespace, "i_namespace =", i_namespace)
#     p_namespace == i_namespace

#     allow_by_container_types(p_oci, i_oci, s_name, p_namespace)
#     allow_by_bundle_or_sandbox_id(p_oci, i_oci, p_storages, i_storages)
#     allow_process(p_oci, i_oci, s_name)

#    #  print("allow_by_sandbox_name: true")
# }

# SETH: Sandbox name is in a different spot in the CRI spec.
# it's at sandboxConfig.metadata.name

# allow_sandbox_name(p_s_name, i_s_name) {
#    #  print("allow_sandbox_name 1: start")

#     p_s_name == i_s_name

#    #  print("allow_sandbox_name 1: true")
# }
# allow_sandbox_name(p_s_name, i_s_name) {
#    #  print("allow_sandbox_name 2: start")

#     # TODO: should generated names be handled differently?
#     contains(p_s_name, "$(generated-name)")

#    #  print("allow_sandbox_name 2: true")
# }

# Check that the "io.kubernetes.cri.container-type" and
# "io.katacontainers.pkg.oci.container_type" annotations designate the
# expected type - either a "sandbox" or a "container". Then, validate
# other annotations based on the actual "sandbox" or "container" value
# from the input container.

# SETH: container type isn't present in the CRI spec. It looks like this is used for differentiating between sandbox  (pause container) and regular container. I don't think this is needed.

# allow_by_container_types(p_oci, i_oci, s_name, s_namespace) {
#    #  print("allow_by_container_types: checking io.kubernetes.cri.container-type")

#     c_type := "io.kubernetes.cri.container-type"

#     p_cri_type := p_oci.Annotations[c_type]
#     i_cri_type := i_oci.Annotations[c_type]
#    #  print("allow_by_container_types: p_cri_type =", p_cri_type, "i_cri_type =", i_cri_type)
#     p_cri_type == i_cri_type

#     allow_by_container_type(i_cri_type, p_oci, i_oci, s_name, s_namespace)

#    #  print("allow_by_container_types: true")
# }

# allow_by_container_type(i_cri_type, p_oci, i_oci, s_name, s_namespace) {
#    #  print("allow_by_container_type 1: i_cri_type =", i_cri_type)
#     i_cri_type == "sandbox"

#     i_kata_type := i_oci.Annotations["io.katacontainers.pkg.oci.container_type"]
#    #  print("allow_by_container_type 1: i_kata_type =", i_kata_type)
#     i_kata_type == "pod_sandbox"

# TODO SETH: See if these functions need to be moved around even though the container type isn't needed.
#     allow_sandbox_container_name(p_oci, i_oci)
#     allow_sandbox_net_namespace(p_oci, i_oci)
#     allow_sandbox_log_directory(p_oci, i_oci, s_name, s_namespace)

#    #  print("allow_by_container_type 1: true")
# }

# allow_by_container_type(i_cri_type, p_oci, i_oci, s_name, s_namespace) {
#    #  print("allow_by_container_type 2: i_cri_type =", i_cri_type)
#     i_cri_type == "container"

#     i_kata_type := i_oci.Annotations["io.katacontainers.pkg.oci.container_type"]
#    #  print("allow_by_container_type 2: i_kata_type =", i_kata_type)
#     i_kata_type == "pod_container"

# TODO SETH: See if these functions need to be moved around even though the container type isn't needed.
#     allow_container_name(p_oci, i_oci)
#     allow_net_namespace(p_oci, i_oci)
#     allow_log_directory(p_oci, i_oci)

#    #  print("allow_by_container_type 2: true")
# }


# SETH: do we need sandbox name?
# "io.kubernetes.cri.container-name" annotation
allow_sandbox_container_name(p_sandbox, i_sandbox) if {
   #  print("allow_sandbox_container_name: start")
    p_sandbox.metadata.name == i_sandbox.metadata.name
    # container_annotation_missing(p_config, i_config, "io.kubernetes.cri.container-name")

   #  print("allow_sandbox_container_name: true")
}

allow_container_name(p_config, i_config) if {
   #  print("allow_container_name: start")
    p_config.metadata.name == i_config.metadata.name
    # allow_container_annotation(p_config, i_config, "io.kubernetes.cri.container-name")

   #  print("allow_container_name: true")
}

# container_annotation_missing(p_oci, i_oci, key) if {
#    #  print("container_annotation_missing:", key)

#     not p_oci.Annotations[key]
#     not i_oci.Annotations[key]

#    #  print("container_annotation_missing: true")
# }

# allow_container_annotation(p_oci, i_oci, key) if {
#    #  print("allow_container_annotation: key =", key)

#     p_value := p_oci.Annotations[key]
#     i_value := i_oci.Annotations[key]
#    #  print("allow_container_annotation: p_value =", p_value, "i_value =", i_value)

#     p_value == i_value

#    #  print("allow_container_annotation: true")
# }

# "nerdctl/network-namespace" annotation
# SETH: it doesn't look like this is in the CRI spec.
# allow_sandbox_net_namespace(p_oci, i_oci) {
#    #  print("allow_sandbox_net_namespace: start")

#     key := "nerdctl/network-namespace"

#     p_namespace := p_oci.Annotations[key]
#     i_namespace := i_oci.Annotations[key]
#    #  print("allow_sandbox_net_namespace: p_namespace =", p_namespace, "i_namespace =", i_namespace)

#     regex.match(p_namespace, i_namespace)

#    #  print("allow_sandbox_net_namespace: true")
# }

# allow_net_namespace(p_oci, i_oci) {
#    #  print("allow_net_namespace: start")

#     key := "nerdctl/network-namespace"

#     not p_oci.Annotations[key]
#     not i_oci.Annotations[key]

#    #  print("allow_net_namespace: true")
# }


# "io.kubernetes.cri.sandbox-log-directory" annotation
allow_sandbox_log_directory(p_sandbox, i_sandbox, s_name, s_namespace) if {
   #  print("allow_sandbox_log_directory: start")

    p_dir := p_sandbox.logDirectory
    regex1 := replace(p_dir, "$(sandbox-name)", s_name)
    regex2 := replace(regex1, "$(sandbox-namespace)", s_namespace)
   #  print("allow_sandbox_log_directory: regex2 =", regex2)

    i_dir := i_sandbox.logDirectory
   #  print("allow_sandbox_log_directory: i_dir =", i_dir)

    regex.match(regex2, i_dir)
   #  print("allow_sandbox_log_directory: true")
}


# SETH: How is this different than allow_sandbox_log_directory
allow_log_directory(p_sandbox, i_sandbox) if {
   #  print("allow_log_directory: start")

    not p_sandbox.logDirectory
    not i_sandbox.logDirectory
   #  print("allow_log_directory: true")
}

# SETH: I don't see namespaces directly but there is NamespaceOptions
allow_linux(p_linux, i_linux) if {
    # TODO SETH: make sure securityContext is not empty
    p_namespaces := p_linux.namespaces
   #  print("allow_linux: p namespaces =", p_namespaces)

    i_namespaces := i_linux.namespaces
   #  print("allow_linux: i namespaces =", i_namespaces)

    p_namespaces == i_namespaces

    allow_masked_paths(p_linux, i_linux)
    allow_readonly_paths(p_linux, i_linux)

   #  print("allow_linux: true")
}

# SETH: This is in a different location, under config.securityContext.maskedPaths
allow_masked_paths(p_linux, i_linux) if {
    p_paths := p_linux.securityContext.maskedPaths
   #  print("allow_masked_paths 1: p_paths =", p_paths)

    i_paths := i_linux.securityContext.maskedPaths
   #  print("allow_masked_paths 1: i_paths =", i_paths)

    allow_masked_paths_array(p_paths, i_paths)

   #  print("allow_masked_paths 1: true")
}
allow_masked_paths(p_linux, i_linux) if {
   #  print("allow_masked_paths 2: start")

    not p_linux.securityContext.maskedPaths
    not i_linux.securityContext.maskedPaths

   #  print("allow_masked_paths 2: true")
}

# All the policy masked paths must be masked in the input data too.
# Input is allowed to have more masked paths than the policy.
allow_masked_paths_array(p_array, i_array) if {
    every p_elem in p_array {
        allow_masked_path(p_elem, i_array)
    }
}

allow_masked_path(p_elem, i_array) if {
   #  print("allow_masked_path: p_elem =", p_elem)

    some i_elem in i_array
    p_elem == i_elem

   #  print("allow_masked_path: true")
}

allow_readonly_paths(p_linux, i_linux) if {
    p_paths := p_linux.securityContext.readonlyPaths
   #  print("allow_readonly_paths 1: p_paths =", p_paths)

    i_paths := i_linux.securityContext.readonlyPaths
   #  print("allow_readonly_paths 1: i_paths =", i_paths)

    allow_readonly_paths_array(p_paths, i_paths, i_linux.securityContext.maskedPaths)

   #  print("allow_readonly_paths 1: true")
}
allow_readonly_paths(p_linux, i_linux) if {
   #  print("allow_readonly_paths 2: start")

    not p_linux.securityContext.readonlyPaths
    not i_linux.securityContext.readonlyPaths

   #  print("allow_readonly_paths 2: true")
}

# All the policy readonly paths must be either:
# - Present in the input readonly paths, or
# - Present in the input masked paths.
# Input is allowed to have more readonly paths than the policy.
allow_readonly_paths_array(p_array, i_array, masked_paths) if {
    every p_elem in p_array {
        allow_readonly_path(p_elem, i_array, masked_paths)
    }
}

allow_readonly_path(p_elem, i_array, _) if {
   #  print("allow_readonly_path 1: p_elem =", p_elem)

    some i_elem in i_array
    p_elem == i_elem

   #  print("allow_readonly_path 1: true")
}
allow_readonly_path(p_elem, _, masked_paths) if {
   #  print("allow_readonly_path 2: p_elem =", p_elem)

    some i_masked in masked_paths
    p_elem == i_masked

   #  print("allow_readonly_path 2: true")
}

# SETH: I don't see bundle, but sandbox ID is present
# Check the consistency of the input "io.katacontainers.pkg.oci.bundle_path"
# and io.kubernetes.cri.sandbox-id" values with other fields.
allow_by_bundle_or_sandbox_id(p_oci, i_oci, p_storages, i_storages) if {
   #  print("allow_by_bundle_or_sandbox_id: start")

    bundle_path := i_oci.Annotations["io.katacontainers.pkg.oci.bundle_path"]
    bundle_id := replace(bundle_path, "/run/containerd/io.containerd.runtime.v2.task/k8s.io/", "")

    key := "io.kubernetes.cri.sandbox-id"

    p_regex := p_oci.Annotations[key]
    sandbox_id := i_oci.Annotations[key]

   #  print("allow_by_bundle_or_sandbox_id: sandbox_id =", sandbox_id, "regex =", p_regex)
    regex.match(p_regex, sandbox_id)

    allow_root_path(p_oci, i_oci, bundle_id)

    every i_mount in input.OCI.Mounts {
        allow_mount(p_oci, i_mount, bundle_id, sandbox_id)
    }

    allow_storages(p_storages, i_storages, bundle_id, sandbox_id)

   #  print("allow_by_bundle_or_sandbox_id: true")
}


#####################################################
# PROCESSES
#####################################################

# SETH: I don't see process, but I do see command
allow_process(p_config, i_config, s_name) if {

   #  print("allow_process: i terminal =", i_process.terminal, "p terminal =", p_process.terminal)
    # p_process.terminal == i_process.terminal

    # print("allow_process: i cwd =", i_process.Cwd, "i cwd =", p_process.Cwd)
    # p_process.Cwd == i_process.Cwd

    # print("allow_process: i noNewPrivileges =", i_process.no_new_privileges, "p noNewPrivileges =", p_process.no_new_privileges)
    # p_process.no_new_privileges == i_process.no_new_privileges

    # SETH: all of these are used in the CRI spec, caps and user are in securityContext
    # TODO SETH: args and env should be done, caps and user are still tbd
    allow_caps(p_config.Capabilities, i_config.Capabilities)
    allow_user(p_config, i_config)
    allow_args(p_config, i_config, s_name)
    allow_env(p_config, i_config, s_name)

   #  print("allow_config: true")
}

# SETH: I see runAsUser for the container, not for a process

allow_user(p_config, i_config) if {
    p_user := p_config.user
    i_user := i_config.user

   #  print("allow_user: input uid =", i_user.UID, "policy uid =", p_user.UID)
    p_user.UID == i_user.UID

    # TODO: track down the reason for registry.k8s.io/pause:3.9 being
    #       executed with gid = 0 despite having "65535:65535" in its container image
    #       config.
    #print("allow_user: input gid =", i_user.GID, "policy gid =", p_user.GID)
    #p_user.GID == i_user.GID

    # TODO: compare the additionalGids field too after computing its value
    # based on /etc/passwd and /etc/group from the container image.
}

#####################################################
# ARGS
#####################################################

allow_args(p_config, i_config, _) if {
   #  print("allow_args 1: no args")

    not p_config.command
    not i_config.command

   #  print("allow_args 1: true")
}
allow_args(p_config, i_config, s_name) if {
   #  print("allow_args 2: policy args =", p_config.args)
   #  print("allow_args 2: input args =", i_config.args)

    count(p_config.command) == count(i_config.command)

    every i, i_arg in i_config.command {
        allow_arg(i, i_arg, p_config, s_name)
    }

   #  print("allow_args 2: true")
}
allow_arg(i, i_arg, p_config, _) if {
    p_arg := p_config.command[i]
   #  print("allow_arg 1: i =", i, "i_arg =", i_arg, "p_arg =", p_arg)

    p_arg2 := replace(p_arg, "$$", "$")
    p_arg2 == i_arg

   #  print("allow_arg 1: true")
}

# TODO SETH: not sure if these 2 below are needed. can you have node-name or sandbox-name in the args?
allow_arg(i, _, p_config, _) if {
    p_arg := p_config.command[i]
   #  print("allow_arg 2: i =", i, "i_arg =", i_arg, "p_arg =", p_arg)

    # TODO: can $(node-name) be handled better?
    contains(p_arg, "$(node-name)")

   #  print("allow_arg 2: true")
}
allow_arg(i, i_arg, p_config, s_name) if {
    p_arg := p_config.command[i]
   #  print("allow_arg 3: i =", i, "i_arg =", i_arg, "p_arg =", p_arg)

    p_arg2 := replace(p_arg, "$$", "$")
    p_arg3 := replace(p_arg2, "$(sandbox-name)", s_name)
   #  print("allow_arg 3: p_arg3 =", p_arg3)
    p_arg3 == i_arg

   #  print("allow_arg 3: true")
}

#####################################################
# ENVIRONMENT VARIABLES
#####################################################

# OCI process.envs field, s-name is sandbox name
allow_env(p_container, i_container, s_name) if {
   #  print("allow_env: p env =", p_container.Env)
   #  print("allow_env: i env =", i_container.Env)

    every i_var in i_container.envs {
       #  print("allow_env: i_var =", i_var)
        allow_var(p_container, i_container, i_var, s_name)
    }

   #  print("allow_env: true")
}

# Allow input env variables that are present in the policy data too.
allow_var(p_container, _, i_var, _) if {
    some p_var in p_container.envs
    p_var == i_var
   #  print("allow_var 1: true")
}

# TODO SETH: I don't think we need this overload of the function. it doesn't look like sandbox-name shows up in the env vars
# Match input with one of the policy variables, after substituting $(sandbox-name).
# allow_var(p_container, _, i_var, s_name) if {
#     some p_var in p_container.envs
#     p_var2 := replace(p_var, "$(sandbox-name)", s_name)

#    #  print("allow_var 2: p_var2 =", p_var2)
#     p_var2 == i_var

#    #  print("allow_var 2: true")
# }

# Allow input env variables that match with a request_defaults regex.
allow_var(_, _, i_var, _) if {
    some p_regex1 in policy_data.request_defaults.CreateContainerRequest.allow_env_regex
    p_regex2 := replace(p_regex1, "$(ipv4_a)", policy_data.common.ipv4_a)
    p_regex3 := replace(p_regex2, "$(ip_p)", policy_data.common.ip_p)
    p_regex4 := replace(p_regex3, "$(svc_name)", policy_data.common.svc_name)
    p_regex5 := replace(p_regex4, "$(dns_label)", policy_data.common.dns_label)

#    #  print("allow_var 3: p_regex5 =", p_regex5)
    regex.match(p_regex5, i_var)

   #  print("allow_var 3: true")
}

# Allow fieldRef "fieldPath: status.podIP" values.
allow_var(p_container, _, i_var, _) if {
    name_value := i_var.value
    is_ip(name_value)

    some p_var in p_container.envs
    allow_pod_ip_var(name_value, p_var)

   #  print("allow_var 4: true")
}

# Allow common fieldRef variables.
allow_var(p_container, _, i_var, _) if {
    name_value := i_var.name

    some p_var in p_container.envs
    p_name_value := p_var.value
    p_name_value == name_value

    # TODO: should these be handled in a different way?
    always_allowed := ["$(host-name)", "$(node-name)", "$(pod-uid)"]
    some allowed in always_allowed
    contains(p_name_value, allowed)

   #  print("allow_var 5: true")
}

# Allow fieldRef "fieldPath: status.hostIP" values.
allow_var(p_container, _, i_var, _) if {
    name_value := i_var.name
    is_ip(name_value)

    some p_var in p_container.envs
    allow_host_ip_var(name_value, p_var)

   #  print("allow_var 6: true")
}

# Allow resourceFieldRef values (e.g., "limits.cpu").
allow_var(p_container, _, i_var, _) if {
    name_value := i_var.name

    some p_var in p_container.envs
    p_name_value := p_var.value
    p_name_value == name_value

    # TODO: should these be handled in a different way?
    always_allowed = ["$(resource-field)", "$(todo-annotation)"]
    some allowed in always_allowed
    contains(p_name_value, allowed)

   #  print("allow_var 7: true")
}

#####################################################
# IP ADDRESSES
#####################################################

# SETH: these look the same as OCI if they're needed (probably are)
allow_pod_ip_var(var_name, p_var) if {
   #  print("allow_pod_ip_var: var_name =", var_name, "p_var =", p_var)

    p_var.key == var_name
    p_var.value == "$(pod-ip)"

   #  print("allow_pod_ip_var: true")
}

allow_host_ip_var(var_name, p_var) if {
   #  print("allow_host_ip_var: var_name =", var_name, "p_var =", p_var)

    p_var.key == var_name
    p_var.value == "$(host-ip)"

   #  print("allow_host_ip_var: true")
}

is_ip(value) if {
    bytes = split(value, ".")
    count(bytes) == 4

    is_ip_first_byte(bytes[0])
    is_ip_other_byte(bytes[1])
    is_ip_other_byte(bytes[2])
    is_ip_other_byte(bytes[3])
}
is_ip_first_byte(component) if {
    number = to_number(component)
    number >= 1
    number <= 255
}
is_ip_other_byte(component) if {
    number = to_number(component)
    number >= 0
    number <= 255
}

# TODO SETH: I don't think root path is needed
# OCI root.Path
# allow_root_path(p_oci, i_oci, bundle_id) if {
#     i_path := i_oci.Root.Path
#     p_path1 := p_oci.Root.Path
#    #  print("allow_root_path: i_path =", i_path, "p_path1 =", p_path1)

#     p_path2 := replace(p_path1, "$(cpath)", policy_data.common.cpath)
# #    #  print("allow_root_path: p_path2 =", p_path2)

#     p_path3 := replace(p_path2, "$(bundle-id)", bundle_id)
#    #  print("allow_root_path: p_path3 =", p_path3)

#     p_path3 == i_path

#    #  print("allow_root_path: true")
# }

#####################################################
# MOUNTS - DONE
#####################################################

# OCI Mount:
# {
#   "destination": "/var/run/secrets/kubernetes.io/serviceaccount",
#   "source": "$(sfprefix)serviceaccount$",
#   "type_": "bind",
#   "options": [
#     "rbind",
#     "rprivate",
#     "ro"
#   ]
# },

# CRI Mount:
# {
#   "containerPath": "/var/run/secrets/kubernetes.io/serviceaccount",
#   "hostPath": "/var/lib/kubelet/pods/1339872b-4273-4ca3-b975-0a1d3bb32c7e/volumes/kubernetes.io~projected/kube-api-access-s4nnl",
#   "readonly": true
#},
# device mounts
allow_mount(p_oci, i_mount, bundle_id, sandbox_id) if {
   #  print("allow_mount: i_mount =", i_mount)

    some p_mount in p_oci.Mounts
   #  print("allow_mount: p_mount =", p_mount)
    check_mount(p_mount, i_mount, bundle_id, sandbox_id)

    # TODO: are there any other required policy checks for mounts - e.g.,
    #       multiple mounts with same source or destination?

   #  print("allow_mount: true")
}

check_mount(p_mount, i_mount, _, _) if {
    p_mount == i_mount
   #  print("check_mount 1: true")
}
check_mount(p_mount, i_mount, bundle_id, sandbox_id) if {
    p_mount.containerPath == i_mount.containerPath
    p_mount.readonly == i_mount.readonly

    mount_source_allows(p_mount, i_mount, bundle_id, sandbox_id)

   #  print("check_mount 2: true")
}

# TODO SETH: Can this be combined with the one below it? only regex4 is different
mount_source_allows(p_mount, i_mount, bundle_id, _) if {
    regex1 := p_mount.hostPath
    regex2 := replace(regex1, "$(sfprefix)", policy_data.common.sfprefix)
    regex3 := replace(regex2, "$(cpath)", policy_data.common.cpath)
    regex4 := replace(regex3, "$(bundle-id)", bundle_id)

#    #  print("mount_source_allows 1: regex4 =", regex4)
    regex.match(regex4, i_mount.hostPath)

   #  print("mount_source_allows 1: true")
}
mount_source_allows(p_mount, i_mount, _, sandbox_id) if {
    regex1 := p_mount.hostPath
    regex2 := replace(regex1, "$(sfprefix)", policy_data.common.sfprefix)
    regex3 := replace(regex2, "$(cpath)", policy_data.common.cpath)
    regex4 := replace(regex3, "$(sandbox-id)", sandbox_id)

#    #  print("mount_source_allows 2: regex4 =", regex4)
    regex.match(regex4, i_mount.hostPath)

   #  print("mount_source_allows 2: true")
}
mount_source_allows(p_mount, i_mount, _, _) if {
   #  print("mount_source_allows 3: i_mount.hostPath=", i_mount.hostPath)

    i_source_parts = split(i_mount.hostPath, "/")
    b64_direct_vol_path = i_source_parts[count(i_source_parts) - 1]

    base64.is_valid(b64_direct_vol_path)

    source1 := p_mount.hostPath
   #  print("mount_source_allows 3: source1 =", source1)

    source2 := replace(source1, "$(spath)", policy_data.common.spath)
#    #  print("mount_source_allows 3: source2 =", source2)

    source3 := replace(source2, "$(b64-direct-vol-path)", b64_direct_vol_path)
   #  print("mount_source_allows 3: source3 =", source3)

    source3 == i_mount.hostPath

   #  print("mount_source_allows 3: true")
}

######################################################################
# Create container Storages
######################################################################
# SETH: I don't see storages, but I do see volumes
allow_storages(p_storages, i_storages, bundle_id, sandbox_id) if {
    p_count := count(p_storages)
    i_count := count(i_storages)
   #  print("allow_storages: p_count =", p_count, "i_count =", i_count)

    p_count == i_count

    # Get the container image layer IDs and verity root hashes, from the "overlayfs" storage.
    some overlay_storage in p_storages
    overlay_storage.driver == "overlayfs"
   #  print("allow_storages: overlay_storage =", overlay_storage)
    count(overlay_storage.options) == 2

    layer_ids := split(overlay_storage.options[0], ":")
   #  print("allow_storages: layer_ids =", layer_ids)

    root_hashes := split(overlay_storage.options[1], ":")
   #  print("allow_storages: root_hashes =", root_hashes)

    every i_storage in i_storages {
        allow_storage(p_storages, i_storage, bundle_id, sandbox_id, layer_ids, root_hashes)
    }

   #  print("allow_storages: true")
}

allow_storage(p_storages, i_storage, bundle_id, sandbox_id, layer_ids, root_hashes) if {
    some p_storage in p_storages

   #  print("allow_storage: p_storage =", p_storage)
   #  print("allow_storage: i_storage =", i_storage)

    p_storage.driver           == i_storage.driver
    p_storage.driver_options   == i_storage.driver_options
    p_storage.fs_group         == i_storage.fs_group

    allow_storage_options(p_storage, i_storage, layer_ids, root_hashes)
    allow_mount_point(p_storage, i_storage, bundle_id, sandbox_id, layer_ids)

    # TODO: validate the source field too.

   #  print("allow_storage: true")
}

allow_storage_options(p_storage, i_storage, _, _) if {
   #  print("allow_storage_options 1: start")

    p_storage.driver != "overlayfs"
    p_storage.options == i_storage.options

   #  print("allow_storage_options 1: true")
}
allow_storage_options(p_storage, i_storage, layer_ids, _) if {
   #  print("allow_storage_options 2: start")

    p_storage.driver == "overlayfs"
    count(p_storage.options) == 2

    policy_ids := split(p_storage.options[0], ":")
   #  print("allow_storage_options 2: policy_ids =", policy_ids)
    policy_ids == layer_ids

    policy_hashes := split(p_storage.options[1], ":")
   #  print("allow_storage_options 2: policy_hashes =", policy_hashes)

    p_count := count(policy_ids)
   #  print("allow_storage_options 2: p_count =", p_count)
    p_count >= 1
    p_count == count(policy_hashes)

    i_count := count(i_storage.options)
   #  print("allow_storage_options 2: i_count =", i_count)
    i_count == p_count + 3

   #  print("allow_storage_options 2: i_storage.options[0] =", i_storage.options[0])
    i_storage.options[0] == "io.katacontainers.fs-opt.layer-src-prefix=/var/lib/containerd/io.containerd.snapshotter.v1.tardev/layers"

   #  print("allow_storage_options 2: i_storage.options[i_count - 2] =", i_storage.options[i_count - 2])
    i_storage.options[i_count - 2] == "io.katacontainers.fs-opt.overlay-rw"

    lowerdir := concat("=", ["lowerdir", p_storage.options[0]])
   #  print("allow_storage_options 2: lowerdir =", lowerdir)

   #  print("allow_storage_options 2: i_storage.options[i_count - 1] =", i_storage.options[i_count - 1])
    i_storage.options[i_count - 1] == lowerdir

    every i, policy_id in policy_ids {
        allow_overlay_layer(policy_id, policy_hashes[i], i_storage.options[i + 1])
    }

   #  print("allow_storage_options 2: true")
}
allow_storage_options(p_storage, i_storage, _, root_hashes) if {
   #  print("allow_storage_options 3: start")

    p_storage.driver == "blk"
    count(p_storage.options) == 1

    startswith(p_storage.options[0], "$(hash")
    hash_suffix := trim_left(p_storage.options[0], "$(hash")

    endswith(hash_suffix, ")")
    hash_index := trim_right(hash_suffix, ")")
    i := to_number(hash_index)
   #  print("allow_storage_options 3: i =", i)

    hash_option := concat("=", ["io.katacontainers.fs-opt.root-hash", root_hashes[i]])
   #  print("allow_storage_options 3: hash_option =", hash_option)

    count(i_storage.options) == 4
    i_storage.options[0] == "ro"
    i_storage.options[1] == "io.katacontainers.fs-opt.block_device=file"
    i_storage.options[2] == "io.katacontainers.fs-opt.is-layer"
    i_storage.options[3] == hash_option

   #  print("allow_storage_options 3: true")
}
allow_storage_options(p_storage, i_storage, _, _) if {
   #  print("allow_storage_options 4: start")

    p_storage.driver == "smb"
    count(i_storage.options) == 8
    i_storage.options[0] == "dir_mode=0666"
    i_storage.options[1] == "file_mode=0666"
    i_storage.options[2] == "mfsymlinks"
    i_storage.options[3] == "cache=strict"
    i_storage.options[4] == "nosharesock"
    i_storage.options[5] == "actimeo=30"
    startswith(i_storage.options[6], "addr=")
    creds = split(i_storage.options[7], ",")
    count(creds) == 2
    startswith(creds[0], "username=")
    startswith(creds[1], "password=")

   #  print("allow_storage_options 4: true")
}

######################################################################
# OVERLAY LAYERS
######################################################################

# allow_overlay_layer(policy_id, policy_hash, i_option) if {
#    #  print("allow_overlay_layer: policy_id =", policy_id, "policy_hash =", policy_hash)
#    #  print("allow_overlay_layer: i_option =", i_option)
#
#     startswith(i_option, "io.katacontainers.fs-opt.layer=")
#     i_value := replace(i_option, "io.katacontainers.fs-opt.layer=", "")
#     i_value_decoded := base64.decode(i_value)
#    #  print("allow_overlay_layer: i_value_decoded =", i_value_decoded)
#
#     policy_suffix := concat("=", ["tar,ro,io.katacontainers.fs-opt.block_device=file,io.katacontainers.fs-opt.is-layer,io.katacontainers.fs-opt.root-hash", policy_hash])
#     p_value := concat(",", [policy_id, policy_suffix])
#    #  print("allow_overlay_layer: p_value =", p_value)
#
#     p_value == i_value_decoded
#
#    #  print("allow_overlay_layer: true")
# }
#
# allow_mount_point(p_storage, i_storage, _, _, layer_ids) if {
#     p_storage.fstype == "tar"
#
#     startswith(p_storage.mount_point, "$(layer")
#     mount_suffix := trim_left(p_storage.mount_point, "$(layer")
#
#     endswith(mount_suffix, ")")
#     layer_index := trim_right(mount_suffix, ")")
#     i := to_number(layer_index)
#    #  print("allow_mount_point 1: i =", i)
#
#     layer_id := layer_ids[i]
#    #  print("allow_mount_point 1: layer_id =", layer_id)
#
#     p_mount := concat("/", ["/run/kata-containers/sandbox/layers", layer_id])
#    #  print("allow_mount_point 1: p_mount =", p_mount)
#
#     p_mount == i_storage.mount_point
#
#    #  print("allow_mount_point 1: true")
# }
# allow_mount_point(p_storage, i_storage, bundle_id, _, _) if {
#     p_storage.fstype == "fuse3.kata-overlay"
#
#     mount1 := replace(p_storage.mount_point, "$(cpath)", policy_data.common.cpath)
#     mount2 := replace(mount1, "$(bundle-id)", bundle_id)
# #    #  print("allow_mount_point 2: mount2 =", mount2)
#
#     mount2 == i_storage.mount_point
#
#    #  print("allow_mount_point 2: true")
# }
# allow_mount_point(p_storage, i_storage, _, sandbox_id, _) if {
#     p_storage.fstype == "local"
#
#     mount1 := p_storage.mount_point
#    #  print("allow_mount_point 3: mount1 =", mount1)
#
#     mount2 := replace(mount1, "$(cpath)", policy_data.common.cpath)
# #    #  print("allow_mount_point 3: mount2 =", mount2)
#
#     mount3 := replace(mount2, "$(sandbox-id)", sandbox_id)
#    #  print("allow_mount_point 3: mount3 =", mount3)
#
#     regex.match(mount3, i_storage.mount_point)
#
#    #  print("allow_mount_point 3: true")
# }
# allow_mount_point(p_storage, i_storage, bundle_id, _, _) if {
#     p_storage.fstype == "bind"
#
#     mount1 := p_storage.mount_point
#    #  print("allow_mount_point 4: mount1 =", mount1)
#
#     mount2 := replace(mount1, "$(cpath)", policy_data.common.cpath)
# #    #  print("allow_mount_point 4: mount2 =", mount2)
#
#     mount3 := replace(mount2, "$(bundle-id)", bundle_id)
#    #  print("allow_mount_point 4: mount3 =", mount3)
#
#     regex.match(mount3, i_storage.mount_point)
#
#    #  print("allow_mount_point 4: true")
# }
# allow_mount_point(p_storage, i_storage, _, _, _) if {
#     p_storage.fstype == "tmpfs"
#
#     mount1 := p_storage.mount_point
#    #  print("allow_mount_point 5: mount1 =", mount1)
#
#     regex.match(mount1, i_storage.mount_point)
#
#    #  print("allow_mount_point 5: true")
# }
# allow_mount_point(p_storage, i_storage, _, _, _) if {
#    #  print("allow_mount_point 6: i_storage.mount_point =", i_storage.mount_point)
#     allow_direct_vol_driver(p_storage, i_storage)
#
#     mount1 := p_storage.mount_point
#    #  print("allow_mount_point 6: mount1 =", mount1)
#
#     mount2 := replace(mount1, "$(spath)", policy_data.common.spath)
# #    #  print("allow_mount_point 6: mount2 =", mount2)
#
#     direct_vol_path := i_storage.source
#     mount3 := replace(mount2, "$(b64-direct-vol-path)", base64url.encode(direct_vol_path))
#    #  print("allow_mount_point 6: mount3 =", mount3)
#
#     mount3 == i_storage.mount_point
#
#    #  print("allow_mount_point 6: true")
# }
#
# allow_direct_vol_driver(p_storage, _) if {
#    #  print("allow_direct_vol_driver 1: start")
#     p_storage.driver == "blk"
#    #  print("allow_direct_vol_driver 1: true")
# }
# allow_direct_vol_driver(p_storage, _) if {
#    #  print("allow_direct_vol_driver 2: start")
#     p_storage.driver == "smb"
#    #  print("allow_direct_vol_driver 2: true")
# }

######################################################################
# CAPABILITIES
######################################################################

# process.Capabilities
allow_caps(p_caps, i_caps) if {
   #  print("allow_caps: policy ambient =", p_caps.ambient)
   #  print("allow_caps: input ambient =", i_caps.ambient)
    match_caps(p_caps.ambient, i_caps.ambient)

   #  print("allow_caps: policy bounding =", p_caps.bounding)
   #  print("allow_caps: input bounding =", i_caps.bounding)
    match_caps(p_caps.bounding, i_caps.bounding)

   #  print("allow_caps: policy effective =", p_caps.effective)
   #  print("allow_caps: input effective =", i_caps.effective)
    match_caps(p_caps.effective, i_caps.effective)

   #  print("allow_caps: policy inheritable =", p_caps.inheritable)
   #  print("allow_caps: input inheritable =", i_caps.inheritable)
    match_caps(p_caps.inheritable, i_caps.inheritable)

   #  print("allow_caps: policy permitted =", p_caps.permitted)
   #  print("allow_caps: input permitted =", i_caps.permitted)
    match_caps(p_caps.permitted, i_caps.permitted)
}

match_caps(p_caps, i_caps) if {
   #  print("match_caps 1: start")

    p_caps == i_caps

   #  print("match_caps 1: true")
}
match_caps(p_caps, i_caps) if {
   #  print("match_caps 2: start")

    count(p_caps) == 1
    p_caps[0] == "$(default_caps)"

   #  print("match_caps 2: default_caps =", policy_data.common.default_caps)
    policy_data.common.default_caps == i_caps

   #  print("match_caps 2: true")
}
match_caps(p_caps, i_caps) if {
   #  print("match_caps 3: start")

    count(p_caps) == 1
    p_caps[0] == "$(privileged_caps)"

   #  print("match_caps 3: privileged_caps =", policy_data.common.privileged_caps)
    policy_data.common.privileged_caps == i_caps

   #  print("match_caps 3: true")
}

######################################################################
check_directory_traversal(i_path) if {
    contains(i_path, "../") == false
    endswith(i_path, "/..") == false
    i_path != ".."
}

check_symlink_source if {
    # TODO: delete this rule once the symlink_src field gets implemented
    # by all/most Guest VMs.
    not input.symlink_src
}
check_symlink_source if {
    i_src := input.symlink_src
   #  print("check_symlink_source: i_src =", i_src)

    startswith(i_src, "/") == false
    check_directory_traversal(i_src)
}

######################################################################
# SANDBOX STORAGES
######################################################################

allow_sandbox_storages(i_storages) if {
   #  print("allow_sandbox_storages: i_storages =", i_storages)

    p_storages := policy_data.sandbox.storages
    every i_storage in i_storages {
        allow_sandbox_storage(p_storages, i_storage)
    }

   #  print("allow_sandbox_storages: true")
}

allow_sandbox_storage(p_storages, i_storage) if {
   #  print("allow_sandbox_storage: i_storage =", i_storage)

    some p_storage in p_storages
   #  print("allow_sandbox_storage: p_storage =", p_storage)
    i_storage == p_storage

   #  print("allow_sandbox_storage: true")
}

######################################################################
# REQUESTS
######################################################################
# SETH: don't worry about requests other than CreateContainer for now

# CopyFileRequest {
#    #  print("CopyFileRequest: input.path =", input.path)
#
#     check_symlink_source
#     check_directory_traversal(input.path)
#
#     some regex1 in policy_data.request_defaults.CopyFileRequest
#     regex2 := replace(regex1, "$(sfprefix)", policy_data.common.sfprefix)
#     regex3 := replace(regex2, "$(cpath)", policy_data.common.cpath)
#     regex4 := replace(regex3, "$(bundle-id)", "[a-z0-9]{64}")
#    #  print("CopyFileRequest: regex4 =", regex4)
#
#     regex.match(regex4, input.path)
#
#    #  print("CopyFileRequest: true")
# }
#
# CreateSandboxRequest {
#    #  print("CreateSandboxRequest: input.guest_hook_path =", input.guest_hook_path)
#     count(input.guest_hook_path) == 0
#
#    #  print("CreateSandboxRequest: input.kernel_modules =", input.kernel_modules)
#     count(input.kernel_modules) == 0
#
#     i_pidns := input.sandbox_pidns
#    #  print("CreateSandboxRequest: i_pidns =", i_pidns)
#     i_pidns == false
#
#     allow_sandbox_storages(input.storages)
# }
#
# ExecProcessRequest {
#    #  print("ExecProcessRequest 1: input =", input)
#
#     i_command = concat(" ", input.process.Args)
#    #  print("ExecProcessRequest 1: i_command =", i_command)
#
#     some p_command in policy_data.request_defaults.ExecProcessRequest.commands
#    #  print("ExecProcessRequest 1: p_command =", p_command)
#     p_command == i_command
#
#    #  print("ExecProcessRequest 1: true")
# }
# ExecProcessRequest {
#    #  print("ExecProcessRequest 2: input =", input)
#
#     # TODO: match input container ID with its corresponding container.exec_commands.
#     i_command = concat(" ", input.process.Args)
#    #  print("ExecProcessRequest 3: i_command =", i_command)
#
#     some container in policy_data.containers
#     some p_command in container.exec_commands
#    #  print("ExecProcessRequest 2: p_command =", p_command)
#
#     # TODO: should other input data fields be validated as well?
#     p_command == i_command
#
#    #  print("ExecProcessRequest 2: true")
# }
# ExecProcessRequest {
#    #  print("ExecProcessRequest 3: input =", input)
#
#     i_command = concat(" ", input.process.Args)
#    #  print("ExecProcessRequest 3: i_command =", i_command)
#
#     some p_regex in policy_data.request_defaults.ExecProcessRequest.regex
#    #  print("ExecProcessRequest 3: p_regex =", p_regex)
#
#     regex.match(p_regex, i_command)
#
#    #  print("ExecProcessRequest 3: true")
# }
#
# CloseStdinRequest {
#     policy_data.request_defaults.CloseStdinRequest == true
# }
#
# ReadStreamRequest {
#     policy_data.request_defaults.ReadStreamRequest == true
# }
#
# UpdateEphemeralMountsRequest {
#     policy_data.request_defaults.UpdateEphemeralMountsRequest == true
# }
#
# WriteStreamRequest {
#     policy_data.request_defaults.WriteStreamRequest == true
# }


