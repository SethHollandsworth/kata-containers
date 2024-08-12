// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::policy;
use crate::policy::KeyValueEnvVar;

// Default process field from containerd.
// pub fn get_process(privileged_container: bool, common: &policy::CommonData) -> policy::KataProcess {
pub fn get_process() -> policy::KataProcess {
    // pub fn get_process(common: &policy::CommonData) -> policy::KataProcess {
    // let capabilities = if privileged_container {
    //     policy::KataLinuxCapabilities {
    //         ambient: vec![],
    //         bounding: common.privileged_caps.clone(),
    //         effective: common.privileged_caps.clone(),
    //         inheritable: vec![],
    //         permitted: common.privileged_caps.clone(),
    //     }
    // } else {
    //     policy::KataLinuxCapabilities {
    //         ambient: vec![],
    //         bounding: common.default_caps.clone(),
    //         effective: common.default_caps.clone(),
    //         inheritable: vec![],
    //         permitted: common.default_caps.clone(),
    //     }
    // };

    policy::KataProcess {
        terminal: false,
        // user: Default::default(),
        args: Vec::new(),
        // env: Vec::new(),
        envs: Vec::new(),
        cwd: "/".to_string(),
        // capabilities: capabilities,
        no_new_privileges: false,
    }
}

// Default mounts field from containerd.
// pub fn get_mounts(is_pause_container: bool, privileged_container: bool) -> Vec<policy::KataMount> {
// pub fn get_mounts(_privileged_container: bool) -> Vec<policy::KataMount> {
    // let sysfs_read_write_option = if privileged_container { "rw" } else { "ro" };

    // let mounts = vec![
        // policy::KataMount {
        //     containerPath: "/proc".to_string(),
        //     type_: "proc".to_string(),
        //     source: "proc".to_string(),
        //     options: vec![
        //         "nosuid".to_string(),
        //         "noexec".to_string(),
        //         "nodev".to_string(),
        //     ],
        // },
        // policy::KataMount {
        //     containerPath: "/dev".to_string(),
        //     type_: "tmpfs".to_string(),
        //     source: "tmpfs".to_string(),
        //     options: vec![
        //         "nosuid".to_string(),
        //         "strictatime".to_string(),
        //         "mode=755".to_string(),
        //         "size=65536k".to_string(),
        //     ],
        // },
        // policy::KataMount {
        //     destination: "/dev/pts".to_string(),
        //     type_: "devpts".to_string(),
        //     source: "devpts".to_string(),
        //     options: vec![
        //         "nosuid".to_string(),
        //         "noexec".to_string(),
        //         "newinstance".to_string(),
        //         "ptmxmode=0666".to_string(),
        //         "mode=0620".to_string(),
        //         "gid=5".to_string(),
        //     ],
        // },
        // policy::KataMount {
        //     destination: "/dev/shm".to_string(),
        //     type_: "tmpfs".to_string(),
        //     source: "shm".to_string(),
        //     options: vec![
        //         "nosuid".to_string(),
        //         "noexec".to_string(),
        //         "nodev".to_string(),
        //         "mode=1777".to_string(),
        //         "size=65536k".to_string(),
        //     ],
        // },
        // policy::KataMount {
        //     destination: "/dev/mqueue".to_string(),
        //     type_: "mqueue".to_string(),
        //     source: "mqueue".to_string(),
        //     options: vec![
        //         "nosuid".to_string(),
        //         "noexec".to_string(),
        //         "nodev".to_string(),
        //     ],
        // },
        // policy::KataMount {
        //     destination: "/sys".to_string(),
        //     type_: "sysfs".to_string(),
        //     source: "sysfs".to_string(),
        //     options: vec![
        //         "nosuid".to_string(),
        //         "noexec".to_string(),
        //         "nodev".to_string(),
        //         sysfs_read_write_option.to_string(),
        //     ],
        // },
    // ];

    // if !is_pause_container {
    //     mounts.push(policy::KataMount {
    //         destination: "/sys/fs/cgroup".to_string(),
    //         type_: "cgroup".to_string(),
    //         source: "cgroup".to_string(),
    //         options: vec![
    //             "nosuid".to_string(),
    //             "noexec".to_string(),
    //             "nodev".to_string(),
    //             "relatime".to_string(),
    //             sysfs_read_write_option.to_string(),
    //         ],
    //     });
    // }

    // mounts.push(policy::KataMount {
    //     destination: "/sys/fs/cgroup".to_string(),
    //     type_: "cgroup".to_string(),
    //     source: "cgroup".to_string(),
    //     options: vec![
    //         "nosuid".to_string(),
    //         "noexec".to_string(),
    //         "nodev".to_string(),
    //         "relatime".to_string(),
    //         sysfs_read_write_option.to_string(),
    //     ],
    // });

    // mounts
// }

// Default policy::KataLinux field from containerd.
pub fn get_linux(privileged_container: bool) -> policy::KataLinux {
    if !privileged_container {
        policy::KataLinux {
            security_context: policy::SecurityContext {
                run_as_group: 0,
                run_as_user: 0,
                run_as_nonroot: true,
                masked_paths: vec![
                    "/proc/asound".to_string(),
                    "/proc/acpi".to_string(),
                    "/proc/kcore".to_string(),
                    "/proc/keys".to_string(),
                    "/proc/latency_stats".to_string(),
                    "/proc/timer_list".to_string(),
                    "/proc/timer_stats".to_string(),
                    "/proc/sched_debug".to_string(),
                    "/proc/scsi".to_string(),
                    "/sys/firmware".to_string(),
                ],
                readonly_paths: vec![
                    "/proc/bus".to_string(),
                    "/proc/fs".to_string(),
                    "/proc/irq".to_string(),
                    "/proc/sys".to_string(),
                    "/proc/sysrq-trigger".to_string(),
                ],
            },
            // namespaces: vec![],
        }
    } else {
        policy::KataLinux {
            security_context: policy::SecurityContext {
                masked_paths: vec![],
                readonly_paths: vec![],
                run_as_group: 0,
                run_as_user: 0,
                run_as_nonroot: true,
            },
            // namespaces: vec![],
        }
    }
}

pub fn get_default_unix_env(envs: &mut Vec<KeyValueEnvVar>) {
    assert!(envs.is_empty());

    // Return the value of defaultUnixEnv from containerd.
    envs.push(KeyValueEnvVar {
        key: "PATH".to_string(),
        value: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    });
}
