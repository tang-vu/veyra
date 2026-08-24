#![no_main]

use std::fmt::Write;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use veyra_policy::resource_covers;
use veyra_protocol::ResourceScope;

#[derive(Arbitrary, Debug)]
struct ScopeInput {
    granted: Vec<u8>,
    child: Vec<u8>,
    raw: String,
}

fn clean_segment(bytes: &[u8]) -> String {
    let mut segment = String::with_capacity(bytes.len().saturating_mul(2).max(1));
    for byte in bytes {
        write!(segment, "{byte:02x}").unwrap();
    }
    if segment.is_empty() {
        segment.push('0');
    }
    segment
}

fuzz_target!(|input: ScopeInput| {
    let granted_segment = clean_segment(&input.granted);
    let child_segment = clean_segment(&input.child);
    let workspace = format!("workspace-{granted_segment}");
    let granted_path = format!("safe/{granted_segment}");
    let child_path = format!("{granted_path}/{child_segment}");

    let granted = ResourceScope::Filesystem {
        workspace: workspace.clone(),
        path: granted_path.clone(),
    };
    let child = ResourceScope::Filesystem {
        workspace: workspace.clone(),
        path: child_path.clone(),
    };
    assert!(resource_covers(&granted, &granted));
    assert!(resource_covers(&granted, &child));

    let sibling = ResourceScope::Filesystem {
        workspace: workspace.clone(),
        path: format!("{granted_path}-sibling/{child_segment}"),
    };
    assert!(!resource_covers(&granted, &sibling));

    let traversal = ResourceScope::Filesystem {
        workspace: workspace.clone(),
        path: format!("{granted_path}/../{child_segment}"),
    };
    assert!(!resource_covers(&granted, &traversal));

    let other_workspace = ResourceScope::Filesystem {
        workspace: format!("{workspace}-other"),
        path: child_path.clone(),
    };
    assert!(!resource_covers(&granted, &other_workspace));

    let set = ResourceScope::FilesystemSet {
        workspace: workspace.clone(),
        paths: vec![child_path],
    };
    assert!(resource_covers(&granted, &set));

    let raw = ResourceScope::Filesystem {
        workspace,
        path: input.raw,
    };
    let _ = resource_covers(&granted, &raw);

    let domain = format!("{granted_segment}.example.invalid");
    let prefix = format!("/api/{granted_segment}");
    let http_grant = ResourceScope::Http {
        scheme: "https".into(),
        domain: domain.clone(),
        port: None,
        path_prefix: prefix.clone(),
    };
    let http_child = ResourceScope::Http {
        scheme: "HTTPS".into(),
        domain: domain.to_ascii_uppercase(),
        port: None,
        path_prefix: format!("{prefix}/{child_segment}"),
    };
    assert!(resource_covers(&http_grant, &http_child));

    let http_sibling = ResourceScope::Http {
        scheme: "https".into(),
        domain: domain.clone(),
        port: None,
        path_prefix: format!("{prefix}-sibling/{child_segment}"),
    };
    assert!(!resource_covers(&http_grant, &http_sibling));

    let other_domain = ResourceScope::Http {
        scheme: "https".into(),
        domain: format!("other-{domain}"),
        port: None,
        path_prefix: prefix,
    };
    assert!(!resource_covers(&http_grant, &other_domain));

    let process = ResourceScope::Process {
        executable: granted_segment.clone(),
        workdir: child_segment.clone(),
    };
    assert!(resource_covers(&process, &process));
    assert!(!resource_covers(
        &process,
        &ResourceScope::Process {
            executable: format!("{granted_segment}-other"),
            workdir: child_segment.clone(),
        }
    ));

    let generic = ResourceScope::Generic {
        namespace: granted_segment.clone(),
        resource: child_segment.clone(),
    };
    assert!(resource_covers(&generic, &generic));
    assert!(!resource_covers(
        &generic,
        &ResourceScope::Generic {
            namespace: granted_segment,
            resource: format!("{child_segment}-other"),
        }
    ));
});
