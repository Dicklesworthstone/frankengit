//! Read-only integrity checking of custody selected by authenticated native
//! pointers. Names and directory listings never establish payload completeness.

use super::{
    ArtifactOperation, Deadline, LfsStore, MAX_OBJECT_BYTES, Options, files, identity_json,
    inventory, revalidate, with_node,
};

pub(super) fn run(options: &Options, deadline: Deadline) -> Result<String, String> {
    let root = options.custody.as_ref().ok_or("missing LFS custody root")?;
    files::directory(root, true)?;
    with_node(options, |node| {
        let request = node.request_context();
        let inventory = inventory(node, &request, options, deadline)?;
        let store = LfsStore::open(
            root,
            options.tenant,
            options.repository,
            inventory.source.incarnation,
        )
        .map_err(|error| error.to_string())?;
        let live = || deadline.live(&request);
        // One absolute operation budget covers every payload. `contains`
        // streams the complete original container into a sink and verifies its
        // scope, metadata, length and digest; it neither trusts a filename nor
        // creates the private delivery copy used by downloads and exports.
        let operation = ArtifactOperation::new(MAX_OBJECT_BYTES, deadline.remaining()?, &live)
            .map_err(|error| error.to_string())?;
        for &object in &inventory.objects {
            deadline.request(&request)?;
            match store.contains(object, &operation) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(format!(
                        "LFS custody missing for {} ({} bytes); verification incomplete",
                        object.oid, object.size,
                    ));
                }
                Err(error) => {
                    return Err(format!(
                        "LFS custody verification failed for {} ({} bytes): {error}",
                        object.oid, object.size,
                    ));
                }
            }
        }
        revalidate(node, &request, &inventory.receipt, deadline)?;
        // The host buffers this receipt until node shutdown succeeds. A late
        // timeout, output failure or changed head prevents successful return;
        // a broken output stream may still have received a receipt prefix.
        Ok(format!(
            concat!(
                "{{\"type\":\"lfs_verify\",\"schema_version\":1,\"source\":{},",
                "\"native_objects\":{},\"native_bytes\":{},\"objects\":{},\"payload_bytes\":{},",
                "\"complete\":true,\"scope\":\"authority_selected_native_pointers\",",
                "\"custody_verified\":true,\"head_revalidated\":true,\"node_closed\":true,",
                "\"refs_published\":false,\"physical_orphans_included\":false}}"
            ),
            identity_json(&inventory.source),
            inventory.native_objects,
            inventory.native_bytes,
            inventory.objects.len(),
            inventory.payload_bytes,
        ))
    })
}
