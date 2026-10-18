//! Closed, versioned generation layouts. A selected directory is mandatory
//! backing, never an optional cache that can silently fall back after damage.
use super::*;

pub(super) const fn schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("source-symbol-index"), 1, 0)
}
const fn directory_schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("source-symbol-index"), 1, 1)
}
const fn omission_schema(directory: bool) -> SchemaId {
    SchemaId::new(
        SchemaFamily::from_static("source-symbol-index"),
        2,
        if directory { 1 } else { 0 },
    )
}
pub(super) fn has_omissions(body: &GraphGenerationBody) -> bool {
    body.graph_schema_id() == omission_schema(false)
        || body.graph_schema_id() == omission_schema(true)
}
pub(super) fn symbol_manifest_root(body: &GraphGenerationBody) -> Result<Digest, Failure> {
    let root = *body.index_manifest_root();
    let profile = |name: &str| {
        BuilderProfileId::try_new(name.as_bytes()).map_err(|e| Failure::Index(e.into()))
    };
    let legacy = (body.graph_schema_id() == schema()
        && body.source().builder_profile == profile(data::INDEX_PROFILE)?)
        || (body.graph_schema_id() == omission_schema(false)
            && body.source().builder_profile == profile(data::OMISSION_INDEX_PROFILE)?);
    let directory = (body.graph_schema_id() == directory_schema()
        && body.source().builder_profile == profile(data::DIRECTORY_PROFILE)?)
        || (body.graph_schema_id() == omission_schema(true)
            && body.source().builder_profile == profile(data::OMISSION_DIRECTORY_PROFILE)?);
    if (!legacy && !directory)
        || body.authority_class() != GraphAuthorityClass::DeterministicDerived
        || body.source().parser_model_root != data::profile_root().map_err(Failure::Index)?
        || *body.vertices_root() != root
        || *body.evidence_root() != root
        || (legacy && *body.edges_root() != root)
    {
        return Err(Failure::Index(data::Error::Invalid("generation profile")));
    }
    Ok(root)
}
pub(super) fn symbol_directory_root(body: &GraphGenerationBody) -> Result<Option<Digest>, Failure> {
    symbol_manifest_root(body)?;
    Ok((body.graph_schema_id() == directory_schema()
        || body.graph_schema_id() == omission_schema(true))
    .then(|| *body.edges_root()))
}
pub(super) fn generation_body(
    source: &data::Source,
    manifest: Digest,
    directory: Option<Digest>,
    predecessor: Option<GraphGenerationId>,
    omissions: bool,
) -> Result<GraphGenerationBody, Failure> {
    let (schema, profile) = if omissions {
        (
            omission_schema(directory.is_some()),
            if directory.is_some() {
                data::OMISSION_DIRECTORY_PROFILE
            } else {
                data::OMISSION_INDEX_PROFILE
            },
        )
    } else if directory.is_some() {
        (directory_schema(), data::DIRECTORY_PROFILE)
    } else {
        (schema(), data::INDEX_PROFILE)
    };
    Ok(GraphGenerationBody::new(
        view()?,
        schema,
        GraphAuthorityClass::DeterministicDerived,
        GraphSourceStamp {
            source_rcr_id: source.rcr,
            source_forge_position_root: source.forge,
            builder_profile: BuilderProfileId::try_new(profile.as_bytes())
                .map_err(|e| Failure::Index(e.into()))?,
            parser_model_root: data::profile_root().map_err(Failure::Index)?,
        },
        // Document/evidence catalogs bind the complete manifest, including
        // omissions in v2. Edges may bind the exact name-to-document directory.
        manifest,
        directory.unwrap_or(manifest),
        manifest,
        manifest,
        predecessor,
    ))
}
impl OneNode {
    pub(super) async fn verify_symbol_directory_in(
        &self,
        request: &NodeRequestContext,
        body: &GraphGenerationBody,
        manifest: &data::Manifest,
        bytes: &mut usize,
        maximum: usize,
    ) -> Result<(), Failure> {
        if let Some(root) = symbol_directory_root(body)? {
            let raw = self
                .read_symbol_payload(request, root, bytes, maximum)
                .await?;
            data::NameDirectory::decode(&raw, root, manifest, &|| !workspace_request_live(request))
                .map_err(Failure::Index)?;
        }
        live(request)
    }
}

#[cfg(test)]
#[path = "directory_tests.rs"]
mod tests;
