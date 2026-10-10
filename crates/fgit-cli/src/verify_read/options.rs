use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, RefName, RepositoryAuthorityHeadId,
};

use super::{Error, USAGE};

#[derive(Debug)]
pub(super) enum Input {
    File(PathBuf),
    Http(Url),
}
#[derive(Debug)]
pub(super) struct Url {
    pub address: SocketAddr,
    pub route: String,
}
#[derive(Debug)]
pub(super) struct Options {
    pub input: Input,
    pub token: Option<PathBuf>,
    pub head: RepositoryAuthorityHeadId,
    pub reference: RefName,
    pub path: Vec<u8>,
    pub output: Option<PathBuf>,
}

pub(super) fn parse(arguments: &[String]) -> Result<Options, Error> {
    if arguments.is_empty()
        || arguments.len() > 16
        || !arguments.len().is_multiple_of(2)
        || arguments.iter().any(|value| value.len() > 8192)
        || arguments.iter().map(String::len).sum::<usize>() > 24 * 1024
    {
        return Err(Error::new("invalid_arguments", USAGE));
    }
    let mut fields = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        if !matches!(
            pair[0].as_str(),
            "--input"
                | "--url"
                | "--token-file"
                | "--trusted-head"
                | "--ref"
                | "--ref-hex"
                | "--path"
                | "--path-hex"
                | "--output"
        ) || pair[1].is_empty()
            || fields.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(Error::new(
                "invalid_arguments",
                "unknown, empty, or duplicate option",
            ));
        }
    }
    let head = head(fields.remove("--trusted-head").ok_or_else(|| {
        Error::new(
            "trusted_head_required",
            "supply an independently trusted --trusted-head commitment",
        )
    })?)?;
    let reference = RefName::try_new(&bytes(&mut fields, "--ref", "--ref-hex", 1024)?)
        .map_err(|_| Error::new("invalid_ref", "expected an exact full reference name"))?;
    let path = bytes(&mut fields, "--path", "--path-hex", 4096)?;
    if path.split(|byte| *byte == b'/').any(|part| {
        part.is_empty() || part.len() > 255 || part == b"." || part == b".." || part.contains(&0)
    }) || path.split(|byte| *byte == b'/').count() > 64
    {
        return Err(Error::new(
            "invalid_path",
            "expected a relative literal repository path with at most 64 components",
        ));
    }
    let token = fields.remove("--token-file").map(PathBuf::from);
    let input = match (fields.remove("--input"), fields.remove("--url")) {
        (Some(file), None) if token.is_none() => Input::File(PathBuf::from(file)),
        (None, Some(value)) if token.is_some() => Input::Http(url(value)?),
        _ => {
            return Err(Error::new(
                "invalid_input",
                "choose --input without credentials or --url with --token-file",
            ));
        }
    };
    let output = fields.remove("--output").map(PathBuf::from);
    if output
        .as_ref()
        .is_some_and(|path| path.file_name().is_none())
    {
        return Err(Error::new(
            "invalid_output",
            "output must name a new regular file",
        ));
    }
    Ok(Options {
        input,
        token,
        head,
        reference,
        path,
        output,
    })
}

fn bytes(
    fields: &mut BTreeMap<&str, &str>,
    text: &str,
    encoded: &str,
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    match (fields.remove(text), fields.remove(encoded)) {
        (Some(value), None) if value.len() <= maximum => Ok(value.as_bytes().to_vec()),
        (None, Some(value)) => unhex(value, maximum),
        _ => Err(Error::new(
            "invalid_selection",
            format!("choose exactly one of {text} or {encoded}"),
        )),
    }
}

fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, Error> {
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || text.len() > maximum * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::new(
            "invalid_hex",
            "hex bytes must use complete lowercase pairs within the field limit",
        ));
    }
    let digit = |byte| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    Ok(text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| digit(pair[0]) << 4 | digit(pair[1]))
        .collect())
}

fn head(text: &str) -> Result<RepositoryAuthorityHeadId, Error> {
    let invalid = || {
        Error::new(
            "invalid_trusted_head",
            "expected alg:<algorithm>:<lowercase-digest>",
        )
    };
    let (algorithm, digest) = text
        .strip_prefix("alg:")
        .and_then(|value| value.split_once(':'))
        .ok_or_else(invalid)?;
    if algorithm.is_empty()
        || !algorithm.bytes().all(|byte| byte.is_ascii_digit())
        || algorithm.starts_with('0')
    {
        return Err(invalid());
    }
    let algorithm = DigestAlgorithmId::try_new(algorithm.parse().map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let digest = DigestBytes::try_new(&unhex(digest, 64)?).map_err(|_| invalid())?;
    Ok(RepositoryAuthorityHeadId::from_digest(
        algorithm,
        CANONICAL_CODEC_VERSION,
        digest,
    ))
}

fn url(text: &str) -> Result<Url, Error> {
    let invalid = || {
        Error::new(
            "invalid_url",
            "expected http://<numeric-loopback>:<port>/<repository-route> without credentials, query, or fragment",
        )
    };
    let (authority, route) = text
        .strip_prefix("http://")
        .and_then(|value| value.split_once('/'))
        .ok_or_else(invalid)?;
    let address: SocketAddr = authority.parse().map_err(|_| invalid())?;
    if !address.ip().is_loopback()
        || address.port() == 0
        || route.len() > 1024
        || route.split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
        })
    {
        return Err(invalid());
    }
    Ok(Url {
        address,
        route: format!("/{route}"),
    })
}
