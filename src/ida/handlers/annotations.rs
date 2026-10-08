//! Comment and rename handlers.

use std::path::Path;

use crate::error::ToolError;
use crate::ida::handlers::checked_text;
use crate::ida::handlers::target::{
    decompile_mutation_target, resolve_mutation_target, TargetSpec,
};
use crate::ida::types::{
    ListPseudocodeCommentsResult, PseudocodeCommentInfo, SetPseudocodeCommentResult,
};
use idalib::IDB;
use serde_json::{json, Value};

const MAX_COMMENT_LOCATOR_BYTES: usize = 128;
const MAX_COMMENT_BYTES: usize = 16_384;

pub(crate) fn check_pseudocode_comment(locator: &str, comment: &str) -> Result<(), ToolError> {
    checked_text(locator, "comment_locator", MAX_COMMENT_LOCATOR_BYTES)?;
    // Unlike other text, an empty comment is valid: it removes the comment.
    if comment.len() > MAX_COMMENT_BYTES || comment.contains('\0') {
        return Err(ToolError::InvalidParams(format!(
            "comment must contain at most {MAX_COMMENT_BYTES} bytes and no NUL"
        )));
    }
    Ok(())
}

pub(crate) fn handle_list_pseudocode_comments(
    idb: &Option<IDB>,
    database: Option<&Path>,
    target: TargetSpec<'_>,
    offset: usize,
    limit: usize,
) -> Result<ListPseudocodeCommentsResult, ToolError> {
    let (cfunc, target) = decompile_mutation_target(idb, database, target)?;
    let all = cfunc.pseudocode_comment_locations()?;
    let total = all.len();
    let locations: Vec<PseudocodeCommentInfo> = all
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|location| PseudocodeCommentInfo {
            locator: location.locator,
            address: format!("{:#x}", location.address),
            line_number: location.line_number,
            text: location.text,
            comment: location.comment,
        })
        .collect();
    let end = offset.saturating_add(locations.len());
    Ok(ListPseudocodeCommentsResult {
        target,
        locations,
        total,
        next_offset: (end < total).then_some(end),
    })
}

pub(crate) fn handle_set_pseudocode_comment(
    idb: &Option<IDB>,
    database: Option<&Path>,
    target: TargetSpec<'_>,
    locator: &str,
    comment: &str,
) -> Result<SetPseudocodeCommentResult, ToolError> {
    let (cfunc, target) = decompile_mutation_target(idb, database, target)?;
    cfunc.set_pseudocode_comment(locator, comment)?;
    Ok(SetPseudocodeCommentResult {
        target,
        comment_locator: locator.to_string(),
        deleted: comment.is_empty(),
    })
}

pub(crate) fn handle_set_comments(
    idb: &Option<IDB>,
    database: Option<&Path>,
    target: TargetSpec<'_>,
    comment: &str,
    repeatable: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let (addr, target) = resolve_mutation_target(db, database, target)?;
    if repeatable {
        db.set_cmt_with(addr, comment, true)?;
    } else {
        db.set_cmt(addr, comment)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "repeatable": repeatable,
        "comment": comment,
        "target": target,
    }))
}

/// Rename the target. `target.symbol` in the result is the name before the
/// rename; `name` is the name it has now.
pub(crate) fn handle_rename(
    idb: &Option<IDB>,
    database: Option<&Path>,
    target: TargetSpec<'_>,
    name: &str,
    flags: i32,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let (addr, target) = resolve_mutation_target(db, database, target)?;
    if flags == 0 {
        db.set_name(addr, name)?;
    } else {
        db.set_name_with_flags(addr, name, flags)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "name": name,
        "flags": flags,
        "target": target,
    }))
}

#[cfg(test)]
mod tests {
    use crate::ida::handlers::annotations::{
        check_pseudocode_comment, MAX_COMMENT_BYTES, MAX_COMMENT_LOCATOR_BYTES,
    };

    #[test]
    fn pseudocode_comment_input_is_bounded_and_allows_deletion() {
        assert!(check_pseudocode_comment("pcmt1:x", "").is_ok());
        assert!(check_pseudocode_comment("pcmt1:x", &"c".repeat(MAX_COMMENT_BYTES)).is_ok());
        for (locator, comment) in [
            (String::new(), "note".to_string()),
            (
                "x".repeat(MAX_COMMENT_LOCATOR_BYTES + 1),
                "note".to_string(),
            ),
            ("pcmt1:\0".to_string(), "note".to_string()),
            ("pcmt1:x".to_string(), "c".repeat(MAX_COMMENT_BYTES + 1)),
            ("pcmt1:x".to_string(), "nul\0text".to_string()),
        ] {
            assert!(
                check_pseudocode_comment(&locator, &comment).is_err(),
                "{locator:?} {}",
                comment.len()
            );
        }
    }
}
