//! Exact-target Hex-Rays local-variable operations.

use std::path::Path;

use idalib::decompiler::{CFunction, LocalVariable};
use idalib::IDB;

use crate::error::ToolError;
use crate::ida::handlers::target::{acting_at, resolve_mutation_target, TargetSpec};
use crate::ida::types::{
    ListLvarsResult, LocalVariableInfo, LocalVariableSelector, MutationTarget, RenameLvarResult,
    SetLvarTypeResult,
};

/// Refuse pathological decompilations instead of truncating an exact-name scan.
const MAX_LOCALS: usize = 100_000;
const MAX_NAME_BYTES: usize = 1024;
const MAX_DECL_BYTES: usize = 16_384;
const MAX_LOCATOR_BYTES: usize = 16_384;

fn checked_text(value: &str, field: &str, max: usize) -> Result<(), ToolError> {
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(ToolError::InvalidParams(format!(
            "{field} must contain 1–{max} bytes and no NUL"
        )));
    }
    Ok(())
}

pub(crate) fn local_selector(
    name: Option<String>,
    locator: Option<String>,
) -> Result<LocalVariableSelector, ToolError> {
    match (name, locator) {
        (Some(name), None) => {
            checked_text(&name, "lvar_name", MAX_NAME_BYTES)?;
            Ok(LocalVariableSelector::Name(name))
        }
        (None, Some(locator)) => {
            checked_text(&locator, "lvar_locator", MAX_LOCATOR_BYTES)?;
            Ok(LocalVariableSelector::Locator(locator))
        }
        (None, None) | (Some(_), Some(_)) => Err(ToolError::InvalidParams(
            "pass exactly one of lvar_name or lvar_locator".into(),
        )),
    }
}

fn decompile_target<'a>(
    idb: &'a Option<IDB>,
    database: Option<&Path>,
    target: TargetSpec<'_>,
) -> Result<(CFunction<'a>, MutationTarget), ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let (address, target) = resolve_mutation_target(db, database, target)?;
    if !db.decompiler_available() {
        return Err(ToolError::DecompilerUnavailable);
    }
    let function = db
        .function_at(address)
        .ok_or(ToolError::FunctionNotFound(address))?;
    let target = acting_at(target, function.start_address());
    let cfunc = db.decompile(&function)?;
    if cfunc.local_variable_count()? > MAX_LOCALS {
        return Err(ToolError::IdaError(format!(
            "function has more than {MAX_LOCALS} decompiler locals"
        )));
    }
    Ok((cfunc, target))
}

fn variable_info(var: LocalVariable) -> LocalVariableInfo {
    LocalVariableInfo {
        name: var.name,
        type_name: var.type_name,
        location: var.location,
        locator: var.locator,
        definition_address: var
            .definition_address
            .map(|address| format!("{address:#x}")),
        size: u32::try_from(var.width).ok(),
        is_argument: var.is_argument,
        has_user_name: var.has_user_name,
        has_user_type: var.has_user_type,
    }
}

fn exact_local_index(
    query: &str,
    names: impl IntoIterator<Item = Result<(usize, String), ToolError>>,
) -> Result<usize, ToolError> {
    let mut found = None;
    let mut similar = Vec::new();
    let folded = query.to_lowercase();
    for entry in names {
        let (index, name) = entry?;
        if name == query {
            if found.is_some() {
                return Err(ToolError::InvalidParams(format!(
                    "more than one decompiler local is named exactly {query:?}; no change was made"
                )));
            }
            found = Some(index);
        } else if similar.len() < 8 && name.to_lowercase().contains(&folded) {
            similar.push(name);
        }
    }
    found.ok_or_else(|| {
        let hint = if similar.is_empty() {
            "use list_lvars to find its exact name".to_string()
        } else {
            format!("similar names: {similar:?}")
        };
        ToolError::InvalidParams(format!(
            "no decompiler local is named exactly {query:?}; {hint}. No change was made"
        ))
    })
}

fn selected_local(
    cfunc: &CFunction<'_>,
    selector: &LocalVariableSelector,
) -> Result<(usize, LocalVariableInfo), ToolError> {
    let fetch = |index| -> Result<LocalVariable, ToolError> {
        cfunc.local_variable(index)?.ok_or_else(|| {
            ToolError::IdaError("decompiler local disappeared before the edit".to_string())
        })
    };
    let vars = (0..cfunc.local_variable_count()?).map(|index| Ok((index, fetch(index)?)));
    let index = match selector {
        LocalVariableSelector::Name(name) => exact_local_index(
            name,
            vars.map(|entry| entry.map(|(index, var)| (index, var.name))),
        )?,
        LocalVariableSelector::Locator(locator) => exact_locator_index(
            locator,
            vars.map(|entry| entry.map(|(index, var)| (index, var.locator))),
        )?,
    };
    Ok((index, variable_info(fetch(index)?)))
}

fn exact_locator_index(
    query: &str,
    locators: impl IntoIterator<Item = Result<(usize, Option<String>), ToolError>>,
) -> Result<usize, ToolError> {
    let mut found = None;
    for entry in locators {
        let (index, locator) = entry?;
        if locator.as_deref() == Some(query) && found.replace(index).is_some() {
            return Err(ToolError::InvalidParams(
                "lvar_locator matches multiple current locals; no change was made".into(),
            ));
        }
    }
    found.ok_or_else(|| {
        ToolError::InvalidParams(
            "lvar_locator is stale or does not belong to this function; use list_lvars again. \
             No change was made"
                .into(),
        )
    })
}

pub(crate) fn handle_list_lvars(
    idb: &Option<IDB>,
    database: Option<&Path>,
    target: TargetSpec<'_>,
    offset: usize,
    limit: usize,
) -> Result<ListLvarsResult, ToolError> {
    let (cfunc, target) = decompile_target(idb, database, target)?;
    let mut total = 0usize;
    let mut lvars = Vec::new();
    for index in 0..cfunc.local_variable_count()? {
        let var = cfunc.local_variable(index)?.ok_or_else(|| {
            ToolError::IdaError("decompiler local disappeared while listing".to_string())
        })?;
        // Hex-Rays also keeps unnamed internal temporaries. Only names that
        // can be passed back to the edit tools belong in this listing.
        if var.name.is_empty() {
            continue;
        }
        if total >= offset && lvars.len() < limit {
            lvars.push(variable_info(var));
        }
        total += 1;
    }
    let end = offset.saturating_add(lvars.len());
    Ok(ListLvarsResult {
        target,
        lvars,
        total,
        next_offset: (end < total).then_some(end),
    })
}

pub(crate) fn handle_rename_lvar(
    idb: &Option<IDB>,
    database: Option<&Path>,
    target: TargetSpec<'_>,
    selector: &LocalVariableSelector,
    new_name: &str,
) -> Result<RenameLvarResult, ToolError> {
    checked_text(new_name, "new_name", MAX_NAME_BYTES)?;
    let (cfunc, target) = decompile_target(idb, database, target)?;
    let (index, variable) = selected_local(&cfunc, selector)?;
    cfunc.rename_local_variable(index, new_name)?;
    Ok(RenameLvarResult {
        target,
        variable,
        new_name: new_name.to_string(),
        renamed: true,
    })
}

pub(crate) fn handle_set_lvar_type(
    idb: &Option<IDB>,
    database: Option<&Path>,
    target: TargetSpec<'_>,
    selector: &LocalVariableSelector,
    decl: &str,
) -> Result<SetLvarTypeResult, ToolError> {
    checked_text(decl, "decl", MAX_DECL_BYTES)?;
    let (cfunc, target) = decompile_target(idb, database, target)?;
    let (index, variable) = selected_local(&cfunc, selector)?;
    let type_name = cfunc.set_local_variable_type(index, decl)?;
    Ok(SetLvarTypeResult {
        target,
        variable,
        type_name,
        applied: true,
    })
}

#[cfg(test)]
mod tests {
    use crate::ida::handlers::lvars::{
        checked_text, exact_local_index, exact_locator_index, local_selector, MAX_DECL_BYTES,
        MAX_LOCATOR_BYTES,
    };

    #[test]
    fn exact_local_names_never_fall_back_to_partial_or_case_matches() {
        let names = || {
            [
                Ok((0, "value".to_string())),
                Ok((1, "value_length".to_string())),
            ]
        };
        assert_eq!(exact_local_index("value", names()).unwrap(), 0);
        for query in ["val", "VALUE", "missing"] {
            assert!(exact_local_index(query, names()).is_err(), "{query}");
        }
        assert!(
            exact_local_index("value", [Ok((0, "value".into())), Ok((1, "value".into()))]).is_err()
        );
    }

    #[test]
    fn declarations_are_bounded_before_entering_ida() {
        assert!(checked_text("", "decl", MAX_DECL_BYTES).is_err());
        assert!(checked_text("int\0ignored", "decl", MAX_DECL_BYTES).is_err());
        assert!(checked_text(&"x".repeat(MAX_DECL_BYTES + 1), "decl", MAX_DECL_BYTES).is_err());
    }

    #[test]
    fn local_locator_selection_rejects_stale_and_ambiguous_identities() {
        // The old display name now belongs to index 0, but its original
        // locator belongs to index 1. Never fall back to the name or index.
        let current = || {
            [
                Ok((0, Some("other".to_string()))),
                Ok((1, Some("original".to_string()))),
                Ok((2, None)),
            ]
        };
        assert_eq!(exact_locator_index("original", current()).unwrap(), 1);
        assert!(exact_locator_index("stale", current()).is_err());
        assert!(exact_locator_index(
            "original",
            [
                Ok((0, Some("original".into()))),
                Ok((1, Some("original".into()))),
            ]
        )
        .is_err());
        assert!(local_selector(None, None).is_err());
        assert!(local_selector(Some("v1".into()), Some("original".into())).is_err());
        assert!(local_selector(None, Some("x".repeat(MAX_LOCATOR_BYTES + 1))).is_err());
    }
}
