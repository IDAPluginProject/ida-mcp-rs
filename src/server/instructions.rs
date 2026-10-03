//! Server instructions derived from the enabled tool set, so a filtered
//! server never points a client at a tool it does not advertise.

use crate::server::tool_filter::ToolFilter;
use crate::tool_registry::{self, ToolCategory};

const HEADER: &str = "IDA Pro headless analysis server for reverse engineering binaries.";

pub fn build(filter: &ToolFilter, close_hint: &str) -> String {
    let mut sections = vec![HEADER.to_string()];
    push_section(
        &mut sections,
        "Workflow:",
        workflow_lines(filter, close_hint),
    );
    push_section(&mut sections, "Tool categories:", category_lines(filter));
    push_section(&mut sections, "Tips:", tip_lines(filter));
    sections.join("\n\n")
}

fn push_section(sections: &mut Vec<String>, title: &str, lines: Vec<String>) {
    if lines.is_empty() {
        return;
    }
    let body = lines
        .iter()
        .map(|line| format!("- {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    sections.push(format!("{title}\n{body}"));
}

/// Whether `text` names, as a whole word, a registered tool that `filter`
/// does not expose.
fn mentions_disabled_tool(filter: &ToolFilter, text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|word| tool_registry::get_tool(word).is_some() && !filter.is_enabled(word))
}

/// Drop every line that would point a client at a tool it cannot call.
fn only_enabled(filter: &ToolFilter, lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .filter(|line| !mentions_disabled_tool(filter, line))
        .collect()
}

fn workflow_lines(filter: &ToolFilter, close_hint: &str) -> Vec<String> {
    // Mode-specific close hints can name other tools (HTTP refers to the
    // close_token from open_idb); fall back to a hint that names none.
    let close_line = [
        format!("close_idb: {close_hint}"),
        "close_idb: release the database when done.".to_string(),
    ]
    .into_iter()
    .find(|line| !mentions_disabled_tool(filter, line));

    let mut lines = vec![
        "open_idb: open a .i64/.idb or a raw binary (Mach-O/ELF/PE); pass arch for a \
         universal Mach-O. Large databases may take 30+ seconds."
            .to_string(),
        "open_dsc: open a module from a dyld_shared_cache instead of the whole cache.".to_string(),
        "load_debug_info: load dSYM/DWARF into an open database.".to_string(),
        "analysis_status: check auto-analysis when cross-references or decompilation \
         look incomplete."
            .to_string(),
    ];
    lines.extend(close_line);
    only_enabled(filter, lines)
}

fn category_lines(filter: &ToolFilter) -> Vec<String> {
    ToolCategory::all()
        .iter()
        .filter(|category| {
            tool_registry::tools_by_category(**category).any(|tool| filter.is_enabled(tool.name))
        })
        .map(|category| format!("{}: {}", category.as_str(), category.description()))
        .collect()
}

fn tip_lines(filter: &ToolFilter) -> Vec<String> {
    let mut lines = Vec::new();
    let dsc_growth = ["dsc_add_dylib", "dsc_add_region"]
        .into_iter()
        .filter(|name| filter.is_enabled(name))
        .collect::<Vec<_>>();
    if !dsc_growth.is_empty() {
        let follow_up = if filter.is_enabled("analyze_funcs") {
            "; if auto_is_ok=false, run analyze_funcs before relying on cross-references \
             or decompilation"
        } else {
            ""
        };
        lines.push(format!(
            "After {}, call analysis_status{follow_up}.",
            dsc_growth.join(" or ")
        ));
    }
    lines.push(
        "After a timeout or cancellation, call recent_operations to inspect the last \
         recorded foreground phase."
            .to_string(),
    );
    lines.push(
        "save_idb checkpoints renames, comments, types, and patches without closing.".to_string(),
    );
    lines.push(
        "tool_catalog(query='what you want to do') finds a tool by task; tool_help(name) \
         returns its full documentation and an example."
            .to_string(),
    );
    only_enabled(filter, lines)
}

#[cfg(test)]
mod tests {
    use crate::server::instructions::{build, mentions_disabled_tool, tip_lines, workflow_lines};
    use crate::server::tool_filter::ToolFilter;
    use crate::server::{close_hint_for, ServerMode};
    use crate::tool_registry;

    fn names(list: &str) -> Vec<String> {
        vec![list.to_string()]
    }

    /// Every close hint the server can actually emit.
    fn real_close_hints() -> Vec<&'static str> {
        let mut hints = Vec::new();
        for mode in [ServerMode::Stdio, ServerMode::Http, ServerMode::Worker] {
            for pooled in [false, true] {
                for workspace in [false, true] {
                    hints.push(close_hint_for(mode, pooled, workspace));
                }
            }
        }
        hints
    }

    fn filters_under_test() -> Vec<ToolFilter> {
        let mut filters = vec![
            ToolFilter::unrestricted(),
            ToolFilter::from_inputs(&[], &[], &[], true).unwrap(),
            ToolFilter::from_inputs(&[], &[], &names("open_idb"), false).unwrap(),
            ToolFilter::from_inputs(&[], &[], &names("analysis_status,tool_help"), false).unwrap(),
            ToolFilter::from_inputs(
                &[],
                &names("dsc_add_region,analysis_status,analyze_funcs"),
                &[],
                false,
            )
            .unwrap(),
            ToolFilter::from_inputs(&[], &names("open_idb,close_idb,run_script"), &[], false)
                .unwrap(),
        ];
        // Each tool alone, and everything except each tool.
        for tool in tool_registry::all_tools() {
            filters.push(ToolFilter::from_inputs(&[], &names(tool.name), &[], false).unwrap());
            filters.push(ToolFilter::from_inputs(&[], &[], &names(tool.name), false).unwrap());
        }
        filters
    }

    #[test]
    fn workflow_and_tips_never_mention_a_disabled_tool() {
        for filter in filters_under_test() {
            for hint in real_close_hints() {
                let lines = workflow_lines(&filter, hint)
                    .into_iter()
                    .chain(tip_lines(&filter));
                for line in lines {
                    assert!(
                        !mentions_disabled_tool(&filter, &line),
                        "line names a disabled tool: {line}"
                    );
                }
            }
        }
    }

    #[test]
    fn hidden_decompile_is_not_referenced_by_the_dsc_tip() {
        let filter = ToolFilter::from_inputs(
            &[],
            &names("dsc_add_region,analysis_status,analyze_funcs"),
            &[],
            false,
        )
        .unwrap();
        let tips = tip_lines(&filter).join("\n");
        assert!(tips.contains("run analyze_funcs"));
        assert!(mentions_disabled_tool(
            &filter,
            "run analyze_funcs before decompile"
        ));
    }

    #[test]
    fn http_close_hint_falls_back_when_open_idb_is_hidden() {
        let filter = ToolFilter::from_inputs(&[], &[], &names("open_idb"), false).unwrap();
        let hint = close_hint_for(ServerMode::Http, false, false);
        assert!(hint.contains("open_idb"));
        let workflow = workflow_lines(&filter, hint).join("\n");
        assert!(workflow.contains("close_idb: release the database when done."));
        assert!(!workflow.contains("open_idb"));
    }

    #[test]
    fn unrestricted_server_describes_the_apple_loading_workflow() {
        let hint = close_hint_for(ServerMode::Stdio, false, false);
        let text = build(&ToolFilter::unrestricted(), hint);
        assert!(text.contains("open_dsc"));
        assert!(text.contains("universal Mach-O"));
        assert!(text.contains("dsc_add_dylib or dsc_add_region"));
        assert!(text.contains(&format!("close_idb: {hint}")));
        assert!(text.contains("save_idb"));
    }

    #[test]
    fn lists_only_categories_with_an_enabled_tool() {
        let filter = ToolFilter::from_inputs(&names("decompile"), &[], &[], false).unwrap();
        let text = build(&filter, "unused");
        assert!(text.contains("- decompile:"));
        assert!(!text.contains("- editing:"));
        assert!(!text.contains("Workflow:"));
    }

    #[test]
    fn discovery_tip_needs_both_discovery_tools() {
        let filter = ToolFilter::from_inputs(&[], &[], &names("tool_help"), false).unwrap();
        assert!(!build(&filter, "unused").contains("tool_catalog("));
    }
}
