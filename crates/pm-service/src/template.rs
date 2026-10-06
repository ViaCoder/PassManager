//! `{{name}}` 占位符。

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

/// 找出所有占位符（按出现顺序去重）。
pub fn find_names(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let _ = substitute(s, |n| {
        if !out.iter().any(|x: &String| x == n) {
            out.push(n.to_string());
        }
        Some(String::new())
    });
    out
}

/// 替换占位符。`f` 返回 None 时整体失败并返回该名称。
pub fn substitute(s: &str, mut f: impl FnMut(&str) -> Option<String>) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        let name = after[..end].trim();
        if name.is_empty() || !name.chars().all(is_name_char) {
            out.push_str(&rest[..start + 2]);
            rest = after;
            continue;
        }
        out.push_str(&rest[..start]);
        match f(name) {
            Some(v) => out.push_str(&v),
            None => return Err(name.to_string()),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders() {
        assert_eq!(find_names("Bearer {{github}} and {{ gh.2 }} {{github}}"), vec!["github", "gh.2"]);
        assert_eq!(find_names("{{ not valid! }} {x}"), Vec::<String>::new());
        let r = substitute("a{{x}}b{{y}}c", |n| Some(n.to_uppercase())).unwrap();
        assert_eq!(r, "aXbYc");
        assert_eq!(substitute("a{{zz}}", |_| None).unwrap_err(), "zz");
    }
}
