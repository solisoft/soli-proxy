// Application-wide view helpers

// Truncate text to a maximum length with ellipsis
fn truncate_text(text: String, length: Int, suffix: String) -> String {
    if len(text) <= length {
        return text;
    }
    return substring(text, 0, length - len(suffix)) + suffix;
}

// Capitalize first letter of a string
fn capitalize(text: String) -> String {
    if len(text) == 0 {
        return text;
    }
    return upcase(substring(text, 0, 1)) + substring(text, 1, len(text));
}

// Generate an HTML link
fn link_to(text: String, url: String) -> String {
    return "<a href=\"" + html_escape(url) + "\">" + html_escape(text) + "</a>";
}

// Generate an HTML link with CSS class
fn link_to_class(text: String, url: String, css_class: String) -> String {
    return "<a href=\"" + html_escape(url) + "\" class=\"" + html_escape(css_class) + "\">" + html_escape(text) + "</a>";
}

// Pluralize a word based on count
fn pluralize(count: Int, singular: String, plural: String) -> String {
    if count == 1 {
        return str(count) + " " + singular;
    }
    return str(count) + " " + plural;
}

// Simple pluralize (adds 's')
fn pluralize_simple(count: Int, word: String) -> String {
    if count == 1 {
        return str(count) + " " + word;
    }
    return str(count) + " " + word + "s";
}
