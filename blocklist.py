DEFAULT_BLOCKLIST = {
    "facebook.com.",
    "instagram.com.",
    "ads.google.com.",
}


def normalize_domain(domain):
    """Normalize domains to lowercase fully-qualified form."""
    cleaned = domain.strip().lower()
    if cleaned and not cleaned.endswith("."):
        cleaned += "."
    return cleaned


def load_blocklist(path):
    """Load blocked domains from file; fall back to defaults if unavailable."""
    try:
        with open(path, "r", encoding="utf-8") as file_handle:
            loaded = set()
            for line in file_handle:
                normalized = normalize_domain(line)
                if not normalized or normalized.startswith("#"):
                    continue
                loaded.add(normalized)
            return loaded or set(DEFAULT_BLOCKLIST)
    except FileNotFoundError:
        return set(DEFAULT_BLOCKLIST)
