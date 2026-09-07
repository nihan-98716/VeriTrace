"""
VeriTrace Semantic Impact & NLP-Powered Tamper Assessment Engine
Fully grounded on uploaded text files alone. Analyzes line-by-line and word-by-word
alterations to classify the severity, intent, and legal/informational risk of tampering.
Non-text and binary files are strictly excluded.
"""
import re
import difflib
from typing import Dict, List, Any, Optional

NEGATION_TERMS = {
    "not", "never", "no", "none", "neither", "nor", "without", "except",
    "cannot", "can't", "won't", "isn't", "aren't", "didn't", "wasn't",
    "weren't", "don't", "doesn't", "refuse", "refuses", "refused", "deny",
    "denies", "denied", "prohibit", "prohibits", "prohibited", "unauthorized",
    "disallowed", "unlawful", "invalid", "void"
}

OBLIGATION_TERMS = {
    "shall", "must", "will", "agrees", "agree", "agreed", "liable", "indemnify",
    "warrant", "guarantee", "terminate", "penalty", "breach", "covenant",
    "waive", "binding", "obligated", "obligation", "release", "released"
}

# Comprehensive antonym & polarity pairs (canonical mappings)
ANTONYM_PAIRS = [
    ("agree", "disagree"), ("agrees", "disagrees"), ("agreed", "disagreed"), ("agreement", "disagreement"),
    ("agree", "refuse"), ("agrees", "refuses"), ("agreed", "refused"),
    ("accept", "reject"), ("accepts", "rejects"), ("accepted", "rejected"),
    ("accept", "deny"), ("accepts", "denies"), ("accepted", "denied"),
    ("approve", "reject"), ("approves", "rejects"), ("approved", "rejected"), ("approval", "rejection"),
    ("allow", "deny"), ("allows", "denies"), ("allowed", "denied"),
    ("permit", "prohibit"), ("permits", "prohibits"), ("permitted", "prohibited"),
    ("true", "false"), ("valid", "invalid"), ("validity", "invalidity"),
    ("legal", "illegal"), ("legitimate", "illegitimate"),
    ("authorized", "unauthorized"), ("authorization", "unauthorized"),
    ("compliant", "noncompliant"), ("compliant", "uncompliant"),
    ("guilty", "innocent"), ("liable", "exempt"), ("liability", "exemption"),
    ("success", "failure"), ("successful", "unsuccessful"),
    ("passed", "failed"), ("pass", "fail"),
    ("increase", "decrease"), ("increased", "decreased"), ("increases", "decreases"),
    ("profit", "loss"), ("gain", "loss"), ("credit", "debit"),
    ("safe", "unsafe"), ("secure", "insecure"), ("positive", "negative"),
    ("obligated", "released"), ("bound", "unbound"),
    ("effective", "ineffective"), ("enforceable", "unenforceable"),
    ("confidential", "public"), ("private", "public"),
    ("paid", "unpaid"), ("owing", "cleared"), ("owe", "settled")
]

# Build quick lookup dictionary mapping word -> set of its antonyms
ANTONYM_MAP: Dict[str, set] = {}
for w1, w2 in ANTONYM_PAIRS:
    ANTONYM_MAP.setdefault(w1.lower(), set()).add(w2.lower())
    ANTONYM_MAP.setdefault(w2.lower(), set()).add(w1.lower())


def _is_binary_or_non_text(file_bytes: bytes, filename: Optional[str] = None) -> bool:
    """Detects whether bytes belong to binary files (images, zip, pdf, etc.) rather than plain text."""
    if filename:
        ext = filename.lower().split(".")[-1]
        if ext in ("png", "jpg", "jpeg", "webp", "bmp", "gif", "tiff", "tif", "ico",
                   "pdf", "zip", "tar", "gz", "exe", "bin", "so", "dll", "pyc"):
            return True

    if not file_bytes:
        return False

    # Check common binary magic byte headers
    if (file_bytes.startswith(b"\x89PNG") or
        file_bytes.startswith(b"\xff\xd8\xff") or
        file_bytes.startswith(b"GIF8") or
        file_bytes.startswith(b"%PDF") or
        file_bytes.startswith(b"PK\x03\x04") or
        file_bytes.startswith(b"BM") or
        (file_bytes.startswith(b"RIFF") and b"WEBP" in file_bytes[:16])):
        return True

    # Check for null bytes in sample (standard binary heuristic)
    sample = file_bytes[:4096]
    if b"\x00" in sample:
        return True

    # Check unprintable control character ratio
    try:
        text = sample.decode("utf-8")
        unprintable = sum(1 for ch in text if ord(ch) < 32 and ch not in "\r\n\t\f\b")
        if len(text) > 0 and (unprintable / len(text)) > 0.05:
            return True
    except UnicodeDecodeError:
        return True

    return False


def _tokenize_words(text: str) -> List[str]:
    """Tokenize words preserving numbers, currency, and punctuation inside tokens."""
    return re.findall(r'\b[a-zA-Z0-9_$€£%.-]+\b', text)


def _extract_numbers(text: str) -> List[str]:
    """Finds financial amounts, percentages, and numeric figures."""
    pattern = r'(?:[\$€£]\s*[0-9,]+(?:\.[0-9]+)?|[0-9,]+(?:\.[0-9]+)?%|[0-9]+(?:\.[0-9]+)?)'
    return re.findall(pattern, text)


def assess_document_tampering(original_file_bytes: bytes, current_file_bytes: bytes, filename: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Grounded NLP document tamper assessment.
    Strictly operates on valid text documents. If binary/image bytes are passed, returns None.
    Computes exact line-level and word-level diffs with grounded entity and polarity checks.
    """
    if _is_binary_or_non_text(original_file_bytes, filename) or _is_binary_or_non_text(current_file_bytes, filename):
        return None

    try:
        orig_text = original_file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            orig_text = original_file_bytes.decode("latin1")
        except Exception:
            return None

    try:
        curr_text = current_file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            curr_text = current_file_bytes.decode("latin1")
        except Exception:
            return None

    orig_lines = orig_text.splitlines()
    curr_lines = curr_text.splitlines()

    assessments = []
    overall_risk = "BENIGN"
    risk_weights = {"BENIGN": 0, "MODERATE": 1, "SUBSTANTIVE": 2, "CRITICAL": 3}

    matcher = difflib.SequenceMatcher(None, orig_lines, curr_lines)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue

        orig_chunk = " ".join(orig_lines[i1:i2]).strip() if i1 < i2 else ""
        curr_chunk = " ".join(curr_lines[j1:j2]).strip() if j1 < j2 else ""

        line_label = f"Line {i1 + 1}" if i2 - i1 == 1 else (f"Lines {i1 + 1}–{i2}" if i2 > i1 else "")
        if tag == "insert":
            line_label = f"Line {j1 + 1} (Inserted)"
        elif tag == "delete":
            line_label = f"Line {i1 + 1} (Deleted)"

        orig_words = _tokenize_words(orig_chunk)
        curr_words = _tokenize_words(curr_chunk)

        orig_lower = [w.lower() for w in orig_words]
        curr_lower = [w.lower() for w in curr_words]

        # Word-level diff using SequenceMatcher
        word_matcher = difflib.SequenceMatcher(None, orig_lower, curr_lower)
        added_terms: List[str] = []
        removed_terms: List[str] = []
        replaced_pairs: List[tuple] = []

        for wtag, wi1, wi2, wj1, wj2 in word_matcher.get_opcodes():
            if wtag == "replace":
                for ow, cw in zip(orig_words[wi1:wi2], curr_words[wj1:wj2]):
                    replaced_pairs.append((ow, cw))
                # Handle leftover words if chunks have unequal word count
                if wi2 - wi1 > wj2 - wj1:
                    removed_terms.extend(orig_words[wi1 + (wj2 - wj1):wi2])
                elif wj2 - wj1 > wi2 - wi1:
                    added_terms.extend(curr_words[wj1 + (wi2 - wi1):wj2])
            elif wtag == "delete":
                removed_terms.extend(orig_words[wi1:wi2])
            elif wtag == "insert":
                added_terms.extend(curr_words[wj1:wj2])

        # Analyze semantic impact
        reasons = []
        risk_level = "BENIGN"

        # 1. Antonym / Polarity flips
        for ow, cw in replaced_pairs:
            if cw.lower() in ANTONYM_MAP.get(ow.lower(), set()):
                reasons.append(f"Opposite polarity flip: '{ow}' -> '{cw}'")
                risk_level = "CRITICAL"

        # 2. Number / Financial alterations
        orig_nums = _extract_numbers(orig_chunk)
        curr_nums = _extract_numbers(curr_chunk)
        if orig_nums != curr_nums:
            diff_nums = []
            for ow, cw in replaced_pairs:
                if re.search(r'\d', ow) or re.search(r'\d', cw):
                    diff_nums.append(f"'{ow}' -> '{cw}'")
            if not diff_nums and (orig_nums or curr_nums):
                diff_nums.append(f"Original: {orig_nums}, Current: {curr_nums}")
            reasons.append(f"Numeric/financial value modified ({', '.join(diff_nums)})")
            risk_level = "CRITICAL"

        # 3. Negation alterations
        orig_negs = set(w.lower() for w in orig_words if w.lower() in NEGATION_TERMS)
        curr_negs = set(w.lower() for w in curr_words if w.lower() in NEGATION_TERMS)
        if orig_negs != curr_negs:
            added_negs = curr_negs - orig_negs
            removed_negs = orig_negs - curr_negs
            if added_negs:
                reasons.append(f"Negation modifier added: {list(added_negs)}")
            if removed_negs:
                reasons.append(f"Negation modifier removed: {list(removed_negs)}")
            risk_level = "CRITICAL"

        # 4. Legal / Contractual obligation changes
        orig_oblig = set(w.lower() for w in orig_words if w.lower() in OBLIGATION_TERMS)
        curr_oblig = set(w.lower() for w in curr_words if w.lower() in OBLIGATION_TERMS)
        if orig_oblig != curr_oblig and risk_level != "CRITICAL":
            reasons.append(f"Legal/obligation terms altered: {list(orig_oblig ^ curr_oblig)}")
            risk_level = "CRITICAL"

        # 5. General term changes
        if not reasons:
            details = []
            if replaced_pairs:
                details.append("Replaced: " + ", ".join(f"'{ow}' -> '{cw}'" for ow, cw in replaced_pairs[:4]))
            if added_terms:
                details.append("Added: " + ", ".join(f"'{w}'" for w in added_terms[:4]))
            if removed_terms:
                details.append("Removed: " + ", ".join(f"'{w}'" for w in removed_terms[:4]))

            total_word_changes = len(replaced_pairs) + len(added_terms) + len(removed_terms)
            if total_word_changes > 3:
                risk_level = "SUBSTANTIVE"
                reasons.append(f"Substantive text alteration: {'; '.join(details)}")
            elif total_word_changes > 0:
                risk_level = "MODERATE"
                reasons.append(f"Wording modified: {'; '.join(details)}")
            else:
                risk_level = "BENIGN"
                reasons.append("Minor whitespace or formatting alteration")

        if risk_weights[risk_level] > risk_weights[overall_risk]:
            overall_risk = risk_level

        # Calculate word overlap similarity for semantic drift score
        all_words = set(orig_lower) | set(curr_lower)
        overlap = set(orig_lower) & set(curr_lower)
        drift = 1.0 - (len(overlap) / len(all_words)) if all_words else 0.0

        assessments.append({
            "segment_name": line_label,
            "risk_level": risk_level,
            "risk_reasons": reasons,
            "semantic_drift": round(drift, 3),
            "original_text": orig_chunk[:160] + ("…" if len(orig_chunk) > 160 else ""),
            "tampered_text": curr_chunk[:160] + ("…" if len(curr_chunk) > 160 else ""),
            "added_words": added_terms,
            "removed_words": removed_terms,
            "replaced_words": [f"'{o}' -> '{c}'" for o, c in replaced_pairs]
        })

    summary_msg = f"Overall Risk: {overall_risk}. "
    if overall_risk == "CRITICAL":
        summary_msg += "High-severity alteration detected (polarity flip, numeric alteration, or legal obligation breach)."
    elif overall_risk == "SUBSTANTIVE":
        summary_msg += "Substantive contextual rewording detected."
    elif overall_risk == "MODERATE":
        summary_msg += "Specific terms or phrasing were modified."
    else:
        summary_msg += "Minor or non-critical formatting changes detected."

    return {
        "overall_risk": overall_risk,
        "summary": summary_msg,
        "altered_count": len(assessments),
        "assessments": assessments
    }

