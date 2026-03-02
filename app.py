import fnmatch
import io
import os
import re
import uuid
import zipfile
from datetime import datetime
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for
from markupsafe import Markup
import markdown

try:
    import bleach
except ImportError:  # Optional fallback when dependency is not present.
    bleach = None

from azure_client import get_missing_config, get_provider
from analysis_engine import (
    LOG_PROFILES,
    analyze_with_ai,
    ask_log_question,
    decode_file,
    detect_log_type,
    extract_errors,
    extract_performance_metrics,
    sanitize_log,
    save_feedback,
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB total request size

ALLOWED_UPLOAD_EXTENSIONS = {".log", ".zip", ".txt"}
MAX_UPLOAD_FILES = 10
MAX_UPLOAD_FILE_BYTES = 20 * 1024 * 1024  # 20MB per file
MAX_ZIP_ENTRY_BYTES = 25 * 1024 * 1024  # 25MB max for extracted file inside ZIP
MAX_ZIP_FILES_TO_EXTRACT = 3
STATE_TTL_MINUTES = 120
MAX_STATE_SESSIONS = 500

# In-memory state by browser session id. Keeps large snippets out of cookies.
APP_STATE = {}
LOG_TYPE_PRIORITY = {"GENERIC": 0, "INTUNE": 1, "FSLOGIX": 2}


def _prune_state(now):
    stale_keys = []
    for sid, state in APP_STATE.items():
        last_accessed = state.get("last_accessed")
        if not last_accessed or (now - last_accessed).total_seconds() > STATE_TTL_MINUTES * 60:
            stale_keys.append(sid)

    for sid in stale_keys:
        APP_STATE.pop(sid, None)

    if len(APP_STATE) <= MAX_STATE_SESSIONS:
        return

    sorted_sessions = sorted(
        APP_STATE.items(),
        key=lambda item: item[1].get("last_accessed", datetime.min),
    )
    excess = len(APP_STATE) - MAX_STATE_SESSIONS
    for sid, _ in sorted_sessions[:excess]:
        APP_STATE.pop(sid, None)


def get_state():
    now = datetime.now()
    _prune_state(now)

    sid = session.get("sid")
    if not sid:
        sid = str(uuid.uuid4())
        session["sid"] = sid

    if sid not in APP_STATE:
        APP_STATE[sid] = {
            "report_history": [],
            "active_analysis": None,
            "active_snippet": None,
            "qa_history": [],
            "detected_log_type": None,
            "snippet": None,
            "metrics": None,
            "uploaded_files": [],
            "analysis_mode": "default",
            "last_accessed": now,
        }

    APP_STATE[sid]["last_accessed"] = now
    return APP_STATE[sid]


def get_file_size(uploaded_file):
    uploaded_file.stream.seek(0, os.SEEK_END)
    size = uploaded_file.stream.tell()
    uploaded_file.stream.seek(0)
    return size


def is_allowed_upload(filename):
    return Path(filename).suffix.lower() in ALLOWED_UPLOAD_EXTENSIONS


def validate_uploads(uploaded_files):
    if not uploaded_files or not any(f.filename for f in uploaded_files):
        return "Please upload at least one log file."

    actual_files = [f for f in uploaded_files if f and f.filename]
    if len(actual_files) > MAX_UPLOAD_FILES:
        return f"Too many files uploaded. Maximum allowed is {MAX_UPLOAD_FILES}."

    for uploaded_file in actual_files:
        if not is_allowed_upload(uploaded_file.filename):
            return f"Unsupported file type: {uploaded_file.filename}. Allowed: .log, .txt, .zip"

        if get_file_size(uploaded_file) > MAX_UPLOAD_FILE_BYTES:
            return (
                f"File too large: {uploaded_file.filename}. "
                f"Maximum per-file size is {MAX_UPLOAD_FILE_BYTES // (1024 * 1024)}MB."
            )

    return None


def update_detected_type(current_type, candidate_type):
    """Preserve the most specific detected log type across all uploads."""
    return (
        candidate_type
        if LOG_TYPE_PRIORITY.get(candidate_type, 0) > LOG_TYPE_PRIORITY.get(current_type, 0)
        else current_type
    )



def _select_zip_candidates(zip_handle, file_names, detected_type):
    target_patterns = LOG_PROFILES[detected_type]["priority_files"]
    selected = []
    seen = set()

    for pattern in target_patterns:
        matches = [
            file_name
            for file_name in file_names
            if fnmatch.fnmatch(file_name.lower(), pattern.lower())
        ]
        for match in sorted(
            matches,
            key=lambda file_name: zip_handle.getinfo(file_name).file_size,
            reverse=True,
        ):
            if match not in seen:
                selected.append(match)
                seen.add(match)
            if len(selected) >= MAX_ZIP_FILES_TO_EXTRACT:
                return selected

    if selected:
        return selected

    logs = [file_name for file_name in file_names if file_name.lower().endswith(".log")]
    logs.sort(
        key=lambda file_name: zip_handle.getinfo(file_name).file_size,
        reverse=True,
    )
    return logs[:MAX_ZIP_FILES_TO_EXTRACT]

def parse_uploads(uploaded_files):
    combined_log_text = ""
    file_names = [f.filename for f in uploaded_files if f and f.filename]
    detected_log_type = "GENERIC"

    for uploaded_file in uploaded_files:
        if not uploaded_file or not uploaded_file.filename:
            continue

        file_text = ""
        uploaded_file.stream.seek(0)

        if uploaded_file.filename.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(uploaded_file.stream) as zip_handle:
                    all_files = [name for name in zip_handle.namelist() if not name.endswith("/")]
                    zip_detected = detect_log_type(uploaded_file.filename, file_list=all_files)
                    detected_log_type = update_detected_type(detected_log_type, zip_detected)

                    chosen_files = _select_zip_candidates(zip_handle, all_files, zip_detected)
                    for chosen_file in chosen_files:
                        chosen_info = zip_handle.getinfo(chosen_file)
                        if chosen_info.file_size > MAX_ZIP_ENTRY_BYTES:
                            flash(
                                f"Skipped {chosen_file} from {uploaded_file.filename}: "
                                f"file is larger than {MAX_ZIP_ENTRY_BYTES // (1024 * 1024)}MB.",
                                "error",
                            )
                            continue

                        combined_log_text += (
                            f"\n\n--- EXTRACTED: {chosen_file} (from {uploaded_file.filename}) ---\n"
                        )
                        with zip_handle.open(chosen_file) as extracted_file:
                            decoded = decode_file(extracted_file.read())
                            if decoded:
                                file_text += f"\n{decoded}" if file_text else decoded
            except Exception as exc:
                flash(f"Error reading ZIP {uploaded_file.filename}: {exc}", "error")
        else:
            combined_log_text += f"\n\n--- FILE: {uploaded_file.filename} ---\n"
            file_text = decode_file(uploaded_file.stream.read())
            file_detected = detect_log_type(uploaded_file.filename, content=file_text)
            detected_log_type = update_detected_type(detected_log_type, file_detected)

        if file_text:
            combined_log_text += file_text

    return combined_log_text, file_names, detected_log_type


def _parse_pipe_row(segment):
    cells = [cell.strip() for cell in segment.split("|") if cell.strip()]
    return cells if len(cells) >= 3 else None


def normalize_remediation_markdown(content):
    """Normalize flattened pipe-delimited remediation output into a markdown table."""
    if not content:
        return content

    if "| ---" in content or "|---" in content:
        return content

    rows = []
    segments = [part.strip() for part in re.split(r"\s*\|\|\s*", content.strip()) if part.strip()]
    for segment in segments:
        parsed = _parse_pipe_row(segment)
        if parsed:
            rows.append(parsed[:3])

    if len(rows) < 2:
        flat_cells = [cell.strip() for cell in content.replace("\n", " ").split("|") if cell.strip()]
        if len(flat_cells) >= 6:
            rows = [
                flat_cells[idx:idx + 3]
                for idx in range(0, len(flat_cells), 3)
                if len(flat_cells[idx:idx + 3]) == 3
            ]

    if len(rows) < 2:
        return content

    header = rows[0]
    if [h.lower() for h in header] != ["phase", "action", "command"]:
        return content

    table_lines = [
        "| Phase | Action | Command |",
        "| --- | --- | --- |",
    ]
    for phase, action, command in rows[1:]:
        table_lines.append(f"| {phase} | {action} | {command} |")

    return "\n".join(table_lines)


def render_markdown(content):
    rendered_html = markdown.markdown(content, extensions=["tables", "fenced_code"])
    if bleach:
        allowed_tags = list(bleach.sanitizer.ALLOWED_TAGS) + [
            "p",
            "pre",
            "code",
            "table",
            "thead",
            "tbody",
            "tr",
            "th",
            "td",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "ul",
            "ol",
            "li",
            "strong",
            "em",
            "blockquote",
            "hr",
            "br",
        ]
        allowed_attrs = {
            "a": ["href", "title", "target", "rel"],
            "th": ["colspan", "rowspan"],
            "td": ["colspan", "rowspan"],
        }
        rendered_html = bleach.clean(
            rendered_html,
            tags=allowed_tags,
            attributes=allowed_attrs,
            protocols=["http", "https", "mailto"],
            strip=True,
        )
    else:
        rendered_html = re.sub(
            r"<(script|style).*?>.*?</\1>",
            "",
            rendered_html,
            flags=re.IGNORECASE | re.DOTALL,
        )
    return Markup(rendered_html)


@app.route("/", methods=["GET"])
def index():
    state = get_state()
    analysis = state.get("active_analysis")
    analysis_part1 = None
    analysis_part2 = None
    if analysis:
        if "|||SPLIT|||" in analysis:
            analysis_part1, analysis_part2 = analysis.split("|||SPLIT|||", 1)
        else:
            analysis_part1 = analysis

    selected_mode = state.get("analysis_mode", "default")
    missing_config = get_missing_config(profile=selected_mode)
    backend_provider = get_provider(profile=selected_mode)
    has_missing_config = False
    if isinstance(missing_config, dict):
        has_missing_config = any(missing_config.get(key) for key in ["azure", "openai"])
    else:
        has_missing_config = bool(missing_config)

    return render_template(
        "index.html",
        state=state,
        missing_config=missing_config,
        has_missing_config=has_missing_config,
        backend_provider=backend_provider,
        analysis_mode=selected_mode,
        max_upload_files=MAX_UPLOAD_FILES,
        max_upload_file_mb=MAX_UPLOAD_FILE_BYTES // (1024 * 1024),
        analysis_part1=render_markdown(analysis_part1) if analysis_part1 else None,
        analysis_part2=render_markdown(normalize_remediation_markdown(analysis_part2))
        if analysis_part2
        else None,
    )


@app.post("/analyze")
def analyze():
    state = get_state()
    uploaded_files = request.files.getlist("log_files")
    enable_sanitization = request.form.get("sanitize") == "on"
    analysis_mode = request.form.get("analysis_mode", "default").strip().lower()
    if analysis_mode not in {"default", "deep"}:
        analysis_mode = "default"

    upload_error = validate_uploads(uploaded_files)
    if upload_error:
        flash(upload_error, "error")
        return redirect(url_for("index"))

    combined_log_text, file_names, detected_log_type = parse_uploads(uploaded_files)

    if len(combined_log_text) <= 100:
        flash("Could not decode files.", "error")
        return redirect(url_for("index"))

    processed_text = sanitize_log(combined_log_text) if enable_sanitization else combined_log_text
    snippet = extract_errors(processed_text, log_type=detected_log_type)

    state["qa_history"] = []
    raw_response, _ = analyze_with_ai(
        snippet,
        log_type=detected_log_type,
        analysis_mode=analysis_mode,
    )
    state["active_analysis"] = raw_response
    state["active_snippet"] = snippet
    state["snippet"] = snippet
    state["detected_log_type"] = detected_log_type
    state["uploaded_files"] = file_names
    state["analysis_mode"] = analysis_mode
    state["metrics"] = (
        extract_performance_metrics(processed_text) if detected_log_type == "FSLOGIX" else None
    )

    state["report_history"].append(
        {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "files": ", ".join(file_names),
            "result": raw_response,
        }
    )
    flash(f"Analysis complete ({detected_log_type}, mode: {analysis_mode}).", "success")
    return redirect(url_for("index"))


@app.post("/ask")
def ask():
    state = get_state()
    question = request.form.get("question", "").strip()
    if not state.get("active_snippet"):
        flash("Run an analysis before asking questions.", "error")
        return redirect(url_for("index"))
    if not question:
        flash("Question cannot be empty.", "error")
        return redirect(url_for("index"))

    analysis_mode = state.get("analysis_mode", "default")
    answer = ask_log_question(state["active_snippet"], question, analysis_mode=analysis_mode)
    state["qa_history"].append((question, answer))
    return redirect(url_for("index"))


@app.post("/feedback")
def feedback():
    state = get_state()
    sentiment = request.form.get("sentiment")
    if not state.get("active_analysis"):
        flash("No active analysis to rate.", "error")
        return redirect(url_for("index"))

    sentiment_text = "Positive" if sentiment == "positive" else "Negative"
    save_feedback(
        sentiment_text,
        "User Voted",
        state.get("active_snippet", ""),
        state.get("active_analysis", ""),
    )
    flash("Feedback saved.", "success")
    return redirect(url_for("index"))


@app.get("/download")
def download_report():
    state = get_state()
    analysis = state.get("active_analysis")
    if not analysis:
        flash("No report to download.", "error")
        return redirect(url_for("index"))

    report_content = analysis.replace("|||SPLIT|||", "\n\n## Remediation Plan\n")
    report_bytes = io.BytesIO(report_content.encode("utf-8"))
    report_bytes.seek(0)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        report_bytes,
        as_attachment=True,
        download_name=f"log_report_{timestamp}.md",
        mimetype="text/markdown",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8501, debug=True)
