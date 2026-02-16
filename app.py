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

from azure_client import get_missing_config
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

# In-memory state by browser session id. Keeps large snippets out of cookies.
APP_STATE = {}


def get_state():
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
        }
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
                    all_files = zip_handle.namelist()
                    detected_log_type = detect_log_type(uploaded_file.filename, file_list=all_files)

                    target_patterns = LOG_PROFILES[detected_log_type]["priority_files"]
                    chosen_file = None
                    for pattern in target_patterns:
                        matches = [
                            file_name
                            for file_name in all_files
                            if fnmatch.fnmatch(file_name.lower(), pattern.lower())
                        ]
                        if matches:
                            chosen_file = matches[0]
                            break

                    if not chosen_file:
                        logs = [file_name for file_name in all_files if file_name.lower().endswith(".log")]
                        if logs:
                            logs.sort(
                                key=lambda file_name: zip_handle.getinfo(file_name).file_size,
                                reverse=True,
                            )
                            chosen_file = logs[0]

                    if chosen_file:
                        combined_log_text += (
                            f"\n\n--- EXTRACTED: {chosen_file} (from {uploaded_file.filename}) ---\n"
                        )
                        with zip_handle.open(chosen_file) as extracted_file:
                            decoded = decode_file(extracted_file.read())
                            if decoded:
                                file_text = decoded
            except Exception as exc:
                flash(f"Error reading ZIP {uploaded_file.filename}: {exc}", "error")
        else:
            combined_log_text += f"\n\n--- FILE: {uploaded_file.filename} ---\n"
            file_text = decode_file(uploaded_file.stream.read())
            file_detected = detect_log_type(uploaded_file.filename, content=file_text)
            if file_detected != "GENERIC":
                detected_log_type = file_detected

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

    missing_config = get_missing_config()
    backend_provider = os.environ.get("LLM_PROVIDER", "auto")
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
    raw_response, _ = analyze_with_ai(snippet, log_type=detected_log_type)
    state["active_analysis"] = raw_response
    state["active_snippet"] = snippet
    state["snippet"] = snippet
    state["detected_log_type"] = detected_log_type
    state["uploaded_files"] = file_names
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
    flash(f"Analysis complete ({detected_log_type}).", "success")
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

    answer = ask_log_question(state["active_snippet"], question)
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
