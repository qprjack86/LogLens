import fnmatch
import os
import re
import uuid
import zipfile
from datetime import datetime

from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for
from markupsafe import Markup
import markdown

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


def parse_uploads(uploaded_files):
    combined_log_text = ""
    file_names = [f.filename for f in uploaded_files if f and f.filename]
    detected_log_type = "GENERIC"

    for uploaded_file in uploaded_files:
        if not uploaded_file or not uploaded_file.filename:
            continue

        file_text = ""

        if uploaded_file.filename.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(uploaded_file.stream) as z:
                    all_files = z.namelist()
                    detected_log_type = detect_log_type(uploaded_file.filename, file_list=all_files)

                    target_patterns = LOG_PROFILES[detected_log_type]["priority_files"]
                    chosen_file = None
                    for pattern in target_patterns:
                        matches = [f for f in all_files if fnmatch.fnmatch(f.lower(), pattern.lower())]
                        if matches:
                            chosen_file = matches[0]
                            break

                    if not chosen_file:
                        logs = [f for f in all_files if f.lower().endswith(".log")]
                        if logs:
                            logs.sort(key=lambda x: z.getinfo(x).file_size, reverse=True)
                            chosen_file = logs[0]

                    if chosen_file:
                        combined_log_text += (
                            f"\n\n--- EXTRACTED: {chosen_file} (from {uploaded_file.filename}) ---\n"
                        )
                        with z.open(chosen_file) as f:
                            decoded = decode_file(f.read())
                            if decoded:
                                file_text = decoded
            except Exception as exc:
                flash(f"Error reading ZIP {uploaded_file.filename}: {exc}", "error")
        else:
            combined_log_text += f"\n\n--- FILE: {uploaded_file.filename} ---\n"
            file_text = decode_file(uploaded_file.read())
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

    # If a valid markdown table separator already exists, keep original formatting.
    if "| ---" in content or "|---" in content:
        return content

    rows = []
    segments = [part.strip() for part in re.split(r"\s*\|\|\s*", content.strip()) if part.strip()]
    for segment in segments:
        parsed = _parse_pipe_row(segment)
        if parsed:
            rows.append(parsed[:3])

    # Fallback for flattened text like: | Phase | Action | Command | | Phase | ...
    if len(rows) < 2:
        flat_cells = [cell.strip() for cell in content.replace("\n", " ").split("|") if cell.strip()]
        if len(flat_cells) >= 6:
            rows = [flat_cells[idx:idx + 3] for idx in range(0, len(flat_cells), 3) if len(flat_cells[idx:idx + 3]) == 3]

    if len(rows) < 2:
        return content

    header = rows[0]
    expected_header = ["phase", "action", "command"]
    if [h.lower() for h in header] != expected_header:
        return content

    table_lines = [
        "| Phase | Action | Command |",
        "| --- | --- | --- |",
    ]
    for phase, action, command in rows[1:]:
        table_lines.append(f"| {phase} | {action} | {command} |")

    return "\n".join(table_lines)


def render_markdown(content):
    return Markup(markdown.markdown(content, extensions=["tables", "fenced_code"]))


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

    return render_template(
        "index.html",
        state=state,
        missing_config=missing_config,
        analysis_part1=render_markdown(analysis_part1) if analysis_part1 else None,
        analysis_part2=render_markdown(normalize_remediation_markdown(analysis_part2)) if analysis_part2 else None,
    )


@app.post("/analyze")
def analyze():
    state = get_state()
    uploaded_files = request.files.getlist("log_files")
    enable_sanitization = request.form.get("sanitize") == "on"

    if not uploaded_files or not any(f.filename for f in uploaded_files):
        flash("Please upload at least one log file.", "error")
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
    path = "log_report.md"
    with open(path, "w", encoding="utf-8") as file:
        file.write(report_content)
    return send_file(path, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8501, debug=True)
