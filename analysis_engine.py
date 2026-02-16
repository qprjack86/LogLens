import re
import csv
import os
from datetime import datetime
from collections import deque
from azure_client import get_client_and_deployment

# --- CONFIGURATION: LOG PROFILES ---
LOG_PROFILES = {
    "FSLOGIX": {
        "keywords": ["ERROR", "Reason:", "Status:", "FrxStatus"],
        "role": "Tier 3 FSLogix Escalation Engineer",
        "context_hint": "Focus on VHD locks, Authentication (0x52e), and Profile attachment.",
        "docs_link": "https://learn.microsoft.com/en-us/fslogix/troubleshooting-known-issues",
        "priority_files": ["*Profile_*.log", "*ODFC_*.log", "*frx*.log"],
    },
    "INTUNE": {
        "keywords": ["Error", "Fail", "Exception", "ExitCode", "Return code", "fatal"],
        "role": "Senior Microsoft Intune Engineer",
        "context_hint": "Focus on Win32 App installation failures, IME (Intune Management Extension) errors, PowerShell script timeouts, and Detection Method failures.",
        "docs_link": "https://learn.microsoft.com/en-us/mem/intune/apps/troubleshoot-app-install",
        "priority_files": ["*IntuneManagementExtension.log", "*AgentExecutor.log", "*AppWorkload.log"],
    },
    "GENERIC": {
        "keywords": ["Error", "Fail", "Exception", "Fatal", "Critical", "Warning"],
        "role": "Senior Windows Systems Administrator",
        "context_hint": "Analyze the log for general application or system failures.",
        "docs_link": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/welcome-windows-server",
        "priority_files": ["*.log", "*.txt"],
    },
}


def decode_file(bytes_data):
    encodings = ["utf-8", "utf-16-le", "cp1252", "latin-1"]
    for enc in encodings:
        try:
            return bytes_data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def detect_log_type(filename, content=None, file_list=None):
    """
    Determines log type based on:
    1. ZIP Contents (file_list) - MOST ACCURATE for bundles
    2. Filename
    3. Content
    """
    filename = filename.lower()

    if file_list:
        files_str = " ".join(file_list).lower()
        if "intunemanagementextension.log" in files_str or "mdmdiagnostics" in files_str:
            return "INTUNE"
        if "profile_" in files_str and ".log" in files_str:
            return "FSLOGIX"

    if "profile" in filename or "frx" in filename:
        return "FSLOGIX"
    if "intune" in filename or "ime" in filename:
        return "INTUNE"

    if content:
        if "FrxStatus" in content or "FSLogix" in content:
            return "FSLOGIX"
        if "IntuneManagementExtension" in content or "<![LOG[" in content:
            return "INTUNE"

    return "GENERIC"


def sanitize_log(log_content):
    log_content = re.sub(r"S-1-5-21-\d+-\d+-\d+-\d+", r"[USER_SID]", log_content)
    log_content = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", r"[USER_UPN]", log_content)
    log_content = re.sub(r"([a-zA-Z0-9-]+\\[a-zA-Z0-9._-]+)", r"[DOMAIN\\USER]", log_content)
    log_content = re.sub(r"\\\\([a-zA-Z0-9\.\-_]+)", r"\\\\[FILE_SERVER]", log_content)
    return log_content


def extract_errors(log_content, log_type="GENERIC"):
    lines = log_content.split("\n")
    relevant_lines = []
    line_buffer = deque(maxlen=3)

    keywords = LOG_PROFILES[log_type]["keywords"]

    count = 0
    for line in lines:
        if any(k.lower() in line.lower() for k in keywords):
            relevant_lines.extend(list(line_buffer))
            relevant_lines.append(line.strip())
            relevant_lines.append("---")
            count += 1
            if count >= 60:
                relevant_lines.append("... [Truncated] ...")
                break
        line_buffer.append(line.strip())

    if not relevant_lines:
        relevant_lines = ["--- No explicit ERROR tags found. Showing last 20 lines ---"] + lines[-20:]

    seen = set()
    final_lines = []
    for line in relevant_lines:
        if line not in seen:
            final_lines.append(line)
            seen.add(line)

    full_text = "\n".join(final_lines)
    if len(full_text) > 12000:
        return full_text[:12000] + "\n... [Hard truncated]"
    return full_text


def save_feedback(sentiment, feedback_text, log_snippet, ai_response):
    file_exists = os.path.isfile("feedback_log.csv")
    with open("feedback_log.csv", mode="a", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        if not file_exists:
            writer.writerow(["Timestamp", "Sentiment", "Feedback", "Snippet", "AI_Response"])
        writer.writerow(
            [
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                sentiment,
                feedback_text,
                log_snippet[:200],
                ai_response[:200],
            ]
        )


def _backend_unavailable_message(error_message):
    return (
        "### Model Backend Configuration Error\n"
        f"{error_message}\n\n"
        "Configure one backend and retry:\n"
        "\nAzure OpenAI:\n"
        "- AZURE_OPENAI_API_KEY\n"
        "- AZURE_OPENAI_API_VERSION\n"
        "- AZURE_OPENAI_ENDPOINT\n"
        "- AZURE_OPENAI_DEPLOYMENT_NAME\n"
        "\nOpenAI-compatible (e.g., kimi):\n"
        "- OPENAI_API_KEY\n"
        "- OPENAI_MODEL\n"
        "- OPENAI_BASE_URL (optional if using non-default endpoint)\n"
        "- LLM_PROVIDER=openai (optional, forces provider selection)"
    )


def analyze_with_ai(sanitized_snippet, log_type="GENERIC"):
    if not sanitized_snippet or len(sanitized_snippet) < 5:
        return "ERROR_EMPTY", None

    client, deployment_name, error_message = get_client_and_deployment()
    if error_message:
        return _backend_unavailable_message(error_message), None

    profile = LOG_PROFILES[log_type]

    prompt = f"""
    You are a {profile['role']}. Your goal is to provide a forensic analysis of the log failure.
    **Context:** {profile['context_hint']}

    **Instructions:**
    1. **Be Forensic:** Do not guess. Quote specific error codes, exit codes, or failure reasons.
    2. **Identify Variables:** Identify the App Name, Script Path, or User involved.
    3. **PowerShell First:** Remediation commands must be PowerShell.

    **Output Structure (Strict Order):**

    **Part 1: Analysis**
    - Start immediately with a header: `### 🎯 Incident Summary`
    - **Scope:** Identify the Log Type detected ({log_type}).
    - **The Smoking Gun:** Quote the EXACT log line (with timestamp) that proves the failure.
    - **Explanation:** In technical terms, explain the mechanism of failure.

    **Part 2: Error Table**
    - Output the Markdown Table of errors (Code, Meaning, Documentation).
    - **Docs:** Link to official MS Learn pages. Primary Link: {profile['docs_link']}

    **Part 3: Separator**
    - Print exactly: |||SPLIT|||

    **Part 4: Remediation**
    - **CRITICAL:** Do NOT print the text "Remediation Plan".
    - **Start immediately** with the Markdown Table: `| Phase | Action | Command |`
    - **Style Rules:** NO backticks or code blocks inside table cells. NO prefixes.
    - **Logic:** Validation -> Fix -> Prevention.

    **Part 5: Stop**
    - End the response immediately after the table.

    LOG DATA:
    {sanitized_snippet}
    """
    try:
        response = client.chat.completions.create(
            model=deployment_name,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4000,
        )
        return response.choices[0].message.content, response.usage
    except Exception as exc:
        message = str(exc)
        if "404" in message and "Resource not found" in message:
            return (
                "Error: Resource not found from model backend. "
                "Check your deployment/model name and endpoint settings. "
                f"Current model/deployment value: {deployment_name}"
            ), None
        return f"Error: {message}", None


def ask_log_question(snippet, question):
    client, deployment_name, error_message = get_client_and_deployment()
    if error_message:
        return _backend_unavailable_message(error_message)

    prompt = f"You are a Log Assistant. Context:\n{snippet}\nQuestion: {question}\nAnswer concisely."
    try:
        response = client.chat.completions.create(
            model=deployment_name,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
        )
        return response.choices[0].message.content
    except Exception as exc:
        message = str(exc)
        if "404" in message and "Resource not found" in message:
            return (
                "Error: Resource not found from model backend. "
                "Check your deployment/model name and endpoint settings. "
                f"Current model/deployment value: {deployment_name}"
            )
        return f"Error: {message}"


def extract_performance_metrics(log_content):
    metrics = {}
    error_count = log_content.count("[ERROR")
    metrics["Total Errors"] = error_count
    match_load = re.search(r"LoadProfile successful.*Time:\s*(\d+)ms", log_content)
    if match_load:
        metrics["Load Profile Time"] = f"{int(match_load.group(1)) / 1000}s"
    else:
        metrics["Load Profile Time"] = "Failed" if error_count > 0 else "Not Found"
    match_mount = re.search(r"MountVhd Request.*Time:\s*(\d+)ms", log_content)
    if match_mount:
        metrics["VHD Mount Time"] = f"{int(match_mount.group(1))}ms"
    else:
        metrics["VHD Mount Time"] = "No Mount" if error_count > 0 else "N/A"
    return metrics
