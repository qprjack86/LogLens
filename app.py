import streamlit as st
from openai import AzureOpenAI
import zipfile
import re
import os
import pandas as pd
import csv
from datetime import datetime

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="FSLogix Log Analyser",
    page_icon="🔍",
    layout="wide"
)

# --- 1. INITIALIZE SESSION STATE ---
if "report_history" not in st.session_state:
    st.session_state.report_history = []
if "active_analysis" not in st.session_state:
    st.session_state.active_analysis = None
if "active_snippet" not in st.session_state:
    st.session_state.active_snippet = None

# --- AI CLIENT SETUP ---
def get_secret(key):
    value = os.environ.get(key)
    if value: return value
    try: return st.secrets[key]
    except: return None

try:
    client = AzureOpenAI(
        api_key=get_secret("AZURE_OPENAI_API_KEY"),
        api_version=get_secret("AZURE_OPENAI_API_VERSION"),
        azure_endpoint=get_secret("AZURE_OPENAI_ENDPOINT")
    )
    DEPLOYMENT_NAME = get_secret("AZURE_OPENAI_DEPLOYMENT_NAME")
except Exception as e:
    st.error(f"Connection Error: {e}")
    st.stop()

# --- HELPER FUNCTIONS ---

def decode_file(bytes_data):
    encodings = ['utf-8', 'utf-16-le', 'cp1252', 'latin-1']
    for enc in encodings:
        try: return bytes_data.decode(enc)
        except UnicodeDecodeError: continue
    return None 

def sanitize_log(log_content):
    log_content = re.sub(r'S-1-5-21-\d+-\d+-\d+-\d+', r'[USER_SID]', log_content)
    log_content = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', r'[USER_UPN]', log_content)
    log_content = re.sub(r'([a-zA-Z0-9-]+\\[a-zA-Z0-9._-]+)', r'[DOMAIN\\USER]', log_content)
    log_content = re.sub(r'\\\\([a-zA-Z0-9\.\-_]+)', r'\\\\[FILE_SERVER]', log_content)
    return log_content

def get_log_timeline(log_content):
    matches = re.findall(r"^\[(\d{2}:\d{2}:\d{2})", log_content, re.MULTILINE)
    if not matches: return None
    df = pd.DataFrame(matches, columns=['Time'])
    df['Count'] = 1
    return df.groupby('Time').count().reset_index()

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

def extract_errors(log_content):
    lines = log_content.split('\n')
    relevant_lines = []
    count = 0
    for line in lines:
        if any(keyword in line for keyword in ["ERROR", "Reason:", "Status:"]):
            relevant_lines.append(line.strip())
            count += 1
            if count >= 40: 
                relevant_lines.append("... [Truncated] ...")
                break
    if not relevant_lines:
        relevant_lines = ["--- No explicit ERROR tags found. Showing last 20 lines ---"] + lines[-20:]
    
    full_text = "\n".join(relevant_lines)
    if len(full_text) > 12000: return full_text[:12000] + "\n... [Hard truncated]"
    return full_text

def save_feedback(sentiment, feedback_text, log_snippet, ai_response):
    """
    Saves user feedback to a local CSV file.
    Note: In Azure Container Apps, this file is ephemeral (lost on restart).
    To make it permanent, you would send this data to Azure Log Analytics or Blob Storage.
    """
    file_exists = os.path.isfile('feedback_log.csv')
    with open('feedback_log.csv', mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['Timestamp', 'Sentiment', 'Feedback', 'Snippet', 'AI_Response'])
        
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            sentiment,
            feedback_text,
            log_snippet[:200], # Save just the start of the log for context
            ai_response[:200]
        ])

@st.cache_data(show_spinner=False, ttl=3600)
def analyze_with_ai(sanitized_snippet):
    if not sanitized_snippet or len(sanitized_snippet) < 5:
        return "ERROR_EMPTY", None

    prompt = f"""
    You are a Senior FSLogix Escalation Engineer.
    Analyze the log snippet below.

    **Output Structure (Strict Order):**

    1. **ROOT CAUSE EXECUTIVE SUMMARY** (Text Only):
       - Start with a header: `### 🎯 Root Cause: [Short Reason]`
       - Write 2-3 sentences explaining exactly *why* this happened.

    2. **ERROR CODE TABLE** (Markdown Table):
       - Summarize unique error codes.
       - Columns: [Code, Meaning, Context]

    3. **Separator:**
       - IMMEDIATELY AFTER the error table, print exactly: |||SPLIT|||

    4. **TROUBLESHOOTING TABLE** (Markdown Table Only):
       - **CRITICAL INSTRUCTION:** Do NOT print a text title (like "Troubleshooting Plan").
       - **Start IMMEDIATELY** with the Markdown table headers.
       - **Columns:** [Step, Phase, Action, Command/Detail]
       - **Mandatory Flow:**
         - Validation -> Immediate Fix -> Prevention -> Escalation.

    LOG DATA:
    {sanitized_snippet}
    """
    try:
        response = client.chat.completions.create(
            model=DEPLOYMENT_NAME,
            messages=[{"role": "user", "content": prompt}],
            max_completion_tokens=4000 
        )
        return response.choices[0].message.content, response.usage
    except Exception as e:
        return f"Error: {str(e)}", None

# --- MAIN UI ---
st.title("🔍 FSLogix AI Analyser")
st.markdown("""
This tool uses **Azure OpenAI** to analyse FSLogix profile logs.
> 🔒 **Security Note:** Logs are processed **in memory** and discarded immediately.
""")
st.divider()

col_settings, col_upload = st.columns([1, 2])
with col_settings:
    st.subheader("⚙️ Settings")
    enable_sanitization = st.checkbox("Strip PII (Usernames/SIDs)", value=False)

with col_upload:
    uploaded_files = st.file_uploader("Upload Logs", type=["log", "zip", "txt"], accept_multiple_files=True)

if uploaded_files:
    combined_log_text = ""
    file_names = [f.name for f in uploaded_files]

    for uploaded_file in uploaded_files:
        file_text = ""
        combined_log_text += f"\n\n--- FILE: {uploaded_file.name} ---\n"
        if uploaded_file.name.endswith('.zip'):
            try:
                with zipfile.ZipFile(uploaded_file) as z:
                    logs = [f for f in z.namelist() if "Profile_" in f and f.endswith(".log")]
                    if logs:
                        with z.open(logs[0]) as f: file_text = decode_file(f.read())
            except: pass
        else:
            file_text = decode_file(uploaded_file.getvalue())
        if file_text: combined_log_text += file_text

    if len(combined_log_text) > 100:
        processed_text = sanitize_log(combined_log_text) if enable_sanitization else combined_log_text
        
        # --- DASHBOARD & METRICS ---
        metrics = extract_performance_metrics(processed_text)
        if metrics:
            st.subheader("⏱️ Session Health")
            m1, m2, m3 = st.columns(3)
            m1.metric("Profile Load Time", metrics.get("Load Profile Time"), help="If 'Failed', logon crashed.")
            m2.metric("VHD Mount Time", metrics.get("VHD Mount Time"), help=">1000ms = Storage Latency")
            count = metrics.get("Total Errors", 0)
            m3.metric("Critical Errors", count, delta="Issues" if count > 0 else "Healthy", delta_color="inverse")
            
            timeline_df = get_log_timeline(processed_text)
            if timeline_df is not None and not timeline_df.empty:
                st.line_chart(timeline_df, x='Time', y='Count', color="#0078D4", height=200)
            st.divider()

        # --- EXTRACT SNIPPET ---
        snippet = extract_errors(processed_text)
        with st.expander(f"📂 View Extracted Snippet"): st.text(snippet)
        
        # --- ACTION: RUN ANALYSIS ---
        if st.button("Run Analysis", type="primary"):
            with st.spinner('Analyzing...'):
                raw_response, usage_stats = analyze_with_ai(snippet)
                
                # SAVE TO STATE (Persists across feedback clicks)
                st.session_state.active_analysis = raw_response
                st.session_state.active_snippet = snippet
                st.session_state.report_history.append({
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "files": ", ".join(file_names),
                    "result": raw_response
                })
        
        # --- DISPLAY RESULT (IF EXISTS) ---
        if st.session_state.active_analysis:
            raw_response = st.session_state.active_analysis
            
            if "|||SPLIT|||" in raw_response:
                part1, part2 = raw_response.split("|||SPLIT|||")
                c1, c2 = st.columns(2)
                with c1: st.markdown(part1)
                with c2: 
                    st.subheader("🛠️ Suggested Troubleshooting Plan")
                    st.markdown(part2)
            else:
                st.warning("Raw Output:")
                st.markdown(raw_response)
            
            st.divider()
            
            # --- FEEDBACK LOOP ---
            st.subheader("📢 Rate this Analysis")
            st.caption("Help us improve the AI accuracy.")
            
            # This widget creates Thumbs Up/Down buttons
            sentiment = st.feedback("thumbs")
            
            if sentiment is not None:
                # 0 = Down, 1 = Up
                sentiment_text = "Positive" if sentiment == 1 else "Negative"
                save_feedback(sentiment_text, "User Voted", st.session_state.active_snippet, raw_response)
                st.toast(f"Thank you for your feedback! ({sentiment_text})")

            # --- DOWNLOAD ---
            st.download_button("📥 Download Report", raw_response.replace("|||SPLIT|||", "\n\n## Troubleshooting\n"), "fslogix_report.md")

    elif uploaded_files: st.error("❌ Could not decode files.")

# --- SIDEBAR HISTORY ---
with st.sidebar:
    st.header("🕒 Recent Analysis")
    if not st.session_state.report_history: st.info("No logs analyzed yet.")
    for item in reversed(st.session_state.report_history):
        with st.expander(f"{item['timestamp']} - {item['files'][:20]}..."):
            if "|||SPLIT|||" in item['result']:
                parts = item['result'].split("|||SPLIT|||")
                st.markdown("**Root Cause:**\n" + parts[0])
                st.markdown("---")
                st.markdown("**Fixes:**\n" + parts[1])
            else: st.markdown(item['result'])