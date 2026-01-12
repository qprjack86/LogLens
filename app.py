import streamlit as st
import zipfile
from datetime import datetime

# --- IMPORT MODULES ---
from analysis_engine import (
    decode_file, 
    sanitize_log, 
    extract_performance_metrics, 
    extract_errors, 
    analyze_with_ai, 
    save_feedback
)

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="FSLogix Log Analyser", page_icon="🔍", layout="wide")

# --- SESSION STATE ---
if "report_history" not in st.session_state: st.session_state.report_history = []
if "active_analysis" not in st.session_state: st.session_state.active_analysis = None
if "active_snippet" not in st.session_state: st.session_state.active_snippet = None

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
        
        # --- DASHBOARD ---
        metrics = extract_performance_metrics(processed_text)
        if metrics:
            st.subheader("⏱️ Session Health")
            m1, m2, m3 = st.columns(3)
            m1.metric("Profile Load", metrics.get("Load Profile Time"), help="If 'Failed', logon crashed.")
            m2.metric("VHD Mount", metrics.get("VHD Mount Time"), help=">1000ms = Storage Latency")
            count = metrics.get("Total Errors", 0)
            m3.metric("Critical Errors", count, delta="Issues" if count > 0 else "Healthy", delta_color="inverse")
            st.divider()

        # --- SNIPPET & ANALYSIS ---
        snippet = extract_errors(processed_text)
        with st.expander(f"📂 View Extracted Snippet"): st.text(snippet)
        
        if st.button("Run Analysis", type="primary"):
            with st.spinner('Analyzing...'):
                raw_response, usage_stats = analyze_with_ai(snippet)
                st.session_state.active_analysis = raw_response
                st.session_state.active_snippet = snippet
                st.session_state.report_history.append({
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "files": ", ".join(file_names),
                    "result": raw_response
                })
        
        # --- RESULTS & FEEDBACK ---
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
            
            st.subheader("📢 Rate this Analysis")
            sentiment = st.feedback("thumbs")
            if sentiment is not None:
                sentiment_text = "Positive" if sentiment == 1 else "Negative"
                save_feedback(sentiment_text, "User Voted", st.session_state.active_snippet, raw_response)
                st.toast(f"Thank you for your feedback! ({sentiment_text})")

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