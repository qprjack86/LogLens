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
    save_feedback,
    ask_log_question 
)

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="FSLogix Log Analyser", page_icon="🔍", layout="wide")

# --- SESSION STATE ---
if "report_history" not in st.session_state: st.session_state.report_history = []
if "active_analysis" not in st.session_state: st.session_state.active_analysis = None
if "active_snippet" not in st.session_state: st.session_state.active_snippet = None
if "qa_history" not in st.session_state: st.session_state.qa_history = [] 

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
                st.session_state.qa_history = [] # Reset Q&A
                raw_response, usage_stats = analyze_with_ai(snippet)
                st.session_state.active_analysis = raw_response
                st.session_state.active_snippet = snippet
                st.session_state.report_history.append({
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "files": ", ".join(file_names),
                    "result": raw_response
                })
        
        # --- RESULTS ---
        if st.session_state.active_analysis:
            raw_response = st.session_state.active_analysis
            
            # --- LAYOUT FIX: STACKED instead of COLUMNS ---
            if "|||SPLIT|||" in raw_response:
                part1, part2 = raw_response.split("|||SPLIT|||")
                
                # Part 1: Root Cause & Error Table (FULL WIDTH)
                st.markdown(part1) 
                
                st.divider()
                
                # Part 2: Remediation Plan (FULL WIDTH)
                # Removed the manual "Suggested Troubleshooting Plan" header
                st.subheader("🛠️ Remediation Plan") 
                st.markdown(part2)
            else:
                st.warning("Raw Output:")
                st.markdown(raw_response)
            
            st.divider()

            # --- FEEDBACK & DOWNLOAD (MIDDLE SECTION) ---
            c_feed, c_dl = st.columns([3, 1])
            with c_feed:
                st.subheader("📢 Rate Analysis")
                sentiment = st.feedback("thumbs")
                if sentiment is not None:
                    sentiment_text = "Positive" if sentiment == 1 else "Negative"
                    save_feedback(sentiment_text, "User Voted", st.session_state.active_snippet, raw_response)
                    st.toast(f"Feedback Saved: {sentiment_text}")
            
            with c_dl:
                st.download_button("📥 Download Report", raw_response.replace("|||SPLIT|||", "\n\n## Remediation Plan\n"), "fslogix_report.md")

            st.divider()

            # --- ASK THE LOG (BOTTOM SECTION) ---
            st.subheader("💬 Ask the Log")
            st.caption("Ask specific questions like 'What time did the VHD attach?' or 'Was the network down?'")
            
            # Display History
            for q, a in st.session_state.qa_history:
                with st.chat_message("user"): st.write(q)
                with st.chat_message("assistant"): st.write(a)

            # Input (Pins to bottom)
            if question := st.chat_input("Ask a question about this log..."):
                with st.chat_message("user"): st.write(question)
                with st.spinner("Checking log..."):
                    answer = ask_log_question(st.session_state.active_snippet, question)
                    with st.chat_message("assistant"): st.write(answer)
                    st.session_state.qa_history.append((question, answer))
            
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