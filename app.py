import streamlit as st
import zipfile
import fnmatch
from datetime import datetime

# --- IMPORT MODULES ---
from analysis_engine import (
    decode_file, 
    sanitize_log, 
    extract_performance_metrics, 
    extract_errors, 
    analyze_with_ai, 
    save_feedback,
    ask_log_question,
    detect_log_type,
    LOG_PROFILES
)

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="Universal Log Analyser", page_icon="🔍", layout="wide")

# --- SESSION STATE ---
if "report_history" not in st.session_state: st.session_state.report_history = []
if "active_analysis" not in st.session_state: st.session_state.active_analysis = None
if "active_snippet" not in st.session_state: st.session_state.active_snippet = None
if "qa_history" not in st.session_state: st.session_state.qa_history = [] 

# --- MAIN UI ---
st.title("🔍 Universal Log Analyser")
st.markdown("Analyze **FSLogix**, **Intune**, and **System** logs using Azure OpenAI.")
st.divider()

col_settings, col_upload = st.columns([1, 2])
with col_settings:
    st.subheader("⚙️ Settings")
    enable_sanitization = st.checkbox("Strip PII (Usernames/SIDs)", value=False)

with col_upload:
    uploaded_files = st.file_uploader("Upload Logs (ZIPs supported)", type=["log", "zip", "txt"], accept_multiple_files=True)

if uploaded_files:
    combined_log_text = ""
    file_names = [f.name for f in uploaded_files]
    detected_log_type = "GENERIC" # Default
    
    # 1. READ FILES SMARTLY
    for uploaded_file in uploaded_files:
        file_text = ""
        
        # --- ZIP HANDLING ---
        if uploaded_file.name.endswith('.zip'):
            try:
                with zipfile.ZipFile(uploaded_file) as z:
                    all_files = z.namelist()
                    
                    # A. Detect Type based on file structure
                    detected_log_type = detect_log_type(uploaded_file.name, file_list=all_files)
                    
                    # B. Find Priority File
                    # We look for the "Best" log file inside the zip based on the profile
                    target_patterns = LOG_PROFILES[detected_log_type]["priority_files"]
                    
                    chosen_file = None
                    for pattern in target_patterns:
                        # Find matching file (case insensitive wildcard match)
                        matches = [f for f in all_files if fnmatch.fnmatch(f.lower(), pattern.lower())]
                        if matches:
                            chosen_file = matches[0] # Pick the first match
                            break
                    
                    # C. Fallback: If no priority file found, grab largest .log
                    if not chosen_file:
                        logs = [f for f in all_files if f.endswith(".log")]
                        if logs: 
                            # Sort by size to get the main log, not a tiny setup log
                            logs.sort(key=lambda x: z.getinfo(x).file_size, reverse=True)
                            chosen_file = logs[0]

                    if chosen_file:
                        combined_log_text += f"\n\n--- EXTRACTED: {chosen_file} (from {uploaded_file.name}) ---\n"
                        with z.open(chosen_file) as f: 
                            decoded = decode_file(f.read())
                            if decoded: file_text = decoded
            except Exception as e:
                st.error(f"Error reading ZIP: {e}")

        # --- SINGLE FILE HANDLING ---
        else:
            combined_log_text += f"\n\n--- FILE: {uploaded_file.name} ---\n"
            file_text = decode_file(uploaded_file.getvalue())
            # Update detection for single files
            if detect_log_type(uploaded_file.name, content=file_text) != "GENERIC":
                 detected_log_type = detect_log_type(uploaded_file.name, content=file_text)

        if file_text: combined_log_text += file_text

    if len(combined_log_text) > 100:
        
        # UI Badge for Log Type
        if detected_log_type == "FSLOGIX":
            st.info(f"📂 **Detected:** FSLogix Profile Log")
        elif detected_log_type == "INTUNE":
            st.success(f"📱 **Detected:** Microsoft Intune Log")
        else:
            st.warning(f"📄 **Detected:** Generic Log")

        processed_text = sanitize_log(combined_log_text) if enable_sanitization else combined_log_text
        
        # DASHBOARD (FSLogix Only)
        if detected_log_type == "FSLOGIX":
            metrics = extract_performance_metrics(processed_text)
            if metrics:
                st.subheader("⏱️ Session Health")
                m1, m2, m3 = st.columns(3)
                m1.metric("Profile Load", metrics.get("Load Profile Time"))
                m2.metric("VHD Mount", metrics.get("VHD Mount Time"))
                m3.metric("Critical Errors", metrics.get("Total Errors"))
                st.divider()

        # EXTRACTION
        snippet = extract_errors(processed_text, log_type=detected_log_type)
        with st.expander(f"📂 View Extracted Snippet ({detected_log_type} Filter)"): st.text(snippet)
        
        # ANALYSIS
        if st.button("Run Analysis", type="primary"):
            with st.spinner(f'Analyzing as {detected_log_type}...'):
                st.session_state.qa_history = [] 
                raw_response, usage_stats = analyze_with_ai(snippet, log_type=detected_log_type)
                
                st.session_state.active_analysis = raw_response
                st.session_state.active_snippet = snippet
                st.session_state.report_history.append({
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "files": ", ".join(file_names),
                    "result": raw_response
                })
        
        # RESULTS
        if st.session_state.active_analysis:
            raw_response = st.session_state.active_analysis
            
            if "|||SPLIT|||" in raw_response:
                part1, part2 = raw_response.split("|||SPLIT|||")
                st.markdown(part1) 
                st.divider()
                st.subheader("🛠️ Remediation Plan") 
                st.markdown(part2)
            else:
                st.warning("Raw Output:")
                st.markdown(raw_response)
            
            st.divider()

            # FEEDBACK
            c_feed, c_dl = st.columns([3, 1])
            with c_feed:
                st.subheader("📢 Rate Analysis")
                sentiment = st.feedback("thumbs")
                if sentiment is not None:
                    sentiment_text = "Positive" if sentiment == 1 else "Negative"
                    save_feedback(sentiment_text, "User Voted", st.session_state.active_snippet, raw_response)
                    st.toast(f"Feedback Saved")
            
            with c_dl:
                st.download_button("📥 Download Report", raw_response.replace("|||SPLIT|||", "\n\n## Remediation Plan\n"), "log_report.md")

            st.divider()

            # Q&A
            st.subheader("💬 Ask the Log")
            for q, a in st.session_state.qa_history:
                with st.chat_message("user"): st.write(q)
                with st.chat_message("assistant"): st.write(a)

            if question := st.chat_input("Ask a question about this log..."):
                with st.chat_message("user"): st.write(question)
                with st.spinner("Checking log..."):
                    answer = ask_log_question(st.session_state.active_snippet, question)
                    with st.chat_message("assistant"): st.write(answer)
                    st.session_state.qa_history.append((question, answer))
            
    elif uploaded_files: st.error("❌ Could not decode files.")

# SIDEBAR
with st.sidebar:
    st.header("🕒 Recent Analysis")
    for item in reversed(st.session_state.report_history):
        with st.expander(f"{item['timestamp']} - {item['files'][:20]}..."):
            if "|||SPLIT|||" in item['result']:
                parts = item['result'].split("|||SPLIT|||")
                st.markdown(parts[0])
            else: st.markdown(item['result'])