import re
import csv
import os
import streamlit as st
from datetime import datetime
from collections import deque
from azure_client import client, DEPLOYMENT_NAME

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
    
    # 1. Keep a running buffer of the last 3 lines (Pre-Context)
    # This helps catch "Disk Full" or "Network Timeout" events that occur 
    # immediately *before* the actual [ERROR] tag.
    line_buffer = deque(maxlen=3) 
    
    count = 0
    for line in lines:
        if any(keyword in line for keyword in ["ERROR", "Reason:", "Status:"]):
            # Add the context (lines leading up to the error)
            relevant_lines.extend(list(line_buffer))
            # Add the error line itself
            relevant_lines.append(line.strip())
            # Add a visual separator for the AI
            relevant_lines.append("---")
            
            count += 1
            if count >= 40: 
                relevant_lines.append("... [Truncated] ...")
                break
        
        # Update buffer
        line_buffer.append(line.strip())
            
    if not relevant_lines:
        relevant_lines = ["--- No explicit ERROR tags found. Showing last 20 lines ---"] + lines[-20:]
    
    # Deduplicate lines while preserving order
    seen = set()
    final_lines = []
    for line in relevant_lines:
        if line not in seen:
            final_lines.append(line)
            seen.add(line)
    
    full_text = "\n".join(final_lines)
    if len(full_text) > 12000: return full_text[:12000] + "\n... [Hard truncated]"
    return full_text

def save_feedback(sentiment, feedback_text, log_snippet, ai_response):
    file_exists = os.path.isfile('feedback_log.csv')
    with open('feedback_log.csv', mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['Timestamp', 'Sentiment', 'Feedback', 'Snippet', 'AI_Response'])
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            sentiment,
            feedback_text,
            log_snippet[:200], 
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
       - Columns: [Code, Meaning, Context, Documentation]
       - **Instruction:** In the 'Documentation' column, provide a generic Microsoft Learn search link or official KBA if known.

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

# --- NEW: Q&A Function ---
def ask_log_question(snippet, question):
    """
    Allows the user to ask specific follow-up questions about the log.
    """
    prompt = f"""
    You are an FSLogix Log Assistant.
    Context (Log Snippet):
    {snippet}
    
    User Question: "{question}"
    
    Answer concisely based ONLY on the log data provided. If the log doesn't show the answer, say "Not found in log snippet."
    """
    try:
        response = client.chat.completions.create(
            model=DEPLOYMENT_NAME,
            messages=[{"role": "user", "content": prompt}],
            max_completion_tokens=500
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {str(e)}"