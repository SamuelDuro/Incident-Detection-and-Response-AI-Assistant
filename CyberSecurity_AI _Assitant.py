import operator
import sqlite3
import time
import streamlit as st
import ollama
import subprocess
import json
import re
import platform
import math
from typing import Annotated, List, TypedDict, Dict, Any
from datetime import datetime
from langchain_ollama import ChatOllama
from langchain_community.utilities import WikipediaAPIWrapper
from langchain_community.tools import WikipediaQueryRun, DuckDuckGoSearchRun
from langchain_core.tools import tool
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from langgraph.types import interrupt, Command

# Function to detect available network interfaces
def get_available_interfaces():
    """Detect available network interfaces for packet capture"""
    interfaces = []
    system = platform.system()
    
    try:
        if system == "Windows":
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                   capture_output=True, text=True, shell=True)
            for line in result.stdout.split('\n'):
                if 'Connected' in line:
                    parts = line.split()
                    if len(parts) > 3:
                        interfaces.append(parts[-1])
        else:
            try:
                result = subprocess.run(['tshark', '-D'], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if '.' in line and '(' in line:  # FIXED: Removed extra parenthesis
                        interface = line.split('.')[1].split('(')[0].strip()
                        if interface and interface not in ['lo', 'loopback']:
                            interfaces.append(interface)
            except:
                pass
            
            if not interfaces:
                try:
                    result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if line and not line.startswith(' ') and 'flags' in line:
                            interface = line.split(':')[0]
                            if interface not in ['lo', 'loopback']:
                                interfaces.append(interface)
                except:
                    pass
    except Exception as e:
        if system == "Windows":
            interfaces = ['Ethernet', 'Wi-Fi']
        elif system == "Darwin":
            interfaces = ['en0', 'en1']
        else:
            interfaces = ['eth0', 'wlan0']
    
    return interfaces if interfaces else ['eth0', 'en0', 'wlan0']

def is_tshark_installed():
    """Check if TShark is installed and accessible"""
    try:
        result = subprocess.run(['tshark', '--version'], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        return False

# ---- CYBERSECURITY TOOLS THAT ACTUALLY PERFORM ACTIONS ----

@tool
def execute_live_packet_capture(interface: str = None, packet_count: int = 10) -> str:
    """Actually capture live network packets and return the results."""
    if not is_tshark_installed():
        return "ERROR: TShark not installed"
    
    try:
        if not interface:
            interfaces = get_available_interfaces()
            if interfaces:
                interface = interfaces[0]
            else:
                return "ERROR: No network interfaces found"
        
        packet_count = min(packet_count, 15)  # Limit for faster display
        
        cmd = [
            "tshark", "-i", interface,
            "-T", "fields",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-c", str(packet_count),
            "-a", "duration:5"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            return f"Capture error: {result.stderr[:200]}"
        
        packets = result.stdout.strip().split('\n')
        if not packets or (len(packets) == 1 and not packets[0]):
            return f"No packets on {interface}"
        
        # Simple compact output
        output = f"🌐 INTERFACE: {interface}\n"
        output += f"📦 PACKETS: {len(packets)}\n"
        output += "-" * 40 + "\n"
        
        for i, packet in enumerate(packets[:10], 1):
            fields = packet.split('\t')
            if len(fields) >= 4:
                src = fields[1][:15] if len(fields) > 1 and fields[1] else "?"
                dst = fields[2][:15] if len(fields) > 2 and fields[2] else "?"
                proto = fields[3][:5] if len(fields) > 3 else "?"
                output += f"{i:2}. {src} → {dst}\n"
                output += f"     Protocol: {proto}\n"
        
        return output
        
    except Exception as e:
        return f"Error: {str(e)[:100]}"

@tool
def check_ip_threat(ip_address: str) -> str:
    """Check if an IP address is malicious."""
    
    threats = {
        "185.130.5.253": "EMOTET Command & Control Server",
        "45.155.205.233": "TRICKBot Command & Control",
        "103.115.17.88": "QakBot Infrastructure"
    }
    
    if ip_address in threats:
        return f"⚠️ CRITICAL: {ip_address} is a known threat ({threats[ip_address]}) - BLOCK IMMEDIATELY"
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_address):
        if ip_address.startswith(('10.', '192.168.', '172.')):
            return f"✅ SAFE: {ip_address} is an internal/private IP address"
        else:
            return f"ℹ️ UNKNOWN: {ip_address} is a public IP with no known threats"
    else:
        return f"❌ INVALID: '{ip_address}' is not a valid IP address format"

@tool
def analyze_security_log(log_line: str) -> str:
    """Analyze a security log entry for threats."""
    
    if "failed password" in log_line.lower():
        if "root" in log_line.lower():
            return "🔴 CRITICAL: Root login failure - Possible brute force attack"
        return "⚠️ WARNING: Failed login attempt detected"
    elif "sudo" in log_line.lower():
        return "ℹ️ INFO: Privilege escalation (sudo) command executed"
    elif "sql injection" in log_line.lower():
        return "🔴 CRITICAL: SQL injection attack detected!"
    elif "malware" in log_line.lower() or "virus" in log_line.lower():
        return "🔴 CRITICAL: Malware indicator found!"
    elif "port scan" in log_line.lower():
        return "⚠️ WARNING: Port scanning detected - Possible reconnaissance"
    else:
        return "✅ CLEAN: No threats detected in this log entry"

@tool
def calculate_risk(probability: float, impact: float) -> str:
    """Calculate risk score."""
    risk = probability * impact
    if risk >= 0.7:
        level = "CRITICAL"
        action = "Immediate action required"
    elif risk >= 0.4:
        level = "HIGH"
        action = "Urgent mitigation needed"
    elif risk >= 0.2:
        level = "MEDIUM"
        action = "Plan remediation"
    else:
        level = "LOW"
        action = "Monitor only"
    
    return f"""RISK ASSESSMENT:
- Probability: {probability:.0%}
- Impact: {impact:.0%}
- Risk Score: {risk:.2f}
- Risk Level: {level}
- Action: {action}"""

# Define tools
cyber_tools = [
    execute_live_packet_capture,
    check_ip_threat,
    analyze_security_log,
    calculate_risk
]

# SQLite connection
conn = sqlite3.connect("cyber_checkpoints.sqlite", check_same_thread=False)
memory = SqliteSaver(conn)

# --- STATE & MODEL CONFIGURATION ---
class AgentState(TypedDict):
    task: str
    user_request: str
    expert_outputs: Annotated[List[Dict[str, str]], operator.add]
    final_draft: str
    timing_logs: Annotated[List[str], operator.add]
    approved: bool
    node_outputs: Annotated[List[Dict[str, Any]], operator.add]
    revision_feedback: str
    revision_count: int
    tool_results: str
    last_response: str

# --- PAGE SETUP ---
st.set_page_config(page_title="Cybersecurity Agent", layout="wide", page_icon="🛡️")

# CSS for compact display
st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(135deg, #f0f4f8 0%, #e2e8f0 100%);
    }
    
    [data-testid="stSidebar"] {
        background: linear-gradient(135deg, #87CEEB 0%, #6BB5D9 100%) !important;
        padding: 20px 15px !important;
    }
    
    [data-testid="stSidebar"] * {
        color: #1a1a2e !important;
    }
    
    [data-testid="stSidebar"] .stCodeBlock {
        background-color: #0d2b42 !important;
        border-radius: 10px !important;
        border: 2px solid #ffffff !important;
    }
    
    [data-testid="stSidebar"] .stCodeBlock pre {
        background-color: #0d2b42 !important;
        color: #00ff88 !important;
        font-size: 11px !important;
        padding: 8px !important;
    }
    
    [data-testid="stSidebar"] .stButton button {
        background: linear-gradient(135deg, #FF6B35 0%, #FF8C42 100%) !important;
        color: #FFFFFF !important;
        font-weight: 800 !important;
        border: 2px solid #FFFFFF !important;
        border-radius: 10px !important;
        padding: 10px 16px !important;
    }
    
    .stChatMessage {
        background-color: #ffffff !important;
        border-radius: 10px !important;
        padding: 8px 12px !important;
        margin: 5px 0 !important;
        overflow: visible !important;
        max-height: none !important;
    }
    
    [data-testid="stChatMessage"][data-testid*="user"] {
        background: linear-gradient(135deg, #0d2b42 0%, #1a4a6e 100%) !important;
        color: white !important;
    }
    
    [data-testid="stChatMessage"][data-testid*="assistant"] {
        background-color: #ffffff !important;
        border-left: 3px solid #0d2b42 !important;
    }
    
    .stCodeBlock pre {
        background-color: #1e1e1e !important;
        color: #d4d4d4 !important;
        padding: 6px !important;
        font-size: 11px !important;
    }
    
    .stMarkdown p {
        margin-bottom: 4px !important;
        line-height: 1.3 !important;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Cybersecurity Incident Response Agent")

# Detect interfaces
available_interfaces = get_available_interfaces()
tshark_installed = is_tshark_installed()

# Session state
if "sidebar_capture_result" not in st.session_state:
    st.session_state.sidebar_capture_result = None
if "last_revision" not in st.session_state:
    st.session_state.last_revision = None

with st.sidebar:
    st.header("⚙️ Settings")
    
    if tshark_installed:
        st.success("✅ TShark ready")
    else:
        st.error("❌ TShark not installed")
        st.info("Install: brew install wireshark")
    
    try:
        response = ollama.list()
        model_names = [m.model for m in response.models]
        chat_models = [n for n in model_names if "embed" not in n.lower()]

        if chat_models:
            st.markdown("**🤖 Model Selection**")
            selected_manager = st.selectbox("Manager", options=chat_models, index=0)
            selected_researcher = st.selectbox("Researcher", options=chat_models, index=min(1, len(chat_models)-1))
            selected_editor = st.selectbox("Editor", options=chat_models, index=min(2, len(chat_models)-1))
        else:
            st.error("No Ollama models found")
            selected_manager = selected_researcher = selected_editor = None

        st.divider()
        
        st.markdown("**📡 Network**")
        if available_interfaces:
            network_interface = st.selectbox("Interface", options=available_interfaces, index=0)
        else:
            network_interface = st.text_input("Interface", value="eth0")
        
        packet_count = st.slider("Packets", 5, 20, 10)
        
        st.divider()
        thread_id = st.text_input("Session ID", value=f"session_{datetime.now().strftime('%H%M%S')}")
    except Exception as e:
        st.error(f"Ollama error: {e}")
        selected_manager = selected_researcher = selected_editor = None
        network_interface = "eth0"
        packet_count = 10

    st.divider()
    
    st.markdown("**📡 Live Capture**")
    st.caption(f"Interface: {network_interface}")
    
    if st.button("🎯 CAPTURE NOW", use_container_width=True):
        if not tshark_installed:
            st.error("❌ TShark not installed")
        else:
            with st.spinner("Capturing..."):
                result = execute_live_packet_capture.invoke({
                    "interface": network_interface,
                    "packet_count": packet_count
                })
                st.session_state.sidebar_capture_result = result
                st.markdown("---")
                st.markdown("**Results:**")
                st.code(result, language="text")
                st.success("✅ Complete")
    
    if st.session_state.sidebar_capture_result:
        st.markdown("**Last:**")
        st.code(st.session_state.sidebar_capture_result[:200], language="text")
        if st.button("Clear", use_container_width=True):
            st.session_state.sidebar_capture_result = None
            st.rerun()

config = {"configurable": {"thread_id": thread_id}}

# ---- NODES ----

def researcher_node(state: AgentState):
    """Threat Hunter - EXECUTES tools"""
    start_time = time.time()
    
    if selected_researcher:
        user_request = state.get('user_request', state['task'])
        revision_feedback = state.get('revision_feedback', '')
        tool_result = ""
        response = ""
        
        if "live traffic" in user_request.lower() or "capture" in user_request.lower() or "packet" in user_request.lower():
            tool_result = execute_live_packet_capture.invoke({
                "interface": network_interface,
                "packet_count": packet_count
            })
            response = f"🔍 **LIVE TRAFFIC CAPTURE:**\n\n{tool_result}\n\n"
            if "No packets" in tool_result:
                response += "⚠️ No packets detected. Generate some network traffic."
            elif "ERROR" in tool_result:
                response += "❌ Capture failed. Please check TShark installation."
            else:
                response += f"✅ Successfully captured {packet_count} packets."
        
        elif "check ip" in user_request.lower() or "ioc" in user_request.lower():
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_request)
            if ip_match:
                ip = ip_match.group()
                tool_result = check_ip_threat.invoke({"ip_address": ip})
                response = f"🔍 **THREAT INTELLIGENCE:**\n\n{tool_result}"
            else:
                response = "🔍 **THREAT INTELLIGENCE:**\n\nPlease provide a specific IP address."
        
        elif "log" in user_request.lower() or "analyze" in user_request.lower():
            if len(user_request) > 50:
                tool_result = analyze_security_log.invoke({"log_line": user_request[:500]})
                response = f"🔍 **LOG ANALYSIS:**\n\n{tool_result}"
            else:
                response = "🔍 **LOG ANALYSIS:**\n\nPlease provide the log entry to analyze."
        
        else:
            llm = ChatOllama(model=selected_researcher, temperature=0.3)
            prompt = f"Answer this cybersecurity question directly (max 100 words): {user_request}"
            response = llm.invoke(prompt).content
        
        if revision_feedback:
            llm = ChatOllama(model=selected_researcher, temperature=0.4)
            prompt = f"""The user requested revision: "{revision_feedback}"
            Previous: {response[:300]}
            Provide UPDATED response addressing the feedback:"""
            response = llm.invoke(prompt).content
    
    else:
        response = "❌ No model selected"
    
    duration = round(time.time() - start_time, 2)
    
    return {
        "expert_outputs": [{"source": "Researcher", "content": response[:800], "duration": duration}],
        "timing_logs": [f"Researcher: {duration}s"],
        "node_outputs": [{"node": "researcher", "output": response[:800], "duration": duration}],
        "tool_results": tool_result,
        "last_response": response[:800]
    }

def editor_node(state: AgentState):
    """Security Analyst - reviews response"""
    start_time = time.time()
    
    if selected_editor:
        user_request = state.get('user_request', state['task'])
        researcher_output = ""
        revision_feedback = state.get('revision_feedback', '')
        
        for output in state.get("expert_outputs", []):
            if output['source'] == 'Researcher':
                researcher_output = output['content']
        
        if revision_feedback:
            llm = ChatOllama(model=selected_editor, temperature=0.4)
            prompt = f"Confirm revision '{revision_feedback}' was addressed. Brief response:"
            response = llm.invoke(prompt).content
        else:
            llm = ChatOllama(model=selected_editor, temperature=0.2)
            prompt = f"Verify response for '{user_request}' is appropriate. Reply with APPROVED or feedback:"
            response = llm.invoke(prompt).content
    else:
        response = "No model selected"
    
    duration = round(time.time() - start_time, 2)
    
    return {
        "expert_outputs": [{"source": "Editor", "content": response[:300], "duration": duration}],
        "timing_logs": [f"Editor: {duration}s"],
        "node_outputs": [{"node": "editor", "output": response[:300], "duration": duration}]
    }

def manager_node(state: AgentState):
    """Incident Commander - synthesizes final response"""
    start_time = time.time()
    
    if selected_manager:
        user_request = state.get('user_request', state['task'])
        revision_feedback = state.get('revision_feedback', '')
        revision_count = state.get('revision_count', 0)
        researcher_output = ""
        
        for output in state.get("expert_outputs", []):
            if output['source'] == 'Researcher':
                researcher_output = output['content']
        
        llm = ChatOllama(model=selected_manager, temperature=0.3)
        
        if revision_feedback:
            prompt = f"""
            REVISION #{revision_count + 1}: {revision_feedback}
            UPDATED: {researcher_output[:400]}
            
            Provide FINAL response showing revision was implemented.
            Acknowledge the feedback at the beginning.
            """
        else:
            prompt = f"Provide final response for: {user_request}\nAnalysis: {researcher_output[:400]}"
        
        response = llm.invoke(prompt).content
    else:
        response = "❌ No model selected"
    
    duration = round(time.time() - start_time, 2)
    
    return {
        "final_draft": response[:600],
        "timing_logs": [f"Manager: {duration}s"],
        "node_outputs": [{"node": "manager", "output": response[:600], "duration": duration}]
    }

def human_approval_node(state: AgentState):
    """HITL with feedback loop"""
    current_draft = state["final_draft"]
    revision_count = state.get('revision_count', 0)
    
    user_feedback = interrupt({
        "msg": "📋 Review Response",
        "draft": current_draft,
        "revision_count": revision_count,
        "prompt": "Enter 'approve' or provide revision instructions:"
    })

    if user_feedback.lower() == "approve":
        return {"approved": True}
    else:
        new_revision_count = revision_count + 1
        
        return {
            "task": f"REVISION: {user_feedback}",
            "user_request": state.get('user_request', state['task']),
            "expert_outputs": [],
            "approved": False,
            "revision_feedback": user_feedback,
            "revision_count": new_revision_count,
            "tool_results": state.get('tool_results', ''),
            "last_response": state.get('last_response', '')
        }

# --- GRAPH CONSTRUCTION ---
builder = StateGraph(AgentState)
builder.add_node("researcher", researcher_node)
builder.add_node("editor", editor_node)
builder.add_node("manager", manager_node)
builder.add_node("human_approval", human_approval_node)

builder.add_edge(START, "researcher")
builder.add_edge(START, "editor")
builder.add_edge("researcher", "manager")
builder.add_edge("editor", "manager")
builder.add_edge("manager", "human_approval")

builder.add_conditional_edges(
    "human_approval",
    lambda state: END if state["approved"] else "researcher",
    {"researcher": "researcher", END: END}
)

graph = builder.compile(checkpointer=memory, interrupt_before=["human_approval"])

# --- CHAT INTERFACE ---
if "messages" not in st.session_state:
    st.session_state.messages = []
if "displayed_outputs" not in st.session_state:
    st.session_state.displayed_outputs = set()

for message in st.session_state.messages[-15:]:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

def display_node_outputs(state_values):
    if state_values and "node_outputs" in state_values:
        for output in state_values["node_outputs"]:
            output_key = f"{output['node']}_{output['duration']}"
            if output_key not in st.session_state.displayed_outputs:
                with st.chat_message("assistant"):
                    if output['node'] == 'researcher':
                        st.markdown(f"🔍 **Threat Hunter**\n{output['output'][:500]}")
                    elif output['node'] == 'editor':
                        st.markdown(f"✏️ **Analyst**\n{output['output'][:200]}")
                    elif output['node'] == 'manager':
                        st.markdown(f"📋 **Commander**\n{output['output'][:500]}")
                    st.caption(f"⏱️ {output['duration']}s")
                st.session_state.displayed_outputs.add(output_key)

if prompt := st.chat_input("Ask about cybersecurity (e.g., 'Show live traffic', 'Check IP 185.130.5.253')..."):
    st.session_state.displayed_outputs = set()
    st.session_state.messages.append({"role": "user", "content": prompt})
    
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Parallel Expert Nodes thinking.."):
            initial_state = {
                "task": prompt,
                "user_request": prompt,
                "expert_outputs": [],
                "final_draft": "",
                "timing_logs": [],
                "approved": False,
                "node_outputs": [],
                "revision_feedback": "",
                "revision_count": 0,
                "tool_results": "",
                "last_response": ""
            }

            for event in graph.stream(initial_state, config):
                for node_name, node_output in event.items():
                    st.caption(f"✅ {node_name}")
                    
                    current_state = graph.get_state(config)
                    if current_state and current_state.values:
                        display_node_outputs(current_state.values)

            final_state = graph.get_state(config)
            if final_state and final_state.values and "final_draft" in final_state.values:
                final_draft = final_state.values["final_draft"]
                st.session_state.messages.append({"role": "assistant", "content": final_draft})

# Handle HITL interrupt
snapshot = graph.get_state(config)
if snapshot and snapshot.next and snapshot.tasks and snapshot.tasks[0].interrupts:
    review_data = snapshot.tasks[0].interrupts[0].value
    revision_count = review_data.get('revision_count', 0)
    
    st.divider()
    st.warning(f"✋ **Human-in-the-Loop Review (Round {revision_count + 1})**")
    
    with st.expander("📋 Current Response", expanded=True):
        st.markdown(review_data['draft'])
    
    st.markdown("**Options:**")
    st.markdown("- Type `approve` to accept")
    st.markdown("- Or provide revision feedback")
    
    feedback = st.text_area("Feedback:", key="hitl_feedback", height=80)
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("✅ Approve", type="primary", use_container_width=True):
            for event in graph.stream(Command(resume="approve"), config):
                st.caption(f"Finalizing: {list(event.keys())[0]}")
            st.success("✅ Approved!")
            st.rerun()
    with col2:
        if st.button("🔄 Revise", type="secondary", use_container_width=True):
            if feedback and feedback.lower() != "approve":
                with st.spinner("Revising..."):
                    for event in graph.stream(Command(resume=feedback), config):
                        st.caption(f"Revising: {list(event.keys())[0]}")
                    st.info(f"🔄 Revision #{revision_count + 1} complete!")
                    st.rerun()
            else:
                st.error("Please provide revision feedback")

if snapshot and snapshot.values and "timing_logs" in snapshot.values:
    with st.sidebar:
        st.divider()
        st.markdown("**📊 Metrics**")
        for log in snapshot.values.get("timing_logs", []):
            st.caption(log)
        
        revision_count = snapshot.values.get("revision_count", 0)
        if revision_count > 0:
            st.info(f"🔄 Revisions: {revision_count}")

# Show system info
with st.sidebar:
    with st.expander("ℹ️ System Info"):
        st.markdown(f"""
        - **OS:** {platform.system()} {platform.release()}
        - **TShark:** {'✅ Installed' if tshark_installed else '❌ Not installed'}
        - **Interfaces:** {', '.join(available_interfaces[:3])}
        """)
        
        if not tshark_installed:
            st.markdown("**Install:**")
            if platform.system() == "Darwin":
                st.code("brew install wireshark")
            elif platform.system() == "Linux":
                st.code("sudo apt-get install tshark")

with st.sidebar:
    st.divider()
    if st.button("🗑️ New Session", use_container_width=True):
        st.session_state.messages = []
        st.session_state.displayed_outputs = set()
        st.session_state.sidebar_capture_result = None
        st.rerun()
    
    with st.expander("ℹ️ Help"):
        st.markdown("""
        **Examples:**
        - "Show live traffic"
        - "Check IP 185.130.5.253"
        
        **HITL Testing:**
        1. Make a request
        2. Provide revision feedback
        3. See updated response
        """)