"""
app.py — LogSloth Streamlit dashboard entry point.

Launch with:  streamlit run app.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is on the Python path when run via `streamlit run`
sys.path.insert(0, str(Path(__file__).parent))

import streamlit as st

# ---- Page config must be first Streamlit call ----
st.set_page_config(
    page_title="LogSloth — Error Detective",
    page_icon="🦥",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---- Custom CSS ----
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

code, pre, .stCode {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Dark gradient background */
.stApp {
    background: linear-gradient(135deg, #0f0f1a 0%, #12121f 50%, #0a0a14 100%);
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #13131f 0%, #0d0d18 100%);
    border-right: 1px solid rgba(99,102,241,0.2);
}

/* Metric cards */
[data-testid="stMetric"] {
    background: rgba(99,102,241,0.08);
    border: 1px solid rgba(99,102,241,0.25);
    border-radius: 12px;
    padding: 16px !important;
    transition: border-color 0.2s ease;
}
[data-testid="stMetric"]:hover {
    border-color: rgba(99,102,241,0.6);
}

/* Severity badges */
.badge-critical { background:#7f1d1d; color:#fca5a5; padding:2px 8px; border-radius:99px; font-size:0.75rem; font-weight:600; }
.badge-error    { background:#431407; color:#fdba74; padding:2px 8px; border-radius:99px; font-size:0.75rem; font-weight:600; }
.badge-warning  { background:#3d2c00; color:#fde68a; padding:2px 8px; border-radius:99px; font-size:0.75rem; font-weight:600; }
.badge-info     { background:#0c2340; color:#93c5fd; padding:2px 8px; border-radius:99px; font-size:0.75rem; font-weight:600; }
.badge-debug    { background:#1a1f2e; color:#94a3b8; padding:2px 8px; border-radius:99px; font-size:0.75rem; font-weight:600; }
.badge-spike    { background:#4c1d95; color:#c4b5fd; padding:2px 8px; border-radius:99px; font-size:0.75rem; font-weight:600; }

/* Incident card */
.incident-card {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 16px;
    margin-bottom: 12px;
    transition: border-color 0.2s, background 0.2s;
    cursor: pointer;
}
.incident-card:hover {
    background: rgba(99,102,241,0.06);
    border-color: rgba(99,102,241,0.4);
}

/* Section headers */
h1, h2, h3 { color: #e2e8f0 !important; }

/* AI analysis block */
.ai-block {
    background: linear-gradient(135deg, rgba(99,102,241,0.08) 0%, rgba(168,85,247,0.06) 100%);
    border: 1px solid rgba(168,85,247,0.3);
    border-radius: 12px;
    padding: 20px;
    margin-top: 16px;
}

/* Divider */
hr { border-color: rgba(255,255,255,0.08) !important; }

/* Scrollable code block */
.stCodeBlock { max-height: 300px; overflow-y: auto; }

/* Spinner */
[data-testid="stSpinner"] { color: #818cf8; }
</style>
""",
    unsafe_allow_html=True,
)

import datetime
from collections import defaultdict
from typing import Optional

from config import Config
from logsloth.analyzer import OllamaClient, analyse_incident, apply_analysis_to_incident
from logsloth.collector import collect_files, ingest_directory
from logsloth.detector import build_incidents, detect_spikes, group_by_fingerprint
from logsloth.fingerprint import compute_fingerprint
from logsloth.models import Incident, LogEntry, Severity
from logsloth.reporter import export_report, incident_to_markdown
from logsloth.storage import initialise, load_all_incidents, upsert_incident, record_entry_ids

Config.ensure_dirs()

# ========================================================================
# Session state helpers
# ========================================================================

def _init_state() -> None:
    defaults = {
        "incidents": {},
        "entries": [],
        "selected_fp": None,
        "log_dir": str(Config.LOG_DIR),
        "ollama_url": Config.OLLAMA_BASE_URL,
        "ollama_model": Config.OLLAMA_MODEL,
        "spike_window": Config.SPIKE_WINDOW_SECONDS,
        "spike_mult": Config.SPIKE_MULTIPLIER,
        "search_query": "",
        "sev_filter": "All",
        "page": "overview",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


_init_state()

# ========================================================================
# Data pipeline
# ========================================================================

def run_pipeline(log_dir: Path) -> tuple[dict[str, Incident], list[LogEntry]]:
    """
    Full deterministic pipeline:  collect → parse+redact → group → count → detect spikes → persist.
    """
    entries = ingest_directory(log_dir)
    groups = group_by_fingerprint(entries)

    # Load existing incidents for count merging (deduplication is handled via SQLite)
    existing = load_all_incidents(Config.DB_PATH)
    incidents = build_incidents(groups, existing_incidents=existing)
    incidents = detect_spikes(
        incidents,
        entries,
        window_seconds=st.session_state.spike_window,
        multiplier=st.session_state.spike_mult,
    )

    # Persist
    initialise(Config.DB_PATH)
    for inc in incidents.values():
        upsert_incident(Config.DB_PATH, inc)

    return incidents, entries


# ========================================================================
# Sidebar navigation
# ========================================================================

with st.sidebar:
    st.markdown("## 🦥 LogSloth")
    st.caption("Lazy Developer's Error Detective")
    st.divider()

    nav = st.radio(
        "Navigation",
        ["📊 Overview", "🔍 Incidents", "⚙️ Settings"],
        label_visibility="collapsed",
    )

    st.divider()

    # Quick load button
    log_dir = Path(st.session_state.log_dir)
    if st.button("🔄 Analyse Logs", use_container_width=True, type="primary"):
        with st.spinner("Parsing and grouping…"):
            try:
                incidents, entries = run_pipeline(log_dir)
                st.session_state.incidents = incidents
                st.session_state.entries = entries
                st.success(f"✅ {len(entries)} events, {len(incidents)} incidents")
            except Exception as exc:
                st.error(f"Pipeline error: {exc}")

    # Ollama status
    st.divider()
    client = OllamaClient(
        base_url=st.session_state.ollama_url,
        model=st.session_state.ollama_model,
    )
    ok, msg = client.is_available()
    if ok:
        st.markdown("🟢 **Ollama** connected")
    else:
        st.markdown("🔴 **Ollama** unavailable")
        st.caption(msg)

# ========================================================================
# Main content
# ========================================================================

incidents: dict[str, Incident] = st.session_state.incidents
entries: list[LogEntry] = st.session_state.entries

# ---- Overview ----------------------------------------------------------------
if nav == "📊 Overview":
    st.title("📊 LogSloth Dashboard")
    st.caption("You relax. We read the logs.")

    if not incidents:
        st.info("👈 Click **Analyse Logs** in the sidebar to load your log files.")
        st.markdown(
            """
**Getting started:**
1. Make sure your log files are in `./sample_logs/` (or configure a different path in Settings).
2. Click **Analyse Logs** in the sidebar.
3. LogSloth will parse, group, and rank your errors automatically.
4. Use the **Incidents** tab to drill into individual error groups.
            """
        )
    else:
        total_events = len(entries)
        total_incidents = len(incidents)
        error_count = sum(
            1 for i in incidents.values() if i.severity in (Severity.ERROR, Severity.CRITICAL)
        )
        critical_count = sum(1 for i in incidents.values() if i.severity == Severity.CRITICAL)
        spike_count = sum(1 for i in incidents.values() if i.spike_flagged)

        # Metric row
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Events", f"{total_events:,}")
        c2.metric("Incident Groups", f"{total_incidents:,}")
        c3.metric("Errors / Critical", f"{error_count} / {critical_count}")
        c4.metric("⚠ Spikes", f"{spike_count}")
        c5.metric(
            "Most Severe",
            max((i.severity.value for i in incidents.values()), key=lambda s: Severity(s).numeric)
            if incidents
            else "—",
        )

        st.divider()

        # Error rate timeline
        st.subheader("📈 Error Rate Timeline")
        ts_counts: dict[str, int] = defaultdict(int)
        for e in entries:
            if e.timestamp and e.severity in (Severity.ERROR, Severity.CRITICAL):
                bucket = e.timestamp.strftime("%H:%M")
                ts_counts[bucket] += 1

        if ts_counts:
            import pandas as pd

            df = pd.DataFrame(
                sorted(ts_counts.items()), columns=["Time (HH:MM)", "Error Count"]
            ).set_index("Time (HH:MM)")
            st.line_chart(df, height=220)
        else:
            st.caption("No timestamped error events found.")

        st.divider()

        # Top incidents
        st.subheader("🔥 Top Incidents by Occurrence")
        top = sorted(incidents.values(), key=lambda i: i.occurrence_count, reverse=True)[:8]
        for inc in top:
            sev_class = f"badge-{inc.severity.value.lower()}"
            spike_badge = '<span class="badge-spike">⚡ spike</span>' if inc.spike_flagged else ""
            st.markdown(
                f"""<div class="incident-card">
                    <strong>{inc.title}</strong>&nbsp;
                    <span class="{sev_class}">{inc.severity.value}</span>&nbsp;{spike_badge}
                    <br><small style="color:#64748b">{inc.occurrence_count}× · 
                    fp: <code>{inc.fingerprint}</code> · 
                    last: {inc.last_seen.strftime('%H:%M:%S') if inc.last_seen else '?'}</small>
                </div>""",
                unsafe_allow_html=True,
            )

# ---- Incidents ---------------------------------------------------------------
elif nav == "🔍 Incidents":
    st.title("🔍 Incident Explorer")

    if not incidents:
        st.info("No incidents loaded. Click **Analyse Logs** in the sidebar first.")
    else:
        # --- Filters ---
        col_s, col_sev, col_src = st.columns([3, 2, 2])

        with col_s:
            search = st.text_input("🔍 Search", placeholder="Type to filter…", key="search_query")

        with col_sev:
            sev_opts = ["All"] + [s.value for s in Severity]
            sev_filter = st.selectbox("Severity", sev_opts, key="sev_filter")

        with col_src:
            sources = ["All"] + sorted(
                {f for inc in incidents.values() for f in inc.source_files}
            )
            src_filter = st.selectbox("Source file", sources)

        sort_by = st.radio(
            "Sort by", ["Occurrences ↓", "Severity ↓", "Last seen ↓"], horizontal=True
        )

        # --- Filter + sort ---
        def _matches(inc: Incident) -> bool:
            if sev_filter != "All" and inc.severity.value != sev_filter:
                return False
            if src_filter != "All" and src_filter not in inc.source_files:
                return False
            q = search.lower()
            if q and q not in inc.title.lower() and q not in inc.representative_message.lower():
                return False
            return True

        filtered = [i for i in incidents.values() if _matches(i)]

        if sort_by == "Occurrences ↓":
            filtered.sort(key=lambda i: i.occurrence_count, reverse=True)
        elif sort_by == "Severity ↓":
            filtered.sort(key=lambda i: i.severity.numeric, reverse=True)
        else:
            filtered.sort(key=lambda i: i.last_seen or datetime.datetime.min, reverse=True)

        st.caption(f"Showing {len(filtered)} of {len(incidents)} incidents")
        st.divider()

        if not filtered:
            st.warning("No incidents match the current filters.")
        else:
            # Incident list
            for inc in filtered:
                sev_class = f"badge-{inc.severity.value.lower()}"
                spike_badge = (
                    '<span class="badge-spike">⚡ spike</span>' if inc.spike_flagged else ""
                )
                ai_badge = "🤖" if inc.ai_analyzed else ""

                col_l, col_r = st.columns([5, 1])
                with col_l:
                    st.markdown(
                        f"""<div class="incident-card">
                            <strong>{ai_badge} {inc.title}</strong>&nbsp;
                            <span class="{sev_class}">{inc.severity.value}</span>&nbsp;{spike_badge}
                            <br><small style="color:#94a3b8">{inc.occurrence_count}× · 
                            first: {inc.first_seen.strftime('%Y-%m-%d %H:%M') if inc.first_seen else '?'} · 
                            last: {inc.last_seen.strftime('%Y-%m-%d %H:%M') if inc.last_seen else '?'}</small>
                            <br><small style="color:#475569">{inc.representative_message[:100]}…</small>
                        </div>""",
                        unsafe_allow_html=True,
                    )
                with col_r:
                    if st.button("View →", key=f"view_{inc.fingerprint}"):
                        st.session_state.selected_fp = inc.fingerprint
                        st.rerun()

            # ---- Detail view (rendered below the list if selected) ----
            if st.session_state.selected_fp:
                sel_fp = st.session_state.selected_fp
                sel_inc = incidents.get(sel_fp)
                if sel_inc:
                    st.divider()
                    st.subheader(f"📋 {sel_inc.title}")

                    # Top metadata
                    d1, d2, d3, d4 = st.columns(4)
                    d1.metric("Severity", sel_inc.severity.value)
                    d2.metric("Occurrences", sel_inc.occurrence_count)
                    d3.metric("First seen", sel_inc.first_seen.strftime("%H:%M:%S") if sel_inc.first_seen else "?")
                    d4.metric("Last seen", sel_inc.last_seen.strftime("%H:%M:%S") if sel_inc.last_seen else "?")

                    if sel_inc.spike_flagged:
                        st.warning(f"⚡ **Spike detected:** {sel_inc.spike_reason}")

                    st.markdown(f"**Fingerprint:** `{sel_inc.fingerprint}`")
                    st.markdown(f"**Sources:** {', '.join(sel_inc.source_files) or 'unknown'}")

                    # Message
                    st.markdown("**Representative Message (sanitised)**")
                    st.code(sel_inc.representative_message, language="")

                    # Stack trace
                    if sel_inc.representative_stack:
                        with st.expander("Stack Trace (sanitised)", expanded=True):
                            st.code(sel_inc.representative_stack, language="python")

                    # AI analysis section
                    st.markdown("---")
                    st.subheader("🤖 AI Diagnostic")

                    ai_col, btn_col = st.columns([4, 1])
                    with btn_col:
                        run_ai = st.button(
                            "▶ Analyse",
                            key=f"ai_{sel_fp}",
                            help="Run local AI analysis via Ollama",
                        )

                    if run_ai:
                        ollama_ok, ollama_msg = client.is_available()
                        if not ollama_ok:
                            st.error(f"Ollama unavailable: {ollama_msg}")
                        else:
                            with st.spinner("Running AI analysis…"):
                                sample_lines = [
                                    e.message for e in entries
                                    if compute_fingerprint(e) == sel_fp
                                ][:Config.MAX_EVIDENCE_LINES]
                                result = analyse_incident(
                                    sel_inc,
                                    sample_lines,
                                    client=client,
                                )
                                apply_analysis_to_incident(sel_inc, result)
                                if sel_inc.ai_analyzed:
                                    upsert_incident(Config.DB_PATH, sel_inc)
                                    st.session_state.incidents[sel_fp] = sel_inc
                                    st.success("Analysis complete!")
                                    st.rerun()
                                else:
                                    st.error(f"AI analysis failed: {sel_inc.ai_error}")

                    if sel_inc.ai_analyzed:
                        st.markdown(
                            f"""<div class="ai-block">
                            <h4 style="color:#c4b5fd">🤖 {sel_inc.ai_title or sel_inc.title}</h4>
                            <p style="color:#e2e8f0">{sel_inc.ai_summary}</p>
                            </div>""",
                            unsafe_allow_html=True,
                        )

                        if sel_inc.ai_probable_causes:
                            st.markdown("**Probable Causes**")
                            for cause in sel_inc.ai_probable_causes:
                                st.markdown(f"- {cause}")

                        if sel_inc.ai_evidence:
                            st.markdown("**Supporting Evidence**")
                            for ev in sel_inc.ai_evidence:
                                st.markdown(f"- `{ev}`")

                        if sel_inc.ai_suggested_checks:
                            st.markdown("**Suggested Checks**")
                            for step in sel_inc.ai_suggested_checks:
                                st.markdown(f"- {step}")

                        st.caption(
                            f"Confidence: **{sel_inc.ai_confidence}** · {sel_inc.ai_limitations}"
                        )
                    elif sel_inc.ai_error:
                        st.info(f"Last attempt: {sel_inc.ai_error}")
                    else:
                        st.info("Click **▶ Analyse** to run AI diagnostics on this incident.")

                    # Export
                    st.markdown("---")
                    st.subheader("📤 Export")
                    md_content = incident_to_markdown(sel_inc)
                    st.download_button(
                        "⬇ Download Markdown Report",
                        data=md_content,
                        file_name=f"incident_{sel_inc.fingerprint}.md",
                        mime="text/markdown",
                    )

                    if st.button("❌ Close detail view", key="close_detail"):
                        st.session_state.selected_fp = None
                        st.rerun()

# ---- Settings ----------------------------------------------------------------
elif nav == "⚙️ Settings":
    st.title("⚙️ Settings")

    st.subheader("📁 Log Source")
    new_log_dir = st.text_input("Log directory", value=st.session_state.log_dir)
    if new_log_dir != st.session_state.log_dir:
        st.session_state.log_dir = new_log_dir

    avail = collect_files(Path(new_log_dir))
    if avail:
        st.success(f"Found {len(avail)} log file(s):")
        for f in avail:
            st.markdown(f"- `{f.name}`")
    else:
        st.warning("No log files found in that directory.")

    st.divider()
    st.subheader("🤖 Ollama / AI Model")
    col1, col2 = st.columns(2)
    with col1:
        new_url = st.text_input("Ollama base URL", value=st.session_state.ollama_url)
        st.session_state.ollama_url = new_url
    with col2:
        new_model = st.text_input("Model name", value=st.session_state.ollama_model)
        st.session_state.ollama_model = new_model

    if st.button("Test Ollama connection"):
        test_client = OllamaClient(base_url=new_url, model=new_model)
        ok, msg = test_client.is_available()
        if ok:
            st.success("✅ Ollama connected and model available.")
        else:
            st.error(f"❌ {msg}")

    st.divider()
    st.subheader("📈 Spike Detection")
    sw = st.slider("Window (seconds)", 60, 1800, st.session_state.spike_window, step=60)
    sm = st.slider("Multiplier (×baseline)", 1.5, 10.0, st.session_state.spike_mult, step=0.5)
    st.session_state.spike_window = sw
    st.session_state.spike_mult = sm

    st.divider()
    st.subheader("🔒 Redaction Rules")
    st.info(
        "LogSloth applies regex-based redaction to bearer tokens, API keys, passwords, "
        "JWTs, AWS keys, URL-embedded credentials, and sensitive query parameters. "
        "**Limitation:** Custom secret formats may bypass these patterns. "
        "Do not rely solely on this feature for production privacy compliance."
    )

    st.divider()
    st.subheader("🗄️ Database")
    st.markdown(f"SQLite path: `{Config.DB_PATH}`")
    if st.button("Clear incident database", type="secondary"):
        if Config.DB_PATH.exists():
            Config.DB_PATH.unlink()
            st.session_state.incidents = {}
            st.session_state.entries = []
            st.success("Database cleared.")
        else:
            st.info("No database file found.")
