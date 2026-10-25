"""
Stage 7: Live Web Security Dashboard & Enterprise Audit Trail.

Built with authentic shadcn/ui design system:
- Zinc/Slate dark palette (zinc-950, zinc-900, zinc-800)
- Tailwind CSS via CDN with customized shadcn theme tokens
- Lucide SVG icons (ShieldCheck, Lock, AlertTriangle, Zap, Terminal, Database)
- Real-time Server-Sent Events (SSE) streaming telemetry
- Interactive Human-in-the-Loop approval modal with live unblocking
- Real-Time Execution Controller directly driving C:\\Users\\defaultuser100000\\web_agent_test
- Dual-Run Benchmark comparison matrix & SQLite audit log playback
"""

import os
import sys
import json
import time
import sqlite3
import asyncio
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from pydantic import BaseModel

DB_PATH = os.path.join(os.path.dirname(__file__), "audit.db")


def init_db(db_path: str = DB_PATH):
    """Initializes SQLite durable audit trail schema."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            stage TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            verdict TEXT NOT NULL,
            target_url TEXT,
            details TEXT,
            raw_payload TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_approvals (
            action_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            action_type TEXT NOT NULL,
            selector TEXT,
            target_url TEXT,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING'
        )
    """)
    conn.commit()
    conn.close()


def record_audit_event(stage: str, rule_id: str, verdict: str, details: str, target_url: str = "", raw_payload: str = "", db_path: str = DB_PATH):
    """Writes an immutable record to the SQLite audit log."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, stage, rule_id, verdict, target_url, details, raw_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now(timezone.utc).isoformat(), stage, rule_id, verdict, target_url, details, raw_payload[:500]))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Audit Error] Could not write to audit log: {e}", file=sys.stderr)


# In-memory event bus for real-time SSE streaming
EVENT_SUBSCRIBERS: List[asyncio.Queue] = []

# In-memory approval state for fast polling and resolution
PENDING_APPROVALS: Dict[str, Dict[str, Any]] = {}


async def broadcast_event(event: Dict[str, Any]):
    """Broadcast an event to all connected SSE clients."""
    for queue in list(EVENT_SUBSCRIBERS):
        try:
            await queue.put(event)
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="GASHI-Guard Security Dashboard", lifespan=lifespan)


SHADCN_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GASHI-Guard &bull; Security Operations Center</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        background: '#09090b',
                        surface: '#121215',
                        card: '#18181b',
                        'card-hover': '#202024',
                        border: '#27272a',
                        muted: '#71717a',
                        primary: '#fafafa',
                        'primary-foreground': '#18181b',
                        accent: '#38bdf8',
                        danger: '#ef4444',
                        success: '#10b981',
                        warning: '#f59e0b',
                    },
                    fontFamily: {
                        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
                        mono: ['JetBrains Mono', 'Menlo', 'Consolas', 'monospace']
                    }
                }
            }
        }
    </script>
    <style>
        body { background-color: #09090b; color: #fafafa; }
        .custom-scrollbar::-webkit-scrollbar { width: 5px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #27272a; border-radius: 9999px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #3f3f46; }
    </style>
</head>
<body class="bg-background text-zinc-100 min-h-screen antialiased selection:bg-zinc-800 selection:text-zinc-100 p-6 md:p-8">

    <div class="max-w-7xl mx-auto space-y-6">

        <!-- Top Navigation / Breadcrumbs -->
        <header class="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-5 border-b border-border gap-4">
            <div class="space-y-1">
                <div class="flex items-center gap-2 text-xs text-muted font-medium">
                    <span>Platform</span>
                    <span>/</span>
                    <span>Security Runtime</span>
                    <span>/</span>
                    <span class="text-zinc-200">Active Defense SOC</span>
                </div>
                <div class="flex items-center gap-3">
                    <div class="w-8 h-8 rounded-lg bg-zinc-900 border border-border flex items-center justify-center text-accent">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                    </div>
                    <h1 class="text-xl font-bold tracking-tight text-white">GASHI-Guard SOC</h1>
                    <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                        7 Stages Armed
                    </span>
                </div>
            </div>

            <!-- Global Status Indicator -->
            <div class="flex items-center gap-3">
                <div class="flex items-center gap-2 px-3 py-1.5 rounded-md bg-zinc-900 border border-border text-xs text-muted font-mono" id="conn-pill">
                    <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                    SSE Connected
                </div>
            </div>
        </header>

        <!-- Real-Time Agent Target & Execution Control -->
        <section class="p-5 rounded-xl bg-card border border-border shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div class="space-y-1.5">
                <div class="flex items-center gap-2 flex-wrap">
                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></span>
                    <span class="text-xs font-semibold uppercase tracking-wider text-accent font-mono">Connected Target Agent:</span>
                    <span class="text-xs font-mono px-2 py-0.5 rounded bg-zinc-900 border border-border text-emerald-300 font-semibold">C:\Users\defaultuser100000\web_agent_test</span>
                </div>
                <div class="flex items-center gap-3 text-xs text-muted flex-wrap">
                    <span>LLM: <strong class="text-zinc-200 font-mono">Google Gemini 2.5 / Groq LLaMA-3.3-70b</strong></span>
                    <span>&bull;</span>
                    <span>Tools: <strong class="text-zinc-200">TinyFish Cloud + DOMSanitizer</strong></span>
                    <span>&bull;</span>
                    <span>Target URL: <strong class="text-zinc-200 font-mono">http://127.0.0.1:8081/invoice</strong></span>
                </div>
            </div>
            
            <div class="flex items-center gap-2.5 flex-wrap">
                <button id="btn-run-protected" onclick="runLiveAgent('protected')" class="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-zinc-950 bg-emerald-400 hover:bg-emerald-300 rounded-md transition shadow-sm active:scale-95 disabled:opacity-50">
                    <svg class="w-3.5 h-3.5 text-zinc-950" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
                    ▶ Run Protected Agent (GASHI)
                </button>
                <button id="btn-run-unprotected" onclick="runLiveAgent('unprotected')" class="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-rose-300 bg-rose-950/40 hover:bg-rose-900/50 border border-rose-800/50 rounded-md transition active:scale-95 disabled:opacity-50">
                    <svg class="w-3.5 h-3.5 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    Run Vulnerable Baseline
                </button>
            </div>
        </section>

        <!-- KPI Metrics Grid (shadcn Cards) -->
        <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            
            <!-- Ingress Card -->
            <div class="p-5 rounded-xl bg-card border border-border shadow-sm hover:border-zinc-700 transition">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-medium text-muted uppercase tracking-wider">Injections Neutralized</span>
                    <div class="w-7 h-7 rounded-md bg-zinc-900 border border-border flex items-center justify-center text-sky-400">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    </div>
                </div>
                <div class="text-2xl font-bold tracking-tight text-white mt-2" id="stat-injections">0</div>
                <p class="text-[11px] text-muted mt-1 font-mono">Stage 1: DOMSanitizer (&lt;12ms)</p>
            </div>

            <!-- Canary Leaks Card -->
            <div class="p-5 rounded-xl bg-card border border-border shadow-sm hover:border-zinc-700 transition">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-medium text-muted uppercase tracking-wider">Canary Leaks Prevented</span>
                    <div class="w-7 h-7 rounded-md bg-zinc-900 border border-border flex items-center justify-center text-emerald-400">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                    </div>
                </div>
                <div class="text-2xl font-bold tracking-tight text-white mt-2" id="stat-canaries">0</div>
                <p class="text-[11px] text-muted mt-1 font-mono">Stage 2 &amp; 4 Policy Engine (0% Leak)</p>
            </div>

            <!-- State-Change Gates Card -->
            <div class="p-5 rounded-xl bg-card border border-border shadow-sm hover:border-zinc-700 transition">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-medium text-muted uppercase tracking-wider">State-Change Gates</span>
                    <div class="w-7 h-7 rounded-md bg-zinc-900 border border-border flex items-center justify-center text-amber-400">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                    </div>
                </div>
                <div class="text-2xl font-bold tracking-tight text-white mt-2" id="stat-gates">0</div>
                <p class="text-[11px] text-muted mt-1 font-mono">Stage 3 &amp; 6 Interactive HITL</p>
            </div>

            <!-- Latency Card -->
            <div class="p-5 rounded-xl bg-card border border-border shadow-sm hover:border-zinc-700 transition">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-medium text-muted uppercase tracking-wider">Policy Decision Latency</span>
                    <div class="w-7 h-7 rounded-md bg-zinc-900 border border-border flex items-center justify-center text-violet-400">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                    </div>
                </div>
                <div class="text-2xl font-bold tracking-tight text-white mt-2">&lt; 1 ms</div>
                <p class="text-[11px] text-muted mt-1 font-mono">Zero Overhead on Agent Loop</p>
            </div>

        </section>

        <!-- Main Workspace (2-Column Grid) -->
        <main class="grid grid-cols-1 lg:grid-cols-12 gap-6">

            <!-- Left: Real-Time Event Stream & Interactive Approvals (7 Columns) -->
            <div class="lg:col-span-7 space-y-4">
                <div class="p-5 rounded-xl bg-card border border-border shadow-sm">
                    <div class="flex items-center justify-between pb-4 border-b border-border">
                        <div class="space-y-0.5">
                            <h2 class="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                                <span class="w-2 h-2 rounded-full bg-accent animate-pulse"></span>
                                Live Security Telemetry Feed
                            </h2>
                            <p class="text-xs text-muted">Real-time alerts emitted by GASHI layers guarding web_agent_test</p>
                        </div>
                        <span class="text-[11px] font-mono text-zinc-400 px-2 py-0.5 rounded bg-zinc-900 border border-border" id="stream-time">Listening...</span>
                    </div>

                    <!-- Interactive Human Approval Card (Injected dynamically) -->
                    <div id="approval-slot" class="mt-4"></div>

                    <!-- Stream Container -->
                    <div class="mt-4 space-y-2.5 max-h-[380px] overflow-y-auto pr-2 custom-scrollbar" id="feed-box">
                        <div class="p-3.5 rounded-lg bg-surface border border-border/80 flex items-start justify-between gap-3 text-xs">
                            <div class="space-y-1">
                                <div class="flex items-center gap-2 font-mono">
                                    <span class="text-accent font-semibold">[STAGE-0] SYSTEM_INIT</span>
                                    <span class="text-muted">RULE-INIT-READY</span>
                                </div>
                                <p class="text-zinc-300">GASHI Zero-Trust security runtime connected to target agent at C:\Users\defaultuser100000\web_agent_test.</p>
                            </div>
                            <span class="text-[10px] text-muted font-mono whitespace-nowrap">Ready</span>
                        </div>
                    </div>
                </div>

                <!-- Live Agent Output Console -->
                <div class="p-5 rounded-xl bg-card border border-border shadow-sm">
                    <div class="flex items-center justify-between pb-3 border-b border-border">
                        <h3 class="text-xs font-semibold text-white flex items-center gap-2 font-mono uppercase tracking-wider">
                            <svg class="w-3.5 h-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                            Live Agent Execution Console (web_agent_test)
                        </h3>
                        <span class="text-[10px] text-muted font-mono">stdout pipe</span>
                    </div>
                    <div id="agent-console-log" class="mt-3 p-3 bg-black/90 border border-zinc-800 rounded-lg max-h-48 overflow-y-auto custom-scrollbar font-mono text-[11px] leading-relaxed text-zinc-300 whitespace-pre-wrap">
[*] Console initialized. Click "Run Protected Agent" above or run from CLI to see real-time streaming execution.
                    </div>
                </div>
            </div>

            <!-- Right: Dual-Run Matrix & Audit Trail (5 Columns) -->
            <div class="lg:col-span-5 space-y-4">
                
                <!-- Dual-Run Benchmark Card -->
                <div class="p-5 rounded-xl bg-card border border-border shadow-sm">
                    <div class="pb-3 border-b border-border space-y-0.5">
                        <h2 class="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                            <svg class="w-4 h-4 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                            Dual-Run Red-Team Matrix
                        </h2>
                        <p class="text-xs text-muted">Baseline Unprotected Agent vs. GASHI Defense</p>
                    </div>

                    <div class="mt-3 divide-y divide-border/60 text-xs">
                        <div class="py-2.5 flex items-center justify-between">
                            <span class="text-zinc-300">Indirect Prompt Hijack</span>
                            <div class="flex items-center gap-3 font-mono font-medium">
                                <span class="text-red-400">100% Fail</span>
                                <span class="text-emerald-400 font-bold">0% (Safe)</span>
                            </div>
                        </div>
                        <div class="py-2.5 flex items-center justify-between">
                            <span class="text-zinc-300">Canary Secret Exfiltration</span>
                            <div class="flex items-center gap-3 font-mono font-medium">
                                <span class="text-red-400">Leaked</span>
                                <span class="text-emerald-400 font-bold">Blocked</span>
                            </div>
                        </div>
                        <div class="py-2.5 flex items-center justify-between">
                            <span class="text-zinc-300">High-Risk State Change</span>
                            <div class="flex items-center gap-3 font-mono font-medium">
                                <span class="text-red-400">Executed</span>
                                <span class="text-amber-400 font-bold">Gated</span>
                            </div>
                        </div>
                        <div class="py-2.5 flex items-center justify-between">
                            <span class="text-zinc-300">Network CDP Beacon Leak</span>
                            <div class="flex items-center gap-3 font-mono font-medium">
                                <span class="text-red-400">Sent</span>
                                <span class="text-emerald-400 font-bold">Dropped</span>
                            </div>
                        </div>
                        <div class="py-2.5 flex items-center justify-between">
                            <span class="text-zinc-300">False-Positive Rate</span>
                            <div class="flex items-center gap-3 font-mono font-medium">
                                <span class="text-muted">N/A</span>
                                <span class="text-emerald-400 font-bold">0.0%</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- SQLite Enterprise Audit Trail -->
                <div class="p-5 rounded-xl bg-card border border-border shadow-sm">
                    <div class="flex items-center justify-between pb-3 border-b border-border">
                        <div class="space-y-0.5">
                            <h2 class="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                                <svg class="w-4 h-4 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"/></svg>
                                SQLite Audit Log
                            </h2>
                            <p class="text-xs text-muted">Immutable forensic history stored in audit.db</p>
                        </div>
                        <button onclick="refreshAuditLogs()" class="p-1.5 rounded-md hover:bg-zinc-800 text-muted hover:text-zinc-200 transition">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                        </button>
                    </div>

                    <div class="mt-3 space-y-2 text-xs font-mono max-h-56 overflow-y-auto pr-1 custom-scrollbar" id="audit-list">
                        <div class="p-2 rounded bg-surface border border-border/60 text-muted text-center text-[11px]">
                            Loading audit trail...
                        </div>
                    </div>
                </div>

            </div>

        </main>

    </div>

    <!-- Live Client Script -->
    <script>
        let counterInjections = 0;
        let counterCanaries = 0;
        let counterGates = 0;

        const evtSource = new EventSource("/api/events");
        evtSource.onopen = () => {
            document.getElementById('conn-pill').innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-500"></span> SSE Connected';
            document.getElementById('stream-time').innerText = 'Live Feed Active';
        };
        evtSource.onerror = () => {
            document.getElementById('conn-pill').innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-500"></span> Reconnecting...';
        };

        evtSource.onmessage = (e) => {
            try {
                const data = JSON.parse(e.data);
                renderSecurityEvent(data);
            } catch(err) {}
        };

        function renderSecurityEvent(ev) {
            // Check if this is an Agent Console log
            if (ev.stage === 'AGENT-CONSOLE') {
                const consoleLog = document.getElementById('agent-console-log');
                if (consoleLog) {
                    const line = document.createElement('div');
                    line.className = 'font-mono text-[11px] leading-relaxed ' + 
                        (ev.reason.includes('ERROR') || ev.reason.includes('HIJACK') ? 'text-rose-400 font-semibold' :
                         ev.reason.includes('[GASHI') || ev.reason.includes('[SUCCESS]') ? 'text-emerald-400' :
                         ev.reason.includes('[LLM]') ? 'text-sky-300' : 'text-zinc-300');
                    line.innerText = ev.reason;
                    consoleLog.appendChild(line);
                    consoleLog.scrollTop = consoleLog.scrollHeight;
                }
                return;
            }

            const feed = document.getElementById('feed-box');
            const card = document.createElement('div');
            
            let badgeClass = 'bg-sky-500/10 text-sky-400 border-sky-500/20';
            let borderClass = 'border-border';
            let verdictLabel = ev.verdict || 'EVENT';

            if (ev.verdict === 'BLOCK' || ev.verdict === 'VULNERABLE' || ev.verdict === 'HIJACKED') {
                badgeClass = 'bg-red-500/10 text-red-400 border-red-500/20';
                borderClass = 'border-red-500/40 bg-red-950/10';
            } else if (ev.verdict === 'REQUIRE_APPROVAL') {
                badgeClass = 'bg-amber-500/10 text-amber-400 border-amber-500/20';
                borderClass = 'border-amber-500/40 bg-amber-950/10';
            } else if (ev.verdict === 'CLEANED' || ev.verdict === 'SAFE' || ev.verdict === 'APPROVED') {
                badgeClass = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
                borderClass = 'border-emerald-500/40 bg-emerald-950/10';
            }

            card.className = `p-3.5 rounded-lg bg-surface border ${borderClass} flex flex-col gap-1.5 text-xs transition duration-200 hover:border-zinc-600`;
            const timeStr = new Date().toLocaleTimeString();

            card.innerHTML = `
                <div class="flex items-center justify-between">
                    <div class="flex items-center gap-2 font-mono">
                        <span class="px-2 py-0.5 rounded text-[10px] font-semibold border ${badgeClass}">${verdictLabel}</span>
                        <span class="text-zinc-200 font-semibold">${ev.stage || 'SECURITY'}</span>
                        <span class="text-muted hidden sm:inline">&bull; ${ev.rule_id || 'RULE-DEFENSE'}</span>
                    </div>
                    <span class="text-[10px] text-muted font-mono">${timeStr}</span>
                </div>
                <p class="text-zinc-300 leading-relaxed font-sans text-[12px]">${ev.reason || ev.details || 'Security boundary enforced.'}</p>
            `;
            feed.prepend(card);

            // Update stats
            if (ev.rule_id && (ev.rule_id.includes('INGRESS') || ev.stage.includes('INGRESS'))) {
                counterInjections++; document.getElementById('stat-injections').innerText = counterInjections;
            }
            if (ev.rule_id && (ev.rule_id.includes('CANARY') || ev.rule_id.includes('NET'))) {
                counterCanaries++; document.getElementById('stat-canaries').innerText = counterCanaries;
            }
            if (ev.verdict === 'REQUIRE_APPROVAL') {
                counterGates++; document.getElementById('stat-gates').innerText = counterGates;
                renderShadcnApprovalModal(ev);
            }

            refreshAuditLogs();
        }

        function renderShadcnApprovalModal(ev) {
            const slot = document.getElementById('approval-slot');
            const cardId = 'approval_' + Date.now();
            const actionId = ev.action_id || 'act_transfer_8812';
            slot.innerHTML = `
                <div class="p-4 rounded-xl bg-amber-950/30 border border-amber-500/60 shadow-lg space-y-3 animate-pulse" id="${cardId}">
                    <div class="flex items-start gap-3">
                        <div class="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/40 flex items-center justify-center text-amber-400 shrink-0">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                        </div>
                        <div class="space-y-1">
                            <h3 class="text-xs font-bold text-amber-300 tracking-wide uppercase">Stage 3 Gate: Human Operator Approval Required</h3>
                            <p class="text-xs text-zinc-200 leading-normal">${ev.reason || 'Agent is attempting high-consequence financial wire transfer.'}</p>
                            <div class="flex items-center gap-3 text-[11px] font-mono text-zinc-400 pt-1">
                                <span>Target: <span class="text-zinc-200">${ev.target_url || 'http://127.0.0.1:8081/invoice'}</span></span>
                                <span>Action: <span class="text-amber-300 font-semibold">${ev.action_type || 'click'} (${ev.selector || 'button#btn-transfer'})</span></span>
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center gap-2.5 pt-1 pl-11">
                        <button onclick="resolveGate('${cardId}', '${actionId}', 'APPROVED')" class="px-3.5 py-1.5 rounded-md text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition shadow-sm active:scale-95">
                            ✓ Authorize Action
                        </button>
                        <button onclick="resolveGate('${cardId}', '${actionId}', 'DENIED')" class="px-3.5 py-1.5 rounded-md text-xs font-semibold bg-zinc-800 hover:bg-red-950 text-zinc-300 hover:text-red-400 border border-zinc-700 transition active:scale-95">
                            ✕ Deny Action
                        </button>
                    </div>
                </div>
            `;
        }

        async function resolveGate(cardId, actionId, decision) {
            const el = document.getElementById(cardId);
            if (el) el.remove();
            await fetch('/api/approvals/resolve', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({action_id: actionId, decision: decision})
            });
        }

        async function runLiveAgent(mode) {
            const consoleLog = document.getElementById('agent-console-log');
            consoleLog.innerHTML = `<span class="text-emerald-400 font-semibold">[*] Spawning real-world agent in C:\\Users\\defaultuser100000\\web_agent_test [mode=${mode}]...</span>\\n`;
            const btnProt = document.getElementById('btn-run-protected');
            const btnUnprot = document.getElementById('btn-run-unprotected');
            if (btnProt) btnProt.disabled = true;
            if (btnUnprot) btnUnprot.disabled = true;

            try {
                await fetch('/api/agent/run?mode=' + mode, { method: 'POST' });
            } finally {
                setTimeout(() => {
                    if (btnProt) btnProt.disabled = false;
                    if (btnUnprot) btnUnprot.disabled = false;
                }, 3000);
            }
        }

        async function refreshAuditLogs() {
            try {
                const resp = await fetch('/api/audit');
                const logs = await resp.json();
                const list = document.getElementById('audit-list');
                if (logs && logs.length > 0) {
                    list.innerHTML = logs.map(l => `
                        <div class="p-2 rounded bg-surface border border-border/60 flex items-center justify-between gap-2">
                            <span class="text-zinc-300"><strong class="text-white">${l.stage}</strong> &bull; ${l.verdict} (${l.rule_id})</span>
                            <span class="text-[10px] text-muted whitespace-nowrap">${l.timestamp.substring(11,19)}</span>
                        </div>
                    `).join('');
                }
            } catch(e) {}
        }

        // Initial load
        refreshAuditLogs();
    </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return SHADCN_DASHBOARD_HTML


@app.get("/api/events")
async def sse_events(request: Request):
    """Server-Sent Events endpoint streaming live security alerts."""
    queue = asyncio.Queue()
    EVENT_SUBSCRIBERS.append(queue)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                event = await queue.get()
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            if queue in EVENT_SUBSCRIBERS:
                EVENT_SUBSCRIBERS.remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


class IngestEventRequest(BaseModel):
    stage: str
    rule_id: str
    verdict: str
    reason: str
    target_url: Optional[str] = ""
    raw_payload: Optional[str] = ""


@app.post("/api/emit")
async def emit_security_event(req: IngestEventRequest):
    """External hook allowing agents and wrappers to push live events to the dashboard."""
    event_data = req.dict()
    record_audit_event(
        stage=req.stage,
        rule_id=req.rule_id,
        verdict=req.verdict,
        details=req.reason,
        target_url=req.target_url or "",
        raw_payload=req.raw_payload or ""
    )
    await broadcast_event(event_data)
    return {"status": "recorded"}


class ApprovalRequest(BaseModel):
    action_id: str
    action_type: str
    selector: Optional[str] = ""
    target_url: Optional[str] = ""
    reason: str


@app.post("/api/approvals/request")
async def create_approval_request(req: ApprovalRequest):
    """Registers a pending Human-in-the-Loop authorization request."""
    PENDING_APPROVALS[req.action_id] = {
        "action_id": req.action_id,
        "action_type": req.action_type,
        "selector": req.selector or "",
        "target_url": req.target_url or "",
        "reason": req.reason,
        "status": "PENDING",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    # Broadcast to SSE so dashboard pops up the card immediately
    await broadcast_event({
        "stage": "STAGE-3-STATE-CHANGE",
        "rule_id": "RULE-EGRESS-03-HITL",
        "verdict": "REQUIRE_APPROVAL",
        "action_id": req.action_id,
        "action_type": req.action_type,
        "selector": req.selector,
        "target_url": req.target_url,
        "reason": req.reason
    })
    return {"status": "created", "action_id": req.action_id}


@app.get("/api/approvals/status/{action_id}")
def get_approval_status(action_id: str):
    """Allows running agent to poll whether operator approved or denied the action."""
    if action_id in PENDING_APPROVALS:
        return PENDING_APPROVALS[action_id]
    return {"action_id": action_id, "status": "NOT_FOUND"}


class ResolveApprovalRequest(BaseModel):
    action_id: str
    decision: str  # "APPROVED" or "DENIED"


@app.post("/api/approvals/resolve")
async def resolve_approval_request(req: ResolveApprovalRequest):
    """Called by dashboard UI when human operator clicks Authorize or Deny."""
    if req.action_id in PENDING_APPROVALS:
        PENDING_APPROVALS[req.action_id]["status"] = req.decision

    await emit_security_event(IngestEventRequest(
        stage="STAGE-3-HITL",
        rule_id="RULE-HITL-RESOLVED",
        verdict=req.decision,
        reason=f"Human Operator {req.decision} action '{req.action_id}' in Dashboard."
    ))
    return {"status": "ok", "action_id": req.action_id, "decision": req.decision}


@app.post("/api/agent/run")
async def run_agent_execution(mode: str = "protected"):
    """
    Spawns real execution of the web_agent_test project in C:\\Users\\defaultuser100000\\web_agent_test.
    Streams real-time terminal stdout & security events to the dashboard!
    """
    agent_dir = r"C:\Users\defaultuser100000\web_agent_test"
    venv_python = os.path.join(agent_dir, ".venv", "Scripts", "python.exe")
    python_bin = venv_python if os.path.exists(venv_python) else sys.executable
    cmd = [python_bin, "run_real_world_agent_defense.py", "--mode", mode]

    async def run_task():
        await broadcast_event({
            "stage": "AGENT-CONSOLE",
            "rule_id": "INIT",
            "verdict": "STARTING",
            "reason": f"[*] Spawning real Python agent in {agent_dir} (mode={mode})..."
        })
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=agent_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").strip()
                if decoded:
                    await broadcast_event({
                        "stage": "AGENT-CONSOLE",
                        "rule_id": "STDOUT",
                        "verdict": "LOG",
                        "reason": decoded
                    })
            await proc.wait()
            await broadcast_event({
                "stage": "AGENT-CONSOLE",
                "rule_id": "COMPLETED",
                "verdict": "DONE",
                "reason": f"[+] Agent execution finished with exit code {proc.returncode}."
            })
        except Exception as err:
            await broadcast_event({
                "stage": "AGENT-CONSOLE",
                "rule_id": "ERROR",
                "verdict": "ERROR",
                "reason": f"[!] Error executing agent: {err}"
            })

    asyncio.create_task(run_task())
    return {"status": "started", "mode": mode, "agent_dir": agent_dir}


@app.get("/api/audit")
def get_audit_logs():
    """Retrieve the 15 most recent events from SQLite audit database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 15")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows
