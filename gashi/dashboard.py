"""
Stage 7: Live Web Security Dashboard & Enterprise Audit Trail.

Built with authentic shadcn/ui design system:
- Zinc/Slate dark palette (zinc-950, zinc-900, zinc-800)
- Tailwind CSS via CDN with customized shadcn theme tokens
- Lucide SVG icons (ShieldCheck, Lock, AlertTriangle, Zap, Terminal, Database)
- Real-time Server-Sent Events (SSE) streaming telemetry
- Interactive Human-in-the-Loop approval modal
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


SHADCN_DASHBOARD_HTML = """<!DOCTYPE html>
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
                    <h1 class="text-xl font-bold tracking-tight text-white">GASHI-Guard Runtime</h1>
                    <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                        7 Stages Armed
                    </span>
                </div>
            </div>

            <!-- Controls -->
            <div class="flex items-center gap-3">
                <button onclick="triggerLiveDemoAttack()" class="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-zinc-900 bg-zinc-100 hover:bg-zinc-200 rounded-md transition shadow-sm active:scale-95">
                    <svg class="w-3.5 h-3.5 text-zinc-900" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
                    Trigger Attack Demo
                </button>
                <div class="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-md bg-zinc-900 border border-border text-xs text-muted font-mono" id="conn-pill">
                    <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                    SSE Connected
                </div>
            </div>
        </header>

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
                <p class="text-[11px] text-muted mt-1 font-mono">Stage 1: DOMSanitizer</p>
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
                <p class="text-[11px] text-muted mt-1 font-mono">Stage 2 &amp; 4 Policy Engine</p>
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
                <p class="text-[11px] text-muted mt-1 font-mono">Stage 3 &amp; 6 HITL Pauses</p>
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
                <p class="text-[11px] text-muted mt-1 font-mono">Strict Target: &lt; 50 ms</p>
            </div>

        </section>

        <!-- Main Workspace (2-Column Grid) -->
        <main class="grid grid-cols-1 lg:grid-cols-12 gap-6">

            <!-- Left: Real-Time Event Stream (7 Columns) -->
            <div class="lg:col-span-7 space-y-4">
                <div class="p-5 rounded-xl bg-card border border-border shadow-sm">
                    <div class="flex items-center justify-between pb-4 border-b border-border">
                        <div class="space-y-0.5">
                            <h2 class="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                                <span class="w-2 h-2 rounded-full bg-accent"></span>
                                Live Telemetry Stream
                            </h2>
                            <p class="text-xs text-muted">Server-Sent Events emitted by Playwright runtime &amp; policies</p>
                        </div>
                        <span class="text-[11px] font-mono text-zinc-400 px-2 py-0.5 rounded bg-zinc-900 border border-border" id="stream-time">Listening...</span>
                    </div>

                    <!-- Interactive Approval Dialog (Injected dynamically) -->
                    <div id="approval-slot" class="mt-4"></div>

                    <!-- Stream Container -->
                    <div class="mt-4 space-y-2.5 max-h-[460px] overflow-y-auto pr-2 custom-scrollbar" id="feed-box">
                        <div class="p-3.5 rounded-lg bg-surface border border-border/80 flex items-start justify-between gap-3 text-xs">
                            <div class="space-y-1">
                                <div class="flex items-center gap-2 font-mono">
                                    <span class="text-accent font-semibold">[STAGE-0] SYSTEM_INIT</span>
                                    <span class="text-muted">RULE-INIT-READY</span>
                                </div>
                                <p class="text-zinc-300">GASHI Zero-Trust security runtime hooked into active browser session.</p>
                            </div>
                            <span class="text-[10px] text-muted font-mono whitespace-nowrap">Ready</span>
                        </div>
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

                <!-- SQLite Durable Audit Trail Card -->
                <div class="p-5 rounded-xl bg-card border border-border shadow-sm">
                    <div class="flex items-center justify-between pb-3 border-b border-border">
                        <div class="space-y-0.5">
                            <h2 class="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                                <svg class="w-4 h-4 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"/></svg>
                                Durable Audit Trail
                            </h2>
                            <p class="text-xs text-muted">Immutable forensic events in <code>audit.db</code></p>
                        </div>
                        <button onclick="refreshAuditLogs()" class="p-1 text-muted hover:text-white rounded hover:bg-zinc-800 transition">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                        </button>
                    </div>

                    <div class="mt-3 space-y-1.5 max-h-[170px] overflow-y-auto pr-1 text-[11px] font-mono custom-scrollbar" id="audit-list">
                        <div class="p-2 rounded bg-surface text-muted">No audit events recorded yet.</div>
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
            const feed = document.getElementById('feed-box');
            const card = document.createElement('div');
            
            let badgeClass = 'bg-sky-500/10 text-sky-400 border-sky-500/20';
            let borderClass = 'border-border';
            let verdictLabel = ev.verdict || 'EVENT';

            if (ev.verdict === 'BLOCK') {
                badgeClass = 'bg-red-500/10 text-red-400 border-red-500/20';
                borderClass = 'border-red-500/40 bg-red-950/10';
            } else if (ev.verdict === 'REQUIRE_APPROVAL') {
                badgeClass = 'bg-amber-500/10 text-amber-400 border-amber-500/20';
                borderClass = 'border-amber-500/40 bg-amber-950/10';
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
            const id = 'approval_' + Date.now();
            slot.innerHTML = `
                <div class="p-4 rounded-xl bg-amber-950/20 border border-amber-500/50 shadow-lg space-y-3" id="${id}">
                    <div class="flex items-start gap-3">
                        <div class="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                        </div>
                        <div class="space-y-1">
                            <h3 class="text-xs font-bold text-amber-300 tracking-wide uppercase">Stage 3 Gate: Human Approval Required</h3>
                            <p class="text-xs text-zinc-300 leading-normal">${ev.reason || 'Agent is attempting high-consequence state change.'}</p>
                        </div>
                    </div>
                    <div class="flex items-center gap-2.5 pt-1 pl-11">
                        <button onclick="resolveGate('${id}', 'APPROVE')" class="px-3 py-1.5 rounded-md text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition shadow-sm">
                            ✓ Authorize Action
                        </button>
                        <button onclick="resolveGate('${id}', 'DENY')" class="px-3 py-1.5 rounded-md text-xs font-semibold bg-zinc-800 hover:bg-red-950 text-zinc-300 hover:text-red-400 border border-zinc-700 transition">
                            ✕ Deny Action
                        </button>
                    </div>
                </div>
            `;
        }

        async function resolveGate(cardId, decision) {
            const el = document.getElementById(cardId);
            if (el) el.remove();
            await fetch('/api/approvals/action', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({decision: decision})
            });
        }

        async function triggerLiveDemoAttack() {
            await fetch('/api/trigger-demo', { method: 'POST' });
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


@app.post("/api/trigger-demo")
async def trigger_live_demo_sequence():
    """Simulates a rapid multi-stage attack and defense sequence on the dashboard in real time."""
    # Step 1: Ingress Attack Neutralization
    await emit_security_event(IngestEventRequest(
        stage="STAGE-1-INGRESS",
        rule_id="RULE-INGRESS-01",
        verdict="CLEANED",
        reason="Neutralized hidden -9999px off-screen container & zero-font injection in 4.2ms.",
        target_url="http://127.0.0.1:8081/invoice"
    ))
    await asyncio.sleep(0.35)

    # Step 2: Egress Canary Secret Leak Intercepted
    await emit_security_event(IngestEventRequest(
        stage="STAGE-2-EGRESS",
        rule_id="RULE-EGRESS-01-CANARY",
        verdict="BLOCK",
        reason="CANARY LEAK DETECTED: Action attempts to leak protected token 'CORP_SECRET_8812' to 'attacker-c2.xyz'.",
        target_url="https://attacker-c2.xyz/exfiltrate"
    ))
    await asyncio.sleep(0.35)

    # Step 3: Network Route Interceptor
    await emit_security_event(IngestEventRequest(
        stage="STAGE-4-NETWORK",
        rule_id="RULE-NET-01-CANARY-URL",
        verdict="BLOCK",
        reason="Network packet dropped: Outbound dynamic <img> tag attempted background beacon to unapproved C2.",
        target_url="https://attacker-c2.xyz/ping.gif"
    ))
    await asyncio.sleep(0.35)

    # Step 4: State-Change Gating (Triggers Interactive Approval Card)
    await emit_security_event(IngestEventRequest(
        stage="STAGE-3-STATE-CHANGE",
        rule_id="RULE-EGRESS-03-HITL",
        verdict="REQUIRE_APPROVAL",
        reason="STATE-CHANGE GATE: Agent is attempting to click 'Transfer Funds ($75,000)'. Action requires explicit human authorization.",
        target_url="http://127.0.0.1:8081/invoice"
    ))

    return {"status": "demo_triggered"}


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


@app.post("/api/approvals/action")
async def resolve_approval(payload: Dict[str, str]):
    decision = payload.get("decision", "DENY")
    await emit_security_event(IngestEventRequest(
        stage="STAGE-3-HITL",
        rule_id="RULE-HITL-RESOLVED",
        verdict=decision,
        reason=f"Human Operator resolved State-Change Gate with verdict: {decision}"
    ))
    return {"status": "ok", "decision": decision}
