"""
🔥 CRYSYS v3.0 - ULTIMATE EDITION 🔥
Updated with:
- Line number tracking for each suspicious log
- Context extraction (5 lines before/after)
- Timestamp extraction
- Error chain detection support
"""

import time
import json
import pickle
import re
import hashlib
from typing import TypedDict, List, Optional, Dict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime
from rich import print as rprint
from rich.panel import Panel
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.live import Live
from rich.text import Text

console = Console()


# ============================================================================
# DATA MODELS
# ============================================================================

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ErrorCategory(str, Enum):
    DATABASE = "DATABASE"
    NULL_POINTER = "NULL_POINTER"
    NETWORK = "NETWORK"
    AUTHENTICATION = "AUTHENTICATION"
    GENERIC = "GENERIC"


class ConfidenceAwareEvent(BaseModel):
    """Event with confidence tracking"""
    error_type: str
    category: ErrorCategory
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0)
    exception_class: str
    affected_component: str
    error_message: str
    needs_review: bool = False
    reasoning: str


class AnalysisState(TypedDict):
    """State with all improvements"""
    # Input
    logs: list[str]
    total_logs: int

    # Memory cache
    cache_hits: int
    cache_misses: int

    # Screening - NOW WITH LINE NUMBERS
    suspicious_indices: list[int]          # Original line numbers in file
    suspicious_with_context: list[dict]    # NEW: Each suspicious log with context
    screening_confidence: float

    # Categorization
    db_errors: list[int]
    null_errors: list[int]
    network_errors: list[int]
    auth_errors: list[int]
    generic_errors: list[int]

    # Analysis results
    error_events: list[dict]
    high_confidence_events: list[dict]
    low_confidence_events: list[dict]

    # Final
    final_summary: str
    recommendations: list[str]
    highest_severity: str
    requires_immediate_attention: bool

    # Metrics
    tokens_used: int
    processing_time: float
    route_taken: str

    # Control
    current_stage: str


# ============================================================================
# MEMORY SYSTEM
# ============================================================================

class PatternMemory:
    """Cache system to remember known patterns"""

    def __init__(self, cache_file: str = "crysys_cache.pkl"):
        self.cache_file = Path(cache_file)
        self.cache = self._load_cache()

    def _load_cache(self) -> dict:
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'rb') as f:
                    cache = pickle.load(f)
                if not isinstance(cache, dict):
                    return self._create_empty_cache()
                if 'critical_patterns' not in cache or 'safe_patterns' not in cache:
                    return self._create_empty_cache()
                console.print(f"[green]✓ Loaded {len(cache.get('critical_patterns', set()))} cached patterns[/green]")
                return cache
            except Exception as e:
                console.print(f"[yellow]⚠ Cache load error: {e}[/yellow]")
                return self._create_empty_cache()
        return self._create_empty_cache()

    def _create_empty_cache(self) -> dict:
        return {
            'critical_patterns': set(),
            'safe_patterns': set(),
            'error_classifications': {}
        }

    def save_cache(self):
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.cache, f)
        except Exception as e:
            console.print(f"[yellow]⚠ Cache save failed: {e}[/yellow]")

    def get_signature(self, log: str) -> str:
        sig = re.sub(r'\d{4}-\d{2}-\d{2}', 'DATE', log)
        sig = re.sub(r'\d{2}:\d{2}:\d{2}', 'TIME', sig)
        sig = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP', sig)
        sig = re.sub(r'[0-9]+', 'NUM', sig)
        sig = re.sub(r'user_[a-zA-Z0-9]+', 'USER_ID', sig)
        return sig[:300]

    def is_known_critical(self, log: str) -> bool:
        return self.get_signature(log) in self.cache['critical_patterns']

    def is_known_safe(self, log: str) -> bool:
        return self.get_signature(log) in self.cache['safe_patterns']

    def mark_critical(self, log: str, classification: dict = None):
        sig = self.get_signature(log)
        self.cache['critical_patterns'].add(sig)
        if classification:
            self.cache['error_classifications'][sig] = classification

    def mark_safe(self, log: str):
        self.cache['safe_patterns'].add(sig := self.get_signature(log))

    def get_classification(self, log: str) -> Optional[dict]:
        return self.cache['error_classifications'].get(self.get_signature(log))

    def clear_cache(self):
        try:
            if self.cache_file.exists():
                self.cache_file.unlink()
                self.cache = self._create_empty_cache()
        except Exception as e:
            console.print(f"[red]Failed to clear cache: {e}[/red]")


# ============================================================================
# NEW: CONTEXT EXTRACTOR
# ============================================================================

class ContextExtractor:
    """
    Extracts surrounding context for each suspicious log
    Shows 5 lines before and after each error
    """

    def __init__(self, context_window: int = 5):
        self.context_window = context_window

    def extract_timestamp(self, log_line: str) -> Optional[str]:
        """Extract timestamp from log line - supports multiple formats"""
        
        # Format 1: Liferay/Java - 2026-02-11 10:15:32 or 2026-02-11T10:15:32
        match = re.search(r'(\d{4}-\d{2}-\d{2})[T\s](\d{2}:\d{2}:\d{2})', log_line)
        if match:
            return f"{match.group(1)} {match.group(2)}"
        
        # Format 2: Apache Error Log - [Thu Jun 09 06:07:04 2005]
        match = re.search(r'\[([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\]', log_line)
        if match:
            try:
                from datetime import datetime
                dt = datetime.strptime(match.group(1), '%a %b %d %H:%M:%S %Y')
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                return match.group(1)
        
        # Format 3: Apache Access Log - [22/Jan/2019:03:56:14 +0330]
        match = re.search(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})', log_line)
        if match:
            try:
                from datetime import datetime
                dt = datetime.strptime(match.group(1), '%d/%b/%Y:%H:%M:%S')
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                return match.group(1)
        
        # Format 4: Linux Syslog - Jun 14 15:16:01 (no year!)
        match = re.search(r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', log_line)
        if match:
            try:
                from datetime import datetime
                current_year = datetime.now().year
                dt = datetime.strptime(f"{match.group(1)} {current_year}", '%b %d %H:%M:%S %Y')
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                return match.group(1)

        return None

    def get_context(self, logs: list[str], line_index: int) -> dict:
        """
        Get context for a specific line
        Returns: lines before, the error line, lines after
        """
        total_lines = len(logs)

        # Calculate context window bounds
        start = max(0, line_index - self.context_window)
        end = min(total_lines - 1, line_index + self.context_window)

        # Extract context lines
        before_lines = []
        for i in range(start, line_index):
            before_lines.append({
                'line_number': i + 1,  # 1-indexed for display
                'content': logs[i],
                'type': 'before'
            })

        after_lines = []
        for i in range(line_index + 1, end + 1):
            after_lines.append({
                'line_number': i + 1,
                'content': logs[i],
                'type': 'after'
            })

        return {
            'line_number': line_index + 1,  # 1-indexed for display
            'line_index': line_index,        # 0-indexed internal
            'log_line': logs[line_index],
            'timestamp': self.extract_timestamp(logs[line_index]),
            'before_context': before_lines,
            'after_context': after_lines,
            'context_start_line': start + 1,
            'context_end_line': end + 1
        }

    def extract_all_contexts(self, logs: list[str], suspicious_indices: list[int]) -> list[dict]:
        """Extract context for all suspicious log lines"""
        contexts = []
        for idx in suspicious_indices:
            if idx < len(logs):
                context = self.get_context(logs, idx)
                contexts.append(context)
        return contexts

    def detect_related_errors(self, contexts: list[dict]) -> list[dict]:
        """
        Detect errors that happened close together (within 5 seconds)
        These are likely related/caused by each other
        """
        chains = []
        current_chain = []

        for i, ctx in enumerate(contexts):
            if i == 0:
                current_chain = [ctx]
                continue

            prev_ts = contexts[i-1].get('timestamp')
            curr_ts = ctx.get('timestamp')

            if prev_ts and curr_ts:
                try:
                    prev_time = datetime.strptime(prev_ts, "%Y-%m-%d %H:%M:%S")
                    curr_time = datetime.strptime(curr_ts, "%Y-%m-%d %H:%M:%S")
                    diff = (curr_time - prev_time).total_seconds()

                    if abs(diff) <= 5:  # Within 5 seconds = likely related
                        current_chain.append(ctx)
                    else:
                        if len(current_chain) > 1:
                            chains.append({
                                'errors': current_chain,
                                'count': len(current_chain),
                                'start_time': current_chain[0].get('timestamp'),
                                'end_time': current_chain[-1].get('timestamp')
                            })
                        current_chain = [ctx]
                except:
                    current_chain = [ctx]
            else:
                current_chain = [ctx]

        if len(current_chain) > 1:
            chains.append({
                'errors': current_chain,
                'count': len(current_chain),
                'start_time': current_chain[0].get('timestamp'),
                'end_time': current_chain[-1].get('timestamp')
            })

        return chains


# ============================================================================
# LIVE DASHBOARD
# ============================================================================

class LiveDashboard:
    """Real-time progress display"""

    def __init__(self):
        self.stats = {
            'total_logs': 0,
            'processed_logs': 0,
            'suspicious_found': 0,
            'cache_hits': 0,
            'errors_analyzed': 0,
            'current_stage': 'Initializing'
        }

    def update(self, **kwargs):
        self.stats.update(kwargs)

    def get_table(self) -> Table:
        table = Table(title="[bold cyan]CRYSYS v3.0 - Live Analysis[/bold cyan]", show_header=False)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="yellow")

        if self.stats['total_logs'] > 0:
            pct = (self.stats['processed_logs'] / self.stats['total_logs']) * 100
            table.add_row("Progress", f"{self.stats['processed_logs']}/{self.stats['total_logs']} ({pct:.1f}%)")

        table.add_row("Current Stage", self.stats['current_stage'])
        table.add_row("Suspicious Found", str(self.stats['suspicious_found']))
        table.add_row("Cache Hits", str(self.stats['cache_hits']))
        table.add_row("Errors Analyzed", str(self.stats['errors_analyzed']))

        return table


# ============================================================================
# MAIN SYSTEM
# ============================================================================

class UltimateCRYSYS:
    """CRYSYS v3.0 with all improvements including context tracking"""

    def __init__(
        self,
        api_key: str,
        model: str = "llama-3.3-70b-versatile",
        max_input_tokens: int = 6000,
        enable_parallel: bool = True,
        enable_cache: bool = True,
        enable_dashboard: bool = True,
        context_window: int = 5  # NEW: lines of context to show
    ):
        self.llm = ChatGroq(api_key=api_key, model=model, temperature=0.3, max_tokens=2000)
        self.max_input_tokens = max_input_tokens
        self.total_tokens_used = 0
        self.enable_parallel = enable_parallel
        self.enable_cache = enable_cache
        self.enable_dashboard = enable_dashboard

        # Systems
        self.memory = PatternMemory() if enable_cache else None
        self.dashboard = LiveDashboard() if enable_dashboard else None
        self.context_extractor = ContextExtractor(context_window=context_window)  # NEW

        console.print(Panel.fit(
            "[bold cyan]CRYSYS v3.0[/bold cyan]\n"
            "[dim]Now with Context Tracking, Timeline Analysis & Error Grouping[/dim]"
        ))

    # ========================================================================
    # UTILITIES
    # ========================================================================

    def estimate_tokens(self, text: str) -> int:
        return len(text) // 4

    def chunk_logs(self, logs: list[str], chunk_size: int = 25) -> list[list[str]]:
        chunks = []
        current = []
        current_tokens = 0

        for log in logs:
            log_tokens = self.estimate_tokens(log[:500])
            if (current_tokens + log_tokens > self.max_input_tokens or
                len(current) >= chunk_size) and current:
                chunks.append(current)
                current = [log]
                current_tokens = log_tokens
            else:
                current.append(log)
                current_tokens += log_tokens

        if current:
            chunks.append(current)

        return chunks

    def safe_llm_call(self, prompt: str, system_msg: str) -> Optional[dict]:
        for attempt in range(2):
            try:
                response = self.llm.invoke([
                    SystemMessage(content=system_msg),
                    HumanMessage(content=prompt)
                ])

                self.total_tokens_used += self.estimate_tokens(prompt + response.content)
                content = response.content.strip()

                if '{' in content:
                    start = content.find('{')
                    end = content.rfind('}') + 1
                    content = content[start:end]

                return json.loads(content)

            except json.JSONDecodeError as e:
                if attempt == 0:
                    time.sleep(1)
                    continue
                return None
            except Exception as e:
                if attempt == 0:
                    time.sleep(2)
                    continue
                return None

        return None

    def keyword_screen(self, logs: list[str], offset: int = 0) -> list[int]:
        suspicious = []
        keywords = ['error', 'exception', 'failed', 'fatal', 'critical', 'null', 'timeout']

        for i, log in enumerate(logs):
            log_lower = log.lower()
            if any(kw in log_lower for kw in keywords):
                if not any(level in log_lower for level in ['info:', 'debug:', 'trace:']):
                    suspicious.append(i + offset)

        return suspicious

    # ========================================================================
    # SCREENING WITH CONTEXT TRACKING (NEW!)
    # ========================================================================

    def create_fewshot_screening_prompt(self, chunk: list[str], offset: int) -> str:
        return f"""You are an expert log screener. Learn from these examples:

EXAMPLE 1 - SUSPICIOUS ✓
"2026-01-20 10:15:32 ERROR [UserService] NullPointerException at line 245"
→ MARK AS SUSPICIOUS (ERROR + Exception)

EXAMPLE 2 - NOT SUSPICIOUS ✗
"2026-01-20 10:15:33 INFO [SystemService] User login successful"
→ DO NOT MARK (INFO level, normal operation)

EXAMPLE 3 - SUSPICIOUS ✓
"2026-01-20 10:15:34 FATAL [DatabasePool] Connection timeout after 30s"
→ MARK AS SUSPICIOUS (FATAL + timeout)

EXAMPLE 4 - NOT SUSPICIOUS ✗
"2026-01-20 10:15:35 DEBUG [CacheManager] Cache hit for user_12345"
→ DO NOT MARK (DEBUG, successful operation)

STRICT RULES:
✓ MARK if contains: ERROR, FATAL, CRITICAL, Exception, Failed, Timeout, Refused, Denied
✗ DO NOT MARK if: INFO, DEBUG, TRACE, successful, completed, started

Now screen these logs (indices {offset} to {offset + len(chunk) - 1}):

{chr(10).join([f"{i+offset}: {log[:200]}" for i, log in enumerate(chunk)])}

Return ONLY valid JSON:
{{"suspicious_indices": [1, 5, 12], "confidence": 0.92}}

Be SELECTIVE - most logs are normal!"""

    def agent_screen_logs(self, state: AnalysisState) -> AnalysisState:
        """
        Screen logs with context tracking.
        Now captures line numbers and surrounding context for each suspicious log.
        """
        console.print("\n[bold cyan]🔍 Screening with Context Tracking[/bold cyan]")

        if self.dashboard:
            self.dashboard.update(current_stage="Screening")

        all_logs = state['logs']
        total_logs = len(all_logs)
        all_suspicious = []
        cache_hits = 0

        # Keyword Pre-filter - Updated for multiple log formats
        console.print(f"[cyan]Step 1: Keyword pre-filter on {total_logs:,} logs...[/cyan]")

        error_keywords = [
            # General error keywords
            'error', 'exception', 'failed', 'fatal', 'critical',
            'timeout', 'refused', 'unavailable', 'failure', 'warn',
            'nullpointer', 'stacktrace', 'caused by',
            # Apache/Linux specific
            'authentication failure', 'connection refused', 
            'cannot create', 'abnormally', 'denied',
            # HTTP error codes
            ' 404 ', ' 500 ', ' 502 ', ' 503 ', ' 504 ',
            # System errors
            'segfault', 'core dumped', 'panic'
        ]
        
        safe_indicators = [
            'info  ', 'debug ', 'trace ', 'notice ',
            # Apache notice (not error)
            '[notice]',
            # Successful operations
            'success', 'ok /etc', 'resuming normal', 'configured',
            'session opened', 'session closed',
            # HTTP success codes
            ' 200 ', ' 201 ', ' 204 ', ' 301 ', ' 302 '
        ]

        keyword_candidates = []

        for i, log in enumerate(all_logs):
            log_lower = log.lower()
            if any(safe in log_lower for safe in safe_indicators):
                if not any(kw in log_lower for kw in error_keywords):
                    continue
            if any(kw in log_lower for kw in error_keywords):
                keyword_candidates.append((i, log))

        console.print(f"[green]  ✓ Pre-filter: {total_logs:,} → {len(keyword_candidates):,} candidates[/green]")

        if len(keyword_candidates) == 0:
            state['suspicious_indices'] = []
            state['suspicious_with_context'] = []
            state['cache_hits'] = total_logs
            state['cache_misses'] = 0
            state['screening_confidence'] = 1.0
            state['current_stage'] = 'routing'
            return state

        # STEP 2: Cache Check
        console.print(f"[cyan]Step 2: Cache check on {len(keyword_candidates):,} candidates...[/cyan]")

        unknown_candidates = []

        if self.enable_cache and self.memory:
            for orig_idx, log in keyword_candidates:
                if self.memory.is_known_critical(log):
                    all_suspicious.append(orig_idx)
                    cache_hits += 1
                elif self.memory.is_known_safe(log):
                    cache_hits += 1
                else:
                    unknown_candidates.append((orig_idx, log))
            console.print(f"[green]  ✓ Cache: {cache_hits} known, {len(unknown_candidates)} need LLM[/green]")
        else:
            unknown_candidates = keyword_candidates

        if self.dashboard:
            self.dashboard.update(cache_hits=cache_hits)

        # STEP 3: LLM Confirmation
        if unknown_candidates:
            MAX_LLM_CANDIDATES = 500
            MAX_LLM_CHUNKS = 10
            CHUNK_SIZE = 25
            DELAY_BETWEEN_CALLS = 1.5

            if len(unknown_candidates) > MAX_LLM_CANDIDATES:
                for orig_idx, log in unknown_candidates:
                    all_suspicious.append(orig_idx)
            else:
                console.print(f"[cyan]Step 3: LLM confirmation on {len(unknown_candidates)} candidates...[/cyan]")

                candidate_logs = [log for _, log in unknown_candidates]
                candidate_indices = [idx for idx, _ in unknown_candidates]

                chunks = []
                for i in range(0, len(candidate_logs), CHUNK_SIZE):
                    chunks.append(candidate_logs[i:i + CHUNK_SIZE])

                chunks_to_process = chunks[:MAX_LLM_CHUNKS]

                llm_offset = 0
                for chunk_idx, chunk in enumerate(chunks_to_process):
                    console.print(f"  [cyan]LLM chunk {chunk_idx + 1}/{len(chunks_to_process)}...[/cyan]", end=" ")

                    prompt = self.create_fewshot_screening_prompt(chunk, llm_offset)
                    result = self.safe_llm_call(
                        prompt=prompt,
                        system_msg="You are a log screener. Be SELECTIVE. Output ONLY valid JSON."
                    )

                    if result and 'suspicious_indices' in result:
                        for llm_idx in result['suspicious_indices']:
                            real_pos = llm_offset + llm_idx
                            if real_pos < len(candidate_indices):
                                all_suspicious.append(candidate_indices[real_pos])
                        console.print(f"[green]✓ found {len(result.get('suspicious_indices', []))}[/green]")
                    else:
                        for i in range(llm_offset, min(llm_offset + CHUNK_SIZE, len(candidate_indices))):
                            all_suspicious.append(candidate_indices[i])
                        console.print(f"[yellow]⚠ fallback[/yellow]")

                    llm_offset += len(chunk)

                    if chunk_idx < len(chunks_to_process) - 1:
                        time.sleep(DELAY_BETWEEN_CALLS)

        # STEP 4: Update Cache
        if self.enable_cache and self.memory:
            for i in all_suspicious:
                if i < len(all_logs):
                    self.memory.mark_critical(all_logs[i])

            safe_sample_indices = [i for i in range(0, total_logs, max(1, total_logs // 5000))
                                   if i not in set(all_suspicious)]
            for i in safe_sample_indices[:5000]:
                if i < len(all_logs):
                    self.memory.mark_safe(all_logs[i])

        # Deduplicate and sort
        all_suspicious = sorted(list(set(all_suspicious)))

        # ====================================================================
        # NEW: EXTRACT CONTEXT FOR EACH SUSPICIOUS LOG
        # ====================================================================
        console.print(f"[cyan]Step 4: Extracting context for {len(all_suspicious)} suspicious logs...[/cyan]")

        suspicious_with_context = self.context_extractor.extract_all_contexts(
            all_logs, all_suspicious
        )

        # Detect related error chains
        error_chains = self.context_extractor.detect_related_errors(suspicious_with_context)

        if error_chains:
            console.print(f"[yellow]  ⚡ Detected {len(error_chains)} error chains (related errors)[/yellow]")

        suspicious_pct = len(all_suspicious) / max(total_logs, 1) * 100
        console.print(f"\n[bold green]✅ Screening: {len(all_suspicious):,}/{total_logs:,} suspicious ({suspicious_pct:.1f}%)[/bold green]")

        state['suspicious_indices'] = all_suspicious
        state['suspicious_with_context'] = suspicious_with_context  # NEW
        state['cache_hits'] = cache_hits
        state['cache_misses'] = len(unknown_candidates)
        state['screening_confidence'] = 0.9
        state['current_stage'] = 'routing'

        if self.dashboard:
            self.dashboard.update(
                processed_logs=total_logs,
                suspicious_found=len(all_suspicious)
            )

        return state

    # ========================================================================
    # CATEGORIZATION
    # ========================================================================

    def agent_categorize_errors(self, state: AnalysisState) -> AnalysisState:
        """Categorize errors by type"""
        suspicious_count = len(state['suspicious_indices'])

        console.print(f"\n[bold cyan]🔀 Categorizing Errors[/bold cyan]")

        if suspicious_count == 0:
            state['route_taken'] = 'skip'
            state['current_stage'] = 'report'
            return state

        suspicious_logs = [state['logs'][i] for i in state['suspicious_indices']
                          if i < len(state['logs'])]

        db_errors = []
        null_errors = []
        network_errors = []
        auth_errors = []
        generic_errors = []

        for i, log in zip(state['suspicious_indices'], suspicious_logs):
            log_lower = log.lower()

            # Database errors
            if any(kw in log_lower for kw in ['database', 'jdbc', 'sql', 'connection pool', 'hibernate']):
                db_errors.append(i)
            # NullPointer errors  
            elif any(kw in log_lower for kw in ['nullpointer', 'null pointer', 'npe']):
                null_errors.append(i)
            # Network errors (includes Apache connection issues)
            elif any(kw in log_lower for kw in ['network', 'timeout', 'connection refused', 'socket', 
                                                  'cannot create', 'factory error', 'unavailable']):
                network_errors.append(i)
            # Authentication errors (Linux/Apache auth failures)
            elif any(kw in log_lower for kw in ['auth', 'login', 'permission', 'unauthorized', 
                                                  'authentication failure', 'check pass', 'user unknown',
                                                  'denied', 'forbidden', ' 401 ', ' 403 ']):
                auth_errors.append(i)
            # HTTP errors (Apache access logs)
            elif any(kw in log_lower for kw in [' 404 ', ' 500 ', ' 502 ', ' 503 ', ' 504 ', 
                                                  ' 400 ', ' 499 ']):
                network_errors.append(i)  # Treat HTTP errors as network issues
            else:
                generic_errors.append(i)

        state['db_errors'] = db_errors
        state['null_errors'] = null_errors
        state['network_errors'] = network_errors
        state['auth_errors'] = auth_errors
        state['generic_errors'] = generic_errors

        console.print(f"  Database: {len(db_errors)}")
        console.print(f"  NullPointer: {len(null_errors)}")
        console.print(f"  Network: {len(network_errors)}")
        console.print(f"  Authentication: {len(auth_errors)}")
        console.print(f"  Generic: {len(generic_errors)}")

        if suspicious_count <= 15:
            state['route_taken'] = 'quick'
            state['current_stage'] = 'quick_analysis'
        else:
            state['route_taken'] = 'specialized'
            state['current_stage'] = 'specialized_analysis'

        return state

    def decide_analysis_route(self, state: AnalysisState) -> str:
        route = state.get('route_taken', 'skip')
        if route == 'skip':
            return 'report'
        elif route == 'quick':
            return 'quick_analysis'
        else:
            return 'specialized_analysis'

    # ========================================================================
    # SPECIALIZED AGENTS - NOW WITH LINE NUMBER INFO
    # ========================================================================

    def _enrich_events_with_context(self, events: list[dict], category_indices: list[int], state: AnalysisState) -> list[dict]:
        """
        NEW: Enrich AI-analyzed events with line numbers and context
        Maps each event back to its original log line
        """
        # Build lookup: index -> context
        context_lookup = {}
        for ctx in state.get('suspicious_with_context', []):
            context_lookup[ctx['line_index']] = ctx

        enriched = []
        for i, event in enumerate(events):
            # Try to match event to a log line
            if i < len(category_indices):
                orig_idx = category_indices[i]
                if orig_idx in context_lookup:
                    ctx = context_lookup[orig_idx]
                    event['line_number'] = ctx['line_number']
                    event['timestamp'] = ctx.get('timestamp', 'Unknown')
                    event['log_line'] = ctx['log_line']
                    event['before_context'] = ctx['before_context']
                    event['after_context'] = ctx['after_context']
                    event['context_start_line'] = ctx['context_start_line']
                    event['context_end_line'] = ctx['context_end_line']

            enriched.append(event)

        return enriched

    def analyze_database_errors(self, logs: list[str], indices: list[int], state: AnalysisState) -> list[dict]:
        """Database specialist with context enrichment"""
        if not logs:
            return []

        prompt = f"""You are a DATABASE ERROR SPECIALIST analyzing database errors.

LOGS TO ANALYZE:
{chr(10).join(logs[:15])}

For EACH error provide:
- exception_class, severity (CRITICAL/HIGH/MEDIUM/LOW), confidence (0.0-1.0)
- component, message, reasoning
- stack_trace_depth, possible_root_causes, recommended_actions

OUTPUT FORMAT:
{{
  "events": [
    {{
      "exception_class": "JDBCConnectionException",
      "severity": "CRITICAL",
      "confidence": 0.95,
      "component": "HikariPool-1",
      "message": "Connection timeout after 30000ms",
      "reasoning": "Connection pool exhausted",
      "stack_trace_depth": 10,
      "possible_root_causes": ["Database server down", "Pool too small"],
      "recommended_actions": ["Check database server", "Increase pool size"]
    }}
  ]
}}

Output ONLY valid JSON."""

        result = self.safe_llm_call(prompt, "You are a database expert. Output ONLY valid JSON.")

        if result and isinstance(result, dict) and 'events' in result:
            events = result['events']
        elif result and isinstance(result, list):
            events = result
        else:
            events = []

        # Enrich with context
        events = self._enrich_events_with_context(events, indices, state)

        return events

    def analyze_nullpointer_errors(self, logs: list[str], indices: list[int], state: AnalysisState) -> list[dict]:
        """NullPointer specialist with context enrichment"""
        if not logs:
            return []

        prompt = f"""You are a NULL POINTER EXCEPTION SPECIALIST.

LOGS TO ANALYZE:
{chr(10).join(logs[:15])}

For EACH error provide:
- exception_class, severity, confidence, component, message, reasoning
- stack_trace_depth, possible_root_causes, recommended_actions

OUTPUT FORMAT:
{{
  "events": [
    {{
      "exception_class": "NullPointerException",
      "severity": "HIGH",
      "confidence": 0.88,
      "component": "UserService",
      "message": "Null user object at line 245",
      "reasoning": "User object not initialized",
      "stack_trace_depth": 8,
      "possible_root_causes": ["User not found in database"],
      "recommended_actions": ["Add null check before user access"]
    }}
  ]
}}

Output ONLY valid JSON."""

        result = self.safe_llm_call(prompt, "You are a null safety expert. Output ONLY valid JSON.")

        if result and isinstance(result, dict) and 'events' in result:
            events = result['events']
        elif result and isinstance(result, list):
            events = result
        else:
            events = []

        events = self._enrich_events_with_context(events, indices, state)
        return events

    def analyze_network_errors(self, logs: list[str], indices: list[int], state: AnalysisState) -> list[dict]:
        """Network specialist with context enrichment"""
        if not logs:
            return []

        prompt = f"""You are a NETWORK ERROR SPECIALIST.

LOGS TO ANALYZE:
{chr(10).join(logs[:15])}

For EACH error provide:
- exception_class, severity, confidence, component, message, reasoning
- stack_trace_depth, possible_root_causes, recommended_actions

OUTPUT FORMAT:
{{
  "events": [
    {{
      "exception_class": "SocketTimeoutException",
      "severity": "HIGH",
      "confidence": 0.92,
      "component": "NetworkClient",
      "message": "Connection timeout after 30s",
      "reasoning": "Remote service not responding",
      "stack_trace_depth": 6,
      "possible_root_causes": ["Remote service down"],
      "recommended_actions": ["Check remote service"]
    }}
  ]
}}

Output ONLY valid JSON."""

        result = self.safe_llm_call(prompt, "You are a network expert. Output ONLY valid JSON.")

        if result and isinstance(result, dict) and 'events' in result:
            events = result['events']
        elif result and isinstance(result, list):
            events = result
        else:
            events = []

        events = self._enrich_events_with_context(events, indices, state)
        return events

    def analyze_authentication_errors(self, logs: list[str], indices: list[int], state: AnalysisState) -> list[dict]:
        """Authentication specialist with context enrichment - handles Linux syslog, Apache, Liferay auth"""
        if not logs:
            return []

        prompt = f"""You are an AUTHENTICATION ERROR SPECIALIST analyzing authentication/authorization failures.

This includes:
- Linux syslog authentication failures (pam_unix, sshd)
- Apache/web server authentication issues
- Application-level auth errors
- HTTP 401/403 errors

LOGS TO ANALYZE:
{chr(10).join(logs[:15])}

For EACH error provide:
- exception_class (e.g., "AuthenticationFailure", "SSHAuthFailure", "HTTP403")
- severity (CRITICAL if many attempts, HIGH for single failures, MEDIUM for expected failures)
- confidence (0.0-1.0)
- component (e.g., "sshd", "Apache", "AuthService")
- message (brief description)
- reasoning (why this is an auth issue)
- stack_trace_depth (usually 0 for system logs)
- possible_root_causes (e.g., "Brute force attack", "Invalid credentials", "Expired session")
- recommended_actions (e.g., "Block IP", "Reset password", "Check firewall")

IMPORTANT:
- Multiple auth failures from same IP = likely brute force attack (CRITICAL)
- "user unknown" = reconnaissance attempt (HIGH)
- Single failure = normal failed login (MEDIUM)

OUTPUT FORMAT:
{{
  "events": [
    {{
      "exception_class": "SSHAuthenticationFailure",
      "severity": "HIGH",
      "confidence": 0.95,
      "component": "sshd",
      "message": "Failed SSH login attempt from 218.188.2.4",
      "reasoning": "Multiple authentication failures indicate brute force attempt",
      "stack_trace_depth": 0,
      "possible_root_causes": ["Brute force attack", "Invalid credentials"],
      "recommended_actions": ["Block IP 218.188.2.4", "Enable fail2ban", "Review SSH config"]
    }}
  ]
}}

Output ONLY valid JSON."""

        result = self.safe_llm_call(prompt, "You are an authentication security expert. Output ONLY valid JSON.")

        if result and isinstance(result, dict) and 'events' in result:
            events = result['events']
        elif result and isinstance(result, list):
            events = result
        else:
            events = []

        events = self._enrich_events_with_context(events, indices, state)
        return events
        """Generic analyst with context enrichment"""
        if not logs:
            return []

        prompt = f"""You are analyzing ERROR LOGS.

LOGS TO ANALYZE:
{chr(10).join(logs[:15])}

For EACH error provide:
- exception_class, severity, confidence, component, message, reasoning
- stack_trace_depth, possible_root_causes, recommended_actions

OUTPUT FORMAT:
{{
  "events": [
    {{
      "exception_class": "RuntimeException",
      "severity": "HIGH",
      "confidence": 0.85,
      "component": "ServiceName",
      "message": "Brief error description",
      "reasoning": "Why this error occurred",
      "stack_trace_depth": 10,
      "possible_root_causes": ["Cause 1", "Cause 2"],
      "recommended_actions": ["Action 1", "Action 2"]
    }}
  ]
}}

Output ONLY valid JSON."""

        result = self.safe_llm_call(prompt, "You are an error analyst. Output ONLY valid JSON.")

        if result and isinstance(result, dict) and 'events' in result:
            events = result['events']
        elif result and isinstance(result, list):
            events = result
        else:
            events = []

        events = self._enrich_events_with_context(events, indices, state)
        return events

    # ========================================================================
    # QUICK ANALYSIS
    # ========================================================================

    def agent_quick_analysis(self, state: AnalysisState) -> AnalysisState:
        """Quick analysis for few errors with context"""
        console.print("\n[bold yellow]🔬 Quick Analysis[/bold yellow]")

        if self.dashboard:
            self.dashboard.update(current_stage="Quick Analysis")

        suspicious_logs = [state['logs'][i] for i in state['suspicious_indices']]
        all_indices = state['suspicious_indices']

        prompt = f"""Analyze these {len(suspicious_logs)} errors:

{chr(10).join(suspicious_logs)}

For each error provide:
- exception_class, severity (CRITICAL/HIGH/MEDIUM/LOW), confidence (0.0-1.0)
- component, message, reasoning
- possible_root_causes, recommended_actions

Return JSON: {{"events": [...]}}"""

        result = self.safe_llm_call(prompt, "You are an error analyst. Output ONLY JSON.")

        if result and 'events' in result:
            events = result['events']
            events = self._enrich_events_with_context(events, all_indices, state)
        else:
            events = []

        state['error_events'] = events
        state['tokens_used'] = self.total_tokens_used
        state['current_stage'] = 'confidence_filter'

        console.print(f"[green]✓ Found {len(events)} events[/green]")
        return state

    # ========================================================================
    # SPECIALIZED ANALYSIS - NOW PASSES INDICES AND STATE
    # ========================================================================

    def agent_specialized_analysis(self, state: AnalysisState) -> AnalysisState:
        """Specialized analysis with context enrichment"""
        console.print("\n[bold cyan]🔬 Specialized Analysis[/bold cyan]")

        if self.dashboard:
            self.dashboard.update(current_stage="Specialized Analysis")

        all_events = []

        # Database specialist
        if state['db_errors']:
            console.print(f"\n[cyan]→ Database specialist analyzing {len(state['db_errors'])} errors...[/cyan]")
            db_logs = [state['logs'][i] for i in state['db_errors'] if i < len(state['logs'])]
            if db_logs:
                db_events = self.analyze_database_errors(db_logs, state['db_errors'], state)
                for event in db_events:
                    event['category'] = 'DATABASE'
                all_events.extend(db_events)
                console.print(f"  [green]✓ Database: {len(db_events)} events[/green]")

        # NullPointer specialist
        if state['null_errors']:
            console.print(f"\n[cyan]→ NullPointer specialist analyzing {len(state['null_errors'])} errors...[/cyan]")
            null_logs = [state['logs'][i] for i in state['null_errors'] if i < len(state['logs'])]
            if null_logs:
                null_events = self.analyze_nullpointer_errors(null_logs, state['null_errors'], state)
                for event in null_events:
                    event['category'] = 'NULL_POINTER'
                all_events.extend(null_events)
                console.print(f"  [green]✓ NullPointer: {len(null_events)} events[/green]")

        # Network specialist
        if state['network_errors']:
            console.print(f"\n[cyan]→ Network specialist analyzing {len(state['network_errors'])} errors...[/cyan]")
            net_logs = [state['logs'][i] for i in state['network_errors'] if i < len(state['logs'])]
            if net_logs:
                net_events = self.analyze_network_errors(net_logs, state['network_errors'], state)
                for event in net_events:
                    event['category'] = 'NETWORK'
                all_events.extend(net_events)
                console.print(f"  [green]✓ Network: {len(net_events)} events[/green]")

        # Authentication specialist (NEW!)
        if state['auth_errors']:
            console.print(f"\n[cyan]→ Authentication specialist analyzing {len(state['auth_errors'])} errors...[/cyan]")
            auth_logs = [state['logs'][i] for i in state['auth_errors'] if i < len(state['logs'])]
            if auth_logs:
                auth_events = self.analyze_authentication_errors(auth_logs, state['auth_errors'], state)
                for event in auth_events:
                    event['category'] = 'AUTHENTICATION'
                all_events.extend(auth_events)
                console.print(f"  [green]✓ Authentication: {len(auth_events)} events[/green]")

        # Generic errors
        if state['generic_errors']:
            console.print(f"\n[cyan]→ Generic analyst analyzing {len(state['generic_errors'])} errors...[/cyan]")
            other_logs = [state['logs'][i] for i in state['generic_errors'] if i < len(state['logs'])]
            if other_logs:
                other_events = self.analyze_generic_errors(other_logs, state['generic_errors'], state)
                for event in other_events:
                    event['category'] = 'GENERIC'
                all_events.extend(other_events)
                console.print(f"  [green]✓ Generic: {len(other_events)} events[/green]")

        state['error_events'] = all_events
        state['tokens_used'] = self.total_tokens_used
        state['current_stage'] = 'confidence_filter'

        console.print(f"\n[bold green]✅ Total events: {len(all_events)}[/bold green]")

        if self.dashboard:
            self.dashboard.update(errors_analyzed=len(all_events))

        return state

    # ========================================================================
    # CONFIDENCE FILTERING
    # ========================================================================

    def agent_confidence_filter(self, state: AnalysisState) -> AnalysisState:
        """Separate high-confidence from low-confidence events"""
        console.print("\n[bold magenta]📊 Confidence Filtering[/bold magenta]")

        if self.dashboard:
            self.dashboard.update(current_stage="Confidence Filtering")

        high_confidence = []
        low_confidence = []

        for event in state['error_events']:
            confidence = event.get('confidence', 0.5)
            if confidence >= 0.7:
                high_confidence.append(event)
            else:
                low_confidence.append(event)
                event['needs_review'] = True

        state['high_confidence_events'] = high_confidence
        state['low_confidence_events'] = low_confidence
        state['current_stage'] = 'report'

        console.print(f"[green]✓ High confidence: {len(high_confidence)}[/green]")
        console.print(f"[yellow]⚠ Low confidence (needs review): {len(low_confidence)}[/yellow]")

        return state

    # ========================================================================
    # REPORT GENERATION
    # ========================================================================

    def agent_generate_report(self, state: AnalysisState) -> AnalysisState:
        """Generate final report"""
        console.print("\n[bold green]📋 Generating Report[/bold green]")

        if self.dashboard:
            self.dashboard.update(current_stage="Generating Report")

        if state['route_taken'] == 'skip':
            state['final_summary'] = "No errors detected. All systems operating normally."
            state['recommendations'] = ["Continue monitoring"]
            state['highest_severity'] = "INFO"
            state['requires_immediate_attention'] = False
        else:
            events = state['error_events']
            critical = sum(1 for e in events if e.get('severity') == 'CRITICAL')
            high = sum(1 for e in events if e.get('severity') == 'HIGH')

            if critical > 0:
                state['highest_severity'] = 'CRITICAL'
                state['requires_immediate_attention'] = True
            elif high > 3:
                state['highest_severity'] = 'HIGH'
                state['requires_immediate_attention'] = True
            else:
                state['highest_severity'] = 'MEDIUM'
                state['requires_immediate_attention'] = False

            cache_efficiency = (state['cache_hits'] / max(state['total_logs'], 1)) * 100 if state.get('cache_hits', 0) > 0 else 0
            state['final_summary'] = f"Analyzed {state['total_logs']} logs "
            if cache_efficiency > 0:
                state['final_summary'] += f"({cache_efficiency:.0f}% from cache) "
            state['final_summary'] += f"and found {len(state['suspicious_indices'])} suspicious ({len(events)} confirmed errors). "

            if critical > 0:
                state['final_summary'] += f"{critical} CRITICAL errors require immediate attention."

            state['recommendations'] = []
            if len(state['low_confidence_events']) > 0:
                state['recommendations'].append(f"Review {len(state['low_confidence_events'])} low-confidence events manually")
            if state['db_errors']:
                state['recommendations'].append("Investigate database connection pool configuration")
            if state['null_errors']:
                state['recommendations'].append("Add null safety checks in affected components")
            if state['network_errors']:
                state['recommendations'].append("Check network connectivity and timeouts")
            if not state['recommendations']:
                state['recommendations'] = ["Monitor for recurring patterns", "Review error logs"]

        state['current_stage'] = 'complete'
        state['tokens_used'] = self.total_tokens_used

        if self.enable_cache and self.memory:
            self.memory.save_cache()
            console.print("[green]✓ Cache saved for next run[/green]")

        return state

    # ========================================================================
    # BUILD GRAPH
    # ========================================================================

    def build_graph(self):
        """Build workflow"""
        workflow = StateGraph(AnalysisState)

        workflow.add_node("screening", self.agent_screen_logs)
        workflow.add_node("categorize", self.agent_categorize_errors)
        workflow.add_node("quick_analysis", self.agent_quick_analysis)
        workflow.add_node("specialized_analysis", self.agent_specialized_analysis)
        workflow.add_node("confidence_filter", self.agent_confidence_filter)
        workflow.add_node("report", self.agent_generate_report)

        workflow.set_entry_point("screening")
        workflow.add_edge("screening", "categorize")

        workflow.add_conditional_edges(
            "categorize",
            self.decide_analysis_route,
            {
                'report': 'report',
                'quick_analysis': 'quick_analysis',
                'specialized_analysis': 'specialized_analysis'
            }
        )

        workflow.add_edge("quick_analysis", "confidence_filter")
        workflow.add_edge("specialized_analysis", "confidence_filter")
        workflow.add_edge("confidence_filter", "report")
        workflow.add_edge("report", END)

        return workflow.compile()

    # ========================================================================
    # MAIN ANALYSIS
    # ========================================================================

    def analyze_logs(self, logs: list[str]) -> dict:
        """Run complete analysis"""
        if self.dashboard:
            self.dashboard.update(total_logs=len(logs), current_stage="Starting")

        console.print(Panel.fit(
            f"[bold yellow]🚀 CRYSYS v3.0[/bold yellow]\n"
            f"Analyzing {len(logs)} logs",
            border_style="yellow"
        ))

        app = self.build_graph()

        initial_state = {
            'logs': logs,
            'total_logs': len(logs),
            'cache_hits': 0,
            'cache_misses': 0,
            'suspicious_indices': [],
            'suspicious_with_context': [],  # NEW
            'screening_confidence': 0.0,
            'db_errors': [],
            'null_errors': [],
            'network_errors': [],
            'auth_errors': [],
            'generic_errors': [],
            'error_events': [],
            'high_confidence_events': [],
            'low_confidence_events': [],
            'final_summary': '',
            'recommendations': [],
            'highest_severity': 'INFO',
            'requires_immediate_attention': False,
            'tokens_used': 0,
            'processing_time': 0.0,
            'route_taken': '',
            'current_stage': 'screening'
        }

        start_time = time.time()

        if self.enable_dashboard and self.dashboard:
            with Live(self.dashboard.get_table(), refresh_per_second=4, console=console):
                final_state = app.invoke(initial_state)
        else:
            final_state = app.invoke(initial_state)

        elapsed = time.time() - start_time
        final_state['processing_time'] = elapsed

        console.print(f"\n[bold green]✅ Analysis Complete in {elapsed:.1f}s[/bold green]")

        return final_state


# ============================================================================
# MAIN
# ============================================================================

def main():
    import sys

    if '--clear-cache' in sys.argv or '--reset' in sys.argv:
        cache_file = Path("crysys_cache.pkl")
        if cache_file.exists():
            cache_file.unlink()
            console.print("[bold green]✓ Cache cleared![/bold green]")
        return

    GROQ_API_KEY = "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"

    sample_logs = [
        "2026-01-20 10:15:32 ERROR [BlogsEntryService] java.lang.NullPointerException at line 245",
        "2026-01-20 10:15:33 ERROR [DatabasePool] org.hibernate.exception.JDBCConnectionException: Cannot connect to database",
        "2026-01-20 10:15:34 INFO [SystemService] Application started successfully",
        "2026-01-20 10:15:35 ERROR [UserService] java.lang.NullPointerException at UserServiceImpl.getUserById",
        "2026-01-20 10:15:36 DEBUG [CacheManager] Cache hit for key user_12345",
        "2026-01-20 10:15:37 INFO [HealthCheck] System health check passed",
        "2026-01-20 10:15:38 ERROR [AuthService] Failed login attempt for user admin from IP 192.168.1.100",
        "2026-01-20 10:15:39 ERROR [NetworkClient] java.net.SocketTimeoutException: Connection timeout after 30s",
        "2026-01-20 10:15:40 ERROR [DatabasePool] Connection pool exhausted, max 100 connections",
        "2026-01-20 10:15:41 INFO [APIController] Request processed successfully in 45ms",
    ] * 20

    try:
        with open("logs/liferay.log", 'r', encoding='utf-8') as f:
            real_logs = [line.strip() for line in f.readlines() if line.strip()]
            if real_logs:
                sample_logs = real_logs
    except:
        console.print("[yellow]⚠ Using sample logs[/yellow]")

    analyzer = UltimateCRYSYS(
        api_key=GROQ_API_KEY,
        enable_parallel=True,
        enable_cache=True,
        enable_dashboard=True,
        context_window=5
    )

    results = analyzer.analyze_logs(sample_logs)

    console.print(f"\n[bold green]Analysis Complete![/bold green]")
    console.print(f"Total errors: {len(results['error_events'])}")
    console.print(f"Processing time: {results['processing_time']:.1f}s")


if __name__ == "__main__":
    main()
