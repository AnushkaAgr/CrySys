"""
Error Grouping and Deduplication Module
Groups similar errors together and detects patterns
"""

import hashlib
from collections import defaultdict
from datetime import datetime
import re


class ErrorGrouper:
    """Groups similar errors and detects patterns"""
    
    def __init__(self):
        self.groups = defaultdict(list)
    
    def get_error_signature(self, error: dict) -> str:
        """
        Create unique signature for error grouping
        Ignores line numbers, timestamps, specific IDs
        """
        # Extract key components
        exception = error.get('exception_class', 'Unknown')
        component = error.get('component', 'Unknown')
        message = error.get('message', '')
        
        # Normalize message - DO TIMESTAMPS FIRST before removing all digits!
        normalized_message = message
        
        # Remove full timestamps FIRST (before general digit removal)
        normalized_message = re.sub(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}', 'TIMESTAMP', normalized_message)  # 2019-01-22 04:15:29
        normalized_message = re.sub(r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', 'TIMESTAMP', normalized_message)  # 22/Jan/2019:04:15:29
        normalized_message = re.sub(r'\d{2}:\d{2}:\d{2}', 'TIME', normalized_message)  # 04:15:29
        normalized_message = re.sub(r'\+\d{4}', '', normalized_message)  # Remove timezone +0330
        
        # Remove dates
        normalized_message = re.sub(r'\d{4}-\d{2}-\d{2}', 'DATE', normalized_message)  # 2019-01-22
        normalized_message = re.sub(r'\d{2}/\w{3}/\d{4}', 'DATE', normalized_message)  # 22/Jan/2019
        
        # Remove IPs
        normalized_message = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP', normalized_message)
        
        # Remove user IDs
        normalized_message = re.sub(r'user_\w+', 'USER_ID', normalized_message)
        
        # NOW remove remaining numbers
        normalized_message = re.sub(r'\d+', 'N', normalized_message)
        
        # Collapse multiple spaces
        normalized_message = re.sub(r'\s+', ' ', normalized_message).strip()
        
        # Create signature - use first 150 chars to capture enough detail
        signature = f"{exception}|{component}|{normalized_message[:150]}"
        
        return hashlib.md5(signature.encode()).hexdigest()
    
    def group_errors(self, errors: list) -> dict:
        """
        Group errors by signature
        Returns: {signature: [error1, error2, ...]}
        """
        groups = defaultdict(list)
        
        for error in errors:
            signature = self.get_error_signature(error)
            groups[signature].append(error)
        
        return dict(groups)
    
    def create_grouped_summary(self, errors: list) -> list:
        """
        Create summary with grouped errors
        """
        groups = self.group_errors(errors)
        summaries = []
        
        for signature, group_errors in groups.items():
            # Take first error as representative
            representative = group_errors[0]
            
            # Extract timestamps if available
            timestamps = []
            line_numbers = []
            
            for err in group_errors:
                if err.get('timestamp'):
                    timestamps.append(err['timestamp'])
                if err.get('line_number'):
                    line_numbers.append(err['line_number'])
            
            # Calculate time range
            first_seen = min(timestamps) if timestamps else None
            last_seen = max(timestamps) if timestamps else None
            
            summary = {
                'signature': signature,
                'representative_error': representative,
                'occurrences': len(group_errors),
                'all_errors': group_errors,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'line_numbers': sorted(line_numbers),
                'severity': representative.get('severity', 'UNKNOWN'),
                'component': representative.get('component', 'Unknown'),
                'exception_class': representative.get('exception_class', 'Unknown')
            }
            
            summaries.append(summary)
        
        # Sort by severity and occurrence count
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        summaries.sort(key=lambda x: (
            severity_order.get(x['severity'], 5),
            -x['occurrences']
        ))
        
        return summaries
    
    def detect_error_chains(self, errors: list) -> list:
        """
        Detect errors that might be causally related (happened close in time)
        """
        if not errors:
            return []
        
        # Sort by timestamp
        sorted_errors = sorted(
            [e for e in errors if e.get('timestamp')],
            key=lambda x: x['timestamp']
        )
        
        chains = []
        current_chain = [sorted_errors[0]] if sorted_errors else []
        
        for i in range(1, len(sorted_errors)):
            prev = sorted_errors[i-1]
            curr = sorted_errors[i]
            
            # If errors happened within 5 seconds, consider them related
            try:
                prev_time = datetime.fromisoformat(prev['timestamp'])
                curr_time = datetime.fromisoformat(curr['timestamp'])
                time_diff = (curr_time - prev_time).total_seconds()
                
                if time_diff <= 5:
                    current_chain.append(curr)
                else:
                    if len(current_chain) > 1:
                        chains.append(current_chain)
                    current_chain = [curr]
            except:
                continue
        
        if len(current_chain) > 1:
            chains.append(current_chain)
        
        return chains
