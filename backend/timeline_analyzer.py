"""
Timeline Analysis Module
Analyzes error patterns over time
"""

from datetime import datetime, timedelta
from collections import defaultdict
import re


class TimelineAnalyzer:
    """Analyzes error distribution over time"""
    
    def __init__(self):
        self.time_buckets = defaultdict(list)
    
    def extract_timestamp(self, log_line: str) -> datetime:
        """
        Extract timestamp from log line
        Supports common formats:
        - 2026-02-11 10:15:32
        - 2026-02-11T10:15:32
        - [11/Feb/2026:10:15:32]
        """
        # ISO format: 2026-02-11 10:15:32
        match = re.search(r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})', log_line)
        if match:
            try:
                return datetime.strptime(f"{match.group(1)} {match.group(2)}", "%Y-%m-%d %H:%M:%S")
            except:
                pass
        
        # ISO with T: 2026-02-11T10:15:32
        match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', log_line)
        if match:
            try:
                return datetime.fromisoformat(match.group(1))
            except:
                pass
        
        # Apache format: [11/Feb/2026:10:15:32]
        match = re.search(r'\[(\d{2}/\w{3}/\d{4}):(\d{2}:\d{2}:\d{2})\]', log_line)
        if match:
            try:
                return datetime.strptime(f"{match.group(1)}:{match.group(2)}", "%d/%b/%Y:%H:%M:%S")
            except:
                pass
        
        return None
    
    def analyze_timeline(self, errors: list, logs: list, suspicious_indices: list) -> dict:
        """
        Analyze error distribution over time
        """
        # Extract timestamps from suspicious logs
        time_data = []
        
        for idx in suspicious_indices:
            if idx < len(logs):
                timestamp = self.extract_timestamp(logs[idx])
                if timestamp:
                    time_data.append({
                        'timestamp': timestamp,
                        'log_index': idx,
                        'log_line': logs[idx]
                    })
        
        if not time_data:
            return {
                'has_timestamps': False,
                'message': 'No timestamps found in logs'
            }
        
        # Sort by time
        time_data.sort(key=lambda x: x['timestamp'])
        
        # Find time range
        start_time = time_data[0]['timestamp']
        end_time = time_data[-1]['timestamp']
        duration = end_time - start_time
        
        # Create time buckets (hourly or minutely based on duration)
        if duration.total_seconds() > 3600:  # More than 1 hour
            bucket_size = timedelta(hours=1)
            bucket_format = "%Y-%m-%d %H:00"
        else:
            bucket_size = timedelta(minutes=5)
            bucket_format = "%Y-%m-%d %H:%M"
        
        # Group into buckets
        buckets = defaultdict(int)
        for item in time_data:
            bucket_key = item['timestamp'].strftime(bucket_format)
            buckets[bucket_key] += 1
        
        # Find error storms (spikes)
        avg_errors = sum(buckets.values()) / len(buckets) if buckets else 0
        error_storms = []
        
        for bucket, count in buckets.items():
            if count > avg_errors * 3:  # 3x average = storm
                error_storms.append({
                    'time': bucket,
                    'count': count,
                    'severity': 'HIGH' if count > avg_errors * 5 else 'MEDIUM'
                })
        
        return {
            'has_timestamps': True,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration.total_seconds(),
            'time_buckets': dict(sorted(buckets.items())),
            'total_suspicious': len(time_data),
            'average_per_bucket': avg_errors,
            'error_storms': error_storms,
            'peak_time': max(buckets.items(), key=lambda x: x[1])[0] if buckets else None,
            'peak_count': max(buckets.values()) if buckets else 0
        }
    
    def get_hourly_distribution(self, errors: list) -> dict:
        """Get error distribution by hour of day"""
        hourly = defaultdict(int)
        
        for error in errors:
            if error.get('timestamp'):
                try:
                    dt = datetime.fromisoformat(error['timestamp'])
                    hourly[dt.hour] += 1
                except:
                    continue
        
        return dict(sorted(hourly.items()))
