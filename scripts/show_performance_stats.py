#!/usr/bin/env python3
"""Display performance statistics and recommendations for Nimbus executors."""

import asyncio
import json
import sys
from argparse import ArgumentParser

import httpx


async def fetch_metrics(base_url: str, token: str) -> dict:
    """Fetch performance metrics from a running Nimbus agent."""
    headers = {"Authorization": f"Bearer {token}"}
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{base_url}/metrics", headers=headers)
            response.raise_for_status()
            return {"metrics": response.text}
        except httpx.HTTPError as e:
            print(f"❌ Failed to fetch metrics: {e}")
            return {}


def parse_prometheus_metrics(metrics_text: str) -> dict:
    """Parse Prometheus metrics and extract executor performance data."""
    lines = metrics_text.split('\n')
    
    performance_data = {
        "job_durations": [],
        "executor_performance": {},
        "warm_hit_rates": {},
        "efficiency_rates": {}
    }
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if line.startswith('nimbus_executor_avg_duration_seconds'):
            parts = line.split()
            if len(parts) >= 2:
                performance_data["avg_duration"] = float(parts[1])
        
        elif line.startswith('nimbus_warm_instance_hit_rate'):
            parts = line.split()
            if len(parts) >= 2:
                performance_data["warm_hit_rate"] = float(parts[1])
        
        elif line.startswith('nimbus_executor_efficiency_ratio'):
            parts = line.split()
            if len(parts) >= 2:
                performance_data["efficiency"] = float(parts[1])
    
    return performance_data


def format_performance_report(data: dict) -> str:
    """Format performance data into a readable report."""
    if not data:
        return "❌ No performance data available"
    
    report = ["🚀 Nimbus Executor Performance Report", "=" * 50, ""]
    
    if "avg_duration" in data:
        report.append(f"📊 Average Job Duration: {data['avg_duration']:.2f}s")
    
    if "warm_hit_rate" in data:
        hit_rate = data["warm_hit_rate"] * 100
        report.append(f"🏊 Warm Instance Hit Rate: {hit_rate:.1f}%")
    
    if "efficiency" in data:
        efficiency = data["efficiency"] * 100
        report.append(f"✅ Job Success Rate: {efficiency:.1f}%")
    
    report.extend(["", "💡 Recommendations:", "-" * 20])
    
    # Generate recommendations based on data
    if data.get("avg_duration", 0) > 30:
        report.append("⚠️  High average duration - consider enabling warm pools")
    
    if data.get("warm_hit_rate", 1.0) < 0.5:
        report.append("🔧 Low warm pool utilization - increase min_warm settings")
    
    if data.get("efficiency", 1.0) < 0.9:
        report.append("🐛 Low success rate - check resource limits and image compatibility")
    
    if data.get("warm_hit_rate", 0) > 0.8:
        report.append("✨ Excellent warm pool utilization!")
    
    if data.get("efficiency", 0) > 0.95:
        report.append("✨ Excellent job reliability!")
    
    return "\n".join(report)


async def main():
    """CLI entry point."""
    parser = ArgumentParser(description="Show Nimbus executor performance stats")
    parser.add_argument("--agent-url", default="http://localhost:9090",
                       help="Base URL for Nimbus agent metrics endpoint")
    parser.add_argument("--token", default="",
                       help="Authentication token (if required)")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                       help="Output format")
    
    args = parser.parse_args()
    
    print("📈 Fetching Nimbus performance metrics...")
    
    try:
        data = await fetch_metrics(args.agent_url, args.token)
        
        if not data:
            print("❌ No data received")
            return 1
        
        if "metrics" in data:
            perf_data = parse_prometheus_metrics(data["metrics"])
        else:
            perf_data = data
        
        if args.format == "json":
            print(json.dumps(perf_data, indent=2))
        else:
            print(format_performance_report(perf_data))
        
        return 0
        
    except KeyboardInterrupt:
        print("\n⏹️  Interrupted")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
