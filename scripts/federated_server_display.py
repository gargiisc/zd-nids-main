#!/usr/bin/env python3
"""
FEDERATED SERVER DISPLAY
========================
Shows real-time status of the Federated Learning Server.
This displays server-side information only.

Run with: python scripts/federated_server_display.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import torch
import torch.nn as nn
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict

try:
    from colorama import Fore, Back, Style, init
except ImportError:
    class Fore:
        CYAN = YELLOW = GREEN = RED = BLUE = MAGENTA = WHITE = ""
    class Back:
        LIGHTWHITE_EX = ""
    class Style:
        RESET_ALL = BRIGHT = DIM = ""
    init = lambda: None

init(autoreset=True)

from federated.federated_server import FederatedServer, ServerConfig, AggregationStrategy


def clear_screen():
    """Clear terminal screen."""
    os.system('clear' if os.name == 'posix' else 'cls')


def print_header(text, color=Fore.CYAN):
    """Print formatted header."""
    print(f"\n{color}{Back.LIGHTWHITE_EX}{'='*80}{Style.RESET_ALL}")
    print(f"{color}{Back.LIGHTWHITE_EX}{text:^80}{Style.RESET_ALL}")
    print(f"{color}{Back.LIGHTWHITE_EX}{'='*80}{Style.RESET_ALL}\n")


def print_section(text):
    """Print section header."""
    print(f"\n{Fore.YELLOW}{'─'*80}")
    print(f"{Fore.YELLOW}► {text}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'─'*80}{Style.RESET_ALL}")


def print_row(label, value, color=Fore.WHITE):
    """Print a key-value row."""
    print(f"{label:.<40} {color}{value}{Style.RESET_ALL}")


def print_table_header(cols):
    """Print table header."""
    header = " | ".join(f"{col:^20}" for col in cols)
    print(f"\n{Fore.CYAN}{header}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-' * len(header)}{Style.RESET_ALL}")


def display_server_info(server):
    """Display server configuration and status."""
    print_header("FEDERATED SERVER STATUS", Fore.CYAN)
    
    print_section("Server Configuration")
    print_row("Server ID", server.config.server_id, Fore.GREEN)
    print_row("Aggregation Strategy", server.config.aggregation_strategy.value.upper(), Fore.GREEN)
    print_row("Min Clients/Round", str(server.config.min_clients_per_round), Fore.GREEN)
    print_row("Max Clients/Round", str(server.config.max_clients_per_round), Fore.GREEN)
    print_row("Client Selection Method", server.config.client_selection, Fore.GREEN)
    print_row("Selection Fraction", f"{server.config.selection_fraction:.1%}", Fore.GREEN)
    print_row("Round Timeout", f"{server.config.round_timeout}s", Fore.GREEN)
    
    print_section("Server Runtime Status")
    print_row("Current Round", str(server.current_round), Fore.BLUE)
    print_row("Total Rounds Completed", str(len(server.round_history)), Fore.BLUE)
    print_row("Server Start Time", server.start_time.strftime("%Y-%m-%d %H:%M:%S") if hasattr(server, 'start_time') else "N/A", Fore.BLUE)
    
    uptime = datetime.now() - server.start_time if hasattr(server, 'start_time') else timedelta(0)
    print_row("Uptime", f"{uptime.total_seconds():.1f}s", Fore.BLUE)
    
    print_section("Global Model Status")
    if server.global_model is not None:
        param_count = sum(p.numel() for p in server.global_model.parameters())
        print_row("Model Type", "Neural Network", Fore.MAGENTA)
        print_row("Total Parameters", f"{param_count:,}", Fore.MAGENTA)
        print_row("Model Size", f"{param_count * 4 / 1e6:.2f} MB", Fore.MAGENTA)
    else:
        print_row("Model Status", "Not initialized", Fore.RED)
    
    print_row("Model Versions Stored", str(len(server.model_versions)), Fore.MAGENTA)
    print_row("Latest Model Version", f"Round {server.current_round}", Fore.MAGENTA)


def display_registered_clients(server):
    """Display all registered clients."""
    print_header("REGISTERED CLIENTS", Fore.GREEN)
    
    clients = list(server.clients.values()) if hasattr(server, 'clients') else []
    
    if not clients:
        print(f"{Fore.YELLOW}⚠️  No clients registered yet{Style.RESET_ALL}")
        return
    
    print_section(f"Total Clients: {len(clients)}")
    
    # Summary stats
    print(f"\n{Fore.CYAN}SUMMARY STATISTICS:{Style.RESET_ALL}")
    total_samples = sum(c.total_samples_contributed for c in clients)
    avg_reliability = np.mean([c.reliability_score for c in clients]) if clients else 0
    avg_accuracy = np.mean([c.avg_accuracy for c in clients]) if clients else 0
    
    print_row("Total Samples Contributed", f"{total_samples:,}", Fore.BLUE)
    print_row("Average Reliability Score", f"{avg_reliability:.3f}", Fore.BLUE)
    print_row("Average Accuracy", f"{avg_accuracy:.2%}", Fore.BLUE)
    
    # Client table
    print_section("Client Details")
    cols = ["Client ID", "Organization", "Rounds", "Samples", "Accuracy"]
    print_table_header(cols)
    
    for client in sorted(clients, key=lambda c: c.total_samples_contributed, reverse=True):
        client_id = client.client_id[:15]
        org = client.organization[:15]
        rounds = str(client.rounds_participated)
        samples = f"{client.total_samples_contributed:,}"
        accuracy = f"{client.avg_accuracy:.2%}"
        
        print(f" {client_id:^20} | {org:^20} | {rounds:^20} | {samples:^20} | {accuracy:^20}")
    
    # Client status breakdown
    print_section("Client Status Breakdown")
    active = sum(1 for c in clients if (datetime.now() - c.last_seen).total_seconds() < 300)
    idle = sum(1 for c in clients if (datetime.now() - c.last_seen).total_seconds() >= 300)
    
    print(f"{Fore.GREEN}✅ Active: {active}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}⏸️  Idle: {idle}{Style.RESET_ALL}")


def display_round_history(server):
    """Display training round history."""
    print_header("TRAINING ROUND HISTORY", Fore.MAGENTA)
    
    rounds = server.round_history if hasattr(server, 'round_history') else []
    
    if not rounds:
        print(f"{Fore.YELLOW}⚠️  No rounds completed yet{Style.RESET_ALL}")
        return
    
    print_section(f"Total Rounds: {len(rounds)}")
    
    # Overall statistics
    print(f"\n{Fore.CYAN}CONVERGENCE METRICS:{Style.RESET_ALL}")
    losses = [r.to_dict()['loss'] for r in rounds if 'loss' in r.to_dict()]
    accuracies = [r.to_dict()['accuracy'] for r in rounds if 'accuracy' in r.to_dict()]
    
    if losses:
        print_row("Initial Loss", f"{losses[0]:.4f}", Fore.BLUE)
        print_row("Current Loss", f"{losses[-1]:.4f}", Fore.BLUE)
        print_row("Loss Improvement", f"{((losses[0] - losses[-1]) / losses[0] * 100):.2f}%", Fore.GREEN)
    
    if accuracies:
        print_row("Initial Accuracy", f"{accuracies[0]:.2%}", Fore.BLUE)
        print_row("Current Accuracy", f"{accuracies[-1]:.2%}", Fore.BLUE)
        print_row("Accuracy Improvement", f"{((accuracies[-1] - accuracies[0]) / accuracies[0] * 100):.2f}%", Fore.GREEN)
    
    # Recent rounds table
    print_section("Last 10 Rounds")
    cols = ["Round", "Clients", "Samples", "Loss", "Accuracy", "Time (s)"]
    print_table_header(cols)
    
    for r in rounds[-10:]:
        rd = r.to_dict()
        round_num = str(rd['round'])
        clients = str(len(rd.get('participated', [])))
        samples = f"{rd.get('samples', 0):,}"
        loss = f"{rd.get('loss', 0):.4f}"
        accuracy = f"{rd.get('accuracy', 0):.2%}"
        time_val = str(rd.get('time', 0))
        
        print(f" {round_num:^20} | {clients:^20} | {samples:^20} | {loss:^20} | {accuracy:^20} | {time_val:^20}")


def display_aggregation_stats(server):
    """Display aggregation statistics."""
    print_header("AGGREGATION STATISTICS", Fore.BLUE)
    
    stats = server.get_aggregation_statistics() if hasattr(server, 'get_aggregation_statistics') else {}
    
    print_section("Aggregation Configuration")
    print_row("Strategy", server.config.aggregation_strategy.value.upper(), Fore.MAGENTA)
    print_row("Weighted by Samples", "Yes", Fore.MAGENTA)
    print_row("Byzantine Detection", "Enabled", Fore.MAGENTA)
    
    print_section("Aggregation Performance")
    print_row("Total Aggregations", str(server.current_round), Fore.BLUE)
    print_row("Avg Aggregation Time", f"{stats.get('avg_aggregation_time', 0):.3f}s", Fore.BLUE)
    print_row("Total Data Communicated", f"{stats.get('total_bytes', 0) / 1e6:.2f} MB", Fore.BLUE)
    print_row("Avg Bytes per Round", f"{stats.get('avg_bytes_per_round', 0) / 1e6:.2f} MB", Fore.BLUE)
    
    print_section("Update Quality")
    print_row("Malicious Updates Detected", str(stats.get('byzantine_detected', 0)), Fore.RED if stats.get('byzantine_detected', 0) > 0 else Fore.GREEN)
    print_row("Failed Updates", str(stats.get('failed_updates', 0)), Fore.RED if stats.get('failed_updates', 0) > 0 else Fore.GREEN)
    print_row("Success Rate", f"{((server.current_round - stats.get('failed_updates', 0)) / max(1, server.current_round) * 100):.2f}%", Fore.GREEN)


def display_privacy_budget(server):
    """Display privacy budget status."""
    print_header("PRIVACY BUDGET TRACKING", Fore.YELLOW)
    
    if not hasattr(server, 'privacy_budget'):
        print(f"{Fore.YELLOW}⚠️  Privacy budget not tracked{Style.RESET_ALL}")
        return
    
    budget = server.privacy_budget
    
    print_section("Privacy Configuration")
    print_row("Mechanism", "Gaussian Differential Privacy", Fore.GREEN)
    print_row("Total Epsilon Budget", f"{budget.total_epsilon:.2f}", Fore.GREEN)
    print_row("Total Delta Budget", f"{budget.total_delta:.2e}", Fore.GREEN)
    
    print_section("Budget Consumption")
    remaining_epsilon = budget.remaining_epsilon()
    used_fraction = budget.spent_epsilon / budget.total_epsilon if budget.total_epsilon > 0 else 0
    
    print_row("Spent Epsilon", f"{budget.spent_epsilon:.4f}", Fore.BLUE)
    print_row("Remaining Epsilon", f"{remaining_epsilon:.4f}", Fore.BLUE)
    print_row("Budget Used", f"{used_fraction:.2%}", Fore.BLUE)
    
    # Progress bar
    bar_length = 40
    filled = int(bar_length * used_fraction)
    bar = "█" * filled + "░" * (bar_length - filled)
    print(f"{Fore.BLUE}Privacy Budget: [{bar}] {used_fraction:.1%}{Style.RESET_ALL}")
    
    print_section("Efficiency")
    epsilon_per_round = budget.spent_epsilon / max(1, budget.rounds_completed)
    rounds_remaining = remaining_epsilon / epsilon_per_round if epsilon_per_round > 0 else float('inf')
    
    print_row("Epsilon per Round", f"{epsilon_per_round:.6f}", Fore.CYAN)
    print_row("Rounds Remaining", f"~{int(rounds_remaining)} rounds", Fore.CYAN)
    print_row("Total Rounds Possible", f"~{int(budget.total_epsilon / epsilon_per_round)}", Fore.CYAN)


def display_server_health(server):
    """Display server health check."""
    print_header("SERVER HEALTH CHECK", Fore.CYAN)
    
    print_section("System Status")
    
    checks = {
        "Server Initialized": server is not None,
        "Global Model Loaded": server.global_model is not None if hasattr(server, 'global_model') else False,
        "Privacy Budget Enabled": hasattr(server, 'privacy_budget'),
        "Round History Recording": hasattr(server, 'round_history') and len(server.round_history) > 0,
        "Clients Registered": len(server.clients) > 0 if hasattr(server, 'clients') else False,
    }
    
    for check_name, status in checks.items():
        status_str = f"{Fore.GREEN}✅ OK{Style.RESET_ALL}" if status else f"{Fore.RED}❌ FAILED{Style.RESET_ALL}"
        print(f"  {check_name:.<50} {status_str}")
    
    print_section("Recommendations")
    
    if len(server.clients) < 3:
        print(f"  {Fore.YELLOW}⚠️  Register more clients for better federation (3+ recommended){Style.RESET_ALL}")
    
    if hasattr(server, 'privacy_budget') and server.privacy_budget.remaining_epsilon() < 1.0:
        print(f"  {Fore.YELLOW}⚠️  Privacy budget running low, consider resetting{Style.RESET_ALL}")
    
    if server.current_round > 0 and len(server.registered_clients) > 0:
        print(f"  {Fore.GREEN}✅ System is operational and running smoothly{Style.RESET_ALL}")


def main():
    """Main display function."""
    print_header("🖥️  FEDERATED LEARNING SERVER MONITOR", Fore.CYAN)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    try:
        # Create server instance for demonstration
        # First create initial model
        initial_model = nn.Sequential(
            nn.Linear(78, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 10)
        )
        
        config = ServerConfig(
            server_id="NIDS-MAIN-SERVER",
            min_clients_per_round=2,
            aggregation_strategy=AggregationStrategy.FEDAVG,
            model_save_frequency=10
        )
        server = FederatedServer(initial_model, config)
        
        # Register some sample clients
        orgs = [
            ("client-1", "BANK-NYC", "192.168.1.0/24"),
            ("client-2", "HOSPITAL-CHI", "192.168.3.0/24"),
            ("client-3", "TELECOM-SEA", "192.168.4.0/24"),
        ]
        
        for client_id, org, subnet in orgs:
            server.register_client(client_id, org, subnet)
        
        # Display all server information
        display_server_info(server)
        display_registered_clients(server)
        display_aggregation_stats(server)
        display_privacy_budget(server)
        display_server_health(server)
        
        # Display round history (simulated)
        print_header("END OF SERVER DISPLAY", Fore.CYAN)
        
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
