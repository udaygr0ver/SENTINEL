import streamlit as st
from streamlit_agraph import Config, Edge, Node, agraph


def format_display_label(label: str, max_len: int = 18) -> str:
    """Truncates long labels with an ellipsis to prevent text overlap in graph view."""
    s = str(label)
    if len(s) <= max_len:
        return s
    return s[:9] + "…" + s[-(max_len - 10):]


def format_edge_label(label: str) -> str:
    """Cleans up raw source_type strings into concise, human-readable edge labels."""
    mapping = {
        "PCAP_DNS": "DNS",
        "PCAP_DNS_TUNNEL": "Tunnel ⚠️",
        "PCAP_HTTP": "HTTP",
        "PCAP_C2_BEACON": "Beacon 🚨",
        "EVTX_4688": "Executed",
        "EVTX_4624": "Logon",
        "EVTX_4625": "Logon Fail",
        "EVTX_7045": "Service",
        "EVTX_4104": "PowerShell",
        "EML_HEADER": "Sender",
        "EML_URL": "Phish Link 🚨",
        "EML_ATTACHMENT": "Attachment",
        "login/execute": "Logged In",
        "detected": "Matched",
    }
    return mapping.get(label, label[:12])


def render_attack_graph(artifacts):
    nodes_map = {}
    edges = []
    seen_edges = set()

    node_font = {
        "color": "#f1f5f9",
        "size": 12,
        "face": "Inter, sans-serif",
        "background": "rgba(15, 23, 42, 0.85)",
        "strokeWidth": 2,
        "strokeColor": "#0f172a"
    }

    edge_font = {
        "color": "#cbd5e1",
        "size": 10,
        "face": "Inter, sans-serif",
        "background": "rgba(30, 41, 59, 0.9)",
        "strokeWidth": 1,
        "strokeColor": "#0f172a",
        "align": "horizontal"
    }
    
    def add_node(node_id, label, group, color, title=None, shape="dot"):
        if node_id and node_id not in nodes_map:
            full_title = f"{group.upper()}: {title or label}"
            display_label = format_display_label(label)
            nodes_map[node_id] = Node(
                id=str(node_id),
                label=display_label,
                size=26,
                shape=shape,
                color=color,
                title=full_title,
                font=node_font
            )

    def add_edge(src, dst, label):
        if src and dst and src in nodes_map and dst in nodes_map:
            edge_key = (str(src), str(dst))
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                clean_label = format_edge_label(str(label))
                edges.append(Edge(
                    source=str(src),
                    target=str(dst),
                    label=clean_label,
                    font=edge_font,
                    color={"color": "rgba(148, 163, 184, 0.45)", "highlight": "#06d6a0"}
                ))

    for a in artifacts:
        # Add Host Node
        if a.host and a.host not in ("UNKNOWN", "SCAN", None):
            add_node(a.host, a.host, "Host", "#118ab2", shape="hexagon")
            
        # Add User Node
        if a.user and a.user not in ("UNKNOWN", "SYSTEM", "NETWORK", None):
            user_id = f"user_{a.user}"
            add_node(user_id, a.user, "User", "#06d6a0", shape="diamond")
            if a.host and a.host not in ("UNKNOWN", "SCAN", None):
                add_edge(a.host, user_id, "login/execute")
                
        # Add IOC/Event Node
        if a.ioc_detected:
            ioc_id = f"ioc_{a.ioc_detected}"
            add_node(ioc_id, a.ioc_detected, "IOC", "#ef476f", title=a.details, shape="star")
            
            # Connect to Host or User
            if a.user and a.user not in ("UNKNOWN", "SYSTEM", "NETWORK", None):
                add_edge(f"user_{a.user}", ioc_id, a.source_type)
            elif a.host and a.host not in ("UNKNOWN", "SCAN", None):
                add_edge(a.host, ioc_id, a.source_type)
            else:
                # Global / Scan match
                add_node("Global", "Global Scan", "Scan", "#ffd166")
                add_edge("Global", ioc_id, "detected")

    if not nodes_map:
        return False
        
    config = Config(
        width=950,
        height=580,
        directed=True,
        physics=True,
        hierarchical=False,
        nodeHighlightBehavior=True,
        highlightColor="#06d6a0"
    )

    # Force strong repulsive physics so nodes push far away from each other and never overlap
    config.physics["solver"] = "barnesHut"
    config.physics["barnesHut"] = {
        "gravitationalConstant": -14000,   # Strong repulsion spreads nodes out
        "centralGravity": 0.15,            # Gentle centering force
        "springLength": 240,               # Generous distance between connected nodes
        "springConstant": 0.03,
        "damping": 0.15,
        "avoidOverlap": 0.95               # Strict overlap prevention
    }
    config.physics["stabilization"] = {
        "enabled": True,
        "iterations": 250,
        "fit": True
    }

    try:
        agraph(nodes=list(nodes_map.values()), edges=edges, config=config)
        return True
    except Exception as e:
        st.caption(f"Graph visualization notice: {e}")
        return False
