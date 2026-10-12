import streamlit as st
from streamlit_agraph import Config, Edge, Node, agraph


def render_attack_graph(artifacts):
    nodes_map = {}
    edges = []
    seen_edges = set()
    
    def add_node(node_id, label, group, color, title=None, shape="dot"):
        if node_id and node_id not in nodes_map:
            nodes_map[node_id] = Node(
                id=str(node_id),
                label=str(label),
                size=25,
                shape=shape,
                color=color,
                title=str(title) if title else str(label)
            )

    def add_edge(src, dst, label):
        if src and dst and src in nodes_map and dst in nodes_map:
            edge_key = (str(src), str(dst))
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                edges.append(Edge(source=str(src), target=str(dst), label=str(label)))

    for a in artifacts:
        # Add Host Node
        if a.host and a.host not in ("UNKNOWN", "SCAN", None):
            add_node(a.host, a.host, "host", "#118ab2", shape="hexagon")
            
        # Add User Node
        if a.user and a.user not in ("UNKNOWN", "SYSTEM", "NETWORK", None):
            user_id = f"user_{a.user}"
            add_node(user_id, a.user, "user", "#06d6a0", shape="diamond")
            if a.host and a.host not in ("UNKNOWN", "SCAN", None):
                add_edge(a.host, user_id, "login/execute")
                
        # Add IOC/Event Node
        if a.ioc_detected:
            ioc_id = f"ioc_{a.ioc_detected}"
            add_node(ioc_id, a.ioc_detected, "ioc", "#ef476f", title=a.details, shape="star")
            
            # Connect to Host or User
            if a.user and a.user not in ("UNKNOWN", "SYSTEM", "NETWORK", None):
                add_edge(f"user_{a.user}", ioc_id, a.source_type)
            elif a.host and a.host not in ("UNKNOWN", "SCAN", None):
                add_edge(a.host, ioc_id, a.source_type)
            else:
                # Global / Scan match
                add_node("Global", "Global Scan", "scan", "#ffd166")
                add_edge("Global", ioc_id, "detected")

    if not nodes_map:
        return False
        
    config = Config(
        width=850,
        height=520,
        directed=True,
        physics=True,
        hierarchical=False,
        nodeHighlightBehavior=True,
        highlightColor="#ffd166"
    )

    try:
        agraph(nodes=list(nodes_map.values()), edges=edges, config=config)
        return True
    except Exception as e:
        st.caption(f"Graph visualization notice: {e}")
        return False
