from streamlit_agraph import Config, Edge, Node, agraph


def render_attack_graph(artifacts):
    nodes_map = {}
    edges = []
    
    def add_node(node_id, label, group, color, title=None, shape="dot"):
        if node_id and node_id not in nodes_map:
            nodes_map[node_id] = Node(
                id=node_id,
                label=label,
                size=25,
                shape=shape,
                color=color,
                title=title if title else label
            )

    def add_edge(src, dst, label):
        if src and dst and src in nodes_map and dst in nodes_map:
            # Check if edge already exists
            if not any(e.source == src and e.target == dst for e in edges):
                edges.append(Edge(source=src, target=dst, label=label))

    for a in artifacts:
        # Add Host Node
        if a.host and a.host != "UNKNOWN" and a.host != "SCAN":
            add_node(a.host, a.host, "host", "#118ab2", shape="hexagon")
            
        # Add User Node
        if a.user and a.user != "UNKNOWN" and a.user != "SYSTEM" and a.user != "NETWORK":
            add_node(f"user_{a.user}", a.user, "user", "#06d6a0", shape="diamond")
            if a.host:
                add_edge(a.host, f"user_{a.user}", "login/execute")
                
        # Add IOC/Event Node
        if a.ioc_detected:
            ioc_id = f"ioc_{a.ioc_detected}"
            add_node(ioc_id, a.ioc_detected, "ioc", "#ef476f", title=a.details, shape="star")
            
            # Connect to Host or User
            if a.user and a.user != "UNKNOWN" and a.user != "SYSTEM" and a.user != "NETWORK":
                add_edge(f"user_{a.user}", ioc_id, a.source_type)
            elif a.host and a.host != "UNKNOWN" and a.host != "SCAN":
                add_edge(a.host, ioc_id, a.source_type)
            else:
                # E.g. Global YARA match
                add_node("Global", "Global Scan", "scan", "#ffd166")
                add_edge("Global", ioc_id, "detected")

    if not nodes_map:
        return False
        
    config = Config(width=800,
                    height=500,
                    directed=True,
                    physics=True,
                    hierarchical=False,
                    nodeHighlightBehavior=True,
                    highlightColor="#ffd166")

    agraph(nodes=list(nodes_map.values()), edges=edges, config=config)
    return True
