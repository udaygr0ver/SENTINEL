import pandas as pd
import plotly.express as px


def render_timeline_chart(artifacts):
    """
    Takes a list of ForensicArtifacts and returns a Plotly figure
    visualizing the attack timeline.
    """
    if not artifacts:
        return None
        
    data = []
    for a in artifacts:
        # We need to make sure the timestamp is valid. If it's a mock timestamp like "now" we skip it,
        # or we try to parse it. 
        try:
            # Simple check if it has a dash (ISO format)
            if "-" in a.timestamp:
                data.append({
                    "Timestamp": pd.to_datetime(a.timestamp),
                    "Source": a.source_type,
                    "Host": a.host if a.host else "Unknown",
                    "Details": a.details[:50] + "..." if len(a.details) > 50 else a.details,
                    "IOC": a.ioc_detected if a.ioc_detected else "None"
                })
        except Exception:
            pass
            
    if not data:
        return None
        
    df = pd.DataFrame(data)
    
    # Sort by timestamp
    df = df.sort_values("Timestamp")
    
    # Create a scatter plot representing events over time
    fig = px.scatter(
        df,
        x="Timestamp",
        y="Source",
        color="Host",
        hover_data=["Details", "IOC"],
        title="Interactive Attack Sequence Timeline",
        labels={"Source": "Artifact Source", "Timestamp": "Time of Execution"},
        template="plotly_dark"
    )
    
    fig.update_traces(marker=dict(size=12, symbol="diamond-dot", line=dict(width=2, color='DarkSlateGrey')))
    
    # Add a horizontal line for visual grouping if needed or just keep it simple
    fig.update_layout(
        xaxis_title="Timeline",
        yaxis_title="Evidence Source",
        hovermode="closest",
        margin=dict(l=20, r=20, t=40, b=20)
    )
    
    return fig
