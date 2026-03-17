"""Client isolation vulnerability testing module (AirSnitch).

Provides Wi-Fi client isolation bypass detection through:
- GTK group key abuse
- Gateway bouncing
- Port stealing (uplink/downlink)
- Broadcast reflection
- Client-to-client and client-to-monitor attacks

Based on research by Mathy Vanhoef (NDSS'26).
"""
