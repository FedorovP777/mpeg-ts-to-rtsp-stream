class Config:
    rtsp_protocol_version = '1.0'
    host = '0.0.0.0'
    rtsp_port = 554
    user_agent = 'Streamer 23.02'
    rtp_rtcp_port_ranges = (160, 560)  # must start from even number. Even - rtp, odd - rtcp
    client_timeout = 1000  # seconds
    tcp_buff_size = 20048
    init_pts = 12345
    interval_client_state_seconds = 10
