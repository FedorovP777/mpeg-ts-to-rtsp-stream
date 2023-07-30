import dataclasses


@dataclasses.dataclass
class SDPSession:
    sdp_version: int = 0
    id: str = ""
    version: int = 0
    start_time: int = 0
    end_time: int = 0
    ttl: int = 0
    user: str = ""
    src_addr: str = ""
    src_type: str = ""
    dst_addr: str = ""
    dst_type: str = ""
    name: str = ""


class SDPMetadata:
    version: int
    id: int


def sdp_version(sdp_version: str) -> str:
    return f"v={sdp_version}"


def ident(id: str, version: str, src_type: str, src_addr: str) -> str:
    return f"o=- {id} {version} IN {src_type} {src_addr}"


def session_name(session_name: str) -> str:
    return f"s={session_name}"


def connection_info(dest_type: str, dest_addr: str) -> str:
    return f"c=IN {dest_type} {dest_addr}"


def time_activity(start_time: str, end_time: str) -> str:
    return f"t={start_time} {end_time}"


def attribute_tool() -> str:
    return f"a=tool:libavformat 58.29.100"


def stream_type(type: str, port: str, payload_type: str) -> str:
    return f"m={type} {port} RTP/AVP {payload_type}"


def bitrate(bitrate):
    return f"b=AS:{bitrate}"


def attribute_stream_id(stream_id):
    return f"a=control:streamid={stream_id}"


def attribute_rtpmap_h264(payload_type):
    return f"a=rtpmap:{payload_type} H264/90000"


def attribute_fmtp_h264(payload_type):
    return f"a=fmtp:{payload_type} profile-level-id=1"


def sdp_create(sdp_session, streams):
    sdp = [
        sdp_version(sdp_session.sdp_version),
        ident(sdp_session.id, sdp_session.version, sdp_session.src_type, sdp_session.src_addr),
        session_name(sdp_session.name),
        connection_info(sdp_session.dst_type, sdp_session.dst_addr),
        time_activity(sdp_session.start_time, sdp_session.end_time),
        attribute_tool(),

    ]
    for stream in streams:
        sdp += [
            stream_type(stream.type, 0, 96 + stream.index),
            attribute_stream_id(1 + stream.index),
            bitrate(200),
            attribute_rtpmap_h264(96 + stream.index),
            attribute_fmtp_h264(96 + stream.index)
        ]
    return "\r\n".join(sdp)
