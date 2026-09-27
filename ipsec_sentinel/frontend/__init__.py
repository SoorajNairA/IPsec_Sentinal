"""Local presentation integration for the IPsec Sentinel analyzer."""

from ipsec_sentinel.frontend.bridge import FrontendServerConfig, analyze_for_frontend, serve
from ipsec_sentinel.frontend.xray import build_xray_projection

__all__ = [
    "FrontendServerConfig",
    "analyze_for_frontend",
    "build_xray_projection",
    "serve",
]

