from typing import List

from pydantic import BaseModel


class UDPTunnelConfig(BaseModel):
    listening_ip: str
    listening_port: int
    remote_ip: str
    remote_port: int

    def get_as_list(self):
        return (
            self.listening_ip,
            self.listening_port,
            self.remote_ip,
            self.remote_port
        )


class XServerConfig(BaseModel):
    ip: str
    port: int


class ClientConfig(BaseModel):
    xserver: XServerConfig
    verbosity: str
    udp_tunnels: List[UDPTunnelConfig]
