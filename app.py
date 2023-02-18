import fastapi
from client_config import ClientConfig
import Xclient

app = fastapi.FastAPI()


@app.post("/start_client/")
async def start_client(config: ClientConfig):
    Xclient.start_client(
        config.xserver.ip,
        config.xserver.port,
        list(map(lambda x: x.get_as_list(), config.udp_tunnels)),
        config.verbosity
    )
    return 200, "Starting!"
