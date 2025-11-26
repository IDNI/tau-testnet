from libp2p import new_host
import trio

async def run():
    host = new_host()
    network = host.get_network()
    print(f"Network type: {type(network)}")
    print(f"Dir: {dir(network)}")

trio.run(run)
