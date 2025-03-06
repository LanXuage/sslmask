import sys
import uvloop
import asyncio
import logging
import argparse

from .log import logger
from .io_async import TLS
from .server import Server
from typing import Optional, List


class ActionNamespace(argparse.Namespace):
    action: str
    debug: bool
    help: bool


class ClientNamespace(argparse.Namespace):
    host: str
    port: int
    help: bool


class ServerNamespace(ClientNamespace):
    fingerprint: str
    key: Optional[str]
    keypass: Optional[str]
    cert: Optional[str]
    userpass: Optional[List[str]]
    config: Optional[str]


async def process_server(args: ServerNamespace, parser: argparse.ArgumentParser):
    if args.help:
        return parser.print_help()
    if args.host is None or args.host.strip() == "" or args.host.isdigit():
        args.host = "0.0.0.0"
    if args.host.isdigit():
        if args.port != 1080:
            args.port = int(args.host)
        else:
            return print(
                parser.prog
                + ": error: argument host: invalid ip or domain value: '"
                + args.host
                + "'"
            )
    if not isinstance(args.port, int):
        args.port = 1080
    userpass_dict = {}
    if isinstance(args.userpass, list) and len(args.userpass) > 0:
        for up in args.userpass:
            u, p = up.split(":")
            userpass_dict[u] = p
    server = Server(
        args.host,
        args.port,
        userpass_dict,
        4096,
        len(userpass_dict) > 0,
        args.key,
        args.keypass,
        args.cert,
    )
    print("Listening on " + args.host + ":" + str(args.port))
    await server.start_server()


async def process_client(args: ClientNamespace, parser: argparse.ArgumentParser):
    if args.help:
        return parser.print_help()
    if args.host is None or args.host.strip() == "":
        return print(
            parser.prog + ": error: the following arguments are required: host"
        )
    if not isinstance(args.port, int):
        args.port = 443
    async with TLS(args.host, args.port) as client:
        print("connected. try to send something: ")
        while True:
            data = input("input:")
            await client.send(data.encode())
            print(await client.read())


def start_run(func):
    if sys.version_info >= (3, 11):
        with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
            runner.run(func)
    else:
        uvloop.install()
        asyncio.run(func)


def main():
    parser = argparse.ArgumentParser(
        add_help=False,
        description="An advanced Python - based proxy solution that not only enables TLS proxying but also ingeniously mimics browser TLS fingerprints",
    )
    server_actions = ["s", "server"]
    client_actions = ["c", "client", "connect"]
    parser.add_argument(
        "action",
        type=str,
        default="",
        nargs="?",
        metavar="server|client",
        help="action, client(c/connect) or server(s)",
    )
    parser.add_argument(
        "-h",
        "--help",
        default=False,
        required=False,
        action="store_true",
        help="show this help message and exit",
    )
    parser.add_argument(
        "-d",
        "--debug",
        default=False,
        required=False,
        action="store_true",
        help="enable the debug",
    )
    client_parser = argparse.ArgumentParser(
        add_help=False,
        description="Attempt to initiate a TLS connection",
    )
    client_parser.add_argument(
        "host",
        type=str,
        nargs="?",
        help="ip or domain",
    )
    client_parser.add_argument(
        "port",
        type=int,
        nargs="?",
        help="default 443",
    )
    server_parser = argparse.ArgumentParser(
        add_help=False,
        description="Start a TLS proxy service capable of browser fingerprint spoofing",
    )
    server_parser.add_argument(
        "host",
        type=str,
        nargs="?",
        help="listen, default 0.0.0.0",
    )
    server_parser.add_argument(
        "port",
        type=int,
        nargs="?",
        help="default 1080",
    )
    server_parser.add_argument(
        "-fp",
        "--fingerprint",
        type=str,
        default="MSEdge133",
        choices=["MSEdge133"],
        help="browser fingerprint, default MSEdge133",
    )
    server_parser.add_argument(
        "-k",
        "--key",
        type=str,
        default=None,
        help="server key file",
    )
    server_parser.add_argument(
        "-kp",
        "--keypass",
        type=str,
        default=None,
        help="server key password",
    )
    server_parser.add_argument(
        "-c",
        "--cert",
        type=str,
        default=None,
        help="server certificate file",
    )
    server_parser.add_argument(
        "-up",
        "--userpass",
        type=str,
        action="append",
        default=None,
        help="user and password of socks",
    )
    server_parser.add_argument(
        "-cf",
        "--config",
        type=str,
        default=None,
        help="server config file",
    )
    action_args, other_args = parser.parse_known_args(namespace=ActionNamespace())
    if action_args.action == "" and action_args.help:
        return parser.print_help()
    if action_args.debug:
        logger.setLevel(logging.DEBUG)
    if action_args.action in server_actions:
        server_parser.prog += " " + action_args.action
        server_args = server_parser.parse_args(other_args, ServerNamespace)
        server_args.help = action_args.help
        start_run(process_server(server_args, server_parser))
    elif action_args.action in client_actions:
        client_parser.prog += " " + action_args.action
        client_args = client_parser.parse_args(other_args, ClientNamespace)
        client_args.help = action_args.help
        start_run(process_client(client_args, client_parser))
    elif action_args.action is not None and action_args.action.strip() != "":
        other_args.insert(0, action_args.action)
        client_args = client_parser.parse_args(other_args, ClientNamespace)
        client_args.help = action_args.help
        start_run(process_client(client_args, client_parser))
    else:
        print(
            parser.prog + ": error: the following arguments are required: server|client"
        )
        exit(1)


if __name__ == "__main__":
    main()
