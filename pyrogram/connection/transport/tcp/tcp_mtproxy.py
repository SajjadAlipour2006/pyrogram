#  Pyrogram - Telegram MTProto API Client Library for Python
#  Copyright (C) 2017-present Dan <https://github.com/delivrance>
#
#  This file is part of Pyrogram.
#
#  Pyrogram is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Pyrogram is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.

import logging
from typing import Optional, Tuple
import base64

from .tcp import TCP, Proxy

log = logging.getLogger(__name__)


class TCPMTProxy(TCP):
    @staticmethod
    def normalize_secret(secret):
        if secret.startswith(("ee", "dd")):
            secret = secret[2:]

        try:
            secret_bytes = bytes.fromhex(secret)
        except ValueError:
            while len(secret) % 4 != 0:
                secret += "="
            secret_bytes = base64.b64decode(secret.encode())

        return secret_bytes[:16]

    def __init__(self, ipv6: bool, proxy: Proxy, dc_id: int) -> None:
        self.dc_id = dc_id
        self.secret = self.normalize_secret(proxy["secret"])
        super().__init__(ipv6, proxy)

    async def connect(self, address: Tuple[str, int]) -> None:
        # Connect to the proxy's host and port instead of telegram's
        address = self.proxy["hostname"], self.proxy["port"]

        await super().connect(address)
        await super().send(b"\xef")

    async def send(self, data: bytes, *args) -> None:
        length = len(data) // 4

        await super().send(
            (bytes([length])
             if length <= 126
             else b"\x7f" + length.to_bytes(3, "little"))
            + data
        )

    async def recv(self, length: int = 0) -> Optional[bytes]:
        length = await super().recv(1)

        if length is None:
            return None

        if length == b"\x7f":
            length = await super().recv(3)

            if length is None:
                return None

        return await super().recv(int.from_bytes(length, "little") * 4)
