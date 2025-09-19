#
# The MIT License (MIT)
#
# Copyright (C) 2017 Marcos Pereira <marcospereira.mpj@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
import base64
import hashlib
import os
from typing import Tuple


def generate_code_verifier(length: int = 128) -> str:
    """
    Generates a high-entropy cryptographic random string for PKCE code_verifier.
    RFC 7636 recommends a length between 43 and 128 characters.
    """
    return base64.urlsafe_b64encode(os.urandom(length)).rstrip(b"=").decode("utf-8")[:length]

def generate_code_challenge(code_verifier: str, method: str = "S256") -> Tuple[str, str]:
    """
    Generates a code_challenge from the code_verifier using the specified method.
    Supported methods: "S256" (default), "plain"
    Returns (code_challenge, code_challenge_method)
    """
    if method == "S256":
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("utf-8")).digest()
        ).rstrip(b"=").decode("utf-8")
        return code_challenge, "S256"
    if method == "plain":
        return code_verifier, "plain"
    raise ValueError(f"Unsupported PKCE method: {method}")
