from os import PathLike
from typing import Literal, NoReturn, final

__version__: str

class WgprobeError(Exception): ...
class ConfigurationError(WgprobeError): ...

_PhaseStatus = Literal["passed", "sent", "unconfirmed", "skipped", "error"]
_Verdict = Literal[
    "authentication_confirmed", "data_plane_confirmed", "unconfirmed", "local_error"
]

@final
class PhaseResult:
    def __new__(cls, _private: NoReturn) -> PhaseResult: ...
    @property
    def phase(self) -> str: ...
    @property
    def target(self) -> str | None: ...
    @property
    def status(self) -> _PhaseStatus: ...
    @property
    def duration_ms(self) -> int: ...
    @property
    def sent_bytes(self) -> int: ...
    @property
    def received_bytes(self) -> int: ...
    @property
    def detail(self) -> str | None: ...
    def to_json(self) -> str: ...

@final
class ProbeReport:
    def __new__(cls, _private: NoReturn) -> ProbeReport: ...
    @property
    def schema_version(self) -> int: ...
    @property
    def verdict(self) -> _Verdict: ...
    @property
    def endpoint(self) -> str: ...
    @property
    def resolved_endpoint(self) -> str | None: ...
    @property
    def local_udp_address(self) -> str | None: ...
    @property
    def client_public_key(self) -> str: ...
    @property
    def duration_ms(self) -> int: ...
    @property
    def sent_bytes(self) -> int: ...
    @property
    def received_bytes(self) -> int: ...
    @property
    def phases(self) -> tuple[PhaseResult, ...]: ...
    def to_json(self) -> str: ...

def probe_file(
    config_path: str | PathLike[str],
    *,
    ping: list[str] | tuple[str, ...] = ...,
    resolve: list[str] | tuple[str, ...] = ...,
    dns_server: str | None = ...,
    handshake_timeout_ms: int = ...,
    ping_timeout_ms: int = ...,
    dns_timeout_ms: int = ...,
    deadline_ms: int = ...,
) -> ProbeReport: ...

def probe_key_file(
    private_key_path: str | PathLike[str],
    peer_key: str,
    endpoint: str,
    *,
    address: str | None = ...,
    allowed_ips: list[str] | tuple[str, ...] = ...,
    ping: list[str] | tuple[str, ...] = ...,
    resolve: list[str] | tuple[str, ...] = ...,
    dns_server: str | None = ...,
    handshake_timeout_ms: int = ...,
    ping_timeout_ms: int = ...,
    dns_timeout_ms: int = ...,
    deadline_ms: int = ...,
) -> ProbeReport: ...
