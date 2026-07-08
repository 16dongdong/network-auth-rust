from dataclasses import dataclass, field


def defaultApiCallIds() -> dict[str, str]:
    return dict({{SdkApiCallIdsPy}})


@dataclass
class Config:
    apiUrl: str = {{SdkApiUrlPy}}
    appCode: str = {{SdkAppCodePy}}
    apiToken: str = {{SdkApiTokenPy}}
    appVersion: str = {{SdkAppVersionPy}}
    successCode: int = {{SdkApiSuccessCodePy}}
    apiCallIds: dict[str, str] = field(default_factory=defaultApiCallIds)
    clientAuthMode: str = {{SdkClientAuthModePy}}
    clientCryptoAlgorithm: str = {{SdkCryptoAlgorithmPy}}
    clientPublicKey: str = {{SdkClientPublicKeyPy}}
    allowEphemeralTicket: bool = True
    forceEphemeralTicket: bool = False
    timeoutSeconds: int = 30
    noticeCacheSeconds: int = 300
    loginNetworkRetries: int = 2
    loginRetryDelaySeconds: float = 1.0

    def callId(self, route: str) -> str:
        return self.apiCallIds.get(route, "")
