from pydantic import BaseModel
from typing import List

class VulnInfo(BaseModel):
    id: str
    cve: str
    name: str
    versions: str
    describtion: str

class PortInfo(BaseModel):
    host: str
    proto: str
    port: str
    state: str
    reason: str
    extrainfo: str
    name: str
    version: str
    product: str
    script: str
    vulnFSTEC: List[VulnInfo]

