from typing import Literal,Annotated
from enum import StrEnum
from pydantic import BaseModel,StringConstraints


class StatusResponse(BaseModel):
    status: Literal['ok']



status = StatusResponse(status= 'ok')


class Role(StrEnum):
    USER = 'USER'
    ADMIN = 'ADMIN'
    MAIN_ADMIN = 'MAIN_ADMIN'


class AccountSchema(BaseModel):
    id: int
    login: str
    name: str
    role: Role

PaswordStr = Annotated[str,StringConstraints(min_length=8,pattern = r'*^[a-zA-Z0-9_-]+$')]

class AccountRegisterSchema(BaseModel):
    login: Annotated[str,StringConstraints(strip_whitespace=True,min_length=1)]
    password: PaswordStr
    name: Annotated[str,StringConstraints(strip_whitespace=True,min_length=1)]
