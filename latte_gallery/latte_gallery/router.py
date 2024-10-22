from fastapi import APIRouter
from latte_gallery.schemas import StatusResponse,AccountRegisterSchema,AccountSchema,Role

status_router = APIRouter(prefix='/status')
accounts_router = APIRouter(prefix = '/accounts')


@status_router.get('',summary='получить статус сервера',tags = ['Статус'])
def get_status()->StatusResponse:
    return StatusResponse(status = 'ok')


@accounts_router.post('/register',summary='Получение данных своего аккаунта')
def register_account(body:AccountRegisterSchema)->AccountSchema:
    return AccountSchema(
        id = 1,
        login = body.login,
        name = body.name,
        role = Role.USER,
    )
@accounts_router.get('/my',summary='Полученние данных своего аккаунта')
def register_account(body:AccountRegisterSchema)-> AccountSchema:
    return AccountSchema(
        id = 1,
        login = 'user1',
        name = 'Вася Пупкин',
        role = Role.USER
        )