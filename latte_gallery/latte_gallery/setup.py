from fastapi import FastAPI
from latte_gallery.router import status_router,accounts_router
from fastapi.middleware.cors import CORSMiddleware
def create_app():
    app = FastAPI(title='LatteGallery')
    app.include_router(status_router)
    app.include_router(accounts_router)
    app.add_middleware(
        CORSMiddleware,
            allow_origins=['*'],
            allow_methods=['*'],
            allow_credentials=True,
        )
    return app