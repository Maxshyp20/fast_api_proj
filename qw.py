from fastapi import FastAPI
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel, Field
from fastapi import FastAPI
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from fastapi import Request, status
from starlette.responses import JSONResponse
from sqlalchemy.orm import Session
from fastapi import Depends

# ------------------------------------------------------------------

DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI()


class CustomAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, header_name: str):
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next):
        print(f"\n\n url = {request.url.path}")
        
        not_secured_addresses = ["/user/register/", "/user/login/"]
        if request.url.path in not_secured_addresses:
            return await call_next(request)
        
        db = get_db()
        user_obj = get_all_inf_user(request, db)

        if user_obj:
            print(f"\n\n user_obj = {user_obj.email}")
            print(f"\n\n user_obj = {user_obj.username}")
            print(f"\n\n user_obj = {user_obj.id}")

            request.state.user = {"id": user_obj.id, "username": user_obj.username, "email": user_obj.email}
            response = await call_next(request)
        else:
            request.state.user = None
            response = JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "error 401"})
        
        return response

app.add_middleware(CustomAuthMiddleware, header_name="Authorization")


def get_db():
    db = SessionLocal()
    try:
        return db
    finally:
        db.close()



def get_all_inf_user(request: Request, db: Session = Depends(get_db)):
    token_qw = request.headers.get("Authorization")
    print(f"\n\n token_qw = {token_qw}")

    if not token_qw:
        return None

    get_token = db.query(Token).filter(Token.string_token == token_qw.split(" ")[1]).first()
    if not get_token:
        return None
    
    get_user = db.query(User).filter(User.id == get_token.user_id).first()
    if not get_user: 
        return None
    
    return get_user

# -------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)

    email = Column(String, unique=True, index=True)
    username = Column(String(55), unique=True)
    password = Column(String(100))
    role = Column(Boolean, nullable=False, default="just user")


EXPERATION_PERIOD = 5

class Token(Base):
    __tablename__ = "token"
    id = Column(Integer, primary_key=True, index=True) 
    user_id = Column(Integer, ForeignKey("users.id"))
    string_token = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=func.now())


class Team(Base):
    __tablename__ = 'team'
    id = Column(Integer, primary_key=True)

    name = Column(String, unique=True, nullable=False)
    player_1 = Column(Integer, nullable=False) #use freignkey
    player_2 = Column(Integer, nullable=False) #use freignkey
    wins_count = Column(Integer, default=0)
    tournament_id = Column(Integer, ForeignKey("tournament.id"))
    is_loser = Column(Boolean, default=False)
    # lose_count = Column(Integer, default=0) 


class Tournament(Base):
    __tablename__ = 'tournament'
    id = Column(Integer, primary_key=True)

    name_tour = Column(String, unique=True, nullable=False)
    # owner_id = Column(Integer, ForeignKey("users.id"))


class Finish(Base):
    __tablename__ = 'finish'
    id = Column(Integer, primary_key=True)

    tour_id = Column(Integer, ForeignKey('tournament.id'))
    win_team = Column(Integer, ForeignKey('team.id'))
    lose_team = Column(Integer, ForeignKey('team.id'))

Base.metadata.create_all(bind=engine)

# ---------------------------------------

class UserCreate(BaseModel):
    email: str
    username: str
    password: str  
    role: str


class TeamCreate(BaseModel):
    name: str
    player_1: int
    player_2: int 
    wins_count: int  
    tournament_id: int   


class TournamentCreate(BaseModel):
    name_tour: str


class FinishCreate(BaseModel):
    tour_id: int
    win_team: int
    lose_team: int


# -------------------RESPONSE-------------------------------------------

class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    role: str

    class Config:
        orm_mode = True


class TeamResponse(BaseModel):
    id: int
    name: str
    player_1: int
    player_2: int
    wins_count: int
    tournament_id: int

    class Config:
        orm_mode = True


class TourResponse(BaseModel):
    id: int
    name_tour: str

    class Config:
        orm_mode = True

class FinishResponse(BaseModel):
    id: int
    tour_id: int
    win_team: int
    lose_team: int

    class Config:
        orm_mode = True


# ----------------------UPDATE----------------------------------------

class UserUpdate(BaseModel):
    email: str
    username: str
    password: str  
    role: str


class UserLoginData(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: str 
    role: str

class UserLogoutData(BaseModel):
    email: str = Field(..., example="user@example.com")
    username: Optional[str] = None
    password: str = Field(..., min_length=6, example="securepassword")


class TokenResponse(BaseModel):
    token: str 

# --------------------------------------------------------------








