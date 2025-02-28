from qw import User, Team, Tournament, Finish, UserResponse, TeamResponse, TourResponse, FinishResponse, UserCreate 
from qw import TeamCreate, TournamentCreate, FinishCreate, UserUpdate, UserLoginData, TokenResponse, Token
from qw import get_db, SessionLocal
from fastapi import FastAPI, Depends, HTTPException, status, Header, Request
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse
from typing import List  
import random
import string
import hashlib


app = FastAPI()

# ---------------------------------------------------------USER----------------------------------------------------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return plain_password == hashed_password

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_auth_token(length=50):
    characters = string.ascii_letters + string.digits + string.punctuation
    
    random_string = ''.join(random.choices(characters, k=length))
    return random_string


@app.post("/user/register/", response_model=UserResponse, summary="Регистрация нового юзера")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = hash_password(user.password)

    # if len(user.password) < 4:
    #     return {"error": "Your password is too short"}
    
    db_user = User(email=user.email, username=user.username, password=hashed_password, role = user.role)
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="email or username already in db")
    
    return db_user

@app.post("/user/login/", response_model=TokenResponse, summary="Логин в юзер")
def login_user(user: UserLoginData, db: Session = Depends(get_db)):
    user_obj = None
    password_hash = hash_password(user.password)

    if user.email:
        user_obj = db.query(User).filter(User.email == user.email).first()
    elif user.username:
        user_obj = db.query(User).filter(User.username == user.username).first()    
    else:
        raise HTTPException(status_code=401, detail="email and username was not found")

    if not verify_password(password_hash, user_obj.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    qw = db.query(Token).filter(Token.user_id == user_obj.id).first()
    
    if qw:
        try:
            db.delete(qw)
            db.commit()
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"error 500, {e}")
    
    tok = Token(user_id = user_obj.id, string_token = generate_auth_token())

    try:
        db.add(tok)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"error 500, {e}")

    new_token = TokenResponse(token=tok.string_token)
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=new_token.dict())


@app.post("/user/logout/", summary="Log out an existing user")
def logout_user(token: str = Header(..., alias = "Authorization", title = "authorization"), db: Session = Depends(get_db)):

    get_token = db.query(Token).filter(Token.string_token == token.split(" ")[1]).first()

    print(f"\n\n token = {token}")
    print(get_token.string_token)


    if not get_token:
        raise HTTPException(status_code=404, detail="Token not found")

    try:
        db.delete(get_token)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error 500, {e}")

    return "logout was successful"



@app.delete("/user/{user_id}/delete/", response_model=UserResponse, summary="Эндпоинт удаляет юзера по айди")
def delete_user(user_id: int, user = UserCreate, db: SessionLocal = Depends(get_db)):

    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.role != 'admin':
        return {"error": "if user not admin he cannot delete other users"}
    
    db.delete(user_to_delete)
    db.commit()
    
    return user_to_delete


@app.put("/user/{user_id}/put/", response_model=UserResponse, summary="Эндпоинт обновляет юзера полностью или частично")
def update_user(user_id: int, user_update: UserUpdate, db: SessionLocal = Depends(get_db)):
    
    user_to_update = db.query(User).filter(User.id == user_id).first()
    if not user_to_update:
        raise HTTPException(status_code=404, detail="User not found")
    
    for key, value in user_update.dict(exclude_unset=True).items():
        setattr(user_to_update, key, value)
   
    db.commit()
    db.refresh(user_to_update)
    
    return user_to_update


@app.get("/users/get/", response_model = List[UserResponse], summary="Эндпоинт достает всех юзеров с бд")
def get_user(db: SessionLocal = Depends(get_db)):
    
    get_users = db.query(User).all()

    if not get_users:
        raise HTTPException(status_code=404, detail="Users was not found")
    
    return get_users


@app.get("/user/get/", response_model = UserResponse, summary="Достает юзера по токену")
def token_user(request: Request):
    # print(f"\n\n email = {user_inf.email}")
    return request.state.user
    
    # return user_inf

# ----------------------------------------------------TEAM-----------------------------------------------------------

@app.post("/team/create/", response_model=TeamResponse, summary="создает новую команду")
def create_team(team: TeamCreate, db: SessionLocal = Depends(get_db)):
    try:
       
        player_1_exists = db.query(User).filter(User.id == team.player_1).first()
        player_2_exists = db.query(User).filter(User.id == team.player_2).first()
        
        if not player_1_exists or not player_2_exists:
            raise HTTPException(status_code=400, detail="Один или оба игрока не существуют.")
        
        player_1_in_team = db.query(Team).filter((Team.player_1 == team.player_1) | (Team.player_2 == team.player_1)).first()
        player_2_in_team = db.query(Team).filter((Team.player_1 == team.player_2) | (Team.player_2 == team.player_2)).first()
        
        if player_1_in_team or player_2_in_team:
            raise HTTPException(status_code=400, detail="Один или оба игрока уже находятся в другой команде.")
        
        get_tours = db.query(Tournament).filter(Tournament.id).all()
        if not get_tours:
            raise HTTPException(status_code=404, detail="турниров в базе данны нет")
        
        new_team = Team(
            name = team.name,
            player_1 = team.player_1,
            player_2 = team.player_2,
            wins_count = team.wins_count,
            tournament_id = team.tournament_id
        )
        
        db.add(new_team)
        db.commit()
        db.refresh(new_team)
    except HTTPException:
        raise 
    except Exception as e:
        db.rollback()
        print(f"Error: {e}")  
        raise HTTPException(status_code=500, detail=f"Error creating team: {str(e)}")
    
    return new_team


@app.delete("/team/{team_id}/delete/", response_model=TeamResponse, summary="Удаляет команду по ее айди")
def delete_team(team_id: int, db: SessionLocal = Depends(get_db)):

    team_to_delete = db.query(Team).filter(Team.id == team_id).first()
    if not team_to_delete:
        raise HTTPException(status_code=404, detail="Team not found")
    
    db.delete(team_to_delete)
    db.commit()
    
    return team_to_delete


@app.put("/team/{team_id}/put/", response_model=TeamResponse, summary="Эндпоинт обновляет команду по ее айди")
def update_team(team_id: int, team_update: TeamCreate, db: SessionLocal = Depends(get_db)):
    print(f"\n\n 123{'qw'}")
    
    team_to_update = db.query(Team).filter(Team.id == team_id).first()
    if not team_to_update:
        raise HTTPException(status_code=404, detail="Team not found")
    
    for key, value in team_update.dict(exclude_unset=True).items():
        setattr(team_to_update, key, value)
   
    db.commit()
    db.refresh(team_to_update)
    
    return team_to_update


@app.get("/team/get/", response_model=List[TeamResponse], summary="Достает все данные с таблици team")
def team_get(db: SessionLocal = Depends(get_db)):
    
    get_teams = db.query(Team).all()

    if not get_teams:
        raise HTTPException(status_code=404, detail="Team was not found")
    
    return get_teams

# -------------------------------------------------TOURNAMENT-----------------------------------------------------

@app.post("/tournament/create/", response_model=TourResponse, summary="Создает турнир") 
def tournament_create(tour: TournamentCreate, db: SessionLocal = Depends(get_db)):
    new_tour = Tournament(name_tour=tour.name_tour)
    
    try:
        db.add(new_tour)
        db.commit()
        db.refresh(new_tour)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Ошибка добавления турнира: {str(e)}")
    
    return new_tour


@app.delete("/tournament/{tournament_id}/delete/", response_model=TourResponse, summary="Удаляет турнир по айди")
def tournament_delete(tournament_id: int, db: SessionLocal = Depends(get_db)):

    tournament_to_delete = db.query(Tournament).filter(Tournament.id == tournament_id).first()
    if not tournament_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(tournament_to_delete)
    db.commit()
    
    return tournament_to_delete


@app.get("/tournament/get/", response_model = List[TourResponse], summary="Достает все турниры по tournament_id в таблице team")
def tournament_get(db: SessionLocal = Depends(get_db)):

    get_tournaments = db.query(Tournament).all()

    if not get_tournaments:
        raise HTTPException(status_code=404, detail="results not found")

    return get_tournaments


@app.put("/tournament/{tournament_id}/update/", response_model=TourResponse, summary="Эндпоинт обновляет турнир по ее айди")
def update_tournament(tournament_id: int, tournament_update: TournamentCreate, db: SessionLocal = Depends(get_db)):
    
    tournament_to_update = db.query(Tournament).filter(Tournament.id == tournament_id).first()
    if not tournament_to_update:
        raise HTTPException(status_code=404, detail="Tour not found")
    
    for key, value in tournament_update.dict(exclude_unset=True).items():
        setattr(tournament_to_update, key, value)
   
    db.commit()
    db.refresh(tournament_to_update)
    
    return tournament_to_update

# -----------------------------------------RESULT-------------------------------------------------------------

@app.post("/finish/create/", response_model=FinishResponse, summary="Создает результат кто выйграл из двух команд")
def finish_create(finish: FinishCreate, db: SessionLocal = Depends(get_db)):

    better_team = db.query(Team).filter(Team.id == finish.win_team).first()
    worste_team = db.query(Team).filter(Team.id == finish.lose_team).first()

    existing_match = (
        db.query(Finish)
        .filter(
            (Finish.win_team == finish.win_team) & 
            (Finish.lose_team == finish.lose_team)
        )
        .first()
    )

    if existing_match:
        raise HTTPException(status_code=400, detail="Эти команды уже сыграли")
    
    elif not better_team or not worste_team:
        raise HTTPException(status_code=404, detail="Одна или обе команды не было найдено")
    
    elif better_team.tournament_id != worste_team.tournament_id:
        raise HTTPException(status_code=400, detail="Эти команды в разных турнирах")
    
    elif better_team.is_loser == True or worste_team.is_loser == True:
        raise HTTPException(status_code=404, detail="Эти команды или команда уже проигровал(и)а")


    try:
        win_team = db.query(Team).filter(Team.id == finish.win_team).first()
        if not win_team:
            raise HTTPException(status_code=404, detail="Выигравшая команда не найдена")

        win_team.wins_count += 1
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка обновления команды: {str(e)}")


    try:
        lose_team = db.query(Team).filter(Team.id == finish.lose_team).first()
        if not lose_team:
            raise HTTPException(status_code=404, detail="Проигравшая команда не найдена")
        
        lose_team.is_loser = True
    except Exception as e:
        db.rallback()
        raise HTTPException(status_code=500, detail=f"Ошибка обновления команды: {str(e)}")

    new_finish = Finish(
        tour_id = finish.tour_id, 
        win_team = finish.win_team, 
        lose_team = finish.lose_team
    )
    try:
        db.add(new_finish)
        db.commit()
        db.refresh(new_finish)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка добавления результата: {str(e)}")

    return new_finish


@app.put("/finish/{finish_id}/update/", response_model=FinishResponse, summary="Эндпоинт обновляет турнир по ее айди")
def update_finish(finish_id: int, finish_update: FinishCreate, db: SessionLocal = Depends(get_db)):
    
    result_to_update = db.query(Finish).filter(Finish.id == finish_id).first()
    if not result_to_update:
        raise HTTPException(status_code=404, detail="Result not found")
    
    for key, value in finish_update.dict(exclude_unset=True).items():
        setattr(result_to_update, key, value)
   
    db.commit()
    db.refresh(result_to_update)
    
    return result_to_update


@app.delete("/finish/{finish_id}/delete/", response_model=FinishResponse, summary="Удаляет результат по айди")
def delete_finish(finish_id: int, db: SessionLocal = Depends(get_db)):

    result_to_delete = db.query(Finish).filter(Finish.id == finish_id).first()
    if not result_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(result_to_delete)
    db.commit()
    
    return result_to_delete



@app.delete("/finish_all/delete/", response_model=List[FinishResponse], summary="Удаляет все записи в таблице результат")
def delete_all_finish(db: SessionLocal = Depends(get_db)):

    result_to_delete = db.query(Finish).all()
    print(f"\n\n{result_to_delete}\n\n")
    if not result_to_delete:
        raise HTTPException(status_code=404, detail="Results not found")

    try:
        for record in result_to_delete:
            db.delete(record)
        db.commit()
    except Exception as e:
        return "error", e

    return result_to_delete


@app.get("/finish/{tour_id}/get/", response_model = List[FinishResponse], summary="Достает все данные с таблици результат")
def get_finish(tour_id: int, db: SessionLocal = Depends(get_db)):

    results = db.query(Finish).filter(Finish.tour_id == tour_id).all()

    if not results:
        raise HTTPException(status_code=404, detail="results not found")





