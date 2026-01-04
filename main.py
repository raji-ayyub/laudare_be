from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from bson import ObjectId
import hashlib

from database.database import users_collection


app = FastAPI(title="User Auth API")


# ------------------------
# Utilities
# ------------------------

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    return hash_password(plain) == hashed


def serialize_user(user) -> dict:
    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "firstName": user.get("first_name"),
        "lastName": user.get("last_name"),
        "is_active": user.get("is_active", True),
    }


# ------------------------
# Schemas
# ------------------------

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    firstName: Optional[str] = None
    lastName: Optional[str] = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserUpdate(BaseModel):
    email: EmailStr
    firstName: Optional[str]
    lastName: Optional[str]
    is_active: bool


class UserPatch(BaseModel):
    email: Optional[EmailStr] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    is_active: Optional[bool] = None


# ------------------------
# Routes
# ------------------------

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(payload: UserCreate):
    existing = await users_collection.find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = {
        "email": payload.email,
        "password": hash_password(payload.password),
        "first_name": payload.firstName,
        "last_name": payload.lastName,
        "is_active": True,
    }

    result = await users_collection.insert_one(user)
    user["_id"] = result.inserted_id

    return serialize_user(user)


@app.post("/login")
async def login_user(payload: UserLogin):
    user = await users_collection.find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "message": "Login successful",
        "user": serialize_user(user),
    }


@app.get("/users", response_model=List[dict])
async def get_all_users():
    users = []
    async for user in users_collection.find():
        users.append(serialize_user(user))
    return users


@app.get("/users/{user_id}")
async def get_user(user_id: str):
    user = await users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return serialize_user(user)


@app.put("/users/{user_id}")
async def update_user(user_id: str, payload: UserUpdate):
    result = await users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "email": payload.email,
                "first_name": payload.firstName,
                "last_name": payload.lastName,
                "is_active": payload.is_active,
            }
        },
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    user = await users_collection.find_one({"_id": ObjectId(user_id)})
    return serialize_user(user)


@app.patch("/users/{user_id}")
async def patch_user(user_id: str, payload: UserPatch):
    update_data = {}

    if payload.email is not None:
        update_data["email"] = payload.email
    if payload.firstName is not None:
        update_data["first_name"] = payload.firstName
    if payload.lastName is not None:
        update_data["last_name"] = payload.lastName
    if payload.is_active is not None:
        update_data["is_active"] = payload.is_active

    if not update_data:
        raise HTTPException(status_code=400, detail="No fields provided")

    result = await users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_data},
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    user = await users_collection.find_one({"_id": ObjectId(user_id)})
    return serialize_user(user)


@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: str):
    result = await users_collection.delete_one({"_id": ObjectId(user_id)})

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
