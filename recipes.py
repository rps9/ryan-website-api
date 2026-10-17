from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from psycopg.types.json import Jsonb

from db import pool
from jwt_utils import current_user


router = APIRouter(prefix="/api/recipes", tags=["recipes"])


class Ingredient(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    amount: str = Field(default="", max_length=80)
    name: str = Field(min_length=1, max_length=120)
    group: Literal["dry", "wet", "other"] = "other"

    @field_validator("id", "amount", "name", mode="before")
    @classmethod
    def _strip_text(cls, value: str) -> str:
        return str(value).strip()


class RecipeStep(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    instruction: str = Field(min_length=1, max_length=1000)
    kind: Literal["prep", "mix", "heat", "cook", "wait", "finish"] = "prep"
    duration_minutes: int = Field(default=0, ge=0, le=1440)
    parallel_note: str = Field(default="", max_length=300)

    @field_validator("id", "instruction", "parallel_note", mode="before")
    @classmethod
    def _strip_text(cls, value: str) -> str:
        return str(value).strip()


class RecipeInput(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    servings: int = Field(default=1, ge=1, le=100)
    ingredients: list[Ingredient] = Field(min_length=1, max_length=100)
    steps: list[RecipeStep] = Field(min_length=1, max_length=100)
    optimization_notes: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("title", "description", mode="before")
    @classmethod
    def _strip_text(cls, value: str) -> str:
        return str(value).strip()

    @field_validator("optimization_notes")
    @classmethod
    def _clean_notes(cls, notes: list[str]) -> list[str]:
        cleaned = [str(note).strip() for note in notes if str(note).strip()]
        if any(len(note) > 300 for note in cleaned):
            raise ValueError("optimization notes must be 300 characters or fewer")
        return cleaned


class Recipe(RecipeInput):
    id: int
    created_at: datetime
    updated_at: datetime


def _recipe_from_row(row: tuple) -> Recipe:
    return Recipe(
        id=row[0],
        title=row[1],
        description=row[2],
        servings=row[3],
        ingredients=row[4],
        steps=row[5],
        optimization_notes=row[6],
        created_at=row[7],
        updated_at=row[8],
    )


RECIPE_COLUMNS = """
    id, title, description, servings, ingredients, steps,
    optimization_notes, created_at, updated_at
"""


@router.get("", response_model=dict[str, list[Recipe]], dependencies=[Depends(current_user)])
def list_recipes(user=Depends(current_user)):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT {RECIPE_COLUMNS} FROM recipes WHERE user_id = %s ORDER BY updated_at DESC",
            (user["id"],),
        )
        recipes = [_recipe_from_row(row) for row in cur.fetchall()]
    return {"recipes": recipes}


@router.post("", response_model=Recipe, status_code=status.HTTP_201_CREATED, dependencies=[Depends(current_user)])
def create_recipe(body: RecipeInput, user=Depends(current_user)):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO recipes (
                user_id, title, description, servings, ingredients, steps, optimization_notes
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING {RECIPE_COLUMNS}
            """,
            (
                user["id"],
                body.title,
                body.description,
                body.servings,
                Jsonb([item.model_dump() for item in body.ingredients]),
                Jsonb([step.model_dump() for step in body.steps]),
                Jsonb(body.optimization_notes),
            ),
        )
        row = cur.fetchone()
    return _recipe_from_row(row)


@router.get("/{recipe_id}", response_model=Recipe, dependencies=[Depends(current_user)])
def get_recipe(recipe_id: int, user=Depends(current_user)):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT {RECIPE_COLUMNS} FROM recipes WHERE id = %s AND user_id = %s",
            (recipe_id, user["id"]),
        )
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="recipe not found")
    return _recipe_from_row(row)


@router.put("/{recipe_id}", response_model=Recipe, dependencies=[Depends(current_user)])
def update_recipe(recipe_id: int, body: RecipeInput, user=Depends(current_user)):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE recipes
            SET title = %s,
                description = %s,
                servings = %s,
                ingredients = %s,
                steps = %s,
                optimization_notes = %s,
                updated_at = now()
            WHERE id = %s AND user_id = %s
            RETURNING {RECIPE_COLUMNS}
            """,
            (
                body.title,
                body.description,
                body.servings,
                Jsonb([item.model_dump() for item in body.ingredients]),
                Jsonb([step.model_dump() for step in body.steps]),
                Jsonb(body.optimization_notes),
                recipe_id,
                user["id"],
            ),
        )
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="recipe not found")
    return _recipe_from_row(row)


@router.delete("/{recipe_id}", dependencies=[Depends(current_user)])
def delete_recipe(recipe_id: int, user=Depends(current_user)):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM recipes WHERE id = %s AND user_id = %s RETURNING id",
            (recipe_id, user["id"]),
        )
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="recipe not found")
    return {"ok": True, "id": row[0]}
