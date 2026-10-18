import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..database import SessionLocal, get_db
from ..deps import Principal, get_principal, require_scope
from ..models import InvestigationPlan, InvestigationTask
from ..services import agent, llm
from . import serializers as ser

router = APIRouter(prefix="/ai", tags=["ai"])


class ChatMessage(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(max_length=8000)


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=40)


class PlanCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field("", max_length=5000)


class PlanUpdate(BaseModel):
    title: str | None = Field(None, max_length=255)
    description: str | None = Field(None, max_length=5000)
    status: str | None = Field(None, pattern="^(active|closed)$")


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)


class TaskUpdate(BaseModel):
    status: str = Field(pattern="^(todo|doing|done)$")


@router.get("/health")
async def ai_health(principal: Principal = Depends(get_principal)):
    return await llm.health()


@router.post("/chat")
async def ai_chat(body: ChatRequest, principal: Principal = Depends(require_scope("write"))):
    """Server-Sent Events: one JSON object per ``data:`` line."""
    history = [m.model_dump() for m in body.messages]

    async def stream():
        async with SessionLocal() as db:
            async for event in agent.run(db, principal.tenant_id, principal.actor, history):
                yield f"data: {json.dumps(event, default=str)}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


async def _plan(db: AsyncSession, principal: Principal, plan_id: str) -> InvestigationPlan:
    plan = await db.scalar(select(InvestigationPlan).options(selectinload(InvestigationPlan.tasks)).where(InvestigationPlan.id == plan_id))
    if plan is None or plan.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Plan not found")
    return plan


@router.get("/plans")
async def list_plans(principal: Principal = Depends(require_scope("read")), db: AsyncSession = Depends(get_db)):
    rows = await db.execute(select(InvestigationPlan).options(selectinload(InvestigationPlan.tasks))
                            .where(InvestigationPlan.tenant_id == principal.tenant_id).order_by(InvestigationPlan.created_at.desc()))
    return [ser.plan(p) for p in rows.scalars()]


@router.post("/plans", status_code=201)
async def create_plan(body: PlanCreate, principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    plan = InvestigationPlan(tenant_id=principal.tenant_id, title=body.title, description=body.description, created_by=principal.user_id)
    db.add(plan)
    await db.commit()
    return ser.plan(await _plan(db, principal, plan.id))


@router.patch("/plans/{plan_id}")
async def update_plan(plan_id: str, body: PlanUpdate, principal: Principal = Depends(require_scope("write")),
                      db: AsyncSession = Depends(get_db)):
    plan = await _plan(db, principal, plan_id)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(plan, k, v)
    await db.commit()
    return ser.plan(plan)


@router.delete("/plans/{plan_id}", status_code=204)
async def delete_plan(plan_id: str, principal: Principal = Depends(require_scope("write")), db: AsyncSession = Depends(get_db)):
    await db.delete(await _plan(db, principal, plan_id))
    await db.commit()


@router.post("/plans/{plan_id}/tasks", status_code=201)
async def add_task(plan_id: str, body: TaskCreate, principal: Principal = Depends(require_scope("write")),
                   db: AsyncSession = Depends(get_db)):
    plan = await _plan(db, principal, plan_id)
    db.add(InvestigationTask(plan_id=plan.id, title=body.title, created_by="human"))
    await db.commit()
    db.expire(plan)
    return ser.plan(await _plan(db, principal, plan_id))


@router.patch("/plans/{plan_id}/tasks/{task_id}")
async def update_task(plan_id: str, task_id: str, body: TaskUpdate, principal: Principal = Depends(require_scope("write")),
                      db: AsyncSession = Depends(get_db)):
    plan = await _plan(db, principal, plan_id)
    task = next((t for t in plan.tasks if t.id == task_id), None)
    if task is None:
        raise HTTPException(404, "Task not found")
    task.status = body.status
    await db.commit()
    return ser.plan(plan)
