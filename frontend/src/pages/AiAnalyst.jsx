import React, { useEffect, useRef, useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronRight, Plus, Send, Square, Trash2, Wrench } from 'lucide-react';
import { api, streamChat } from '../api';
import { Card, Empty, ErrorBox, JsonView, Pill, Spinner, fmtDate, useAsync, useToast } from '../components/ui';

export default function AiAnalyst() {
  const health = useAsync(() => api.aiHealth(), []);
  const [tab, setTab] = useState('chat');
  const h = health.data;
  const tone = h?.status === 'online' ? 'ok' : h?.status === 'disabled' ? 'default' : 'critical';

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>AI Co-Analyst</h1>
          <p className="muted">Ask questions about your exposure. The assistant queries your tenant's data through audited tools.</p>
        </div>
        <div className="btn-row">
          {health.loading && !h && <Spinner inline label="AI status…" />}
          {health.error && <Pill tone="critical">AI status unavailable</Pill>}
          {h && (
            <Pill tone={tone} title={h.available_models?.length ? `Models: ${h.available_models.join(', ')}` : undefined}>
              AI {h.status}{h.active_model ? ` · ${h.active_model}` : ''}
            </Pill>
          )}
        </div>
      </div>

      <div className="warn-box">
        <AlertTriangle size={16} />
        <div>
          Tool output is drawn from untrusted breach, paste and dark-web material. It can contain text written to manipulate
          the model. Verify every claim against the evidence panel before acting on it.
        </div>
      </div>

      <div className="tabs">
        <button className={tab === 'chat' ? 'on' : ''} onClick={() => setTab('chat')}>Chat</button>
        <button className={tab === 'plans' ? 'on' : ''} onClick={() => setTab('plans')}>Investigation plans</button>
      </div>

      {tab === 'chat' ? <Chat disabled={h?.status === 'disabled'} /> : <Plans />}
    </div>
  );
}

let seq = 0;
const nextId = () => `m${++seq}`;

function Chat({ disabled }) {
  const [messages, setMessages] = useState([]); // {id, role, content, thinking, error}
  const [evidence, setEvidence] = useState([]); // {id, name, args, result, at}
  const [input, setInput] = useState('');
  const [streaming, setStreaming] = useState(false);
  const abortRef = useRef(null);
  const endRef = useRef(null);

  useEffect(() => { endRef.current?.scrollIntoView({ block: 'end' }); }, [messages]);
  useEffect(() => () => abortRef.current?.abort(), []);

  const send = async (e) => {
    e?.preventDefault();
    const text = input.trim();
    if (!text || streaming) return;
    const user = { id: nextId(), role: 'user', content: text.slice(0, 8000) };
    const assistant = { id: nextId(), role: 'assistant', content: '', thinking: '', error: null, tools: 0 };
    const history = [...messages, user]
      .filter((m) => (m.role === 'user' || m.role === 'assistant') && m.content)
      .slice(-40)
      .map((m) => ({ role: m.role, content: m.content.slice(0, 8000) }));
    setMessages((ms) => [...ms, user, assistant]);
    setInput('');
    setStreaming(true);
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const patch = (fn) => setMessages((ms) => ms.map((m) => (m.id === assistant.id ? fn(m) : m)));

    try {
      await streamChat(history, (ev) => {
        switch (ev.type) {
          case 'text':
            patch((m) => ({ ...m, content: m.content + (ev.content || '') }));
            break;
          case 'thinking':
            patch((m) => ({ ...m, thinking: m.thinking + (ev.content || '') }));
            break;
          case 'tool_call':
            patch((m) => ({ ...m, tools: m.tools + 1 }));
            setEvidence((xs) => [...xs, { key: `${assistant.id}-${ev.id}-${xs.length}`, id: ev.id, name: ev.name, args: ev.args, result: undefined, at: new Date().toISOString(), turn: assistant.id }]);
            break;
          case 'tool_result':
            setEvidence((xs) => {
              const i = xs.findIndex((x) => x.id === ev.id && x.turn === assistant.id && x.result === undefined);
              if (i === -1) return [...xs, { key: `${assistant.id}-${ev.id}-r${xs.length}`, id: ev.id, name: ev.name, args: undefined, result: ev.data, at: new Date().toISOString(), turn: assistant.id }];
              const copy = [...xs];
              copy[i] = { ...copy[i], result: ev.data };
              return copy;
            });
            break;
          case 'error':
            patch((m) => ({ ...m, error: ev.message || 'Unknown error' }));
            break;
          default:
            break; // done
        }
      }, ctrl.signal);
    } catch (err) {
      if (err.name === 'AbortError') patch((m) => ({ ...m, error: m.error || 'Stopped.' }));
      else patch((m) => ({ ...m, error: err.message }));
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  };

  return (
    <div className="ai-layout">
      <section className="card chat">
        <div className="chat-log">
          {messages.length === 0 && (
            <Empty title="Start an investigation">
              Try: "Summarise this week's critical leaks for acme.example.com" or "Which watch items appear in credential dumps?"
            </Empty>
          )}
          {messages.map((m) => <Message key={m.id} m={m} live={streaming && m === messages[messages.length - 1]} />)}
          <div ref={endRef} />
        </div>
        <form className="chat-input" onSubmit={send}>
          <textarea className="input" rows={2} maxLength={8000} disabled={disabled}
            placeholder={disabled ? 'AI is disabled on this server' : 'Ask about your exposure… (Enter to send, Shift+Enter for newline)'}
            value={input} onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }} />
          {streaming ? (
            <button type="button" className="btn btn-danger" onClick={() => abortRef.current?.abort()}><Square size={14} /> Stop</button>
          ) : (
            <button className="btn btn-primary" disabled={!input.trim() || disabled}><Send size={14} /> Send</button>
          )}
        </form>
      </section>

      <aside className="card evidence">
        <header className="card-head">
          <h2><Wrench size={14} /> Evidence ({evidence.length})</h2>
          {evidence.length > 0 && <button className="btn btn-sm btn-ghost" onClick={() => setEvidence([])}>Clear</button>}
        </header>
        <div className="card-body evidence-list">
          {evidence.length === 0 && <p className="muted small">Every tool call the assistant makes, and the raw data it got back, is listed here.</p>}
          {evidence.map((ev) => <EvidenceItem key={ev.key} ev={ev} />)}
        </div>
      </aside>
    </div>
  );
}

function Message({ m, live }) {
  const [showThinking, setShowThinking] = useState(false);
  return (
    <div className={`msg msg-${m.role}`}>
      <div className="msg-role">{m.role === 'user' ? 'You' : 'Co-Analyst'}</div>
      {m.thinking && (
        <div className="thinking">
          <button className="json-toggle" onClick={() => setShowThinking((v) => !v)}>
            {showThinking ? <ChevronDown size={13} /> : <ChevronRight size={13} />} reasoning
          </button>
          {showThinking && <pre className="thinking-text">{m.thinking}</pre>}
        </div>
      )}
      {m.tools > 0 && <div className="muted small">{m.tools} tool call{m.tools > 1 ? 's' : ''}, see evidence panel</div>}
      {m.content ? <div className="msg-text">{m.content}</div> : live && !m.error ? <Spinner inline label="Working…" /> : null}
      {m.error && <div className="error-text small">{m.error}</div>}
    </div>
  );
}

function EvidenceItem({ ev }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="ev-item">
      <button className="ev-head" onClick={() => setOpen((v) => !v)}>
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        <span className="mono">{ev.name}</span>
        {ev.result === undefined ? <Pill tone="warn">pending</Pill> : <Pill tone="ok">returned</Pill>}
      </button>
      {open && (
        <div className="ev-body">
          {ev.args !== undefined && <JsonView title="tool_call args" data={ev.args} defaultOpen />}
          {ev.result !== undefined && <JsonView title="tool_result data (untrusted)" data={ev.result} defaultOpen />}
          <div className="muted small">call id {ev.id || 'n/a'}</div>
        </div>
      )}
    </div>
  );
}

// ── Investigation plans ─────────────────────────────────────────────────────

function Plans() {
  const plans = useAsync(() => api.plans(), []);
  const toast = useToast();
  const [title, setTitle] = useState('');
  const [desc, setDesc] = useState('');
  const [error, setError] = useState(null);

  const replace = (p) => plans.setData((xs) => xs.map((x) => (x.id === p.id ? p : x)));
  const wrap = (fn) => async (...a) => {
    try {
      await fn(...a);
    } catch (e) {
      toast(e.message, 'error');
    }
  };

  const create = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      const p = await api.createPlan({ title: title.trim(), description: desc });
      plans.setData((xs) => [p, ...(xs || [])]);
      setTitle('');
      setDesc('');
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div className="plans">
      <Card title="New plan">
        <form className="stack" onSubmit={create}>
          <input className="input" required maxLength={255} placeholder="Plan title, e.g. Q3 credential exposure review" value={title}
            onChange={(e) => setTitle(e.target.value)} />
          <textarea className="input" rows={2} maxLength={5000} placeholder="Description (optional)" value={desc} onChange={(e) => setDesc(e.target.value)} />
          <div><button className="btn btn-primary" disabled={!title.trim()}><Plus size={14} /> Create plan</button></div>
        </form>
        <ErrorBox error={error} />
      </Card>
      <ErrorBox error={plans.error} onRetry={plans.reload} />
      {plans.loading && !plans.data && <Spinner />}
      {plans.data?.length === 0 && <Empty title="No investigation plans">Plans hold the tasks you and the assistant are tracking.</Empty>}
      {plans.data?.map((p) => (
        <PlanCard key={p.id} plan={p}
          onToggle={wrap(async () => replace(await api.updatePlan(p.id, { status: p.status === 'active' ? 'closed' : 'active' })))}
          onDelete={wrap(async () => {
            if (!window.confirm(`Delete plan "${p.title}" and its tasks?`)) return;
            await api.deletePlan(p.id);
            plans.setData((xs) => xs.filter((x) => x.id !== p.id));
          })}
          onAddTask={wrap(async (t) => replace(await api.addTask(p.id, t)))}
          onTask={wrap(async (taskId, status) => replace(await api.updateTask(p.id, taskId, status)))}
        />
      ))}
    </div>
  );
}

function PlanCard({ plan, onToggle, onDelete, onAddTask, onTask }) {
  const [task, setTask] = useState('');
  const done = plan.tasks.filter((t) => t.status === 'done').length;
  return (
    <Card className={plan.status === 'closed' ? 'dim' : ''} title={<>{plan.title} <Pill tone={plan.status === 'active' ? 'ok' : 'default'}>{plan.status}</Pill></>}
      actions={
        <>
          <button className="btn btn-sm" onClick={onToggle}>{plan.status === 'active' ? 'Close' : 'Reopen'}</button>
          <button className="icon-btn danger" onClick={onDelete} aria-label="Delete plan"><Trash2 size={15} /></button>
        </>
      }>
      {plan.description && <p className="muted">{plan.description}</p>}
      <div className="muted small">{done}/{plan.tasks.length} tasks done · created {fmtDate(plan.created_at)}</div>
      <ul className="tasks">
        {plan.tasks.map((t) => (
          <li key={t.id} className={`task task-${t.status}`}>
            <select className="input input-sm" value={t.status} onChange={(e) => onTask(t.id, e.target.value)}>
              <option value="todo">todo</option>
              <option value="doing">doing</option>
              <option value="done">done</option>
            </select>
            <span className="task-title">{t.title}</span>
            {t.created_by && t.created_by !== 'human' && <Pill tone="vip">{t.created_by}</Pill>}
          </li>
        ))}
      </ul>
      <form className="input-group" onSubmit={(e) => { e.preventDefault(); if (task.trim()) { onAddTask(task.trim()); setTask(''); } }}>
        <input className="input" maxLength={255} placeholder="Add a task…" value={task} onChange={(e) => setTask(e.target.value)} />
        <button className="btn" disabled={!task.trim()}><Plus size={14} /></button>
      </form>
    </Card>
  );
}
