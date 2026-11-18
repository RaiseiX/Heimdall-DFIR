import { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import {
  FlaskConical, Wand2, Plus, X, ChevronDown, Copy,
  AlertTriangle, Play, RotateCcw, ChevronRight, GripVertical,
} from 'lucide-react';
import { tr } from '../lib/cyberchef/errors.js';
import { utf8Encode, describeBytes, shannonEntropy, isHighEntropy } from '../lib/cyberchef/bytes.js';
import {
  OPS, CATEGORIES, opLabel, opDescription, categoryLabel, paramLabel, optionLabel, defaultParams, matchesSearch, applyRecipe,
} from '../lib/cyberchef/registry.js';
import { detectObfuscation, magicChain } from '../lib/cyberchef/detect.js';

const CAT_COLOR = {
  specialized: 'var(--fl-danger)', encoding: 'var(--fl-accent)', hash: 'var(--fl-warn)',
  cipher: 'var(--fl-gold)', network: 'var(--fl-ok)', extraction: 'var(--fl-ok)', timestamps: 'var(--fl-purple)',
  formatting: 'var(--fl-purple)', info: 'var(--fl-dim)',
};

function viewOf(bytes) {
  const d = describeBytes(bytes);
  return d.kind === 'text' ? { binary: false, text: d.text } : { binary: true, text: d.hex };
}

function suggestionLabel(s) {
  if (s.chain) return tr('ui.chain', { ops: s.ops.map(id => (OPS[id] ? opLabel(OPS[id]) : id)).join(' → ') });
  return tr(s.labelKey, s.labelParams);
}

const mono = { fontFamily:'var(--f-mono, "JetBrains Mono", monospace)' };

function OpBadge({ category }) {
    return (
    <span style={{
      fontSize:8, padding:'0 5px', borderRadius:3,
      background:`color-mix(in srgb, ${CAT_COLOR[category]||'var(--fl-dim)'} 13%, transparent)`,
      color:CAT_COLOR[category]||'var(--fl-dim)',
      border:`1px solid color-mix(in srgb, ${CAT_COLOR[category]||'var(--fl-dim)'} 25%, transparent)`,
      ...mono, fontWeight:700, letterSpacing:'0.05em',
    }}>
      {categoryLabel(category)}
    </span>
  );
}

function RecipeStep({ step, index, result, onRemove, onChange, onDragStart, onDragOver, onDrop, dragging }) {
  const [open, setOpen] = useState(false);
  const op = OPS[step.opId];
  if (!op) return null;
  const hasParams = op.params.length > 0;
  const out = result?.output;
  const err = result?.error;
  const preview = out && out.length ? viewOf(out) : null;
  return (
    <div draggable
      onDragStart={e => onDragStart(e, index)}
      onDragOver={e => onDragOver(e, index)}
      onDrop={e => onDrop(e, index)}
      style={{ border:`1px solid ${err?'color-mix(in srgb, var(--fl-danger) 35%, transparent)':'var(--fl-border)'}`, borderRadius:5, marginBottom:4, background:'var(--fl-bg)', overflow:'hidden', opacity:dragging?0.4:1, transition:'opacity 0.12s' }}>
      <div
        style={{ display:'flex', alignItems:'center', gap:6, padding:'5px 8px', cursor:'pointer', borderBottom:open?'1px solid var(--fl-border)':'none' }}
        onClick={() => setOpen(o=>!o)}
      >
        <GripVertical size={11} style={{ color:'var(--fl-subtle)', flexShrink:0, cursor:'grab' }} onClick={e=>e.stopPropagation()} />
        <span style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', flexShrink:0, minWidth:12 }}>{index+1}.</span>
        <span style={{ ...mono, fontSize:10, color:'var(--fl-on-dark)', flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{opLabel(op)}</span>
        {err && <AlertTriangle size={10} style={{ color:'var(--fl-danger)', flexShrink:0 }} />}
        <OpBadge category={op.category} />
        <ChevronDown size={10} style={{ color:'var(--fl-subtle)', transform:open?'rotate(180deg)':'none', transition:'transform 0.15s', flexShrink:0 }} />
        <button onClick={e=>{e.stopPropagation();onRemove(index);}} style={{ background:'none', border:'none', cursor:'pointer', padding:0, color:'var(--fl-subtle)', display:'flex', flexShrink:0 }}>
          <X size={10} />
        </button>
      </div>
      {open && (
        <div style={{ padding:'6px 8px', display:'flex', flexDirection:'column', gap:6 }}>
          {hasParams && op.params.map(p => (
            <div key={p.id} style={{ display:'flex', alignItems:'center', gap:6 }}>
              <label style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', minWidth:70 }}>{paramLabel(p)}</label>
              {p.type==='select'?(
                <select value={step.params?.[p.id]??p.default} onChange={e=>onChange(index,p.id,e.target.value)}
                  style={{ ...mono, fontSize:9, background:'var(--fl-panel)', color:'var(--fl-on-dark)', border:'1px solid var(--fl-border)', borderRadius:3, padding:'1px 4px', flex:1 }}>
                  {p.options.map(o=><option key={o.value} value={o.value}>{optionLabel(o)}</option>)}
                </select>
              ):(
                <input type={p.type==='number'?'number':'text'} value={step.params?.[p.id]??p.default} min={p.min} max={p.max}
                  onChange={e=>onChange(index,p.id,p.type==='number'?Number(e.target.value):e.target.value)}
                  style={{ ...mono, fontSize:9, background:'var(--fl-panel)', color:'var(--fl-on-dark)', border:'1px solid var(--fl-border)', borderRadius:3, padding:'1px 6px', flex:1, outline:'none' }} />
              )}
            </div>
          ))}
          {result && (
            <div>
              <div style={{ ...mono, fontSize:8, color:'var(--fl-subtle)', letterSpacing:'0.08em', marginBottom:3, display:'flex', justifyContent:'space-between', gap:8 }}>
                <span>{err ? tr('ui.step_error') : tr('ui.step_output')}</span>
                {!err && out != null && <span>{tr('ui.step_stats', { count: out.length, entropy: shannonEntropy(out).toFixed(2) })}</span>}
              </div>
              <div style={{ ...mono, fontSize:9, color:err?'var(--fl-danger)':'var(--fl-dim)', background:'var(--fl-panel)', border:`1px solid ${err?'color-mix(in srgb, var(--fl-danger) 25%, transparent)':'var(--fl-border)'}`, borderRadius:4, padding:'5px 7px', maxHeight:110, overflow:'auto', whiteSpace:'pre-wrap', wordBreak:'break-all', scrollbarWidth:'thin' }}>
                {err ? err : (preview ? preview.text.slice(0,600) + (preview.text.length>600 ? '…' : '') : tr('ui.step_empty'))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function CyberChefPage() {
  const { i18n: i18nInstance } = useTranslation();
  const lang = i18nInstance.language;
  const [input, setInput] = useState('');
  const [recipe, setRecipe] = useState([]);
  const [result, setResult] = useState({ final:new Uint8Array(0), steps:[] });
  const [running, setRunning] = useState(false);
  const [showPicker, setShowPicker] = useState(false);
  const [pickerCat, setPickerCat] = useState('specialized');
  const [pickerSearch, setPickerSearch] = useState('');
  const [suggestions, setSuggestions] = useState([]);
  const [copied, setCopied] = useState(false);
  const [dragIndex, setDragIndex] = useState(null);

  const inputBytes = useMemo(() => utf8Encode(input), [input]);

  useEffect(() => {
    if (!input || recipe.length === 0) { setResult({ final:inputBytes, steps:[] }); return; }
    let cancelled = false;
    setRunning(true);
    applyRecipe(inputBytes, recipe).then(r => { if(!cancelled){ setResult(r); setRunning(false); } });
    return () => { cancelled = true; };
  }, [input, inputBytes, recipe, lang]);

  const { final:output, steps } = result;
  const lastError = steps.find(s => s.error);
  const entropy = input ? shannonEntropy(inputBytes).toFixed(2) : null;
  const outputView = useMemo(() => viewOf(output), [output]);

  const handleDetect = useCallback(() => {
    const single = detectObfuscation(inputBytes);
    const chain = magicChain(inputBytes);
    const out = [];
    if (chain.length > 1) out.push({ confidence:99, ops:chain, chain:true, color:'var(--fl-purple)' });
    out.push(...single);
    setSuggestions(out.length>0 ? out : [{ confidence:0, labelKey:'ui.no_detection', color:'var(--fl-ok)', ops:[] }]);
  }, [inputBytes]);

  const applySuggestion = useCallback((ops) => {
    if (!ops.length) return;
    setRecipe(ops.map(opId => ({ opId, params:defaultParams(OPS[opId]) })));
    setSuggestions([]);
  }, []);

  const handleMagic = useCallback(() => {
    const chain = magicChain(inputBytes);
    if (chain.length) applySuggestion(chain);
    else setSuggestions([{ confidence:0, labelKey:'ui.magic_none', color:'var(--fl-dim)', ops:[] }]);
  }, [inputBytes, applySuggestion]);

  const onStepDragStart = useCallback((e, i) => { setDragIndex(i); e.dataTransfer.effectAllowed = 'move'; }, []);
  const onStepDragOver  = useCallback((e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; }, []);
  const onStepDrop = useCallback((e, i) => {
    e.preventDefault();
    setRecipe(r => {
      if (dragIndex == null || dragIndex === i || dragIndex >= r.length) return r;
      const next = [...r];
      const [moved] = next.splice(dragIndex, 1);
      next.splice(i, 0, moved);
      return next;
    });
    setDragIndex(null);
  }, [dragIndex]);

  const addOp = useCallback((opId) => {
    const op = OPS[opId];
    setRecipe(r => [...r, { opId, params:defaultParams(op) }]);
    setShowPicker(false);
    setPickerSearch('');
  }, []);

  const removeOp = useCallback((i) => setRecipe(r => r.filter((_,idx)=>idx!==i)), []);
  const changeParam = useCallback((si,pid,val) => setRecipe(r=>r.map((s,i)=>i===si?{...s,params:{...s.params,[pid]:val}}:s)), []);

  const copyOutput = useCallback(() => {
    if (!output.length) return;
    navigator.clipboard.writeText(outputView.text).then(()=>{ setCopied(true); setTimeout(()=>setCopied(false),1500); });
  }, [output, outputView]);

  const filteredOps = Object.entries(OPS).filter(([id, op]) => (
    pickerSearch ? matchesSearch(op, pickerSearch) : op.category === pickerCat
  ));

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', background:'var(--fl-bg)', overflow:'hidden' }}>

      <div style={{ display:'flex', alignItems:'center', gap:8, padding:'0 14px', height:36, flexShrink:0, background:'var(--fl-bg)', borderBottom:'1px solid var(--fl-border)' }}>
        <FlaskConical size={13} style={{ color:'var(--fl-accent)' }} />
        <span style={{ ...mono, fontSize:11, color:'var(--fl-on-dark)', fontWeight:700 }}>CyberChef Forensic</span>
        <span style={{ ...mono, fontSize:9, color:'var(--fl-subtle)' }}>— {tr('ui.operations_count', { count: Object.keys(OPS).length })}</span>
        <div style={{ flex:1 }} />
        {running && <span style={{ ...mono, fontSize:9, color:'var(--fl-warn)' }}>{tr('ui.running')}</span>}
        <button onClick={handleMagic} disabled={!input} title={tr('ui.magic_title')}
          style={{ display:'flex', alignItems:'center', gap:5, padding:'3px 10px', borderRadius:'var(--fl-radius-sm)', background:'color-mix(in srgb, var(--fl-purple) 15%, transparent)', border:'1px solid color-mix(in srgb, var(--fl-purple) 40%, transparent)', color:'var(--fl-purple)', cursor:input?'pointer':'default', opacity:input?1:0.5, ...mono, fontSize:10 }}>
          {tr('ui.magic')}
        </button>
        <button onClick={handleDetect} style={{ display:'flex', alignItems:'center', gap:5, padding:'3px 10px', borderRadius:'var(--fl-radius-sm)', background:'color-mix(in srgb, var(--fl-accent) 15%, transparent)', border:'1px solid color-mix(in srgb, var(--fl-accent) 40%, transparent)', color:'var(--fl-accent)', cursor:'pointer', ...mono, fontSize:10 }}>
          <Wand2 size={10} /> {tr('ui.auto_detect')}
        </button>
        <button onClick={()=>{setRecipe([]);setInput('');setSuggestions([]);}} style={{ display:'flex', alignItems:'center', gap:5, padding:'3px 10px', borderRadius:'var(--fl-radius-sm)', background:'none', border:'1px solid var(--fl-border)', color:'var(--fl-subtle)', cursor:'pointer', ...mono, fontSize:10 }}>
          <RotateCcw size={10} /> {tr('ui.reset')}
        </button>
      </div>

      {suggestions.length>0 && (
        <div style={{ padding:'5px 14px', background:'var(--fl-bg)', borderBottom:'1px solid var(--fl-border)', display:'flex', gap:6, flexWrap:'wrap', alignItems:'center' }}>
          <span style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', flexShrink:0 }}>{tr('ui.detection')}</span>
          {suggestions.map((s,i)=>(
            <button key={i} onClick={()=>s.ops.length>0&&applySuggestion(s.ops)}
              style={{ display:'flex', alignItems:'center', gap:5, padding:'2px 8px', borderRadius:'var(--fl-radius-sm)', background:`color-mix(in srgb, ${s.color} 8%, transparent)`, border:`1px solid color-mix(in srgb, ${s.color} 25%, transparent)`, color:s.color, cursor:s.ops.length>0?'pointer':'default', ...mono, fontSize:9 }}>
              {s.confidence>0&&<span style={{ opacity:0.55 }}>{s.confidence}%</span>}
              {suggestionLabel(s)}
              {s.ops.length>0&&<ChevronRight size={9} />}
            </button>
          ))}
          <button onClick={()=>setSuggestions([])} style={{ background:'none', border:'none', cursor:'pointer', color:'var(--fl-subtle)', marginLeft:'auto', display:'flex' }}><X size={10} /></button>
        </div>
      )}

      <div style={{ display:'flex', flex:1, minHeight:0, overflow:'hidden' }}>

        <div style={{ width:250, flexShrink:0, display:'flex', flexDirection:'column', borderRight:'1px solid var(--fl-border)', background:'var(--fl-bg)', overflow:'hidden' }}>
          <div style={{ padding:'6px 10px', borderBottom:'1px solid var(--fl-border)', display:'flex', alignItems:'center', justifyContent:'space-between', flexShrink:0 }}>
            <span style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', }}>
              {tr('ui.recipe_steps', { count: recipe.length })}
            </span>
            <button onClick={()=>setShowPicker(p=>!p)} style={{ display:'flex', alignItems:'center', gap:4, padding:'2px 7px', borderRadius:'var(--fl-radius-sm)', background:'color-mix(in srgb, var(--fl-accent) 15%, transparent)', border:'1px solid color-mix(in srgb, var(--fl-accent) 40%, transparent)', color:'var(--fl-accent)', cursor:'pointer', ...mono, fontSize:9 }}>
              <Plus size={9} /> {tr('ui.add')}
            </button>
          </div>

          {showPicker && (
            <div style={{ background:'var(--fl-bg)', borderBottom:'1px solid var(--fl-border)', flexShrink:0 }}>
              <div style={{ padding:'4px 8px', borderBottom:'1px solid var(--fl-border)' }}>
                <input value={pickerSearch} onChange={e=>setPickerSearch(e.target.value)} placeholder={tr('ui.search_placeholder')}
                  style={{ width:'100%', boxSizing:'border-box', ...mono, fontSize:9, background:'var(--fl-panel)', color:'var(--fl-on-dark)', border:'1px solid var(--fl-border)', borderRadius:'var(--fl-radius-sm)', padding:'3px 6px', outline:'none' }} />
              </div>
              {!pickerSearch && (
                <div style={{ display:'flex', overflowX:'auto', scrollbarWidth:'none', padding:'4px 6px', gap:3, borderBottom:'1px solid var(--fl-border)' }}>
                  {CATEGORIES.map(cat=>(
                    <button key={cat} onClick={()=>setPickerCat(cat)} style={{ flexShrink:0, padding:'2px 6px', borderRadius:'var(--fl-radius-sm)', cursor:'pointer', ...mono, fontSize:8, background:pickerCat===cat?`color-mix(in srgb, ${CAT_COLOR[cat]} 13%, transparent)`:'none', border:`1px solid ${pickerCat===cat?CAT_COLOR[cat]+'60':'transparent'}`, color:pickerCat===cat?CAT_COLOR[cat]:'var(--fl-subtle)' }}>
                      {categoryLabel(cat)}
                    </button>
                  ))}
                </div>
              )}
              <div style={{ maxHeight:220, overflowY:'auto', scrollbarWidth:'thin', scrollbarColor:'var(--fl-border) var(--fl-bg)' }}>
                {filteredOps.length===0
                  ? <div style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', padding:'10px', textAlign:'center' }}>{tr('ui.no_operation')}</div>
                  : filteredOps.map(([id,op])=>(
                    <button key={id} onClick={()=>addOp(id)} style={{ display:'block', width:'100%', textAlign:'left', padding:'5px 10px', background:'none', border:'none', borderBottom:'1px solid var(--fl-border)', cursor:'pointer', ...mono, fontSize:9, color:'var(--fl-on-dark)' }}
                      onMouseEnter={e=>{e.currentTarget.style.background='var(--fl-panel)';}}
                      onMouseLeave={e=>{e.currentTarget.style.background='none';}}>
                      <div style={{ display:'flex', alignItems:'center', gap:4, marginBottom:2 }}>
                        <span style={{ fontWeight:700, flex:1 }}>{opLabel(op)}</span>
                        <OpBadge category={op.category} />
                      </div>
                      <div style={{ fontSize:8, color:'var(--fl-subtle)' }}>{opDescription(op)}</div>
                    </button>
                  ))
                }
              </div>
            </div>
          )}

          <div style={{ flex:1, overflowY:'auto', padding:'6px 8px', scrollbarWidth:'thin', scrollbarColor:'var(--fl-border) var(--fl-bg)' }}>
            {recipe.length===0?(
              <div style={{ ...mono, fontSize:9, color:'var(--fl-subtle)', textAlign:'center', marginTop:28, lineHeight:1.9 }}>
                {tr('ui.empty_recipe')}<br /><br /><span style={{ fontSize:8, opacity:0.7 }}>{tr('ui.drag_hint')}</span>
              </div>
            ):(
              recipe.map((step,i)=>(
                <RecipeStep key={i} step={step} index={i} result={steps[i]} onRemove={removeOp} onChange={changeParam}
                  onDragStart={onStepDragStart} onDragOver={onStepDragOver} onDrop={onStepDrop} dragging={dragIndex===i} />
              ))
            )}
          </div>

          {recipe.length>0&&(
            <div style={{ padding:'5px 8px', borderTop:'1px solid var(--fl-border)', flexShrink:0 }}>
              {lastError?(
                <div style={{ display:'flex', alignItems:'flex-start', gap:4 }}>
                  <AlertTriangle size={9} style={{ color:'var(--fl-danger)', flexShrink:0, marginTop:1 }} />
                  <span style={{ ...mono, fontSize:8, color:'var(--fl-danger)', wordBreak:'break-all' }}>{lastError.error}</span>
                </div>
              ):(
                <div style={{ display:'flex', alignItems:'center', gap:5 }}>
                  <Play size={9} style={{ color:'var(--fl-ok)' }} />
                  <span style={{ ...mono, fontSize:9, color:'var(--fl-ok)' }}>{tr('ui.auto_run')}</span>
                </div>
              )}
            </div>
          )}
        </div>

        <div style={{ flex:1, display:'flex', flexDirection:'column', minWidth:0, overflow:'hidden' }}>
          <div style={{ flex:1, display:'flex', flexDirection:'column', minHeight:0, borderBottom:'2px solid var(--fl-border)' }}>
            <div style={{ display:'flex', alignItems:'center', gap:8, padding:'4px 12px', flexShrink:0, background:'var(--fl-card)', borderBottom:'1px solid var(--fl-border)' }}>
              <span style={{ ...mono, fontSize:9, color:'var(--fl-accent)', letterSpacing:'0.1em', fontWeight:700 }}>{tr('ui.input')}</span>
              {input&&<span style={{ ...mono, fontSize:8, color:'var(--fl-subtle)' }}>{tr('ui.input_stats', { count: inputBytes.length, entropy })}</span>}
              {input&&isHighEntropy(inputBytes)&&<span style={{ ...mono, fontSize:8, padding:'1px 6px', borderRadius:'var(--fl-radius-sm)', background:'color-mix(in srgb, var(--fl-danger) 12%, transparent)', color:'var(--fl-danger)', border:'1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)' }}>{tr('ui.high_entropy')}</span>}
            </div>
            <textarea value={input} onChange={e=>setInput(e.target.value)}
              placeholder={tr('ui.input_placeholder')}
              spellCheck={false}
              style={{ flex:1, resize:'none', outline:'none', background:'var(--fl-bg)', color:'var(--fl-on-dark)', border:'none', padding:'10px 14px', ...mono, fontSize:11, lineHeight:1.6, scrollbarWidth:'thin', scrollbarColor:'var(--fl-border) var(--fl-bg)' }} />
          </div>

          <div style={{ flex:1, display:'flex', flexDirection:'column', minHeight:0 }}>
            <div style={{ display:'flex', alignItems:'center', gap:6, padding:'4px 12px', flexShrink:0, background:'var(--fl-card)', borderBottom:'1px solid var(--fl-border)', flexWrap:'wrap' }}>
              <span style={{ ...mono, fontSize:9, color:'var(--fl-ok)', letterSpacing:'0.1em', fontWeight:700 }}>{tr('ui.output')}</span>
              {output.length>0&&recipe.length>0&&<span style={{ ...mono, fontSize:8, color:'var(--fl-subtle)' }}>{tr('ui.output_bytes', { count: output.length })}</span>}
              <div style={{ flex:1 }} />
              {steps.map((s,i)=>(
                <span key={i} style={{ ...mono, fontSize:8, padding:'1px 6px', borderRadius:'var(--fl-radius-sm)', background:s.error?'color-mix(in srgb, var(--fl-danger) 12%, transparent)':'color-mix(in srgb, var(--fl-ok) 12%, transparent)', color:s.error?'var(--fl-danger)':'var(--fl-ok)', border:`1px solid ${s.error?'color-mix(in srgb, var(--fl-danger) 30%, transparent)':'color-mix(in srgb, var(--fl-ok) 30%, transparent)'}` }}>
                  {s.error&&<AlertTriangle size={8} />}{i+1}. {OPS[s.opId]?opLabel(OPS[s.opId]):s.opId}
                </span>
              ))}
              <button onClick={copyOutput} disabled={!output.length} style={{ display:'flex', alignItems:'center', gap:4, padding:'2px 8px', borderRadius:'var(--fl-radius-sm)', background:copied?'color-mix(in srgb, var(--fl-ok) 15%, transparent)':'none', border:`1px solid ${copied?'color-mix(in srgb, var(--fl-ok) 40%, transparent)':'var(--fl-border)'}`, color:copied?'var(--fl-ok)':'var(--fl-subtle)', cursor:output.length?'pointer':'default', ...mono, fontSize:9, transition:'all 0.2s' }}>
                <Copy size={9} /> {copied?tr('ui.copied'):tr('ui.copy')}
              </button>
            </div>
            <div style={{ flex:1, overflowY:'auto', background:'var(--fl-bg)', padding:'10px 14px', ...mono, fontSize:11, color:lastError?'var(--fl-danger)':'var(--fl-on-dark)', lineHeight:1.6, whiteSpace:'pre-wrap', wordBreak:'break-all', scrollbarWidth:'thin', scrollbarColor:'var(--fl-border) var(--fl-bg)' }}>
              {recipe.length===0
                ? <span style={{ color:'var(--fl-subtle)' }}>{tr('ui.output_placeholder')}</span>
                : (output.length
                  ? <>{outputView.binary&&<div style={{ color:'var(--fl-subtle)', marginBottom:6 }}>{tr('ui.binary_notice')}</div>}{outputView.text}</>
                  : <span style={{ color:'var(--fl-subtle)' }}>{tr('ui.output_empty')}</span>)}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
