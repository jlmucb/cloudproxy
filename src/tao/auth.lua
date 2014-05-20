--[[

Extension primitives for authorization-related predicates.

]]

-- Join a slice of list of strings
function join(delim, v, s, e)
  s = s or 1
  e = e or #v
  if s > e then
    return ""
  elseif s == e then
    j = tostring(v[s])
    while s < e do
      s = s + 1
      j = j .. delim .. tostring(v[s])
    end
    return j
  end
end

-- Split string into name, remainder.
local function splitName(s)
  --print(string.format("splitName: %q\n", s))
  local pred = s:match("%a+")
  if pred then
    return pred, s:sub(pred:len() + 1)
  else
    return nil, s
  end
end

-- Split string into integer, remainder
local function splitInteger(s)
  local num = s:match("%d+")
  if num then
    return num, s:sub(num:len() + 1)
  else
    return nil, s
  end
end

-- Split string into v, remainder
local function split(s, v)
  if s:sub(1, v:len(v)) == v then
    return v, s:sub(v:len(v) + 1)
  else
    return nil, s
  end
end

-- Split string into quoted_string, remainder
local function splitQuotedString(s)
  local q = split(s, '"')
  if q then
    local i = 2
    local escape = false
    while i <= s:len() do
      local c = s:sub(i, i)
      if not escape then
        if c == '"' then
          return s:sub(1, i), s:sub(i+1)
        elseif c == '\\' then
          escape = true
        end
      else
        if (c == '"') or (c == '\\') then
          escape = false
        else
          return nil, s
        end
      end
      i = i + 1
    end
  end
  return nil, s
end

-- Class Pred represents name(args...)
local Pred = {}
Pred.__index = Pred

local function mk_pred(name, args)
  local tbl = {name = name, args = args}
  return setmetatable(tbl, Pred)
end

function Pred:__tostring()
  return self.name .. '(' .. join(", ", self.args) .. ')'
end

-- Split string into Pred, remainder
local function splitPred(s)
  --print(string.format("splitPred: %q\n", s))
  local name, r = splitName(s)
  if not name then
    return nil, s
  else
    local args = {}
    local x, r = split(r, '(')
    if not x then
      -- return mk_pred(name, nil)
      return nil, s
    else
      while r:len() > 0 do
        x, r = split(r, ')')
        if x then
          local c = {}
          return mk_pred(name, args), r
        end
        if #args > 0 then
          x, r = split(r, ", ")
          if not x then
            return nil, s
          end
        end
        t, r = splitQuotedString(r)
        if not t then
          t, r = splitInteger(r)
        end
        if not t then
          return nil, s
        else
          args[(#args)+1] = t
        end
      end
      return nil, s
    end
  end
end

-- Class Prin represents Parent::Extension
local Prin = {}
Prin.__index = Prin

local function mk_subprin(parent, ext)
  local tbl = {parent = parent, ext = ext}
  return setmetatable(tbl, Prin)
end

local function mk_prin(name)
  --print("making prin ", name, "\n")
  --print(string.format("actual: %q\n", name))
  local p, s = splitPred(name)
  --print("split first pred", p, "\n")
  if not p then
    return nil
  end
  local prin = mk_subprin(nil, p) 
  while s:len() > 0 do
    q, s = split(s, "::")
    if not q then
      return nil
    end
    p, s = splitPred(s)
    if not p then
      return nil
    end
    prin = mk_subprin(prin, p)
  end
  return prin
end

function Prin:__tostring()
  if self.parent then
    return tostring(self.parent) .. "::" .. tostring(self.ext)
  else
    return tostring(self.ext)
  end
end

-- subprin/3 primitive. subprin(P, O, E) holds when P is the principal obtained
-- by extending principal O with subprincipal name E, i.e. when P = O::E. This
-- primitive requries that either P is a constant, or both O and E are
-- constants.
local function subprin(literal)
  return function(s, v)
    if v then
      print("end of iter\n")
      return nil
    else
      local p = literal[1]
      local o = literal[2]
      local e = literal[3]
      if p:is_const() then
        local prin = mk_prin(tostring(p.id))
        if not prin or not prin.parent then
          print("bad prin or no parent\n")
          return nil
        else
          print(string.format("got one, prin is %q\n", tostring(prin)))
          return {tostring(prin), tostring(prin.parent), tostring(prin.ext)}
        end
      elseif o:is_const() and e:is_const() then
        local parent = mk_prin(tostring(o.id))
        local ext = mk_prin(tostring(e.id))
        if not parent or not ext or ext.parent then
          print("no parent, no ext, or has ext.parent\n")
          return nil
        else
          return { tostring(parent) .. "::" .. tostring(ext), tostring(parent), tostring(ext) }
        end
      else
        print("too many vars\n")
        return nil
      end
    end
  end
end

datalog.add_iter_prim("subprin", 3, subprin)
