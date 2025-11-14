import jpamb
from jpamb import jvm
from dataclasses import dataclass
import sys
from loguru import logger

logger.remove()
logger.add(sys.stderr, format="[{}] {}".format("{level}", "{message}"))

methodid, input = jpamb.getcase()

# ---------- helpers

def opname(op) -> str:
    return type(op).__name__

def is_int(v: jvm.Value) -> bool:
    # Accept jpamb ints by type name to avoid identity pitfalls
    try:
        return type(getattr(v, "type")).__name__.lower() in ("int", "integer")
    except Exception:
        return False
    
def is_bool(v: jvm.Value) -> bool:
    try:
        return type(getattr(v, "type")).__name__.lower() in ("bool", "boolean")
    except Exception:
        return False

def is_cat2(v: jvm.Value) -> bool:
    try:
        tname = type(getattr(v, "type")).__name__.lower()
        return tname in ("long", "double")
    except Exception:
        return False

def cond_name(cond) -> str:
    # Normalize condition enum/str to {'eq','ne','gt','ge','lt','le'}
    if isinstance(cond, str):
        return cond.strip().lower()
    n = getattr(cond, "name", None)
    if isinstance(n, str):
        return n.strip().lower()
    # Fallback: parse from repr
    s = str(cond).lower()
    for k in ("eq", "ne", "gt", "ge", "lt", "le"):
        if k in s:
            return k
    return s

def get_if_cond_and_target(op) -> tuple[str, int]:
    # Try fields first
    c = getattr(op, "cond", getattr(op, "condition", getattr(op, "operant", getattr(op, "op", None))))
    # NEW: also consider "offset" as a possible jump target field
    t = getattr(op, "target", getattr(op, "offset", None))
    cn = cond_name(c)
    if t is not None and isinstance(t, int):
        return cn, t
    # Fallback to parsing the string "ifz eq 8"
    text = str(op).lower()
    tgt = None
    for k in ("eq", "ne", "gt", "ge", "lt", "le"):
        if f" {k} " in text or f"'{k}'" in text:
            cn = k
            break
    # last token usually the target
    try:
        tgt = int(text.split()[-1].rstrip(')'))
    except Exception:
        pass
    return cn, tgt

def is_returning_int(op) -> bool:
    # Prefer type field if available
    rett = getattr(op, "type", None)
    if rett is not None:
        return type(rett).__name__.lower() in ("int", "integer")
    # Fallback: look at string form (e.g., "return:I" / "return:V")
    return ":i" in str(op).lower()

def make_ref_value(class_name: str) -> jvm.Value:
    """Create a reference Value - store class info in the value field"""
    # Try to create with object notation, or fall back to int with special marker
    try:
        # Create an int value but store metadata separately
        val = jvm.Value.int(0)
        # Store class info as an attribute if possible
        val._ref_data = {"class": class_name, "init": False}
        return val
    except Exception:
        # Last resort: just use int
        return RefObject(class_name)

# ---------- containers\\

@dataclass
class RefObject:
    class_name: str

@dataclass
class PC:
    method: jvm.AbsMethodID
    offset: int
    def __iadd__(self, delta):
        self.offset += delta
        return self
    def __add__(self, delta):
        return PC(self.method, self.offset + delta)
    def __str__(self):
        return f"{self.method}:{self.offset}"

@dataclass
class Bytecode:
    suite: jpamb.Suite
    methods: dict[jvm.AbsMethodID, list[jvm.Opcode]]
    def __getitem__(self, pc: PC) -> jvm.Opcode:
        try:
            ops = self.methods[pc.method]
        except KeyError:
            ops = list(self.suite.method_opcodes(pc.method))
            self.methods[pc.method] = ops
        return ops[pc.offset]

@dataclass
class Stack[T]:
    items: list[T]
    def __bool__(self):
        return len(self.items) > 0
    @classmethod
    def empty(cls):
        return cls([])
    def peek(self) -> T:
        return self.items[-1]
    def pop(self) -> T:
        return self.items.pop(-1)
    def push(self, v):
        self.items.append(v)
        return self
    def __str__(self):
        if not self:
            return "ϵ"
        return "".join(f"{v}" for v in self.items)

suite = jpamb.Suite()
bc = Bytecode(suite, dict())

@dataclass
class Frame:
    locals: dict[int, jvm.Value]
    stack: Stack[jvm.Value]
    pc: PC
    def _str_(self):
        locals_str = ", ".join(f"{k}:{v}" for k, v in sorted(self.locals.items()))
        return f"<{{{locals_str}}}, {self.stack}, {self.pc}>"       
    @staticmethod
    def from_method(m: jvm.AbsMethodID) -> "Frame":
        return Frame({}, Stack.empty(), PC(m, 0))

@dataclass
class State:
    heap: dict[int, jvm.Value]
    frames: Stack[Frame]
    def __str__(self):
        return f"{self.heap} {self.frames}"

# ---------- interpreter

def step(state: State) -> State | str:
    assert isinstance(state, State)
    frame = state.frames.peek()
    op = bc[frame.pc]
    logger.debug(f"STEP {op}\n{state}")

    name = opname(op).lower()

    match op:
        # Push constants
        case _ if name == "push":
            frame.stack.push(op.value)
            frame.pc += 1
            return state

        # Load/Store locals
        case _ if name == "load":
            frame.stack.push(frame.locals[op.index])
            frame.pc += 1
            return state

        case _ if name == "store":
            frame.locals[op.index] = frame.stack.pop()
            frame.pc += 1
            return state

        # Nop (just in case)
        case _ if name == "nop":
            frame.pc += 1
            return state

        # NEW: Pop - discard top-of-stack
        case _ if name == "pop":
            _ = frame.stack.pop()
            frame.pc += 1
            return state

        # NEW: Swap - swap top two stack elements
        case _ if name == "swap":
            v1 = frame.stack.pop()
            v2 = frame.stack.pop()
            frame.stack.push(v1).push(v2)
            frame.pc += 1
            return state

        # Integer arithmetic (div, add, sub, mul)
        case _ if (
            name == "binary"
            or "binary" in name  # NEW: be robust to slight naming variations
        ) and type(getattr(op, "type")).__name__.lower() in ("int", "integer"):
            v2 = frame.stack.pop(); v1 = frame.stack.pop()
            assert is_int(v1) and is_int(v2), f"int binary expects ints: {v1}, {v2}"
            oper = getattr(op, "operant", getattr(op, "op", None))
            oper_s = getattr(oper, "name", str(oper)).lower()
            if "div" in oper_s:
                if v2.value == 0:
                    return "divide by zero"
                res = v1.value // v2.value
            elif "add" in oper_s:
                res = v1.value + v2.value
            elif "sub" in oper_s:
                res = v1.value - v2.value
            elif "mul" in oper_s:
                res = v1.value * v2.value
            else:
                raise NotImplementedError(f"int Binary {oper_s!r}")
            frame.stack.push(jvm.Value.int(res))
            frame.pc += 1
            return state

        # Dup / Dup2
        case _ if name == "dup":
            w = op.words
            assert w in (1, 2)
            if w == 1:
                v1 = frame.stack.peek()
                frame.stack.push(v1)
                frame.pc += 1
                return state
            top = frame.stack.pop()
            if is_cat2(top):
                frame.stack.push(top).push(top)
                frame.pc += 1
                return state
            v1 = top
            assert bool(frame.stack), "stack underflow on dup2"
            v2 = frame.stack.pop()
            frame.stack.push(v2).push(v1).push(v2).push(v1)
            frame.pc += 1
            return state

        # If* against zero (ifeq, ifne, ifgt, ifge, iflt, ifle)
        case _ if name == "ifz":
            v = frame.stack.pop()
            # Handle both int and boolean values
            if is_int(v):
                x = v.value
            elif is_bool(v):
                x = 1 if v.value else 0
            else:
                x = v.value

            c, t = get_if_cond_and_target(op)
            if t is None:
                raise NotImplementedError(f"Ifz missing target: {op!r}")
            jump = (
                (c == "eq" and x == 0) or
                (c == "ne" and x != 0) or
                (c == "gt" and x > 0) or
                (c == "ge" and x >= 0) or
                (c == "lt" and x < 0) or
                (c == "le" and x <= 0)
            )
            frame.pc = PC(frame.pc.method, t) if jump else (frame.pc + 1)
            return state

        # If integer compare (if_icmp* or just "if")
        case _ if name in ("ifcmp", "if_icmp", "ificmp", "if"):
            b = frame.stack.pop(); a = frame.stack.pop()
            assert is_int(a) and is_int(b), f"If comparison expects two ints, got {a}, {b}"
            av, bv = a.value, b.value
            c, t = get_if_cond_and_target(op)
            if t is None:
                raise NotImplementedError(f"If comparison missing target: {op!r}")
            jump = (
                (c == "eq" and av == bv) or
                (c == "ne" and av != bv) or
                (c == "gt" and av > bv) or
                (c == "ge" and av >= bv) or
                (c == "lt" and av < bv) or
                (c == "le" and av <= bv)
            )
            frame.pc = PC(frame.pc.method, t) if jump else (frame.pc + 1)
            return state

        # Goto
        case _ if name == "goto":
            # NEW: robust target lookup
            tgt = getattr(op, "target", getattr(op, "offset", None))
            if tgt is None:
                # Fall back to repr parse
                text = str(op).lower()
                try:
                    tgt = int(text.split()[-1].rstrip(')'))
                except Exception:
                    raise NotImplementedError(f"Goto missing target: {op!r}")
            frame.pc = PC(frame.pc.method, tgt)
            return state

        # Return (int or void)
        case _ if name == "return":
            if is_returning_int(op):
                v1 = frame.stack.pop()
                state.frames.pop()
                if state.frames:
                    caller = state.frames.peek()
                    caller.stack.push(v1)
                    caller.pc += 1
                    return state
                else:
                    return "ok"
            else:
                # treat non-int returns as void
                state.frames.pop()
                if state.frames:
                    caller = state.frames.peek()
                    caller.pc += 1
                    return state
                else:
                    return "ok"

        # Get / GetStatic (we only need static $assertionsDisabled)
        case _ if name in ("getstatic", "get"):
            is_static = (name == "getstatic") or bool(getattr(op, "static", False))
            if not is_static:
                raise NotImplementedError("getfield not implemented")
            fld = getattr(op, "field", None)
            if fld is not None:
                ext = getattr(fld, "extension", None)
                fname = getattr(ext, "name", None) if ext else None
            else:
                fname = getattr(op, "name", None)
            if fname == "$assertionsDisabled":
                # assertions enabled in tests => push boolean false (represented as int 0)
                frame.stack.push(jvm.Value.int(0))
                frame.pc += 1
                return state
            raise NotImplementedError(f"Get static field not handled: {fname}")

        # New <class>
        case _ if name == "new":
            # Parse the class name from the textual form, e.g. "new java/lang/AssertionError"
            text = str(op)
            cls_name = "Unknown"
            try:
                if "new " in text:
                    # take the token right after "new"
                    cls_name = text.split("new", 1)[1].strip().split()[0]
                else:
                    # fallback: last token
                    cls_name = text.split()[-1]
            except Exception:
                pass

            ref_val = make_ref_value(cls_name)
            frame.stack.push(ref_val)
            frame.pc += 1
            return state
        # Invoke (handle invokespecial <init> only)
        case _ if name in ("invoke", "invokespecial", "invokevirtual", "invokestatic"):
            # Get method details
            meth = getattr(op, "method", None)

            # NEW: also use "access" field to detect special invokes
            access = getattr(op, "access", "")
            access_s = str(access).lower() if access is not None else ""
            is_special = (
                name == "invokespecial"
                or "special" in name
                or "special" in access_s  # NEW
            )

            # For <init> constructors, just pop args and object ref
            if is_special and meth is not None:
                method_name = ""
                try:
                    ext = getattr(meth, "extension", None)
                    if ext:
                        method_name = getattr(ext, "name", "")
                except Exception:
                    pass

                if method_name == "<init>":
                    # Pop constructor arguments (if any)
                    try:
                        params = getattr(getattr(meth, "type", None), "params", None)
                        if params:
                            elements = getattr(params, "_elements", ())
                            for _ in elements:
                                frame.stack.pop()
                    except Exception:
                        pass

                    # Pop the object reference
                    obj = frame.stack.pop()
                    # Mark object as initialized
                    try:
                        if hasattr(obj, "_ref_data"):
                            obj._ref_data["init"] = True
                    except Exception:
                        pass
                    
                    frame.stack.push(obj)
                    frame.pc += 1
                    return state

            raise NotImplementedError(f"Invoke {name} for method {meth} not implemented")

        # Throw (athrow)
        case _ if name == "throw":
            ex = frame.stack.pop()
            clsname = None
            
            if isinstance(ex, RefObject):
                clsname = ex.class_name
            else:
            # Try to get the class name from our fake reference metadata
             try:
                 t = getattr(ex, "type", None)
                 n = getattr(t, "name", None)
                 clsname = n if n is not None else t
             except Exception:
              clsname = ""
              
              
            cls_str = str(clsname).lower().replace("/", ".")
            if "assertionerror" in cls_str:
                return "assertion error"
            return "failure"
        # Fallback
        case other:
            raise NotImplementedError(f"Don't know how to handle: {other!r}")

# ---------- bootstrap & run

frame = Frame.from_method(methodid)
for i, v in enumerate(input.values):
    frame.locals[i] = v

state = State({}, Stack.empty().push(frame))

for _ in range(1000):
    state = step(state)
    if isinstance(state, str):
        print(state)
        break
else:
    print("*")