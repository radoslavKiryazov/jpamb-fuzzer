import jpamb
from jpamb import jvm
from dataclasses import dataclass
import sys
from loguru import logger
from jpamb.jvm.opcode import ArrayLoad, ArrayStore, NewArray, ArrayLength


logger.remove()
logger.add(sys.stderr, format="[{}] {}".format("{level}", "{message}"))

methodid, input = jpamb.getcase()

# ---------- helpers

def opname(op) -> str:
    return type(op).__name__

def is_int(v: jvm.Value) -> bool:
    # Accept jpamb ints by type name to avoid identity pitfalls
    try:
        tname = type(getattr(v, "type")).__name__.lower()
        return tname in ("int", "integer", "char")
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
    
def get_param_count(meth) -> int:
    """
    Robustly determine the number of parameters of a method.
    Prefer the .type.params info if available, otherwise parse
    the JVM descriptor from str(meth)
    """
    # 1) Try the type/params metadata first
    param_type = getattr(meth, "type", None)
    params = getattr(param_type, "params", None)
    elems = getattr(params, "_elements", None)
    if elems is not None:
        try:
            return len(elems)
        except TypeError:
            pass  # fall through to descriptor parsing

    # 2) Fallback: parse the descriptor string
    text = str(meth)
    desc = ""
    try:
        # Split off the ":(...)..." part
        desc = text.split(":", 1)[1]
    except Exception:
        return 0

    # We only care about the "(...)" before the ')'
    try:
        sig = desc.split(")", 1)[0]  # e.g. '(Z' or '(IIZ'
    except Exception:
        return 0

    if not sig.startswith("("):
        return 0
    sig = sig[1:]  # drop '('

    # Parse JVM type descriptors to count parameters
    i = 0
    count = 0
    while i < len(sig):
        c = sig[i]
        if c in "ZBCSIJFD":  # primitive: boolean, byte, char, short, int, long, float, double
            count += 1
            i += 1
        elif c == 'L':
            # object type: L...;
            count += 1
            j = sig.find(";", i)
            if j == -1:
                break
            i = j + 1
        elif c == '[':
            # array: one or more '[' then one type
            i += 1
        else:
            # Unexpected char; skip to be safe
            i += 1
    return count


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
            val = op.value
         
            if isinstance(val, str) and len(val) == 1:
                frame.stack.push(jvm.Value.int(ord(val)))
            else:
                frame.stack.push(op.value)
        
            frame.pc += 1
            return state

           # Load/Store locals
        case _ if name == "load":
            idx = op.index

            # jpamb quirk:
            # Some (apparently static) methods still do `load 0` as if there was a receiver.
            # If local slot `idx` is missing, synthesize a dummy "this" reference.
            if idx not in frame.locals:
                frame.locals[idx] = make_ref_value(str(frame.pc.method.classname))

            frame.stack.push(frame.locals[idx])
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
        
        # Integer arithmetic (div, add, sub, mul, rem)
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
            elif "rem" in oper_s or "mod" in oper_s:
                if v2.value == 0:
                    return "divide by zero"
                res = v1.value % v2.value
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
        
        case _ if name == "cast":
            v = frame.stack.pop()
            
            if not is_int(v):
                raise NotImplementedError(f"cast from int {v!r}")
            
            frame.stack.push(jvm.Value.int(v.value))
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
                # Fallback: treat non-primitive as reference:
                # null -> 0, non-null -> 1
                x = 0 if v is None else getattr(v, "value", 1)

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
                # Return (int or void)
                # Return (int or void)
                # ----- RETURN for ANY return type (int, array, reference, void) -----
        case _ if name == "return":
            # op.type is:
            #   - None  for void-return methods (V)
            #   - jvm.Type (Int, Reference, Array, ...) for value-returning methods
            ret_type = getattr(op, "type", None)
            returns_value = ret_type is not None

            # Pop current frame (callee)
            state.frames.pop()

            if state.frames:
                # ---- CASE 1: Returning to a caller ----
                caller = state.frames.peek()

                if returns_value:
                    # Return *whatever* is on top of the callee stack:
                    # int, array, reference, etc.
                    ret_val = frame.stack.pop()
                    caller.stack.push(ret_val)

                # Caller.pc was already advanced in the invoke handler.
                return state

            else:
                # ---- CASE 2: Top-level method finished ----
                if returns_value and frame.stack.items:
                    # Discard top value (jpamb doesn't care about result at top level),
                    # but we must keep stack consistent.
                    _ = frame.stack.pop()

                # Advance PC to avoid re-running the same return instruction
                frame.pc += 1
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

        # Invoke (constructors + real calls)
                # Invoke (static, special, virtual)
        case _ if name in ("invoke", "invokespecial", "invokevirtual", "invokestatic"):
            meth = getattr(op, "method", None)
            if meth is None:
                raise NotImplementedError(f"Invoke missing method: {op}")

            # === Detect AssertionError.<init>, treat as immediate assertion error ===
            cls = str(getattr(meth, "classname", ""))
            ext = getattr(meth, "extension", None)
            mname = getattr(ext, "name", None)
            if "java/lang/AssertionError" in cls and mname == "<init>":
                return "assertion error"
            # =======================================================================

            is_static_call = (name == "invokestatic")

            # ---- ROBUST parameter counting ----
            param_count = get_param_count(meth)

            # ---- Pop args from the caller stack ----
            args = [frame.stack.pop() for _ in range(param_count)][::-1]

            # ---- Receiver for non-static calls ----
            recv = None
            if not is_static_call:
                recv = frame.stack.pop()
                # ignore synthetic receiver objects
                if isinstance(recv, RefObject) or (
                    hasattr(recv, "_ref_data") and not recv._ref_data.get("init", True)
                ):
                    recv = None

            # ---- Create new frame ----
            new_frame = Frame({}, Stack.empty(), PC(meth, 0))

            if recv is None:
                # static or synthetic → args start at local 0
                for i, a in enumerate(args):
                    new_frame.locals[i] = a
            else:
                # real receiver → locals[0] = this
                new_frame.locals[0] = recv
                for i, a in enumerate(args):
                    new_frame.locals[i + 1] = a

            # Move caller PC forward and push new frame
            frame.pc += 1
            state.frames.push(new_frame)
            return state




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
        
        
        #ARRAYSI
        
        case _ if name == "newarray":
            length_val = frame.stack.pop()
            if not is_int(length_val): 
                raise NotImplementedError("newarray expects integer length")

            length = length_val.value
            if length < 0:
                return "out of bounds"
            
            arr = [jvm.Value.int(0) for _ in range(length)]
            frame.stack.push(arr)
            frame.pc += 1
            return state
        
        case _ if name == "arraylength":
            arr = frame.stack.pop()
            
            # Null array check
            if arr is None or (isinstance(arr, jvm.Value) and getattr(arr, "value", None) is None):
                return "null pointer"
            
            if isinstance(arr, jvm.Value):
                elements = arr.value
            else: 
                elements = arr

            frame.stack.push(jvm.Value.int(len(elements)))
            frame.pc += 1
            return state
        
        # handle all the loads
        case _ if name in ("iaload", "aload", "caload", "arrayload", "array_load", "aaload"):
            idx_val = frame.stack.pop()
            arr = frame.stack.pop()

            if arr is None or (isinstance(arr, jvm.Value) and getattr(arr, "value", None) is None):
                return "null pointer"
                        
            if not is_int(idx_val):
                raise NotImplementedError("arrayload expects integer index")

            if isinstance(arr, jvm.Value):
                elems = arr.value
            else:
                elems = arr
            
          

            idx = idx_val.value
            if idx < 0 or idx >= len(elems):
                return "out of bounds"

            element = elems[idx]

            # If jpamb gives literal chars (Python 'h', 'e', ...)
            if isinstance(element, str) and len(element) == 1:
                # Convert char → ASCII int
                frame.stack.push(jvm.Value.int(ord(element)))
            elif isinstance(element, jvm.Value):
                frame.stack.push(element)
            else:
                frame.stack.push(jvm.Value.int(element))
              
            frame.pc += 1
            return state

        # Array stores: ..., arrayref, index, value  ->  ...
        case _ if name in ("iastore", "aastore", "castore", "arraystore", "array_store"):
            val = frame.stack.pop()
            idx_val = frame.stack.pop()
            arr = frame.stack.pop()

            # Null checks
            if arr is None or (
                isinstance(arr, jvm.Value) and getattr(arr, "value", None) is None
            ):
                return "null pointer"

            if not is_int(idx_val):
                raise NotImplementedError("arraystore expects integer index")

            # Unwrap underlying elements
            if isinstance(arr, jvm.Value):
                elems = arr.value
            else:
                elems = arr

            # If jpamb gave us a tuple, make it mutable
            if isinstance(elems, tuple):
                elems = list(elems)
                if isinstance(arr, jvm.Value):
                    arr.value = elems

            idx = idx_val.value
            if idx < 0 or idx >= len(elems):
                return "out of bounds"

            elems[idx] = val
            frame.pc += 1
            return state

        
        case _ if name == "aconst_null":
            frame.stack.push(None)
            frame.pc += 1
            return state
        
        case _ if name == "incr":
            idx = op.index
            amount = op.amount
            cur = frame.locals.get(idx)
            assert is_int(cur), f"incr expects int local, got {cur}"
            frame.locals[idx] = jvm.Value.int(cur.value + amount)
            frame.pc += 1
            return state
        
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
