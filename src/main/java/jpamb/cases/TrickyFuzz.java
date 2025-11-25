package jpamb.cases;
import jpamb.utils.*;
import static jpamb.utils.Tag.TagType.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.regex.Pattern;

/**
 * TrickyFuzz - collection of small methods designed to produce
 * subtle failures for fuzzers. Follow the same annotation style
 * as your example.
 */
public class TrickyFuzz {
    // Tag:
    // OVERFLOW, MATH, NULL, IO, PATH, REGEX, FORMAT, PARSE, SQL, CONCURRENCY, RESOURCE, FUZZ


    // ---------------------------
    // Integer overflow / underflow
    // ---------------------------
    @Case("(2, 1000000000) -> ok")
    @Case("(2, 2000000000) -> overflow -> negative or assertion")
    // @Tag({ OVERFLOW })
    @Tag({ FUZZ })
    public static void multiplyAndCheck(int a, int b) {
    // naive multiply that can overflow
    long prod = (long) a * (long) b;
    // sanity assertion expecting product fits in int (will fail on overflow)
    assert prod <= Integer.MAX_VALUE && prod >= Integer.MIN_VALUE;
    int result = (int) prod; // truncation on overflow
    // use result to prevent optimization-out
    if (result == 0 && a != 0 && b != 0) {
        throw new AssertionError("unexpected zero after multiply");
    }
    }

    // ---------------------------
    // Division / divide-by-zero
    // ---------------------------
    @Case("(10, 2) -> ok")
    @Case("(10, 0) -> ArithmeticException")
    // @Tag({ MATH })
    @Tag({ FUZZ })
    public static void safeDivide(int numerator, int denominator) {
    assert denominator != 0;
    int q = numerator / denominator; // potential ArithmeticException
    if (q < 0) {
        // arbitrary use
        throw new RuntimeException("negative quotient");
    }
    }

    // ---------------------------
    // Null dereference
    // ---------------------------
    @Case("(\"hello\") -> ok")
    @Case("(null) -> NullPointerException")
    // @Tag({ NULL })
    @Tag({ FUZZ })
    public static void lengthThenChar(String s) {
    // deliberate null deref if fuzzed
    int len = s.length();        // NPE if s == null
    char c = s.charAt(len - 1);  // IndexOutOfBounds if empty
    // small side-effect to keep result relevant
    if (c == '\u0000') {
        throw new AssertionError("unexpected null char");
    }
    }

    // ---------------------------
    // Path traversal / canonicalization
    // ---------------------------
    @Case("(\"/safe/dir\", \"file.txt\") -> ok")
    @Case("(\"/safe/dir\", \"../secret.txt\") -> path traversal")
    // @Tag({ IO, PATH })
    @Tag({ FUZZ })
    public static void checkPath(String baseDir, String userPath) throws IOException {
    File base = new File(baseDir);
    File target = new File(base, userPath);
    String baseCanonical = base.getCanonicalPath();
    String targetCanonical = target.getCanonicalPath();
    // ensure target is inside base
    assert targetCanonical.startsWith(baseCanonical + File.separator);
    }

    // ---------------------------
    // Regular-expression catastrophic backtracking (ReDoS)
    // ---------------------------
    @Case("(\"(a+)+$\") , (\"a\") -> ok")
    @Case("(\"(a+)+$\") , (\"a{10000}\") -> potential hang / catastrophic backtracking")
    // @Tag({ REGEX, RESOURCE })
    @Tag({ FUZZ })
    public static void regexMatch(String pattern, String input) {
    // compiling user pattern can be expensive/unsafe
    Pattern p = Pattern.compile(pattern);
    boolean m = p.matcher(input).matches();
    if (!m && input.length() > 1000000) {
        throw new RuntimeException("too-large input");
    }
    }

    // ---------------------------
    // Format string / vulnerable formatting
    // ---------------------------
    @Case("(\"Name: %s\", \"Alice\") -> ok")
    @Case("(\"%s %s %s\", \"onlyOneArg\") -> MissingFormatArgumentException")
    // @Tag({ FORMAT })
    @Tag({ FUZZ })
    public static void userFormat(String fmt, String param) {
    // uses a single param but format may expect more -> exception
    String out = String.format(fmt, param);
    if (out.length() == 0) {
        throw new RuntimeException("empty formatted string");
    }
    }

    // ---------------------------
    // Parsing / NumberFormatException
    // ---------------------------
    @Case("(\"123\") -> ok")
    @Case("(\"   123  \") -> ok (trim allowed)")
    @Case("(\"12abc\") -> NumberFormatException")
    // @Tag({ PARSE })
    @Tag({ FUZZ })
    public static void parseInteger(String s) throws ParseException {
    try {
        int v = Integer.parseInt(s.trim());
        if (v == 0) throw new ParseException("zero not allowed", 0);
    } catch (NumberFormatException e) {
        // rethrow as unchecked to let fuzzers catch it
        throw e;
    }
    }

    // ---------------------------
    // SQL-like string concat (simulated injection)
    // ---------------------------
    @Case("(\"alice\") -> ok")
    @Case("(\"alice';-- \") -> malformed / injection-like input")
    // @Tag({ SQL })
    @Tag({ FUZZ })
    public static void buildSql(String username) {
    // simulate unsafe concatenation (DO NOT execute)
    String sql = "SELECT * FROM users WHERE name = '" + username + "';";
    // very naive detection of dangerous characters
    if (username.contains("'") || username.contains(";") || username.contains("--")) {
        throw new IllegalArgumentException("dangerous characters in username");
    }
    // pretend to use the sql string
    if (sql.length() < 10) throw new AssertionError("sql too short");
    }

    // ---------------------------
    // Simple concurrency race (non-atomic)
    // ---------------------------
    @Case("(100) -> race/incorrect counts possible")
    @Case("(0) -> no-op")
    // @Tag({ CONCURRENCY })
    @Tag({ FUZZ })
    public static void raceIncrement(int n) throws InterruptedException {
    // shared mutable state without synchronization -> race conditions
    final Holder h = new Holder();
    Thread t1 = new Thread(() -> {
        for (int i = 0; i < n; i++) h.x++;
    });
    Thread t2 = new Thread(() -> {
        for (int i = 0; i < n; i++) h.x++;
    });
    t1.start();
    t2.start();
    t1.join();
    t2.join();
    // expected 2*n but race may produce less; assertion can fail under fuzzing
    assert h.x == 2 * n;
    }

    private static class Holder {
    public int x = 0;
    }

    // ---------------------------
    // Resource exhaustion (open handles, large allocation)
    // ---------------------------
    @Case("(10) -> ok")
    @Case("(100000000) -> OutOfMemoryError or long GC pause")
    // @Tag({ RESOURCE })
    @Tag({ FUZZ })
    public static void allocateN(int n) {
    // attempt to allocate array of size n (dangerous if n is huge)
    int[] arr = new int[n];
    // touch it to force allocation
    arr[0] = 1;
    if (arr.length != n) throw new AssertionError("weird length");
    }

}


public class TrickyMinimalOpcodes {
    // Tags:
    // CONDITIONAL, LOOP, INTEGER_OVERFLOW, CALL, ARRAY, RECURSION, STDLIB, FUZZ


    // -------------------------
    // 1) simple loop + iinc (incr) + if_icmp*
    //    - uses: push, load, store, iinc, if_icmpge, goto, return
    // -------------------------
    @Case("(5) -> ok")
    @Case("(0) -> ok")
    //   @Tag({ LOOP })
    @Tag({ FUZZ })
    public static int sumUpTo(int n) {
    // returns sum of 1..n using a simple loop (iinc emitted for i++)
    int i = 1;
    int s = 0;
    while (i <= n) { // compiles to if_icmpgt / if_icmple style comparisons
        s = s + i;     // iadd
        i++;           // iinc
    }
    return s;        // ireturn
    }

    // -------------------------
    // 2) divide and remainder edge cases (ArithmeticException from idiv/irem)
    //    - uses: idiv, irem, ifz/ifne checks optionally
    // -------------------------
    @Case("(10, 2) -> ok")
    @Case("(10, 0) -> ArithmeticException (idiv)")
    // @Tag({ MATH })
    @Tag({ FUZZ })
    public static int divAndRem(int a, int b) {
    // integer division and remainder: will throw on b==0 (via idiv/irem)
    int q = a / b;
    int r = a % b;
    return q + r;
    }

    // -------------------------
    // 3) assertion pattern -> emits getstatic $assertionsDisabled and conditional
    //    - uses: getstatic, ifeq/ifne, goto (from javac generated assert)
    // -------------------------
    @Case("(1) -> ok")
    @Case("(0) -> assertion error")
    // @Tag({ ASSERT })
    @Tag({ FUZZ })
    public static void positiveAssert(int x) {
    // Java 'assert' emits getstatic for assertionsDisabled and conditional branches
    assert x > 0;
    }

    // -------------------------
    // 4) null dereference by invokevirtual (String.length) -> NPE when null
    //    - uses: aconst_null (for test cases), invokevirtual (allowed)
    // -------------------------
    @Case("(\"hello\") -> ok")
    @Case("(null) -> NullPointerException")
    // @Tag({ NULL })
    @Tag({ FUZZ })
    public static int stringLenThenFirstChar(String s) {
    // calling s.length() compiles to invokevirtual; on null it raises NPE
    int len = s.length();
    // charAt would be another invokevirtual, but char handling still uses ints
    return len;
    }

    // -------------------------
    // 5) explicit throw constructed from new/dup/invokespecial + athrow
    //    - uses: new, dup, invokespecial, athrow
    // -------------------------
    @Case("(true) -> IllegalArgumentException thrown")
    @Case("(false) -> return 0")
    // @Tag({ THROW })
    @Tag({ FUZZ })
    public static int conditionalThrow(boolean fail) {
    if (fail) {
        // construct and throw an exception using allowed opcodes
        IllegalArgumentException ex = new IllegalArgumentException("boom");
        throw ex; // athrow
    }
    return 0;
    }

    // -------------------------
    // 6) array creation, store/load, and arraylength
    //    - uses: newarray, arraystore, arrayload, arraylength
    // -------------------------
    @Case("(3) -> ok")
    @Case("(0) -> ok (zero-length array)")
    // @Tag({ IO, ARRAY })
    @Tag({ FUZZ })
    public static int createAndFill(int n) {
    // create an int array of length n, fill with i, then sum via loop
    int[] a = new int[n]; // newarray
    int i = 0;
    while (i < n) {       // if_icmpge / goto pattern
        a[i] = i;           // iastore
        i++;                // iinc
    }
    int len = a.length;   // arraylength
    int s = 0;
    i = 0;
    while (i < len) {     // loop using if_icmpge/goto
        s = s + a[i];       // iaload + iadd
        i++;
    }
    return s;
    }

    // -------------------------
    // 7) overflow-prone multiply (no special opcodes beyond imul)
    //    - uses: imul, ifz, if_icmp* to detect negative due to overflow
    // -------------------------
    @Case("(2, 1000000000) -> ok")
    @Case("(2, 2000000000) -> may overflow -> negative result possible")
    // @Tag({ OVERFLOW })
    @Tag({ FUZZ })
    public static int naiveMul(int x, int y) {
    int r = x * y;     // imul
    // detect surprising negative product (simple check using iflt)
    if (r < 0) {
        // return a sentinel negative to indicate overflow observed
        return -1;
    }
    return r;
    }

    // -------------------------
    // 8) swap/pop/dup usage (stack shuffles) via small helper that returns pair-sum
    //    - uses: dup, swap, pop (the compiler will emit dup for certain patterns)
    // -------------------------
    @Case("(4, 5) -> 9")
    // @Tag({ STACK })
    @Tag({ FUZZ })
    public static int dupAndSum(int a, int b) {
    // trivial use that will compile to straightforward loads and an iadd;
    // clever use of dup/swap is often produced by some bytecode patterns when
    // constructing objects or doing compound expressions. Here we keep it simple.
    return a + b;
    }

    // -------------------------
    // 9) casting to int (cast) — allow e.g., long->int; but we avoid long locals.
    //    Use explicit (int) on an Object-returning method to force a checkcast then int cast.
    //    However, since you limited to cast(to int) we include a small wrapper that
    //    calls a method that returns Integer then unboxes -> will produce intValue (invokevirtual)
    //    This keeps within allowed invokes.
    // -------------------------
    @Case("(\"42\") -> 42")
    @Case("(\"notnum\") -> NumberFormatException")
    // @Tag({ PARSE })
    @Tag({ FUZZ })
    public static int parseAndUnbox(String s) {
    // invoke static Integer.parseInt (invokestatic allowed) -> returns int directly
    int v = Integer.parseInt(s); // invokespecial? actually invokestatic on Integer
    return v;
    }

    // -------------------------
    // 10) small example that uses rem (irem) and goto for a simple check
    // -------------------------
    @Case("(10) -> ok (even)")
    @Case("(11) -> ok (odd)")
    // s@Tag({ MATH })
    @Tag({ FUZZ })
    public static int evenOddMarker(int n) {
    if (n % 2 == 0) {
        return 0;
    }
    return 1;
    }
}

