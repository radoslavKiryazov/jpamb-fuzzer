package jpamb.cases;

import jpamb.utils.*;
import static jpamb.utils.Tag.TagType.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.regex.Pattern;

// /**
//  * TrickyFuzz - collection of small methods designed to produce
//  * subtle failures for fuzzers. Follow the same annotation style
//  * as your example.
//  */
// public class TrickyFuzz {
//     // Tag:
//     // OVERFLOW, MATH, NULL, IO, PATH, REGEX, FORMAT, PARSE, SQL, CONCURRENCY, RESOURCE, FUZZ

//     // ---------------------------
//     // Integer overflow / underflow
//     // ---------------------------
//     @Case("(2, 1000000000) -> ok")
//     @Case("(2, 2000000000) -> overflow -> negative or assertion")
//     // @Tag({ OVERFLOW })
//     @Tag({ FUZZ })
//     public static void multiplyAndCheck(int a, int b) {
//     // naive multiply that can overflow
//     long prod = (long) a * (long) b;
//     // sanity assertion expecting product fits in int (will fail on overflow)
//     assert prod <= Integer.MAX_VALUE && prod >= Integer.MIN_VALUE;
//     int result = (int) prod; // truncation on overflow
//     // use result to prevent optimization-out
//     if (result == 0 && a != 0 && b != 0) {
//         throw new AssertionError("unexpected zero after multiply");
//     }
//     }

//     // ---------------------------
//     // Division / divide-by-zero
//     // ---------------------------
//     @Case("(10, 2) -> ok")
//     @Case("(10, 0) -> ArithmeticException")
//     // @Tag({ MATH })
//     @Tag({ FUZZ })
//     public static void safeDivide(int numerator, int denominator) {
//     assert denominator != 0;
//     int q = numerator / denominator; // potential ArithmeticException
//     if (q < 0) {
//         // arbitrary use
//         throw new RuntimeException("negative quotient");
//     }
//     }

//     // ---------------------------
//     // Null dereference
//     // ---------------------------
//     @Case("(\"hello\") -> ok")
//     @Case("(null) -> NullPointerException")
//     // @Tag({ NULL })
//     @Tag({ FUZZ })
//     public static void lengthThenChar(String s) {
//     // deliberate null deref if fuzzed
//     int len = s.length();        // NPE if s == null
//     char c = s.charAt(len - 1);  // IndexOutOfBounds if empty
//     // small side-effect to keep result relevant
//     if (c == '\u0000') {
//         throw new AssertionError("unexpected null char");
//     }
//     }

//     // ---------------------------
//     // Path traversal / canonicalization
//     // ---------------------------
//     @Case("(\"/safe/dir\", \"file.txt\") -> ok")
//     @Case("(\"/safe/dir\", \"../secret.txt\") -> path traversal")
//     // @Tag({ IO, PATH })
//     @Tag({ FUZZ })
//     public static void checkPath(String baseDir, String userPath) throws IOException {
//     File base = new File(baseDir);
//     File target = new File(base, userPath);
//     String baseCanonical = base.getCanonicalPath();
//     String targetCanonical = target.getCanonicalPath();
//     // ensure target is inside base
//     assert targetCanonical.startsWith(baseCanonical + File.separator);
//     }

//     // ---------------------------
//     // Regular-expression catastrophic backtracking (ReDoS)
//     // ---------------------------
//     @Case("(\"(a+)+$\") , (\"a\") -> ok")
//     @Case("(\"(a+)+$\") , (\"a{10000}\") -> potential hang / catastrophic backtracking")
//     // @Tag({ REGEX, RESOURCE })
//     @Tag({ FUZZ })
//     public static void regexMatch(String pattern, String input) {
//     // compiling user pattern can be expensive/unsafe
//     Pattern p = Pattern.compile(pattern);
//     boolean m = p.matcher(input).matches();
//     if (!m && input.length() > 1000000) {
//         throw new RuntimeException("too-large input");
//     }
//     }

//     // ---------------------------
//     // Format string / vulnerable formatting
//     // ---------------------------
//     @Case("(\"Name: %s\", \"Alice\") -> ok")
//     @Case("(\"%s %s %s\", \"onlyOneArg\") -> MissingFormatArgumentException")
//     // @Tag({ FORMAT })
//     @Tag({ FUZZ })
//     public static void userFormat(String fmt, String param) {
//     // uses a single param but format may expect more -> exception
//     String out = String.format(fmt, param);
//     if (out.length() == 0) {
//         throw new RuntimeException("empty formatted string");
//     }
//     }

//     // ---------------------------
//     // Parsing / NumberFormatException
//     // ---------------------------
//     @Case("(\"123\") -> ok")
//     @Case("(\"   123  \") -> ok (trim allowed)")
//     @Case("(\"12abc\") -> NumberFormatException")
//     // @Tag({ PARSE })
//     @Tag({ FUZZ })
//     public static void parseInteger(String s) throws ParseException {
//     try {
//         int v = Integer.parseInt(s.trim());
//         if (v == 0) throw new ParseException("zero not allowed", 0);
//     } catch (NumberFormatException e) {
//         // rethrow as unchecked to let fuzzers catch it
//         throw e;
//     }
//     }

//     // ---------------------------
//     // SQL-like string concat (simulated injection)
//     // ---------------------------
//     @Case("(\"alice\") -> ok")
//     @Case("(\"alice';-- \") -> malformed / injection-like input")
//     // @Tag({ SQL })
//     @Tag({ FUZZ })
//     public static void buildSql(String username) {
//     // simulate unsafe concatenation (DO NOT execute)
//     String sql = "SELECT * FROM users WHERE name = '" + username + "';";
//     // very naive detection of dangerous characters
//     if (username.contains("'") || username.contains(";") || username.contains("--")) {
//         throw new IllegalArgumentException("dangerous characters in username");
//     }
//     // pretend to use the sql string
//     if (sql.length() < 10) throw new AssertionError("sql too short");
//     }

//     // ---------------------------
//     // Simple concurrency race (non-atomic)
//     // ---------------------------
//     @Case("(100) -> race/incorrect counts possible")
//     @Case("(0) -> no-op")
//     // @Tag({ CONCURRENCY })
//     @Tag({ FUZZ })
//     public static void raceIncrement(int n) throws InterruptedException {
//     // shared mutable state without synchronization -> race conditions
//     final Holder h = new Holder();
//     Thread t1 = new Thread(() -> {
//         for (int i = 0; i < n; i++) h.x++;
//     });
//     Thread t2 = new Thread(() -> {
//         for (int i = 0; i < n; i++) h.x++;
//     });
//     t1.start();
//     t2.start();
//     t1.join();
//     t2.join();
//     // expected 2*n but race may produce less; assertion can fail under fuzzing
//     assert h.x == 2 * n;
//     }

//     private static class Holder {
//     public int x = 0;
//     }

//     // ---------------------------
//     // Resource exhaustion (open handles, large allocation)
//     // ---------------------------
//     @Case("(10) -> ok")
//     @Case("(100000000) -> OutOfMemoryError or long GC pause")
//     // @Tag({ RESOURCE })
//     @Tag({ FUZZ })
//     public static void allocateN(int n) {
//     // attempt to allocate array of size n (dangerous if n is huge)
//     int[] arr = new int[n];
//     // touch it to force allocation
//     arr[0] = 1;
//     if (arr.length != n) throw new AssertionError("weird length");
//     }

// }

public class TrickyMinimalOpcodes {

    @Case("(5) -> ok")
    @Case("(0) -> ok")
    @Tag({ FUZZ })
    public static int sumUpTo(int n) {
        int i = 1, s = 0;
        while (i <= n) {
            s += i;
            i++;
        }
        return s;
    }

    @Case("(10, 2) -> ok")
    @Case("(10, 0) -> ArithmeticException")
    @Tag({ FUZZ })
    public static int divAndRem(int a, int b) {
        int q = a / b;
        int r = a % b;
        return q + r;
    }

    @Case("(1) -> ok")
    @Case("(0) -> assertion error")
    @Tag({ FUZZ })
    public static void positiveAssert(int x) {
        assert x > 0;
    }

    @Case("(true) -> IllegalArgumentException")
    @Case("(false) -> ok")
    @Tag({ FUZZ })
    public static int conditionalThrow(boolean fail) {
        if (fail)
            throw new IllegalArgumentException();
        return 0;
    }

    @Case("(3) -> ok")
    @Case("(0) -> ok")
    @Tag({ FUZZ })
    public static int createAndFill(int n) {
        int[] a = new int[n];
        for (int i = 0; i < n; i++)
            a[i] = i;
        int s = 0;
        for (int x : a)
            s += x;
        return s;
    }

    @Case("(2, 1000000000) -> ok")
    @Case("(2, 2000000000) -> -1")
    @Tag({ FUZZ })
    public static int naiveMul(int x, int y) {
        int r = x * y;
        if (r < 0)
            return -1;
        return r;
    }

    @Case("(4, 5) -> ok")
    @Tag({ FUZZ })
    public static int dupAndSum(int a, int b) {
        return a + b;
    }

    @Case("(10) -> true")
    @Case("(11) -> false")
    @Tag({ FUZZ })
    public static int evenOddMarker(int n) {
        return (n % 2 == 0) ? 0 : 1;
    }
}
