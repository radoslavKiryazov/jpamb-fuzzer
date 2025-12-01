import click
from pathlib import Path
import shlex
import enum
import math
import sys
import json
from inspect import getsourcelines, getsourcefile
from collections import Counter
import matplotlib.pyplot as plt
import matplotlib.colors as colors
import os
import time

from jpamb import model, logger, jvm
from jpamb.logger import log

from jpamb.jfuzzer.fuzzcore import CaseGenerator
from jpamb.jfuzzer.report_preprocess.parser import Parser
from jpamb.jfuzzer.result_analysis.analyzer import analyzer
from jpamb.jfuzzer.util.oracle import Oracle

import subprocess
import dataclasses
from contextlib import contextmanager
from typing import IO


class JpambScore:
    score: float
    time: float
    rel_time: float

    def __init__(self, score, time, rel_time):
        self.score = score
        self.time = time
        self.rel_time = rel_time


def re_parser(ctx_, parms_, expr):
    import re

    if expr:
        return re.compile(expr)


def run(cmd: list[str], /, timeout=2.0, logout=None, logerr=None, **kwargs):
    import threading
    from time import monotonic, perf_counter_ns

    if not logerr:
        def logerr(a):
            pass

    if not logout:
        def logout(a):
            pass

    cp = None
    stdout = []
    stderr = []
    tout = None
    try:
        start = monotonic()
        start_ns = perf_counter_ns()

        if timeout:
            end = start + timeout
        else:
            end = None

        cp = subprocess.Popen(
            cmd,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            **kwargs,
        )
        assert cp and cp.stdout and cp.stderr

        def log_lines(cp):
            assert cp.stderr
            with cp.stderr:
                for line in iter(cp.stderr.readline, ""):
                    stderr.append(line)
                    logerr(line[:-1])

        def save_result(cp):
            assert cp.stdout
            with cp.stdout:
                for line in iter(cp.stdout.readline, ""):
                    stdout.append(line)
                    logout(line[:-1])

        terr = threading.Thread(
            target=log_lines,
            args=(cp,),
            daemon=True,
        )
        terr.start()
        tout = threading.Thread(
            target=save_result,
            args=(cp,),
            daemon=True,
        )
        tout.start()

        terr.join(end and end - monotonic())
        tout.join(end and end - monotonic())
        exitcode = cp.wait(end and end - monotonic())
        end_ns = perf_counter_ns()

        if exitcode != 0:
            raise subprocess.CalledProcessError(
                cmd=cmd,
                returncode=exitcode,
                stderr="".join(stderr),
                output="".join(stdout),
            )

        return ("".join(stdout), end_ns - start_ns)
    except subprocess.CalledProcessError as e:
        if tout:
            tout.join()
        e.stderr = "".join(stderr)
        e.stdout = "".join(stdout)
        raise e
    except subprocess.TimeoutExpired:
        if cp:
            cp.terminate()
            if cp.stdout:
                cp.stdout.close()
            if cp.stderr:
                cp.stderr.close()
        raise


def saver(item, round_num, case, result, filename="data_log.csv"):
    """
    Saves the provided parameters as a new, comma-separated line to a local file.

    Args:
        item: The first data item (e.g., test name).
        round_num: The round number (using 'round_num' to avoid conflict with the built-in 'round').
        case: The specific case/condition.
        result: The outcome or result.
        filename (str): The name of the local file to save the data to.
    """
    data_line = f"{item},{round_num},{case},{result}\n"

    try:
        with open(filename, "a") as file:
            file.write(data_line)

        print(f"Data saved successfully to {os.path.abspath(filename)}")
    except IOError as e:
        print(f"An error occurred while writing to the file: {e}")


@dataclasses.dataclass
class Reporter:
    report: IO
    prefix: str = ""

    @contextmanager
    def context(self, title):
        old = self.prefix
        print(f"{self.prefix[:-1]}┌ {title}", file=self.report)
        self.prefix = f"{self.prefix[:-1]}│ "
        try:
            yield
        finally:
            self.prefix = old
            print(f"{self.prefix[:-1]}└ {title}", file=self.report)

    def output(self, msgs):
        if not isinstance(msgs, str):
            msgs = str(msgs)

        for msg in msgs.splitlines():
            print(f"{self.prefix}{msg}", file=self.report)

    def run(self, args, **kwargs):
        with self.context(f"Run {shlex.join(args)}"):
            with self.context("Stderr"):
                out, time = run(args, logerr=self.output, **kwargs)
            with self.context("Stdout"):
                self.output(out)
            return out


def resolve_cmd(program, with_python=None):
    if with_python is None:
        if str(program[0]).lower().endswith(".py"):
            log.warning(
                "Automatically prepending the current python interpreter to the command. To disable this warning add the '--with-python' flag or prepend intented python interpreter to the command."
            )
            with_python = True
        else:
            with_python = False

    if with_python:
        try:
            executable = str(Path(sys.executable).relative_to(Path.cwd()))
        except ValueError:
            log.warning(
                "Python executable outside of current directory, might be a misconfiguration. "
                "Run the tool with `uv run jpamb ...`."
            )
            executable = sys.executable

        program = (executable,) + program

    return program


@click.group()
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="sets the verbosity of the program, more means more information",
)
@click.option(
    "--workdir",
    type=click.Path(
        exists=True,
        file_okay=False,
        path_type=Path,
        resolve_path=True,
    ),
    default=".",
    help="the base of the jpamb folder.",
)
@click.pass_context
def cli(ctx, workdir: Path, verbose):
    """This is the jpamb main entry point."""
    logger.initialize(verbose)
    log.debug(f"Setup suite in {workdir}")
    ctx.obj = model.Suite(workdir)


@cli.command()
@click.pass_obj
def checkhealth(suite):
    """Check that the repostiory is setup correctly"""
    suite.checkhealth()


@cli.command()
@click.option(
    "--with-python/--no-with-python",
    "-W/-noW",
    help="the analysis is a python script, which should run in the same interpreter as jpamb.",
    default=None,
)
@click.option(
    "--fail-fast/--no-fail-fast",
    help="if we should stop after the first error.",
)
@click.option(
    "--timeout",
    show_default=True,
    default=2.0,
    help="timeout in seconds.",
)
@click.option(
    "--filter",
    "-f",
    help="A regular expression which filter the methods to run on.",
    callback=re_parser,
)
@click.option(
    "--report",
    "-r",
    default="-",
    type=click.File(mode="w"),
    help="A file to write the report to. (Good for golden testing)",
)
@click.argument("PROGRAM", nargs=-1)
@click.pass_obj
def test(suite, program, report, filter, fail_fast, with_python, timeout):
    """Test run a PROGRAM."""

    program = resolve_cmd(program, with_python)

    r = Reporter(report)

    if not filter:
        with r.context("Info"):
            out = r.run(program + ("info",), timeout=timeout)
            info = model.AnalysisInfo.parse(out)

            with r.context("Results"):
                for k, v in sorted(dataclasses.asdict(info).items()):
                    r.output(f"- {k}: {v}")

    total = 0
    for methodid, correct in suite.case_methods():
        if filter and not filter.search(str(methodid)):
            continue

        with r.context(f"Case {methodid}"):
            out = r.run(program + (str(methodid),), timeout=timeout)
            response = model.Response.parse(out)
            with r.context("Results"):
                for k, v in sorted(response.predictions.items()):
                    r.output(f"- {k}: {v} {v.wager:0.2f}")
            score = response.score(correct)
            r.output(f"Score {score:0.2f}")
            total += score

    r.output(f"Total {total:0.2f}")


@cli.command()
@click.option(
    "--with-python/--no-with-python",
    "-W/-noW",
    help="the analysis is a python script, which should run in the same interpreter as jpamb.",
    default=None,
)
@click.option(
    "--stepwise / --no-stepwise",
    help="continue from last failure",
)
@click.option(
    "--timeout",
    show_default=True,
    default=2.0,
    help="timeout in seconds.",
)
@click.option(
    "--filter",
    "-f",
    help="A regular expression which filter the methods to run on.",
    callback=re_parser,
)
@click.option(
    "--report",
    "-r",
    default="-",
    type=click.File(mode="w"),
    help="A file to write the report to. (Good for golden testing)",
)
@click.argument("PROGRAM", nargs=-1)
@click.pass_obj
def interpret(suite, program, report, filter, with_python, timeout, stepwise):
    """Use PROGRAM as an interpreter."""

    r = Reporter(report)
    program = resolve_cmd(program, with_python)
    print(f"PROGRAM", program)

    last_case = None
    if stepwise:
        try:
            with open(".jpamb-stepwise") as f:
                last_case = model.Case.decode(f.read())
        except ValueError as e:
            log.warning(e)
            last_case = None
        except IOError:
            last_case = None

    total = 0
    count = 0
    for case in suite.cases:
        if last_case and last_case != case:
            continue
        last_case = None

        if filter and not filter.search(str(case)):
            continue

        with r.context(f"Case {case}"):
            try:
                out = r.run(
                    program + (case.methodid.encode(), case.input.encode()),
                    timeout=timeout,
                )
                ret = out.splitlines()[-1].strip()
            except subprocess.TimeoutExpired:
                ret = "*"
            except subprocess.CalledProcessError as e:
                log.error(e)
                ret = "failure"
            r.output(f"Expected {case.result!r} and got {ret!r}")
            if case.result == ret:
                total += 1
            elif stepwise:
                with open(".jpamb-stepwise", "w") as f:
                    f.write(case.encode())
                sys.exit(-1)
            count += 1

    Path(".jpamb-stepwise").unlink(True)

    r.output(f"Total {total}/{count}")


@cli.command()
@click.pass_context
@click.option(
    "--with-python/--no-with-python",
    "-W/-noW",
    help="the analysis is a python script, which should run in the same interpreter as jpamb.",
    default=None,
)
@click.option(
    "--iterations",
    "-N",
    show_default=True,
    default=3,
    help="number of iterations.",
)
@click.option(
    "--timeout",
    show_default=True,
    default=2.0,
    help="timeout in seconds.",
)
@click.option(
    "--report",
    "-r",
    default="-",
    type=click.File(mode="w"),
    help="A file to write the report to",
)
@click.argument("PROGRAM", nargs=-1)
def evaluate(ctx, program, report, timeout, iterations, with_python):
    """Evaluate the PROGRAM."""
    """Gernate final evaluation report."""

    program = resolve_cmd(program, with_python)

    def calibrate(count=100_000):
        from time import perf_counter_ns
        from jpamb import timer

        start = perf_counter_ns()
        timer.sieve(count)
        end = perf_counter_ns()
        return end - start

    try:
        (out, _) = run(
            program + ("info",),
            logout=log.info,
            logerr=log.debug,
            timeout=timeout,
        )
        info = model.AnalysisInfo.parse(out)
    except ValueError:
        log.error("Expected info, but got:")
        for o in out.splitlines():
            log.error(o)

    total_score = 0
    total_time = 0
    total_relative = 0
    total_methods = 0
    bymethod = {}

    for methodid, correct in ctx.obj.case_methods():
        log.success(f"Running on {methodid}")
        results = []

        _score = 0
        _time = 0
        _relative = 0
        for i in range(iterations):
            log.info(f"Running on {methodid}, iter {i}")
            r1 = calibrate()
            out, time_ns = run(
                program + (methodid.encode(),), logerr=log.debug, timeout=timeout
            )
            r2 = calibrate()
            response = model.Response.parse(out)
            score = response.score(correct)
            relative = math.log10(time_ns / (r1 + r2) * 2)

            result = {k: v.wager for k, v in response.predictions.items()}

            results.append(
                {
                    "iteration": i,
                    "response": result,
                    "score": score,
                    "time": time_ns,
                    "relative": relative,
                    "calibrates": [r1, r2],
                }
            )

            _score += score
            _relative += relative
            _time += time_ns

        bymethod[str(methodid)] = {
            "score": _score / iterations,
            "time": _time / iterations,
            "relative": _relative / iterations,
            "iterations": results,
        }

        total_score += _score / iterations
        total_time += _time / iterations
        total_relative += _relative / iterations

        total_methods += 1

    json.dump(
        {
            "info": dataclasses.asdict(info),
            "bymethod": bymethod,
            "score": total_score,
            "time": total_time / total_methods,
            "relative": total_relative / total_methods,
        },
        report,
        indent=2,
    )


@cli.command()
@click.option(
    "--compile / --no-compile",
    help="compile the java source files.",
)
@click.option(
    "--decompile / --no-decompile",
    help="decompile the classfiles using jvm2json.",
)
@click.option(
    "--document / --no-document",
    help="decompile the classfiles using jvm2json.",
)
@click.option(
    "--test / --no-test",
    help="test that all cases are correct.",
)
@click.pass_obj
def build(suite, compile, decompile, document, test):
    """Rebuild all benchmarks."""

    if compile:
        run(
            ["mvn", "compile"],
            logerr=log.warning,
            logout=log.info,
            timeout=600,
        )

    if decompile:
        log.info("Decompiling")
        for cl in suite.classes():
            log.info(f"Decompiling {cl}")
            res, t = run(
                [
                    "jvm2json",
                    "-s",
                    suite.classfile(cl),
                ],
                logerr=log.warning,
            )
            with open(suite.decompiledfile(cl), "w") as f:
                json.dump(json.loads(res), f, indent=2, sort_keys=True)
        log.success("Done decompiling")

    if document:
        opcode_counts = Counter()
        opcode_urls = {}
        class_opcodes = {}
        for case in suite.cases:
            class_opcodes[str(case.methodid.classname).split(".")[-1]] = set()
            list_ops = []
            for opcode in suite.method_opcodes(case.methodid):
                index = opcode.mnemonic()
                list_ops.append(index)

                opcode_urls[index] = (
                    opcode.mnemonic(),
                    opcode.url(),
                    opcode,
                )

                opcode_counts[index] += 1

            for o in list_ops:
                class_opcodes[str(case.methodid.classname).split(".")[-1]].add(o)

        with open("OPCODES.md", "w") as document:
            document.write("#Bytecode instructions\n")
            document.write("| Mnemonic | Opcode Name |  Exists in |  Count |\n")
            document.write("| :---- | :---- | :----- | -----: |\n")

            for op, count in opcode_counts.most_common():
                (mnemonic, url, opcode) = opcode_urls[op]
                in_classes = ""

                for classname in class_opcodes:
                    if op in class_opcodes[classname]:
                        in_classes += " " + classname

                rel = Path(getsourcefile(opcode.__class__)).relative_to(Path.cwd())
                giturl = f"{rel}?plain=1#L{getsourcelines(opcode.__class__)[1]}"

                document.write(
                    " | ["
                    + mnemonic
                    + "]("
                    + url
                    + ") | "
                    + f"[{opcode.__class__.__name__}]({giturl})"
                    + " | "
                    + in_classes
                    + " | "
                    + str(count)
                    + " |\n"
                )

    if test:
        log.info("Testing")

        for case in suite.cases:
            log.info(f"Testing {case}")

            folder = suite.classfiles_folder

            try:
                res, x = run(
                    [
                        "java",
                        "-cp",
                        folder,
                        "-ea",
                        "jpamb.Runtime",
                        case.methodid.encode(),
                        case.input.encode(),
                    ],
                    logout=log.info,
                    logerr=log.debug,
                    timeout=2,
                )
            except subprocess.TimeoutExpired:
                res = "*"

            if case.result == res.strip():
                log.success(f"Correct {case}")
            else:
                log.error(f"Incorrect (got {res.strip()}) expected {case}")

        log.success("Done testing")


@cli.command()
@click.option(
    "--format",
    type=click.Choice(["pretty", "real", "repr", "json"], case_sensitive=True),
    default="pretty",
    help="The format to print the instruction in.",
)
@click.argument("METHOD")
@click.pass_obj
def inspect(suite, method, format):
    method = jvm.AbsMethodID.decode(method)
    for i, res in enumerate(suite.findmethod(method)["code"]["bytecode"]):
        op = jvm.Opcode.from_json(res)
        match format:
            case "pretty":
                res = str(op)
            case "real":
                res = op.real()
            case "repr":
                res = repr(op)
            case "json":
                res = json.dumps(res)
        print(f"{i:03d} | {res}")


@cli.command()
@click.pass_context
@click.option(
    "--directory",
    "-d",
    help="Specifying a directory will create a comparative plot of all reports in the directory",
    type=click.Path(exists=True, file_okay=False, readable=True, path_type=Path),
)
@click.option(
    "--report",
    "-r",
    help="Specifying the path to a report.json file will plot the scores of the report",
    type=click.Path(
        exists=True,
        file_okay=True,
        readable=True,
        path_type=Path,
    ),
)
def plot(ctx, report, directory):
    """Plot results of a report or compare reports in a directory"""
    import numpy as np

    prefix = ""

    @contextmanager
    def context(title):
        nonlocal prefix
        old = prefix
        print(f"{prefix[:-1]}┌ {title}", file=report)
        prefix = f"{prefix[:-1]}│ "
        yield
        prefix = old
        print(f"{prefix[:-1]}└ {title}", file=report)

    def parse_report(report):
        import json

        with open(report, "r") as data:
            try:
                report = json.loads(data.read())

                info = report["info"]
                methods = report["bymethod"]
                total_value = JpambScore(
                    max(report["score"], -100), report["time"], report["relative"]
                )
                method_values = {}

                for methodid, correct in ctx.obj.case_methods():
                    method = methods[str(methodid)]
                    method_values[str(methodid)] = JpambScore(
                        max(method["score"], -100), method["time"], method["relative"]
                    )

                return info, method_values, total_value

            except ValueError:
                raise ValueError(f"Cannot read {report}")

    def compare_reports(directory):
        import os

        scores = []
        times = []
        labels = []

        for report in os.listdir(directory):
            if report.endswith(".json"):
                try:
                    rep_info, _, rep_scores = parse_report(directory.joinpath(report))
                    scores.append(rep_scores.score)
                    times.append(rep_scores.rel_time)
                    labels.append(rep_info["name"] + ": " + ", ".join(rep_info["tags"]))
                except ValueError:
                    print(f"Failed to process {report}")

        return scores, times, labels

    def get_plotcolor(problemclass):
        if "Simple" in problemclass:
            return "seagreen"
        if "Calls" in problemclass:
            return "turquoise"
        if "Loops" in problemclass:
            return "mediumslateblue"
        if "Arrays" in problemclass:
            return "violet"
        if "Tricky" in problemclass:
            return "darkviolet"

        return "red"

    def plot_scores(scores, times, labels, classes):
        import numpy as np
        import matplotlib.patches as mpatches

        class MidpointNormalize(colors.Normalize):
            def __init__(self, vmin=None, vmax=None, midpoint=None, clip=True):
                self.midpoint = midpoint
                colors.Normalize.__init__(self, vmin, vmax, clip)

            def __call__(self, value, clip=None):
                x, y = [self.vmin, self.midpoint, self.vmax], [0, 0.5, 1]
                return np.ma.masked_array(np.interp(value, x, y), np.isnan(value))

        simplec = mpatches.Patch(color=get_plotcolor("Simple"), label="Simple")
        arraysc = mpatches.Patch(color=get_plotcolor("Arrays"), label="Arrays")
        callsc = mpatches.Patch(color=get_plotcolor("Calls"), label="Calls")
        loopsc = mpatches.Patch(color=get_plotcolor("Loops"), label="Loops")
        trickyc = mpatches.Patch(color=get_plotcolor("Tricky"), label="Tricky")

        plt.title("JPAMB Test Scores", pad=15.0)
        plt.legend(handles=[simplec, arraysc, callsc, loopsc, trickyc])

        plt.xticks([])
        plt.yticks([])

        plot_times = np.array(times)
        plot_scores = np.array(scores)

        barcolors = [
            get_plotcolor(pc) if score > -100 else "red"
            for (pc, score) in zip(classes, plot_scores)
        ]

        plt.subplot(2, 1, 1)
        plt.bar(labels, plot_scores, color=barcolors, label=classes)
        plt.ylabel("Test Score")
        plt.xticks([])

        max_y = abs(plot_scores).max() * 1.05
        plt.ylim(-max_y, max_y)

        plt.subplot(2, 1, 2)
        plt.bar(labels, plot_times, color=barcolors, label=classes)
        plt.ylabel("Test Time")

        plt.xticks(rotation=80)
        max_y = abs(plot_times).max() * 1.05
        plt.ylim(0, max_y)

        plt.show()

    def plot_directory(scores, times, labels):
        class MidpointNormalize(colors.Normalize):
            def __init__(self, vmin=None, vmax=None, midpoint=None, clip=True):
                self.midpoint = midpoint
                colors.Normalize.__init__(self, vmin, vmax, clip)

            def __call__(self, value, clip=None):
                x, y = [self.vmin, self.midpoint, self.vmax], [0, 0.5, 1]
                return np.ma.masked_array(np.interp(value, x, y), np.isnan(value))

        plot_times = np.array(times)
        plot_norm_times = (plot_times - plot_times.min()) / (
            plot_times.max() - plot_times.min()
        )
        plot_scores = np.array(scores)

        performance_score = 100 * plot_scores * (1 - (plot_norm_times * 0.5))
        performance_score = [max(100, score) for score in performance_score]

        plt.scatter(
            x=plot_scores,
            y=plot_times,
            s=performance_score,
            c=plot_scores,
            cmap="tab20b",
            clim=(plot_times.min(), plot_scores.max()),
            norm=MidpointNormalize(
                midpoint=0, vmin=plot_scores.min(), vmax=plot_scores.max()
            ),
        )

        for i, name in enumerate(labels):
            plt.annotate(name, (plot_scores[i], plot_times[i]))

        plt.title("JPAMB Test Scores", pad=15.0)
        plt.xlabel("Test Score")
        plt.ylabel("Analyzer Relative Execution Time")
        plt.show()

    if directory:
        scores, times, labels = compare_reports(directory)
        plot_directory(scores, times, labels)

    if report:
        info, method_values, total_values = parse_report(report)

        scores = []
        times = []
        labels = []
        classes = []

        for methodid, correct in ctx.obj.case_methods():
            method = method_values[str(methodid)]
            scores.append(method.score)
            times.append(method.time)
            labels.append(methodid.extension.encode())
            classes.append(str(methodid.classname))

        plot_scores(scores, times, labels, classes)


@cli.command()
@click.option(
    "--with-python/--no-with-python",
    "-W/-noW",
    help="the analysis is a python script, which should run in the same interpreter as jpamb.",
    default=None,
)
@click.option(
    "--stepwise / --no-stepwise",
    help="continue from last failure",
)
@click.option(
    "--timeout",
    show_default=True,
    default=2.0,
    help="timeout in seconds.",
)
@click.option(
    "--filter",
    "-f",
    help="A regular expression which filter the methods to run on.",
    callback=re_parser,
)
@click.option(
    "--report",
    "-r",
    default="-",
    type=click.File(mode="w"),
    help="A file to write the report to. (Good for golden testing)",
)
@click.pass_obj
def jfuzz(suite, report, filter, timeout, stepwise, with_python):
    """run fuzzer on alarm reports generated by jpamb analyze."""

    alarm_file = "jpamb/jfuzzer/report_preprocess/distributions_in_pmd.csv"
    CAMPAIGN_ROUNDS = 10

    # 2. load the fuzzer (interpreter)
    interpreter_program = "solutions/fuzzer_interpreter.py"
    program = resolve_cmd((interpreter_program,), with_python)

    # 3. load the report, pre-process, etc.
    p = Parser(alarm_file)
    alarms = p.parse()

    # r is an output formatter
    r = Reporter(report)
    
    total_prompt_tokens = 0
    total_response_tokens = 0
    total_total_tokens = 0

    last_campaign = None
    if stepwise:
        try:
            with open(".jfuzz-stepwise") as f:
                last_campaign = model.Case.decode(f.read())
        except ValueError as e:
            log.warning(e)
            last_campaign = None
        except IOError:
            last_campaign = None

    print(f"ALARMS {alarms[0]}")
    
    print("\n==================== STARTING JFUZZ ====================")
    print(f"Loaded alarms: first alarm --> {alarms[0]}")
    print("========================================================\n")

    # collect all fuzzing results for analysis
    fuzzing_result: list[dict] = []

    # 4. run the fuzzer main loop, and classify results
    for item in alarms:
        alarm_hit = 0

        if last_campaign and last_campaign != item:
            continue
        last_campaign = None

        if filter and not filter.search(str(item)):
            continue
        
        print(f"\n==================== NEW CASE ====================")
        print(f"Target: {item}")
        print("=================================================\n")

        start = time.time()
        casegen_time = []

        with r.context(f"Case {item}"):
            case_generator = CaseGenerator(suite ,item)

            # print(f"======== METHODID {item.methodid} ========")

            for round in range(CAMPAIGN_ROUNDS):
                print(f"\n==================== ROUND {round} ====================")
                oracle = Oracle(item.result)
                target_hit_this_round = False
                get_start = time.time()

                # fuzzing_test_cases = case_generator.generate_new_cases()
                fuzzing_test_cases, usage = case_generator.generate_llm_cases(
                    count=2,
                    previous_results=fuzzing_result[-20:],
                )
                # print("fuzzing cases", fuzzing_test_cases)
                print("========================================================")
                
                if usage:
                    used_prompt = usage.prompt_token_count or 0
                    used_response = usage.candidates_token_count or 0
                    used_total = usage.total_token_count or (used_prompt + used_response)

                    total_prompt_tokens += used_prompt
                    total_response_tokens += used_response
                    total_total_tokens += used_total

                    print(
                        f"[TOKENS] Round {round} | "
                        f"prompt={used_prompt:,} | response={used_response:,} | total={used_total:,} | "
                        f"cumulative={total_total_tokens:,}"
                    )
                else:
                    print("[TOKENS] No usage metadata returned for this LLM call.")
                    
                
                gen_end = time.time()
                gen_time = gen_end - get_start
                casegen_time.append(gen_time)
                
                print(f"[DEBUG] Case generation took {gen_time:.4f}s "
                    f"and produced {len(fuzzing_test_cases)} cases.") 

                print(
                    f"Starting round {round} for issue {item.methodid} "
                    f"with {len(fuzzing_test_cases)} cases"
                )

                for case in fuzzing_test_cases:
                    print(f"\n========== RUNNING TESTCASE ==========")
                    print(f"Input:  {case.encode()}")
                    print(f"Method: {item.methodid.encode()}")
                    print("======================================")

                    try:
                        out = r.run(
                            program + (item.methodid.encode(), case.encode()),
                            timeout=timeout,
                        )
                        
                        # stderr = r.stderr   # depending on how Reporter stores it
                        # stack_trace = extract_stack_frames(stderr)
                        # opcode_trace = extract_opcode_sequence(stderr)

                        print(f"[EXEC RESULT]: {out}")
                        result = out.splitlines()[-1].strip()
                        try: 
                            parsed = json.loads(out.splitlines()[-1])
                            result = parsed["result"]
                            opcodes = parsed["executed_opcodes"]
                            print(f"[GOTOPCODES]: {opcodes}")
                        except:
                            result = out.splitlines()[-1].strip()
                            opcodes = []
                            
                    except subprocess.TimeoutExpired:
                        result = "*"
                        
                    except subprocess.CalledProcessError as e:
                        log.error(e)
                        result = "failure"
                        
                    classification = oracle.classify(result)

                    fuzzing_result.append({
                        "method": str(item.methodid),
                        "round": round,
                        "input": case.encode(),
                        "output": result,
                        "classification": classification,
                        # "opcodes": opcode_trace
                        })


                    saver(item, round, case.encode(), classification)

                    r.output(
                        f"Original report: {item.result!r} \n"
                        f"round {round} result: {result!r} "
                        f"({classification})"
                    )

                    if item.result == result:
                        alarm_hit += 1

                    if stepwise and item.result != result:
                        with open(".jfuzz-stepwise", "w") as f:
                            # assumes item has encode(); if not, adjust accordingly
                            f.write(item.encode())
                        sys.exit(-1)

                    if classification == "TARGET_HIT":
                        print("\n========== TARGET HIT ==========")
                        print("Alarm reproduced. Stopping this round.")
                        print("================================")
                        target_hit_this_round = True
                        break
                

                if target_hit_this_round:
                    print("\n========== FULL STOP ==========")
                    print("Target alarm reproduced. Ending fuzzing for this issue.")
                    print("================================")
                    break

            
        end = time.time()
        print(f"Fuzzing for issue {item.methodid} completed in {end - start} seconds.")
        # r.output(f"Alarm hit {alarm_hit}/{CAMPAIGN_ROUNDS}")

        Path(".jfuzz-stepwise").unlink(True)
        
    print("\n==================== TOKEN SUMMARY ====================")
    print(f"Total prompt tokens:   {total_prompt_tokens:,}")
    print(f"Total response tokens: {total_response_tokens:,}")
    print(f"Total combined tokens: {total_total_tokens:,}")
    print("=======================================================\n")

    # classify results with analyzer
    pruned_results = analyzer.analyze_results(fuzzing_result)
    log.info(f"Analyzer produced results: {pruned_results}")


if __name__ == "__main__":
    cli()
